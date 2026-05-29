require('dotenv').config();

const express    = require('express');
const cors       = require('cors');
const path       = require('path');
const whois      = require('whois-json');
const cron       = require('node-cron');
const { Pool }   = require('pg');
const { Resend } = require('resend');

const app  = express();
const port = process.env.PORT || 3000;

// ─── Middlewares ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// Sert le fichier index.html statique à la racine
app.use(express.static(path.join(__dirname)));

// ─── Base de données PostgreSQL ────────────────────────────────────────────────
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Crée la table si elle n'existe pas encore
async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS subscriptions (
      id         SERIAL PRIMARY KEY,
      domain     VARCHAR(255) NOT NULL,
      email      VARCHAR(255) NOT NULL,
      active     BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(domain, email)
    )
  `);
  console.log('✅ Base de données prête');
}

// ─── Service e-mail (Resend) ───────────────────────────────────────────────────
const resend = new Resend(process.env.RESEND_API_KEY);

async function sendAlertEmail(email, domain) {
  await resend.emails.send({
    from: process.env.EMAIL_FROM,      // ex: alertes@tondomaine.com
    to:   email,
    subject: `🟢 ${domain} est maintenant disponible !`,
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:2rem">
        <h2 style="color:#34c97a">Bonne nouvelle !</h2>
        <p>Le domaine que vous surveilliez est désormais disponible :</p>
        <div style="background:#f0faf5;border-radius:8px;padding:1rem 1.5rem;margin:1.5rem 0">
          <strong style="font-size:1.3rem;font-family:monospace">${domain}</strong>
        </div>
        <p>Dépêchez-vous de l'enregistrer avant qu'il ne soit pris !</p>
        <a href="https://www.namecheap.com/domains/registration/results/?domain=${domain}"
           style="display:inline-block;background:#4f8ef7;color:white;padding:0.75rem 1.5rem;
                  border-radius:8px;text-decoration:none;font-weight:500;margin-top:0.5rem">
          Enregistrer ce domaine →
        </a>
        <p style="color:#999;font-size:0.8rem;margin-top:2rem">
          Vous recevez cet e-mail car vous avez activé une alerte sur DomainWatch.<br/>
          Votre alerte a été désactivée automatiquement.
        </p>
      </div>
    `
  });
}

// ─── Vérification WHOIS ────────────────────────────────────────────────────────

// Analyse la réponse WHOIS pour déterminer si un domaine est disponible
function parseDomainAvailability(whoisData) {
  // Si le WHOIS ne retourne rien de significatif → domaine disponible
  if (!whoisData || Object.keys(whoisData).length === 0) {
    return { available: true };
  }

  const raw = JSON.stringify(whoisData).toLowerCase();

  // Signaux de disponibilité explicites
  const freeSignals = [
    'no match',
    'not found',
    'no entries found',
    'status: free',
    'status: available',
    'object does not exist',
    'no object found'
  ];
  if (freeSignals.some(s => raw.includes(s))) {
    return { available: true };
  }

  // Signaux d'enregistrement
  const takenSignals = [
    'registrar',
    'creation date',
    'created',
    'registrant',
    'name server',
    'nameserver',
    'status: active',
    'status: ok'
  ];
  const isTaken = takenSignals.some(s => raw.includes(s));

  // Date d'expiration (si disponible)
  const expiry =
    whoisData.registryExpiryDate ||
    whoisData.expiresOn ||
    whoisData.expirationDate ||
    whoisData['expiry date'] ||
    whoisData['paid-till'] ||
    null;

  return {
    available: !isTaken,
    expiry: expiry ? new Date(expiry).toLocaleDateString('fr-FR') : null
  };
}

// ─── Route GET /api/check ──────────────────────────────────────────────────────
app.get('/api/check', async (req, res) => {
  const { domain } = req.query;

  if (!domain || !/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/.test(domain)) {
    return res.status(400).json({ error: 'Nom de domaine invalide' });
  }

  try {
    const whoisData = await whois(domain);
    const result    = parseDomainAvailability(whoisData);
    return res.json(result);
  } catch (err) {
    console.error(`Erreur WHOIS pour ${domain}:`, err.message);
    return res.status(500).json({ error: 'Impossible de vérifier ce domaine' });
  }
});

// ─── Route POST /api/subscribe ─────────────────────────────────────────────────
app.post('/api/subscribe', async (req, res) => {
  const { domain, email } = req.body;

  // Validations basiques
  if (!domain || !email) {
    return res.status(400).json({ error: 'Domaine et e-mail requis' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Adresse e-mail invalide' });
  }
  if (!/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/.test(domain)) {
    return res.status(400).json({ error: 'Nom de domaine invalide' });
  }

  try {
    // INSERT ou réactivation si l'abonnement existait déjà
    await db.query(`
      INSERT INTO subscriptions (domain, email, active)
      VALUES ($1, $2, TRUE)
      ON CONFLICT (domain, email)
      DO UPDATE SET active = TRUE, created_at = NOW()
    `, [domain.toLowerCase(), email.toLowerCase()]);

    console.log(`📬 Nouvel abonnement : ${email} surveille ${domain}`);
    return res.json({ success: true });
  } catch (err) {
    console.error('Erreur DB subscribe:', err.message);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── Route GET /api/subscriptions (debug — à retirer en prod) ─────────────────
app.get('/api/subscriptions', async (req, res) => {
  const { rows } = await db.query('SELECT * FROM subscriptions ORDER BY created_at DESC');
  res.json(rows);
});

// ─── Cron job — vérification toutes les heures ─────────────────────────────────
cron.schedule('0 * * * *', async () => {
  console.log(`\n🔄 [${new Date().toISOString()}] Lancement du cron job…`);

  let rows;
  try {
    const result = await db.query(
      'SELECT DISTINCT domain FROM subscriptions WHERE active = TRUE'
    );
    rows = result.rows;
  } catch (err) {
    console.error('Erreur lecture DB (cron):', err.message);
    return;
  }

  for (const { domain } of rows) {
    try {
      const whoisData = await whois(domain);
      const { available } = parseDomainAvailability(whoisData);

      if (available) {
        console.log(`✅ ${domain} est maintenant disponible !`);

        // Récupère tous les e-mails abonnés à ce domaine
        const { rows: subs } = await db.query(
          'SELECT email FROM subscriptions WHERE domain = $1 AND active = TRUE',
          [domain]
        );

        // Envoie un e-mail à chaque abonné
        for (const { email } of subs) {
          try {
            await sendAlertEmail(email, domain);
            console.log(`  📧 Alerte envoyée à ${email}`);
          } catch (mailErr) {
            console.error(`  ❌ Erreur envoi mail à ${email}:`, mailErr.message);
          }
        }

        // Désactive les abonnements pour ce domaine
        await db.query(
          'UPDATE subscriptions SET active = FALSE WHERE domain = $1',
          [domain]
        );
      } else {
        console.log(`⏳ ${domain} toujours pris`);
      }

      // Pause 1 seconde entre chaque domaine pour éviter d'être bloqué
      await new Promise(r => setTimeout(r, 1000));

    } catch (err) {
      console.error(`Erreur cron pour ${domain}:`, err.message);
    }
  }

  console.log('✔️  Cron job terminé\n');
});

// ─── Démarrage ─────────────────────────────────────────────────────────────────
async function start() {
  await initDB();
  app.listen(port, () => {
    console.log(`🚀 DomainWatch en ligne sur http://localhost:${port}`);
    console.log(`   Cron job actif — vérification toutes les heures`);
  });
}








// ─── Route de test cron (à supprimer en prod) ─────────────────────────────────
app.get('/api/test-cron', async (req, res) => {
  const { rows } = await db.query(
    'SELECT email, domain FROM subscriptions WHERE active = TRUE LIMIT 1'
  );
  if (rows.length === 0) return res.json({ message: 'Aucun abonnement actif' });

  const { email, domain } = rows[0];
  try {
    await sendAlertEmail(email, domain);
    res.json({ success: true, message: `E-mail envoyé à ${email} pour ${domain}` });
  } catch (err) {
    res.json({ error: err.message });
  }
});


start();
