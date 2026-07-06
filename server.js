require('dotenv').config();

const express    = require('express');
const cors       = require('cors');
const cookieParser = require('cookie-parser');
const path       = require('path');
const crypto     = require('crypto');
const whois      = require('whois-json');
const cron       = require('node-cron');
const { Pool }   = require('pg');
const { Resend } = require('resend');
const { initializeApp, cert, applicationDefault } = require('firebase-admin/app');
const { getMessaging } = require('firebase-admin/messaging');

const app  = express();
const port = process.env.PORT || 3000;

// ─── Middlewares ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname)));

// ─── Base de données PostgreSQL ────────────────────────────────────────────────
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS subscriptions (
      id          SERIAL PRIMARY KEY,
      domain      VARCHAR(255) NOT NULL,
      email       VARCHAR(255) NOT NULL,
      active      BOOLEAN DEFAULT TRUE,
      created_at  TIMESTAMPTZ DEFAULT NOW(),
      last_status VARCHAR(32) DEFAULT 'taken',
      UNIQUE(domain, email)
    )
  `);
  await db.query(`ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS last_status VARCHAR(32) DEFAULT 'taken'`);
  await db.query(`ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS pending_confirmation_since TIMESTAMPTZ`);
  await db.query(`ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS notified_at TIMESTAMPTZ`);
  await db.query(`
    CREATE TABLE IF NOT EXISTS magic_links (
      id         SERIAL PRIMARY KEY,
      email      VARCHAR(255) NOT NULL,
      token      VARCHAR(255) NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      used       BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      purpose    VARCHAR(20) DEFAULT 'login'
    )
  `);
  await db.query(`ALTER TABLE magic_links ADD COLUMN IF NOT EXISTS purpose VARCHAR(20) DEFAULT 'login'`);
  await db.query(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id             SERIAL PRIMARY KEY,
      email          VARCHAR(255) NOT NULL,
      key            VARCHAR(255) NOT NULL UNIQUE,
      label          VARCHAR(255),
      requests_today INTEGER DEFAULT 0,
      last_reset     DATE DEFAULT CURRENT_DATE,
      active         BOOLEAN DEFAULT TRUE,
      created_at     TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS user_settings (
      email                 VARCHAR(255) PRIMARY KEY,
      email_alerts_enabled  BOOLEAN DEFAULT TRUE,
      grace_alerts_enabled  BOOLEAN DEFAULT TRUE,
      updated_at            TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS push_tokens (
      token      VARCHAR(255) PRIMARY KEY,
      email      VARCHAR(255) NOT NULL,
      platform   VARCHAR(20),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await db.query(`CREATE INDEX IF NOT EXISTS idx_push_tokens_email ON push_tokens (email)`);
  await db.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      token      VARCHAR(255) PRIMARY KEY,
      email      VARCHAR(255) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL
    )
  `);
  await db.query(`CREATE INDEX IF NOT EXISTS idx_sessions_email ON sessions (email)`);
  console.log('✅ Base de données prête');
}

async function getUserSettings(email) {
  const { rows } = await db.query('SELECT * FROM user_settings WHERE email = $1', [email.toLowerCase()]);
  if (rows.length > 0) return rows[0];
  return { email: email.toLowerCase(), email_alerts_enabled: true, grace_alerts_enabled: true };
}

// ─── Token de review permanent pour Google Play ────────────────────────────────
const REVIEW_EMAIL = 'playstore-review@doomname.com';
const REVIEW_TOKEN = 'google-play-review-static-token-doomname-2026';

async function ensureReviewToken() {
  const { rows } = await db.query('SELECT * FROM magic_links WHERE token = $1', [REVIEW_TOKEN]);
  if (rows.length === 0) {
    await db.query(
      'INSERT INTO magic_links (email, token, expires_at, used) VALUES ($1, $2, $3, FALSE)',
      [REVIEW_EMAIL, REVIEW_TOKEN, new Date('2040-01-01')]
    );
    console.log('✅ Token de review Google Play créé');
  }
}

// ─── Sessions persistantes (cookie httpOnly 90 jours) ──────────────────────────
const SESSION_COOKIE = 'dw_session';
const SESSION_MS = 90 * 24 * 60 * 60 * 1000;

async function createSession(res, email) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + SESSION_MS);
  await db.query('INSERT INTO sessions (token, email, expires_at) VALUES ($1, $2, $3)', [token, email.toLowerCase(), expiresAt]);
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,   // inaccessible au JS → protège contre le vol par XSS
    secure: true,     // HTTPS uniquement
    sameSite: 'lax',
    maxAge: SESSION_MS,
    path: '/',
  });
}

// ─── Service e-mail (Resend) ───────────────────────────────────────────────────
const resend = new Resend(process.env.RESEND_API_KEY);
const SITE_URL = 'https://doomname.com';
// Expéditeur unique et cohérent pour TOUS les envois (délivrabilité).
const EMAIL_FROM = process.env.EMAIL_FROM || 'DoomName <noreply@alert.doomname.com>';

// Version texte brut (multipart) dérivée du HTML — Gmail privilégie le multipart.
function htmlToText(html) {
  return html
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|h[1-6]|li|tr)>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>').replace(/&#39;/gi, "'")
    .split('\n').map(l => l.trim()).join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

// Magic link de suppression de compte valable 7 jours (purpose='delete').
async function createDeleteToken(email) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  await db.query(
    "INSERT INTO magic_links (email, token, expires_at, purpose) VALUES ($1, $2, $3, 'delete')",
    [email.toLowerCase(), token, expiresAt]
  );
  return token;
}

// Footer légal ajouté à TOUS les e-mails.
function legalFooter(deleteUrl) {
  return `
    <p style="color:#b0b0b0;font-size:0.72rem;margin-top:2.5rem;border-top:1px solid #eee;padding-top:1rem;line-height:1.6">
      Ce message a été envoyé via <a href="${SITE_URL}" style="color:#999">doomname.com</a>.<br>
      Si vous n'êtes pas à l'origine de cette inscription, vous pouvez <a href="${deleteUrl}" style="color:#999">supprimer votre compte ici</a>.
    </p>`;
}

// Envoi centralisé : from cohérent, footer légal + lien de suppression 7 jours,
// version texte brut (multipart), et en-tête List-Unsubscribe sur les e-mails
// d'alerte uniquement (opts.listUnsub) — jamais sur les magic links.
async function sendEmail(email, subject, innerHtml, opts = {}) {
  const { listUnsub = false } = opts;
  let footer = '';
  let deleteUrl = '';
  try {
    const token = await createDeleteToken(email);
    deleteUrl = `${SITE_URL}/manage.html?token=${token}`;
    footer = legalFooter(deleteUrl);
  } catch (err) {
    console.error('  ⚠️  Footer de suppression non généré:', err.message);
  }

  const html = `
      <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:2rem">
        ${innerHtml}
        ${footer}
      </div>`;
  const text = htmlToText(innerHtml) +
    (deleteUrl ? `\n\n—\nEnvoyé via doomname.com\nGérer ou supprimer votre compte : ${deleteUrl}` : '');

  const headers = {};
  if (listUnsub && deleteUrl) {
    headers['List-Unsubscribe'] = `<${deleteUrl}>`;
    headers['List-Unsubscribe-Post'] = 'List-Unsubscribe=One-Click';
  }

  await resend.emails.send({
    from: EMAIL_FROM,
    to:   email,
    subject,
    html,
    text,
    ...(Object.keys(headers).length ? { headers } : {}),
  });
}

async function sendAlertEmail(email, domain) {
  await sendEmail(email, `🟢 ${domain} est disponible`, `
    <h2 style="color:#34c97a">Bonne nouvelle !</h2>
    <p>Le domaine que vous surveilliez est désormais disponible :</p>
    <div style="background:#f0faf5;border-radius:8px;padding:1rem 1.5rem;margin:1.5rem 0">
      <strong style="font-size:1.3rem;font-family:monospace">${domain}</strong>
    </div>
    <p>Réservez-le rapidement auprès du registrar de votre choix avant qu'il ne soit pris !</p>
    <p style="color:#999;font-size:0.8rem;margin-top:2rem">
      Vous recevez cet e-mail car vous avez activé une alerte sur DoomName.
    </p>`, { listUnsub: true });
}

// ─── Firebase Admin (push web via FCM) ─────────────────────────────────────────
// Initialisé depuis la variable d'env FIREBASE_SERVICE_ACCOUNT (contenu JSON de
// la clé de service du projet domainwatch-7da80), avec repli sur le fichier
// pointé par GOOGLE_APPLICATION_CREDENTIALS en développement local.
let firebaseReady = false;
try {
  let credential = null;
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    credential = cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT));
  } else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    credential = applicationDefault();
  }
  if (credential) {
    initializeApp({ credential });
    firebaseReady = true;
    console.log('✅ Firebase Admin initialisé (push web FCM disponible)');
  } else {
    console.warn('⚠️  FIREBASE_SERVICE_ACCOUNT absent : push web FCM désactivé');
  }
} catch (err) {
  console.error('❌ Init Firebase Admin échouée (push web désactivé):', err.message);
}

// ─── Notifications push ────────────────────────────────────────────────────────
// Deux canaux selon la plateforme du token :
//   • app mobile (Expo)  → API HTTPS Expo Push (exp.host)
//   • web / PWA (FCM)    → Firebase Admin (FCM v1)
// On distingue par la colonne `platform`, avec repli sur la forme du token
// (les tokens Expo commencent par "ExponentPushToken").
async function sendExpoPush(tokens, { title, body, data }) {
  if (tokens.length === 0) return;
  const messages = tokens.map(to => ({
    to, sound: 'default', title, body, data: data || {}, channelId: 'default',
  }));
  try {
    const res = await fetch('https://exp.host/--/api/v2/push/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(messages),
    });
    const json = await res.json();
    const tickets = Array.isArray(json?.data) ? json.data : [];
    for (let i = 0; i < tickets.length; i++) {
      if (tickets[i]?.details?.error === 'DeviceNotRegistered') {
        await db.query('DELETE FROM push_tokens WHERE token = $1', [tokens[i]]);
      }
    }
  } catch (err) {
    console.error(`  ❌ Erreur envoi Expo push:`, err.message);
  }
}

async function sendWebPush(tokens, { title, body, data }) {
  if (tokens.length === 0) return;
  if (!firebaseReady) {
    console.warn(`  ⚠️  ${tokens.length} token(s) web ignoré(s) : Firebase Admin non configuré`);
    return;
  }
  // Message DATA-ONLY : c'est sw.js (onBackgroundMessage) qui affiche la
  // notification, ce qui évite un doublon avec l'affichage auto du SDK.
  // FCM n'accepte que des valeurs string dans `data`.
  const stringData = { title, body, url: '/manage.html' };
  for (const [k, v] of Object.entries(data || {})) stringData[k] = String(v);
  try {
    const res = await getMessaging().sendEachForMulticast({
      tokens,
      data: stringData,
      webpush: { headers: { Urgency: 'high' } },
    });
    // Purge des tokens web devenus invalides.
    res.responses.forEach((r, i) => {
      const code = r.error?.code;
      if (code === 'messaging/registration-token-not-registered' || code === 'messaging/invalid-registration-token') {
        db.query('DELETE FROM push_tokens WHERE token = $1', [tokens[i]]).catch(() => {});
      }
    });
  } catch (err) {
    console.error(`  ❌ Erreur envoi web push (FCM):`, err.message);
  }
}

async function sendPushNotification(email, payload) {
  let rows;
  try {
    ({ rows } = await db.query('SELECT token, platform FROM push_tokens WHERE email = $1', [email.toLowerCase()]));
  } catch (err) {
    console.error(`  ❌ Erreur lecture push_tokens pour ${email}:`, err.message);
    return;
  }
  if (rows.length === 0) return;

  const isWeb = r => r.platform === 'web' || (r.platform == null && !String(r.token).startsWith('ExponentPushToken'));
  const webTokens  = rows.filter(isWeb).map(r => r.token);
  const expoTokens = rows.filter(r => !isWeb(r)).map(r => r.token);

  await Promise.all([
    sendExpoPush(expoTokens, payload),
    sendWebPush(webTokens, payload),
  ]);
  console.log(`  📲 Push envoyé à ${email} (${expoTokens.length} mobile, ${webTokens.length} web)`);
}

const STATUS_LABELS = {
  gracePeriod:      { title: 'en grâce de renouvellement',     detail: "Son propriétaire n'a pas encore renouvelé le domaine. Il dispose d'un délai pour le faire avant qu'il ne passe en période de rédemption." },
  redemptionPeriod: { title: 'en période de rédemption',        detail: "Le domaine n'a pas été renouvelé et entre dans sa dernière phase avant suppression. Il pourrait bientôt devenir disponible." },
  pendingDelete:    { title: 'sur le point d\'être supprimé',   detail: "Le domaine est en cours de suppression définitive par le registre. Il devrait devenir disponible très prochainement." },
};

async function sendStatusChangeEmail(email, domain, status) {
  const info = STATUS_LABELS[status];
  if (!info) return;
  await sendEmail(email, `🟠 ${domain} est désormais ${info.title}`, `
    <h2 style="color:#ba7517">Changement d'état détecté</h2>
    <p>Le domaine que vous surveillez vient de changer de statut :</p>
    <div style="background:#fbf3e8;border-radius:8px;padding:1rem 1.5rem;margin:1.5rem 0">
      <strong style="font-size:1.2rem;font-family:monospace">${domain}</strong>
      <p style="margin-top:0.5rem;color:#555">${info.detail}</p>
    </div>
    <p>Son ancien propriétaire semble avoir abandonné son renouvellement. Restez attentif, une alerte vous sera envoyée dès qu'il sera totalement disponible.</p>
    <p style="color:#999;font-size:0.8rem;margin-top:2rem">
      Vous recevez cet e-mail car vous surveillez ce domaine sur DoomName.
    </p>`, { listUnsub: true });
}

async function sendStatusChangePush(email, domain, status) {
  const info = STATUS_LABELS[status];
  if (!info) return;
  await sendPushNotification(email, {
    title: `🟠 ${domain} est ${info.title}`,
    body: info.detail,
    data: { type: 'status_change', domain, status, screen: 'manage' },
  });
}

// « Dommage » : un domaine signalé disponible vient d'être repris par quelqu'un.
async function sendMissedEmail(email, domain) {
  await sendEmail(email, `${domain} vient d'être repris`, `
    <h2 style="color:#e24b4a">Dommage…</h2>
    <p>Le domaine que vous surveilliez vient d'être enregistré :</p>
    <div style="background:#fdeceb;border-radius:8px;padding:1rem 1.5rem;margin:1.5rem 0">
      <strong style="font-size:1.3rem;font-family:monospace">${domain}</strong>
    </div>
    <p>Quelqu'un a enregistré ce domaine avant vous. <strong>Votre alerte reste active</strong> : nous continuons à le surveiller et vous préviendrons s'il se libère de nouveau.</p>
    <p style="color:#999;font-size:0.8rem;margin-top:2rem">
      Vous recevez cet e-mail car vous surveillez ce domaine sur DoomName.
    </p>`, { listUnsub: true });
}

async function sendMissedPush(email, domain) {
  await sendPushNotification(email, {
    title: `😔 ${domain} vient d'être pris`,
    body: 'Quelqu\'un a enregistré ce domaine avant vous. Votre alerte reste active.',
    data: { type: 'domain_taken', domain, screen: 'manage', filter: 'active' },
  });
}

async function sendAccountDeleteEmail(email, token) {
  const APP_URL = process.env.APP_URL || 'http://localhost:3000';
  const confirmLink = `${APP_URL}/api/account/confirm-delete?token=${token}`;
  await sendEmail(email, '⚠️ Confirmer la suppression de votre compte DoomName', `
    <h2 style="color:#e24b4a">Suppression de compte</h2>
    <p>Une demande de suppression de compte a été effectuée pour cette adresse e-mail.</p>
    <p>Cette action supprimera <strong>définitivement</strong> tous les noms de domaine que vous surveillez. Elle est irréversible.</p>
    <a href="${confirmLink}"
       style="display:inline-block;background:#e24b4a;color:white;padding:0.75rem 1.5rem;
              border-radius:8px;text-decoration:none;font-weight:500;margin-top:1rem">
      Confirmer la suppression →
    </a>
    <p style="color:#999;font-size:0.85rem;margin-top:1.5rem">Ce lien est valable 20 minutes. Si vous n'êtes pas à l'origine de cette demande, ignorez cet e-mail.</p>`);
}

async function sendMagicLinkEmail(email, token) {
  const APP_URL = process.env.APP_URL || 'http://localhost:3000';
  // Page https intermédiaire (les clients mail comme Gmail suppriment les
  // liens vers des schémas personnalisés type doomname://) : elle tente
  // d'ouvrir l'app sur mobile puis se replie automatiquement sur le site,
  // y compris sur un navigateur de bureau où l'app n'existe pas.
  const link = `${APP_URL}/open-app.html?token=${token}`;
  await sendEmail(email, 'Votre lien de connexion DoomName', `
    <h2 style="color:#d97757">Connexion à DoomName</h2>
    <p>Cliquez sur le bouton ci-dessous pour accéder à vos alertes.</p>
    <p style="color:#999;font-size:0.85rem">Ce lien est valable <strong>20 minutes</strong> et ne peut être utilisé qu'une seule fois.</p>
    <a href="${link}"
       style="display:inline-block;background:#d97757;color:white;padding:0.75rem 1.5rem;
              border-radius:8px;text-decoration:none;font-weight:500;margin-top:1rem">
      Accéder à DoomName →
    </a>
    <p style="color:#999;font-size:0.8rem;margin-top:2rem">
      Si vous n'avez pas demandé ce lien, ignorez cet e-mail.
    </p>`);
}

async function sendApiKeyEmail(email, key, label) {
  const APP_URL = process.env.APP_URL || 'http://localhost:3000';
  await sendEmail(email, '🔧 Votre clé API DoomName', `
    <h2 style="color:#d97757">Votre clé API DoomName</h2>
    <p>Voici votre clé API${label ? ` (${label})` : ''} :</p>
    <div style="background:#f5f4f0;border-radius:8px;padding:1rem 1.5rem;margin:1.5rem 0;font-family:monospace;font-size:0.95rem;word-break:break-all">
      ${key}
    </div>
    <p style="font-size:0.9rem">Utilisez-la dans le header de vos requêtes :</p>
    <div style="background:#1a1a18;color:#e8eaf0;border-radius:8px;padding:1rem 1.5rem;margin:1rem 0;font-family:monospace;font-size:0.82rem">
      Authorization: Bearer ${key}
    </div>
    <a href="${APP_URL}/docs.html"
       style="display:inline-block;background:#d97757;color:white;padding:0.75rem 1.5rem;
              border-radius:8px;text-decoration:none;font-weight:500;margin-top:0.5rem">
      Voir la documentation →
    </a>
    <p style="color:#999;font-size:0.8rem;margin-top:2rem">
      Limite : 100 requêtes par jour.<br/>
      Ne partagez pas cette clé publiquement.
    </p>`);
}

// ─── Cache WHOIS (évite le rate-limiting des registrars) ──────────────────────
const whoisCache = new Map();
const CACHE_DURATION_MS = 60 * 1000; // 60 secondes

// ─── Confirmation différée avant alerte "disponible" ───────────────────────────
// Certains domaines à forte valeur sont recapturés en quelques secondes par des
// bots de drop-catching dès leur libération. Plutôt que d'alerter dès la
// première détection "disponible" du cron horaire, on attend 10 minutes et on
// revérifie ce domaine précis avant de notifier — sans changer la fréquence du
// cron principal.
const CONFIRMATION_DELAY_MS = 10 * 60 * 1000; // 10 minutes

async function getWhoisWithCache(domain) {
  const cached = whoisCache.get(domain);
  if (cached && (Date.now() - cached.timestamp) < CACHE_DURATION_MS) {
    return cached.data;
  }
  const whoisData = await whois(domain);
  whoisCache.set(domain, { data: whoisData, timestamp: Date.now() });
  return whoisData;
}

// ─── Vérification WHOIS ────────────────────────────────────────────────────────
function parseDomainAvailability(whoisData) {
  if (!whoisData || Object.keys(whoisData).length === 0) return { available: true };

  const raw = JSON.stringify(whoisData).toLowerCase();

  // Détection de réponse suspecte/tronquée (signe de rate-limiting du registrar)
  const dataSize = JSON.stringify(whoisData).length;
  const hasMinimalFields = Object.keys(whoisData).length <= 2;
  if (dataSize < 100 && hasMinimalFields) {
    throw new Error('Réponse WHOIS suspecte (possible rate-limiting du registrar)');
  }

  const freeSignals = ['no match','not found','no entries found','status: free','status: available','object does not exist','no object found','not registered','available for registration','domain not found'];
  if (freeSignals.some(s => raw.includes(s))) return { available: true, status: 'available' };

  // Mots-clés indiquant un domaine enregistré — inclut les champs spécifiques
  // aux TLD à WHOIS minimaliste (.eu → "organisation"/"holder", .de → "nserver")
  const takenSignals = [
    'registrar', 'creation date', 'created', 'registrant', 'name server', 'nameserver',
    'status: active', 'status: ok', 'status: connect',
    'organisation', 'holder:', 'nserver:', 'tech-c:', 'admin-c:', 'mnt-by:',
    'registered on', 'changed:', 'source: ripe', 'source: denic',
  ];
  const hasTakenKeyword = takenSignals.some(s => raw.includes(s));

  // Repli conservateur : si aucun signal libre/pris ne correspond mais que la
  // réponse est très volumineuse (>600 chars et >5 champs), on suppose pris.
  // Seuil élevé pour éviter de déclarer "pris" des domaines libres dont le
  // registrar renvoie une réponse structurée mais vide de données d'enregistrement.
  const fieldCount = Object.keys(whoisData).length;
  const hasSubstantialData = fieldCount >= 6 && dataSize >= 600;

  const isTaken = hasTakenKeyword || hasSubstantialData;

  const expiry =
    whoisData.registryExpiryDate || whoisData.expiresOn ||
    whoisData.expirationDate || whoisData['expiry date'] ||
    whoisData['paid-till'] || null;

  // Détection des statuts EPP de fin de vie d'un domaine (grace period / redemption / pending delete)
  // afin d'alerter les utilisateurs avant la libération effective du domaine.
  let status = isTaken ? 'taken' : 'available';
  if (isTaken) {
    if (raw.includes('pendingdelete') || raw.includes('pending delete')) status = 'pendingDelete';
    else if (raw.includes('redemptionperiod') || raw.includes('redemption period')) status = 'redemptionPeriod';
    else if (raw.includes('autorenewperiod') || raw.includes('auto-renew') || raw.includes('renewperiod') || raw.includes('grace period')) status = 'gracePeriod';
  }

  return {
    available: !isTaken,
    status,
    expiry: expiry ? new Date(expiry).toLocaleDateString('fr-FR') : null
  };
}

// ─── Middleware API Key ────────────────────────────────────────────────────────
const DAILY_LIMIT = 100;

async function requireApiKey(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Clé API manquante. Header requis : Authorization: Bearer dk_...' });
  }

  const key = authHeader.slice(7).trim();

  try {
    const { rows } = await db.query(
      'SELECT * FROM api_keys WHERE key = $1 AND active = TRUE',
      [key]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Clé API invalide ou désactivée' });
    }

    const apiKey = rows[0];

    if (apiKey.last_reset < new Date().toISOString().slice(0, 10)) {
      await db.query(
        'UPDATE api_keys SET requests_today = 0, last_reset = CURRENT_DATE WHERE id = $1',
        [apiKey.id]
      );
      apiKey.requests_today = 0;
    }

    if (apiKey.requests_today >= DAILY_LIMIT) {
      return res.status(429).json({
        error: 'Limite journalière atteinte (100 requêtes/jour)',
        reset: 'Demain à minuit UTC'
      });
    }

    await db.query(
      'UPDATE api_keys SET requests_today = requests_today + 1 WHERE id = $1',
      [apiKey.id]
    );

    req.apiKey = apiKey;
    next();
  } catch (err) {
    console.error('Erreur middleware API key:', err.message);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
}

// ─── Route GET /api/check ──────────────────────────────────────────────────────
app.get('/api/check', async (req, res) => {
  const { domain } = req.query;
  if (!domain || !/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/.test(domain)) {
    return res.status(400).json({ error: 'Nom de domaine invalide' });
  }
  try {
    const whoisData = await getWhoisWithCache(domain);
    return res.json(parseDomainAvailability(whoisData));
  } catch (err) {
    console.error(`Erreur WHOIS pour ${domain}:`, err.message);
    return res.status(503).json({ error: 'Service WHOIS temporairement indisponible, réessayez dans une minute' });
  }
});

// Détecte immédiatement le statut WHOIS d'un domaine à l'ajout et l'enregistre,
// sans attendre le cron horaire. Si le domaine est déjà disponible, on le marque
// 'available' (+ notified_at) pour qu'il apparaisse aussitôt dans le filtre
// "Disponible". Robuste aux erreurs WHOIS (garde le défaut 'taken' le cas échéant).
// N'interfère pas avec la confirmation différée : on ne fait qu'écrire last_status.
// IMPORTANT : ne JAMAIS envoyer d'e-mail ni de push ici. Les notifications ne
// partent que du cron et des routes de test — l'ajout d'une surveillance (même
// 'available') reste totalement silencieux.
async function detectAndStoreStatus(domain, email) {
  try {
    const whoisData = await getWhoisWithCache(domain);
    const { available, status } = parseDomainAvailability(whoisData);
    if (available) {
      await db.query(
        "UPDATE subscriptions SET last_status = 'available', notified_at = NOW() WHERE domain = $1 AND email = $2",
        [domain, email]
      );
      return 'available';
    }
    const finalStatus = status || 'taken';
    await db.query(
      'UPDATE subscriptions SET last_status = $3, notified_at = NULL WHERE domain = $1 AND email = $2',
      [domain, email, finalStatus]
    );
    return finalStatus;
  } catch (err) {
    console.warn(`Détection de statut immédiate échouée pour ${domain}:`, err.message);
    return null;
  }
}

// ─── Route POST /api/subscribe ─────────────────────────────────────────────────
app.post('/api/subscribe', async (req, res) => {
  const { domain, email } = req.body;
  if (!domain || !email) return res.status(400).json({ error: 'Domaine et e-mail requis' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Adresse e-mail invalide' });
  if (!/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/.test(domain)) return res.status(400).json({ error: 'Nom de domaine invalide' });

  try {
    await db.query(`
      INSERT INTO subscriptions (domain, email, active)
      VALUES ($1, $2, TRUE)
      ON CONFLICT (domain, email)
      DO UPDATE SET active = TRUE, created_at = NOW()
    `, [domain.toLowerCase(), email.toLowerCase()]);
    console.log(`📬 Nouvel abonnement : ${email} surveille ${domain}`);
    const last_status = await detectAndStoreStatus(domain.toLowerCase(), email.toLowerCase());
    return res.json({ success: true, last_status });
  } catch (err) {
    console.error('Erreur DB subscribe:', err.message);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── Routes Magic Link ─────────────────────────────────────────────────────────
app.post('/api/auth/request', async (req, res) => {
  const { email } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Adresse e-mail invalide' });

  const token     = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 20 * 60 * 1000);

  try {
    await db.query('INSERT INTO magic_links (email, token, expires_at) VALUES ($1, $2, $3)', [email.toLowerCase(), token, expiresAt]);
    await sendMagicLinkEmail(email.toLowerCase(), token);
    console.log(`🔑 Magic link envoyé à ${email}`);
    return res.json({ success: true });
  } catch (err) {
    console.error('Erreur magic link:', err.message);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/auth/verify', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'Token manquant' });

  try {
    // Les tokens de suppression (purpose='delete') ne peuvent pas servir à se
    // connecter : ils sont gérés par le flux de confirmation de suppression.
    const { rows } = await db.query(
      "SELECT * FROM magic_links WHERE token = $1 AND used = FALSE AND expires_at > NOW() AND purpose IS DISTINCT FROM 'delete'",
      [token]
    );
    if (rows.length === 0) return res.status(401).json({ error: 'Lien invalide ou expiré' });

    // Le token de review Google Play reste toujours réutilisable
    if (token !== REVIEW_TOKEN) {
      await db.query('UPDATE magic_links SET used = TRUE WHERE token = $1', [token]);
    }

    // Ouvre une session persistante (cookie httpOnly) pour le web — évite de
    // redemander un magic link à chaque visite. Sans effet néfaste pour l'app.
    try { await createSession(res, rows[0].email); } catch (e) { console.error('createSession:', e.message); }

    return res.json({ success: true, email: rows[0].email });
  } catch (err) {
    console.error('Erreur verify token:', err.message);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Session en cours (cookie) — permet à manage.html de reconnecter sans magic link.
app.get('/api/auth/session', async (req, res) => {
  const token = req.cookies?.[SESSION_COOKIE];
  if (!token) return res.json({ authenticated: false });
  try {
    const { rows } = await db.query('SELECT email FROM sessions WHERE token = $1 AND expires_at > NOW()', [token]);
    if (rows.length === 0) return res.json({ authenticated: false });
    return res.json({ authenticated: true, email: rows[0].email });
  } catch (err) {
    console.error('Erreur session:', err.message);
    return res.json({ authenticated: false });
  }
});

// Déconnexion : révoque la session en base et efface le cookie.
app.post('/api/auth/logout', async (req, res) => {
  const token = req.cookies?.[SESSION_COOKIE];
  try { if (token) await db.query('DELETE FROM sessions WHERE token = $1', [token]); } catch {}
  res.clearCookie(SESSION_COOKIE, { path: '/' });
  return res.json({ success: true });
});

// ─── Routes de gestion des abonnements ────────────────────────────────────────
app.get('/api/manage/subscriptions', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'E-mail requis' });
  try {
    const { rows } = await db.query('SELECT id, domain, active, created_at, last_status, notified_at FROM subscriptions WHERE email = $1 ORDER BY created_at DESC', [email.toLowerCase()]);
    return res.json(rows);
  } catch (err) { return res.status(500).json({ error: 'Erreur serveur' }); }
});

app.patch('/api/manage/subscription/:id/toggle', async (req, res) => {
  const { id } = req.params;
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'E-mail requis' });

  try {
    const { rows: sub } = await db.query('SELECT active FROM subscriptions WHERE id = $1 AND email = $2', [id, email.toLowerCase()]);
    if (sub.length === 0) return res.status(404).json({ error: 'Abonnement introuvable' });

    if (!sub[0].active) {
      const { rows: countRows } = await db.query('SELECT COUNT(*) FROM subscriptions WHERE email = $1 AND active = TRUE', [email.toLowerCase()]);
      if (parseInt(countRows[0].count) >= 50) return res.status(400).json({ error: 'Limite de 50 surveillances actives atteinte' });
    }

    const result = await db.query('UPDATE subscriptions SET active = NOT active WHERE id = $1 AND email = $2 RETURNING active', [id, email.toLowerCase()]);
    return res.json({ success: true, active: result.rows[0].active });
  } catch (err) { return res.status(500).json({ error: 'Erreur serveur' }); }
});

app.delete('/api/manage/subscription/:id', async (req, res) => {
  const { id } = req.params;
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'E-mail requis' });

  try {
    const result = await db.query('DELETE FROM subscriptions WHERE id = $1 AND email = $2', [id, email.toLowerCase()]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Abonnement introuvable' });
    return res.json({ success: true });
  } catch (err) { return res.status(500).json({ error: 'Erreur serveur' }); }
});

app.post('/api/manage/subscribe', async (req, res) => {
  const { email, domain } = req.body;
  if (!email || !domain) return res.status(400).json({ error: 'E-mail et domaine requis' });
  if (!/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/.test(domain)) return res.status(400).json({ error: 'Nom de domaine invalide' });

  try {
    const { rows: activeRows } = await db.query('SELECT COUNT(*) FROM subscriptions WHERE email = $1 AND active = TRUE', [email.toLowerCase()]);
    if (parseInt(activeRows[0].count) >= 50) return res.status(400).json({ error: 'Limite de 50 surveillances actives atteinte' });

    const { rows: totalRows } = await db.query('SELECT COUNT(*) FROM subscriptions WHERE email = $1', [email.toLowerCase()]);
    if (parseInt(totalRows[0].count) >= 200) return res.status(400).json({ error: 'Limite de 200 domaines atteinte — supprimez des entrées pour en ajouter de nouvelles' });

    await db.query(`
      INSERT INTO subscriptions (domain, email, active) VALUES ($1, $2, TRUE)
      ON CONFLICT (domain, email) DO UPDATE SET active = TRUE, created_at = NOW()
    `, [domain.toLowerCase(), email.toLowerCase()]);

    console.log(`📬 Ajout depuis manage : ${email} surveille ${domain}`);
    const last_status = await detectAndStoreStatus(domain.toLowerCase(), email.toLowerCase());
    return res.json({ success: true, last_status });
  } catch (err) {
    console.error('Erreur manage/subscribe:', err.message);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── WHOIS complet (consultation depuis "mes alertes") ────────────────────────
app.get('/api/manage/whois', async (req, res) => {
  const { domain, email } = req.query;
  if (!domain || !email) return res.status(400).json({ error: 'Domaine et e-mail requis' });

  try {
    const { rows } = await db.query('SELECT id FROM subscriptions WHERE domain = $1 AND email = $2', [domain.toLowerCase(), email.toLowerCase()]);
    if (rows.length === 0) return res.status(404).json({ error: "Ce domaine n'est pas dans votre liste de surveillance" });

    const whoisData = await getWhoisWithCache(domain.toLowerCase());
    const raw = Object.entries(whoisData || {}).map(([k, v]) => `${k}: ${v}`).join('\n') || 'Aucune donnée WHOIS disponible.';
    return res.json({ domain, raw });
  } catch (err) {
    return res.status(503).json({ error: 'Service WHOIS temporairement indisponible' });
  }
});

// ─── Export CSV ─────────────────────────────────────────────────────────────────
app.get('/api/manage/export', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'E-mail requis' });

  try {
    const { rows } = await db.query('SELECT domain, active, last_status, created_at FROM subscriptions WHERE email = $1 ORDER BY created_at DESC', [email.toLowerCase()]);
    const header = 'domain,active,status,created_at';
    const lines  = rows.map(r => `${r.domain},${r.active},${r.last_status || ''},${r.created_at.toISOString()}`);
    const csv = [header, ...lines].join('\n');

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="doomname-alertes.csv"');
    return res.send(csv);
  } catch (err) {
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── Import CSV ─────────────────────────────────────────────────────────────────
app.post('/api/manage/import', async (req, res) => {
  const { email, domains } = req.body;
  if (!email || !Array.isArray(domains) || domains.length === 0) {
    return res.status(400).json({ error: 'E-mail et liste de domaines requis' });
  }

  const domainRegex = /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/;
  const validDomains = [...new Set(domains.map(d => String(d).toLowerCase().trim()))].filter(d => domainRegex.test(d));

  try {
    const { rows: totalRows } = await db.query('SELECT COUNT(*) FROM subscriptions WHERE email = $1', [email.toLowerCase()]);
    const currentTotal = parseInt(totalRows[0].count);
    const room = Math.max(0, 200 - currentTotal);

    const toImport = validDomains.slice(0, room);
    let imported = 0;
    for (const domain of toImport) {
      const result = await db.query(`
        INSERT INTO subscriptions (domain, email, active) VALUES ($1, $2, TRUE)
        ON CONFLICT (domain, email) DO NOTHING
      `, [domain, email.toLowerCase()]);
      if (result.rowCount > 0) imported++;
    }

    const skipped = domains.length - imported;
    console.log(`📬 Import CSV : ${imported} domaine(s) ajoutés pour ${email}`);
    return res.json({ success: true, imported, skipped });
  } catch (err) {
    console.error('Erreur import CSV:', err.message);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── Préférences d'alertes ──────────────────────────────────────────────────────
app.get('/api/manage/settings', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'E-mail requis' });
  try {
    const settings = await getUserSettings(email);
    return res.json({
      email_alerts_enabled: settings.email_alerts_enabled,
      grace_alerts_enabled: settings.grace_alerts_enabled
    });
  } catch (err) {
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.patch('/api/manage/settings', async (req, res) => {
  const { email, email_alerts_enabled, grace_alerts_enabled } = req.body;
  if (!email) return res.status(400).json({ error: 'E-mail requis' });

  try {
    const current = await getUserSettings(email);
    const next = {
      email_alerts_enabled: typeof email_alerts_enabled === 'boolean' ? email_alerts_enabled : current.email_alerts_enabled,
      grace_alerts_enabled: typeof grace_alerts_enabled === 'boolean' ? grace_alerts_enabled : current.grace_alerts_enabled
    };
    await db.query(`
      INSERT INTO user_settings (email, email_alerts_enabled, grace_alerts_enabled, updated_at)
      VALUES ($1, $2, $3, NOW())
      ON CONFLICT (email) DO UPDATE SET email_alerts_enabled = $2, grace_alerts_enabled = $3, updated_at = NOW()
    `, [email.toLowerCase(), next.email_alerts_enabled, next.grace_alerts_enabled]);
    return res.json({ success: true, ...next });
  } catch (err) {
    console.error('Erreur PATCH settings:', err.message);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── Enregistrement d'un token push (app mobile) ───────────────────────────────
app.post('/api/manage/push-token', async (req, res) => {
  const { email, token, platform } = req.body || {};
  if (!email || !token) return res.status(400).json({ error: 'E-mail et token requis' });
  try {
    await db.query(`
      INSERT INTO push_tokens (token, email, platform, updated_at)
      VALUES ($1, $2, $3, NOW())
      ON CONFLICT (token) DO UPDATE SET email = $2, platform = $3, updated_at = NOW()
    `, [token, email.toLowerCase(), platform || null]);
    return res.json({ success: true });
  } catch (err) {
    console.error('Erreur enregistrement push-token:', err.message);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Dissocie un token (déconnexion) : on le retire pour ne plus notifier ce compte.
app.delete('/api/manage/push-token', async (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'Token requis' });
  try {
    await db.query('DELETE FROM push_tokens WHERE token = $1', [token]);
    return res.json({ success: true });
  } catch (err) {
    console.error('Erreur suppression push-token:', err.message);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── Routes de test push (à retirer après validation) ──────────────────────────
const TEST_DOMAIN = 'test-doomname.com';

app.get('/api/test-push', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'E-mail requis' });
  try {
    // Simule une disponibilité confirmée pour ce compte.
    await db.query(
      "UPDATE subscriptions SET last_status = 'available', notified_at = NOW() WHERE domain = $1 AND email = $2",
      [TEST_DOMAIN, email.toLowerCase()]
    );
    await sendPushNotification(email, {
      title: `🟢 ${TEST_DOMAIN} est disponible !`,
      body: 'Super, ce domaine vient de se libérer !',
      data: { type: 'domain_available', domain: TEST_DOMAIN, screen: 'manage', filter: 'available' },
    });
    // Teste aussi le canal e-mail — en respectant la préférence email_alerts_enabled,
    // comme en production.
    let emailSent = false;
    const settings = await getUserSettings(email);
    if (settings.email_alerts_enabled) {
      try { await sendAlertEmail(email, TEST_DOMAIN); emailSent = true; }
      catch (mailErr) { console.error('  ❌ Erreur envoi mail test-push:', mailErr.message); }
    }
    return res.json({ success: true, message: 'Notification "disponible" envoyée', domain: TEST_DOMAIN, emailSent });
  } catch (err) {
    console.error('Erreur /api/test-push:', err.message);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/test-taken', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'E-mail requis' });
  try {
    // Simule une reprise du domaine (available -> taken). On horodate la reprise
    // (notified_at) pour déclencher le "flash rouge" côté client.
    await db.query(
      "UPDATE subscriptions SET last_status = 'taken', notified_at = NOW() WHERE domain = $1 AND email = $2",
      [TEST_DOMAIN, email.toLowerCase()]
    );
    await sendMissedPush(email, TEST_DOMAIN);
    // Teste aussi le canal e-mail — en respectant la préférence email_alerts_enabled,
    // comme en production.
    let emailSent = false;
    const settings = await getUserSettings(email);
    if (settings.email_alerts_enabled) {
      try { await sendMissedEmail(email, TEST_DOMAIN); emailSent = true; }
      catch (mailErr) { console.error('  ❌ Erreur envoi mail test-taken:', mailErr.message); }
    }
    return res.json({ success: true, message: 'Notification "Dommage" envoyée', domain: TEST_DOMAIN, emailSent });
  } catch (err) {
    console.error('Erreur /api/test-taken:', err.message);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── Suppression de compte ──────────────────────────────────────────────────────
app.post('/api/account/delete-request', async (req, res) => {
  const { email } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Adresse e-mail invalide' });

  const token     = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 20 * 60 * 1000);

  try {
    await db.query(
      'INSERT INTO magic_links (email, token, expires_at, purpose) VALUES ($1, $2, $3, $4)',
      [email.toLowerCase(), token, expiresAt, 'delete']
    );
    await sendAccountDeleteEmail(email.toLowerCase(), token);
    console.log(`🗑️  Demande de suppression de compte envoyée à ${email}`);
    return res.json({ success: true });
  } catch (err) {
    console.error('Erreur delete-request:', err.message);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Valide un token de suppression (purpose='delete') sans le consommer, pour
// afficher un écran de confirmation côté manage.html (lien du footer des e-mails).
app.get('/api/account/delete-info', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.json({ valid: false });
  try {
    const { rows } = await db.query(
      "SELECT email FROM magic_links WHERE token = $1 AND used = FALSE AND expires_at > NOW() AND purpose = 'delete'",
      [token]
    );
    if (rows.length === 0) return res.json({ valid: false });
    return res.json({ valid: true, email: rows[0].email });
  } catch (err) {
    console.error('Erreur delete-info:', err.message);
    return res.status(500).json({ valid: false });
  }
});

app.get('/api/account/confirm-delete', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send('Lien invalide.');

  try {
    const { rows } = await db.query(
      "SELECT * FROM magic_links WHERE token = $1 AND used = FALSE AND expires_at > NOW() AND purpose = 'delete'",
      [token]
    );
    if (rows.length === 0) {
      return res.status(401).send(`<!DOCTYPE html><html lang="fr"><body style="font-family:sans-serif;text-align:center;padding:4rem 1rem"><h2>Lien invalide ou expiré</h2><p>Ce lien de suppression n'est plus valable.</p></body></html>`);
    }

    const { email } = rows[0];
    await db.query('DELETE FROM subscriptions WHERE email = $1', [email]);
    await db.query('DELETE FROM api_keys WHERE email = $1', [email]);
    await db.query('DELETE FROM user_settings WHERE email = $1', [email]);
    await db.query('DELETE FROM push_tokens WHERE email = $1', [email]);
    await db.query('DELETE FROM sessions WHERE email = $1', [email]);
    // Purge tous les magic links de ce compte (dont les liens de suppression 7j
    // encore valides générés dans les footers d'e-mails).
    await db.query('DELETE FROM magic_links WHERE email = $1', [email]);

    console.log(`🗑️  Compte supprimé : ${email}`);
    return res.send(`<!DOCTYPE html><html lang="fr"><body style="font-family:sans-serif;text-align:center;padding:4rem 1rem"><h2>Compte supprimé</h2><p>Toutes vos surveillances de domaines ont été supprimées.</p></body></html>`);
  } catch (err) {
    console.error('Erreur confirm-delete:', err.message);
    return res.status(500).send('Erreur serveur.');
  }
});

// ─── Routes API publique v1 ────────────────────────────────────────────────────

app.post('/api/developer/register', async (req, res) => {
  const { email, label } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Adresse e-mail invalide' });
  }

  try {
    const { rows: existing } = await db.query(
      'SELECT COUNT(*) FROM api_keys WHERE email = $1 AND active = TRUE',
      [email.toLowerCase()]
    );
    if (parseInt(existing[0].count) >= 3) {
      return res.status(400).json({ error: 'Limite de 3 clés API atteinte pour cet e-mail' });
    }

    const key = 'dk_' + crypto.randomBytes(24).toString('hex');
    await db.query(
      'INSERT INTO api_keys (email, key, label) VALUES ($1, $2, $3)',
      [email.toLowerCase(), key, label || null]
    );

    await sendApiKeyEmail(email.toLowerCase(), key, label);
    console.log(`🔧 Nouvelle clé API créée pour ${email}`);
    return res.json({ success: true, message: 'Votre clé API a été envoyée par e-mail.' });
  } catch (err) {
    console.error('Erreur register API key:', err.message);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/v1/check', requireApiKey, async (req, res) => {
  const { domain } = req.query;
  if (!domain || !/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/.test(domain)) {
    return res.status(400).json({ error: 'Nom de domaine invalide' });
  }
  try {
    const whoisData = await whois(domain);
    const result    = parseDomainAvailability(whoisData);
    return res.json({
      domain,
      available:      result.available,
      expiry:         result.expiry || null,
      checked_at:     new Date().toISOString(),
      requests_today: req.apiKey.requests_today + 1,
      daily_limit:    DAILY_LIMIT
    });
  } catch (err) {
    return res.status(500).json({ error: 'Impossible de vérifier ce domaine' });
  }
});

app.post('/api/v1/subscribe', requireApiKey, async (req, res) => {
  const { domain, email } = req.body;
  if (!domain || !email) return res.status(400).json({ error: 'domain et email requis' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'E-mail invalide' });
  if (!/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/.test(domain)) return res.status(400).json({ error: 'Domaine invalide' });

  try {
    const whoisData = await whois(domain);
    const { available } = parseDomainAvailability(whoisData);
    if (available) return res.status(400).json({ error: 'Ce domaine est déjà disponible', available: true });

    await db.query(`
      INSERT INTO subscriptions (domain, email, active) VALUES ($1, $2, TRUE)
      ON CONFLICT (domain, email) DO UPDATE SET active = TRUE, created_at = NOW()
    `, [domain.toLowerCase(), email.toLowerCase()]);

    return res.json({ success: true, domain, email, message: 'Alerte activée.' });
  } catch (err) {
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.delete('/api/v1/unsubscribe', requireApiKey, async (req, res) => {
  const { domain, email } = req.body;
  if (!domain || !email) return res.status(400).json({ error: 'domain et email requis' });

  try {
    await db.query(
      'UPDATE subscriptions SET active = FALSE WHERE domain = $1 AND email = $2',
      [domain.toLowerCase(), email.toLowerCase()]
    );
    return res.json({ success: true, message: 'Alerte désactivée.' });
  } catch (err) {
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── Confirmation différée (suite) ─────────────────────────────────────────────
async function confirmAvailability(domain) {
  console.log(`🔁 [${new Date().toISOString()}] Confirmation différée pour ${domain}…`);
  try {
    const { rows: subs } = await db.query(
      'SELECT email FROM subscriptions WHERE domain = $1 AND active = TRUE AND pending_confirmation_since IS NOT NULL',
      [domain]
    );
    if (subs.length === 0) {
      console.log(`  (plus rien en attente pour ${domain}, abandon)`);
      return;
    }

    const whoisData = await whois(domain);
    const { available, status } = parseDomainAvailability(whoisData);

    if (available) {
      console.log(`✅ ${domain} confirmé disponible après le délai de 10 minutes`);
      for (const { email } of subs) {
        try {
          const settings = await getUserSettings(email);
          if (settings.email_alerts_enabled) {
            await sendAlertEmail(email, domain);
            console.log(`  📧 Alerte envoyée à ${email}`);
          } else {
            console.log(`  🔕 Alertes mail désactivées pour ${email}, envoi ignoré`);
          }
        } catch (mailErr) {
          console.error(`  ❌ Erreur envoi mail à ${email}:`, mailErr.message);
        }
        // Notification push (canal distinct des alertes e-mail) — ouvre "Mes alertes"
        // filtré sur "Disponible".
        await sendPushNotification(email, {
          title: `🟢 ${domain} est disponible !`,
          body: 'Super, ce domaine vient de se libérer !',
          data: { type: 'domain_available', domain, screen: 'manage', filter: 'available' },
        });
      }
      // On garde l'alerte ACTIVE pour continuer à surveiller le domaine : s'il est
      // repris, on pourra envoyer la notification "Dommage". notified_at date la
      // disponibilité (utilisé pour la mise en évidence "récente" côté client).
      await db.query(
        'UPDATE subscriptions SET last_status = $2, notified_at = NOW(), pending_confirmation_since = NULL WHERE domain = $1',
        [domain, status]
      );
    } else {
      console.log(`↩️  ${domain} a été repris avant la fin du délai de confirmation — alerte annulée (statut : ${status})`);
      await db.query(
        'UPDATE subscriptions SET last_status = $2, pending_confirmation_since = NULL WHERE domain = $1',
        [domain, status]
      );
    }
  } catch (err) {
    console.error(`Erreur confirmation différée pour ${domain}:`, err.message);
  }
}

function scheduleConfirmation(domain, delayMs = CONFIRMATION_DELAY_MS) {
  setTimeout(() => { confirmAvailability(domain); }, delayMs);
}

// Rattrape, au démarrage du serveur, les confirmations différées qui auraient
// été perdues lors d'un redémarrage (Railway redéploie régulièrement).
async function recoverPendingConfirmations() {
  try {
    const { rows } = await db.query(
      `SELECT DISTINCT domain, pending_confirmation_since FROM subscriptions
       WHERE active = TRUE AND pending_confirmation_since IS NOT NULL`
    );
    if (rows.length === 0) return;

    console.log(`🔁 ${rows.length} domaine(s) en attente de confirmation à reprendre après redémarrage`);
    for (const { domain, pending_confirmation_since } of rows) {
      const elapsed   = Date.now() - new Date(pending_confirmation_since).getTime();
      const remaining = CONFIRMATION_DELAY_MS - elapsed;
      if (remaining <= 0) {
        console.log(`  ⏩ ${domain} : délai déjà écoulé, vérification immédiate`);
        confirmAvailability(domain);
      } else {
        console.log(`  ⏱️  ${domain} : reprogrammé dans ${Math.round(remaining / 1000)}s`);
        scheduleConfirmation(domain, remaining);
      }
    }
  } catch (err) {
    console.error('Erreur récupération des confirmations en attente:', err.message);
  }
}

// ─── Cron job — vérification toutes les heures ─────────────────────────────────
cron.schedule('0 * * * *', async () => {
  console.log(`\n🔄 [${new Date().toISOString()}] Lancement du cron job…`);

  let rows;
  try {
    const result = await db.query('SELECT DISTINCT domain FROM subscriptions WHERE active = TRUE');
    rows = result.rows;
  } catch (err) {
    console.error('Erreur lecture DB (cron):', err.message);
    return;
  }

  for (const { domain } of rows) {
    try {
      const whoisData = await whois(domain);
      const { available, status } = parseDomainAvailability(whoisData);

      const { rows: subs } = await db.query('SELECT email, last_status, pending_confirmation_since FROM subscriptions WHERE domain = $1 AND active = TRUE', [domain]);

      if (available) {
        const alreadyAvailable = subs.some(s => s.last_status === 'available');
        const alreadyPending   = subs.some(s => s.pending_confirmation_since);
        if (alreadyAvailable) {
          // Déjà signalé disponible : on continue de surveiller (pour détecter
          // une reprise) mais on ne ré-alerte pas.
          console.log(`✅ ${domain} toujours disponible — déjà notifié, pas de nouvelle alerte`);
        } else if (alreadyPending) {
          console.log(`⏳ ${domain} déjà en attente de confirmation, pas de nouvelle vérification programmée`);
        } else {
          console.log(`🕒 ${domain} semble disponible — confirmation différée de 10 min avant alerte`);
          await db.query('UPDATE subscriptions SET pending_confirmation_since = NOW() WHERE domain = $1 AND active = TRUE', [domain]);
          scheduleConfirmation(domain);
        }
      } else {
        console.log(`⏳ ${domain} toujours pris (statut : ${status})`);
        for (const { email, last_status } of subs) {
          if (last_status === 'available') {
            // « Dommage » : le domaine était disponible et vient d'être repris.
            const settings = await getUserSettings(email);
            if (settings.email_alerts_enabled) {
              try {
                await sendMissedEmail(email, domain);
                console.log(`  📧 Notification "Dommage" (repris) envoyée à ${email}`);
              } catch (mailErr) {
                console.error(`  ❌ Erreur envoi mail à ${email}:`, mailErr.message);
              }
            }
            await sendMissedPush(email, domain);
          } else if (status !== last_status && ['gracePeriod', 'redemptionPeriod', 'pendingDelete'].includes(status)) {
            const settings = await getUserSettings(email);
            // La préférence "Période de grâce" pilote toute cette catégorie
            // (grâce / rédemption / suppression), e-mail comme push.
            if (settings.grace_alerts_enabled) {
              if (settings.email_alerts_enabled) {
                try {
                  await sendStatusChangeEmail(email, domain, status);
                  console.log(`  📧 Alerte de changement d'état (${status}) envoyée à ${email}`);
                } catch (mailErr) {
                  console.error(`  ❌ Erreur envoi mail à ${email}:`, mailErr.message);
                }
              }
              await sendStatusChangePush(email, domain, status);
            } else {
              console.log(`  🔕 Alertes de grâce/rédemption désactivées pour ${email}, envoi ignoré`);
            }
          }
        }
        // Si le domaine était disponible et vient d'être repris, on horodate la
        // reprise (notified_at) pour la mise en évidence "flash rouge" côté client ;
        // sinon on efface notified_at (le domaine n'est plus/ n'a jamais été dispo).
        const wasAvailable = subs.some(s => s.last_status === 'available');
        if (wasAvailable) {
          await db.query('UPDATE subscriptions SET last_status = $2, notified_at = NOW(), pending_confirmation_since = NULL WHERE domain = $1', [domain, status]);
        } else {
          await db.query('UPDATE subscriptions SET last_status = $2, notified_at = NULL, pending_confirmation_since = NULL WHERE domain = $1', [domain, status]);
        }
      }

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
  await ensureReviewToken();
  await recoverPendingConfirmations();
  app.listen(port, () => {
    console.log(`🚀 DoomName en ligne sur http://localhost:${port}`);
    console.log(`   Cron job actif — vérification toutes les heures`);
  });
}

start();