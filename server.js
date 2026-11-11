require('dotenv').config();

const express    = require('express');
const cors       = require('cors');
const cookieParser = require('cookie-parser');
const path       = require('path');
const crypto     = require('crypto');
const whoisLib   = require('whois');
const parseWhoisFields = require('whois-json/parse-raw-data.js');
const util       = require('util');
const cron       = require('node-cron');
const { Pool }   = require('pg');
const { Resend } = require('resend');
const { initializeApp, cert, applicationDefault } = require('firebase-admin/app');
const { getMessaging } = require('firebase-admin/messaging');
const { OAuth2Client } = require('google-auth-library');

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
  // Date du dernier changement de last_status (mise en évidence côté client).
  // notified_at, lui, ne date que les envois et n'est jamais remis à NULL.
  await db.query(`ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS last_change_at TIMESTAMPTZ`);
  // Date depuis laquelle le WHOIS voit le domaine libre, que le disjoncteur
  // l'ait cru ou non. Sert uniquement à distinguer les bascules nouvelles.
  await db.query(`ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS whois_free_since TIMESTAMPTZ`);
  await db.query(`ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS lang VARCHAR(2) DEFAULT 'fr'`);
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
  // Sign in with Apple : identifiant stable (sub), refresh token (révocation à la
  // suppression, exigée par Apple) et nom transmis UNE SEULE fois par Apple.
  // UNIQUE crée l'index unique sur apple_sub.
  await db.query(`ALTER TABLE user_settings
    ADD COLUMN IF NOT EXISTS apple_sub VARCHAR(255) UNIQUE,
    ADD COLUMN IF NOT EXISTS apple_refresh_token TEXT,
    ADD COLUMN IF NOT EXISTS display_name VARCHAR(255)`);
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

// Langue préférée (FR par défaut) déduite des abonnements de l'utilisateur.
function normLang(l) { return l === 'en' ? 'en' : 'fr'; }
async function getUserLang(email) {
  try {
    const { rows } = await db.query('SELECT lang FROM subscriptions WHERE email = $1 ORDER BY created_at DESC LIMIT 1', [email.toLowerCase()]);
    return normLang(rows[0]?.lang);
  } catch { return 'fr'; }
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
  return token;
}

// Email de la session courante : cookie httpOnly (web) ou en-tête
// « Authorization: Bearer <jeton> » (app, qui ne dispose pas du cookie).
async function getSessionEmail(req) {
  const auth  = String(req.get('authorization') || '');
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : req.cookies?.[SESSION_COOKIE];
  if (!token) return null;
  const { rows } = await db.query('SELECT email FROM sessions WHERE token = $1 AND expires_at > NOW()', [token]);
  return rows[0]?.email || null;
}

// ─── Service e-mail (Resend) ───────────────────────────────────────────────────
const resend = new Resend(process.env.RESEND_API_KEY);
const SITE_URL = 'https://www.doomname.com';
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

// Footer légal ajouté à TOUS les e-mails (FR/EN).
function legalFooter(deleteUrl, lang = 'fr') {
  const t = lang === 'en'
    ? `This message was sent via <a href="${SITE_URL}" style="color:#999">doomname.com</a>.<br>
       If you did not sign up, you can <a href="${deleteUrl}" style="color:#999">delete your account here</a>.`
    : `Ce message a été envoyé via <a href="${SITE_URL}" style="color:#999">doomname.com</a>.<br>
       Si vous n'êtes pas à l'origine de cette inscription, vous pouvez <a href="${deleteUrl}" style="color:#999">supprimer votre compte ici</a>.`;
  return `
    <p style="color:#b0b0b0;font-size:0.72rem;margin-top:2.5rem;border-top:1px solid #eee;padding-top:1rem;line-height:1.6">
      ${t}
    </p>`;
}

// Envoi centralisé : from cohérent, footer légal + lien de suppression 7 jours,
// version texte brut (multipart), et en-tête List-Unsubscribe sur les e-mails
// d'alerte uniquement (opts.listUnsub) — jamais sur les magic links.
async function sendEmail(email, subject, innerHtml, opts = {}) {
  const { listUnsub = false, lang = 'fr' } = opts;
  let footer = '';
  let deleteUrl = '';
  try {
    const token = await createDeleteToken(email);
    deleteUrl = `${SITE_URL}/manage.html?token=${token}`;
    footer = legalFooter(deleteUrl, lang);
  } catch (err) {
    console.error('  ⚠️  Footer de suppression non généré:', err.message);
  }

  const html = `
      <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:2rem">
        ${innerHtml}
        ${footer}
      </div>`;
  const textFooter = deleteUrl
    ? (lang === 'en'
        ? `\n\n—\nSent via doomname.com\nManage or delete your account: ${deleteUrl}`
        : `\n\n—\nEnvoyé via doomname.com\nGérer ou supprimer votre compte : ${deleteUrl}`)
    : '';
  const text = htmlToText(innerHtml) + textFooter;

  const headers = {};
  if (listUnsub && deleteUrl) {
    headers['List-Unsubscribe'] = `<${deleteUrl}>`;
    headers['List-Unsubscribe-Post'] = 'List-Unsubscribe=One-Click';
  }

  // Resend v3 ne lève pas d'exception sur une erreur d'API : il renvoie { error }.
  // Les adresses relais Apple (« Masquer mon adresse ») rejettent tout expéditeur
  // non enregistré chez Apple → préfixe [apple-relay] pour ne pas confondre un
  // rejet avec un bug d'alerte. Comportement inchangé : on ne lève pas sur { error }.
  const relay = isAppleRelayEmail(email);
  let result;
  try {
    result = await resend.emails.send({
      from: EMAIL_FROM,
      to:   email,
      subject,
      html,
      text,
      ...(Object.keys(headers).length ? { headers } : {}),
    });
  } catch (err) {
    if (relay) console.error(`[apple-relay] Échec d'envoi vers ${email} (${subject}) :`, err.message);
    throw err;
  }
  if (result?.error) {
    const msg = result.error.message || JSON.stringify(result.error);
    if (relay) console.error(`[apple-relay] Envoi rejeté vers ${email} (${subject}) : ${msg} — expéditeur ${EMAIL_FROM} enregistré chez Apple ?`);
    else console.error(`❌ Envoi e-mail rejeté vers ${email} (${subject}) : ${msg}`);
  }
}

function isAppleRelayEmail(e) {
  return /@privaterelay\.appleid\.com$/i.test(String(e || '').trim());
}

// Adresse « système » : domaines trackés par une plateforme partenaire
// (labonnealerte via /api/internal/track). Pas d'utilisateur réel → aucun e-mail.
const PLATFORM_EMAIL = 'platform@labonnealerte.internal';
function isPlatformEmail(e) { return String(e || '').toLowerCase() === PLATFORM_EMAIL; }

async function sendAlertEmail(email, domain, lang = 'fr') {
  if (isPlatformEmail(email)) return; // ligne système : jamais d'e-mail
  const en = lang === 'en';
  const box = `<div style="background:#f0faf5;border-radius:8px;padding:1rem 1.5rem;margin:1.5rem 0"><strong style="font-size:1.3rem;font-family:monospace">${domain}</strong></div>`;
  const subject = en ? `🟢 ${domain} is available` : `🟢 ${domain} est disponible`;
  const body = en ? `
    <h2 style="color:#34c97a">Good news!</h2>
    <p>A domain you were watching is now available:</p>${box}
    <p>Register it quickly with the registrar of your choice before someone else does!</p>
    <p style="color:#999;font-size:0.8rem;margin-top:2rem">You are receiving this email because you set up an alert on DoomName.</p>`
  : `
    <h2 style="color:#34c97a">Bonne nouvelle !</h2>
    <p>Le domaine que vous surveilliez est désormais disponible :</p>${box}
    <p>Réservez-le rapidement auprès du registrar de votre choix avant qu'il ne soit pris !</p>
    <p style="color:#999;font-size:0.8rem;margin-top:2rem">Vous recevez cet e-mail car vous avez activé une alerte sur DoomName.</p>`;
  await sendEmail(email, subject, body, { listUnsub: true, lang });
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
  if (isPlatformEmail(email)) return; // ligne système : pas de push
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
  gracePeriod: {
    fr: { title: 'en grâce de renouvellement', detail: "Son propriétaire n'a pas encore renouvelé le domaine. Il dispose d'un délai pour le faire avant qu'il ne passe en période de rédemption." },
    en: { title: 'in renewal grace period', detail: "The owner has not renewed the domain yet. They have a grace period before it enters the redemption phase." },
  },
  redemptionPeriod: {
    fr: { title: 'en période de rédemption', detail: "Le domaine n'a pas été renouvelé et entre dans sa dernière phase avant suppression. Il pourrait bientôt devenir disponible." },
    en: { title: 'in redemption period', detail: "The domain was not renewed and is entering its final phase before deletion. It may soon become available." },
  },
  pendingDelete: {
    fr: { title: 'sur le point d\'être supprimé', detail: "Le domaine est en cours de suppression définitive par le registre. Il devrait devenir disponible très prochainement." },
    en: { title: 'about to be deleted', detail: "The domain is being permanently deleted by the registry. It should become available very soon." },
  },
};
function statusLabel(status, lang) { return STATUS_LABELS[status]?.[lang === 'en' ? 'en' : 'fr']; }

async function sendStatusChangeEmail(email, domain, status, lang = 'fr') {
  if (isPlatformEmail(email)) return; // ligne système : jamais d'e-mail
  const info = statusLabel(status, lang);
  if (!info) return;
  const en = lang === 'en';
  const box = `<div style="background:#fbf3e8;border-radius:8px;padding:1rem 1.5rem;margin:1.5rem 0"><strong style="font-size:1.2rem;font-family:monospace">${domain}</strong><p style="margin-top:0.5rem;color:#555">${info.detail}</p></div>`;
  const subject = en ? `🟠 ${domain} is now ${info.title}` : `🟠 ${domain} est désormais ${info.title}`;
  const body = en ? `
    <h2 style="color:#ba7517">Status change detected</h2>
    <p>A domain you are watching just changed status:</p>${box}
    <p>Its previous owner seems to have given up on renewal. Stay tuned — we will alert you as soon as it is fully available.</p>
    <p style="color:#999;font-size:0.8rem;margin-top:2rem">You are receiving this email because you watch this domain on DoomName.</p>`
  : `
    <h2 style="color:#ba7517">Changement d'état détecté</h2>
    <p>Le domaine que vous surveillez vient de changer de statut :</p>${box}
    <p>Son ancien propriétaire semble avoir abandonné son renouvellement. Restez attentif, une alerte vous sera envoyée dès qu'il sera totalement disponible.</p>
    <p style="color:#999;font-size:0.8rem;margin-top:2rem">Vous recevez cet e-mail car vous surveillez ce domaine sur DoomName.</p>`;
  await sendEmail(email, subject, body, { listUnsub: true, lang });
}

async function sendStatusChangePush(email, domain, status, lang = 'fr') {
  const info = statusLabel(status, lang);
  if (!info) return;
  await sendPushNotification(email, {
    title: `🟠 ${domain} ${lang === 'en' ? 'is' : 'est'} ${info.title}`,
    body: info.detail,
    data: { type: 'status_change', domain, status, screen: 'manage' },
  });
}

// « Dommage » : un domaine signalé disponible vient d'être repris par quelqu'un.
async function sendMissedEmail(email, domain, lang = 'fr') {
  const en = lang === 'en';
  const box = `<div style="background:#fdeceb;border-radius:8px;padding:1rem 1.5rem;margin:1.5rem 0"><strong style="font-size:1.3rem;font-family:monospace">${domain}</strong></div>`;
  const subject = en ? `${domain} was just registered` : `${domain} vient d'être repris`;
  const body = en ? `
    <h2 style="color:#e24b4a">Too bad…</h2>
    <p>A domain you were watching was just registered:</p>${box}
    <p>Someone registered this domain before you. <strong>Your alert stays active</strong>: we keep watching it and will let you know if it becomes available again.</p>
    <p style="color:#999;font-size:0.8rem;margin-top:2rem">You are receiving this email because you watch this domain on DoomName.</p>`
  : `
    <h2 style="color:#e24b4a">Dommage…</h2>
    <p>Le domaine que vous surveilliez vient d'être enregistré :</p>${box}
    <p>Quelqu'un a enregistré ce domaine avant vous. <strong>Votre alerte reste active</strong> : nous continuons à le surveiller et vous préviendrons s'il se libère de nouveau.</p>
    <p style="color:#999;font-size:0.8rem;margin-top:2rem">Vous recevez cet e-mail car vous surveillez ce domaine sur DoomName.</p>`;
  await sendEmail(email, subject, body, { listUnsub: true, lang });
}

async function sendMissedPush(email, domain, lang = 'fr') {
  const en = lang === 'en';
  await sendPushNotification(email, {
    title: en ? `😔 ${domain} was just registered` : `😔 ${domain} vient d'être pris`,
    body: en ? 'Someone registered this domain before you. Your alert stays active.' : 'Quelqu\'un a enregistré ce domaine avant vous. Votre alerte reste active.',
    data: { type: 'domain_taken', domain, screen: 'manage', filter: 'active' },
  });
}

async function sendAccountDeleteEmail(email, token, lang = 'fr') {
  const APP_URL = process.env.APP_URL || 'http://localhost:3000';
  const confirmLink = `${APP_URL}/api/account/confirm-delete?token=${token}`;
  const en = lang === 'en';
  const btn = `<a href="${confirmLink}" style="display:inline-block;background:#e24b4a;color:white;padding:0.75rem 1.5rem;border-radius:8px;text-decoration:none;font-weight:500;margin-top:1rem">${en ? 'Confirm deletion →' : 'Confirmer la suppression →'}</a>`;
  const subject = en ? 'Confirm the deletion of your DoomName account' : '⚠️ Confirmer la suppression de votre compte DoomName';
  const body = en ? `
    <h2 style="color:#e24b4a">Account deletion</h2>
    <p>A request to delete the account for this email address was made.</p>
    <p>This will <strong>permanently</strong> delete every domain you watch. It is irreversible.</p>${btn}
    <p style="color:#999;font-size:0.85rem;margin-top:1.5rem">This link is valid for 20 minutes. If you did not request this, ignore this email.</p>`
  : `
    <h2 style="color:#e24b4a">Suppression de compte</h2>
    <p>Une demande de suppression de compte a été effectuée pour cette adresse e-mail.</p>
    <p>Cette action supprimera <strong>définitivement</strong> tous les noms de domaine que vous surveillez. Elle est irréversible.</p>${btn}
    <p style="color:#999;font-size:0.85rem;margin-top:1.5rem">Ce lien est valable 20 minutes. Si vous n'êtes pas à l'origine de cette demande, ignorez cet e-mail.</p>`;
  await sendEmail(email, subject, body, { lang });
}

async function sendMagicLinkEmail(email, token, lang = 'fr') {
  const APP_URL = process.env.APP_URL || 'http://localhost:3000';
  // Page https intermédiaire (les clients mail comme Gmail suppriment les
  // liens vers des schémas personnalisés type doomname://) : elle tente
  // d'ouvrir l'app sur mobile puis se replie automatiquement sur le site.
  const link = `${APP_URL}/open-app.html?token=${token}`;
  const en = lang === 'en';
  const btn = `<a href="${link}" style="display:inline-block;background:#d97757;color:white;padding:0.75rem 1.5rem;border-radius:8px;text-decoration:none;font-weight:500;margin-top:1rem">${en ? 'Open DoomName →' : 'Accéder à DoomName →'}</a>`;
  const subject = en ? 'Your DoomName sign-in link' : 'Votre lien de connexion DoomName';
  const body = en ? `
    <h2 style="color:#d97757">Sign in to DoomName</h2>
    <p>Click the button below to access your alerts.</p>
    <p style="color:#999;font-size:0.85rem">This link is valid for <strong>20 minutes</strong> and can be used only once.</p>${btn}
    <p style="color:#999;font-size:0.8rem;margin-top:2rem">If you did not request this link, ignore this email.</p>`
  : `
    <h2 style="color:#d97757">Connexion à DoomName</h2>
    <p>Cliquez sur le bouton ci-dessous pour accéder à vos alertes.</p>
    <p style="color:#999;font-size:0.85rem">Ce lien est valable <strong>20 minutes</strong> et ne peut être utilisé qu'une seule fois.</p>${btn}
    <p style="color:#999;font-size:0.8rem;margin-top:2rem">Si vous n'avez pas demandé ce lien, ignorez cet e-mail.</p>`;
  await sendEmail(email, subject, body, { lang });
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

// ─── WHOIS : file d'attente globale par TLD ────────────────────────────────────
// Incident du 13/10/2026 : le WHOIS AFNIC a rate-limité l'IP Railway et ses
// refus ont été lus comme "disponible". Toutes les requêtes WHOIS du serveur
// (cron, /api/check, API publique, détection à l'ajout, consultation) passent
// désormais par une file unique PAR TLD : jamais deux requêtes simultanées vers
// un même registre, et un délai minimum entre deux requêtes, quelle que soit
// leur origine.
const WHOIS_TIMEOUT_MS   = 15 * 1000;
const TLD_MIN_GAP_MS     = { fr: 1500 };   // AFNIC : 1,5 s minimum entre deux requêtes
const DEFAULT_TLD_GAP_MS = 1000;
const tldQueues = new Map();               // tld → { tail: Promise, waiting: number }

const whoisLookupRaw = util.promisify(whoisLib.lookup);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const tldOf = (domain) => String(domain).toLowerCase().split('.').pop();

class WhoisQueueFullError extends Error {}

// maxWaiting : pour les routes interactives, refuse plutôt que d'attendre
// derrière un cron en cours (le client reçoit un 503, le quota est préservé).
function queuedWhois(domain, { maxWaiting = Infinity } = {}) {
  const tld = tldOf(domain);
  const q = tldQueues.get(tld) || { tail: Promise.resolve(), waiting: 0 };
  tldQueues.set(tld, q);
  if (q.waiting >= maxWaiting) {
    return Promise.reject(new WhoisQueueFullError(`file WHOIS .${tld} saturée (${q.waiting} en attente)`));
  }
  q.waiting++;
  const gap = TLD_MIN_GAP_MS[tld] ?? DEFAULT_TLD_GAP_MS;
  // follow: 0 → on n'interroge que le registre (source qui fait foi pour la
  // disponibilité), pas le registrar, qui a ses propres limites.
  const run = q.tail.then(() => whoisLookupRaw(domain, { follow: 0, timeout: WHOIS_TIMEOUT_MS }));
  q.tail = run.catch(() => {}).then(() => { q.waiting--; return sleep(gap); });
  return run;
}

// ─── Cache WHOIS (requêtes interactives uniquement) ───────────────────────────
// Le cron (et donc la confirmation) n'utilise JAMAIS ce cache : il interroge
// toujours le registre.
const whoisCache = new Map();
const CACHE_DURATION_MS = 60 * 1000; // 60 secondes

async function getWhoisRawWithCache(domain, opts) {
  const cached = whoisCache.get(domain);
  if (cached && (Date.now() - cached.timestamp) < CACHE_DURATION_MS) {
    return cached.raw;
  }
  const raw = await queuedWhois(domain, opts);
  whoisCache.set(domain, { raw, timestamp: Date.now() });
  return raw;
}

// ─── Confirmation différée avant alerte "disponible" ───────────────────────────
// Une première détection "disponible" ne déclenche rien : le domaine passe en
// attente de confirmation, et n'est confirmé que par un run du cron situé au
// moins 1 h plus tard (nouvelle requête au registre, hors cache) — en pratique
// le run horaire suivant ou celui d'après. 1 h sort de la fenêtre de rate-limit ;
// passer par le cron (au lieu d'un setTimeout par domaine) garantit que les
// confirmations sont espacées par la file par TLD et couvertes par le
// disjoncteur, au lieu d'être rejouées en rafale comme le 13/10.
const CONFIRMATION_DELAY_MS = 60 * 60 * 1000; // 1 heure minimum

// ─── Vérification WHOIS ────────────────────────────────────────────────────────
// Règle : "available" n'est conclu QUE sur un marqueur explicite de
// disponibilité propre au TLD. Tout le reste (vide, erreur, timeout, refus,
// réponse non reconnue, TLD non cartographié) → "unknown", qui ne déclenche
// jamais de notification et n'écrase jamais le dernier statut connu.

// Motifs de refus / rate-limit / maintenance — testés AVANT tout marqueur.
const REFUSAL_PATTERNS = [
  /rate.?limit/i, /too many/i, /exceeded/i, /quota/i, /excessive/i,
  /try again/i, /temporarily unavailable/i, /service unavailable/i,
  /maintenance/i, /access denied/i, /query refused/i, /connection refused/i,
  /overload/i, /please wait/i,
];

// Marqueurs explicites de disponibilité, par TLD (TLDs présents en base).
const TLD_RULES = {
  fr:     { free: [/^%% NOT FOUND/m, /^No entries found/mi] },                 // AFNIC
  com:    { free: [/^\s*No match for (domain )?"/mi] },                        // Verisign
  net:    { free: [/^\s*No match for (domain )?"/mi] },                        // Verisign
  io:     { free: [/^\s*Domain not found\.?\s*$/mi, /^\s*NOT FOUND\s*$/mi] },  // Identity Digital
  // .studio : plus de serveur WHOIS (IANA n'en déclare aucun, whois.nic.studio
  // répond "TLD is not supported.") → toujours "unknown" tant qu'un client RDAP
  // n'est pas en place. Marqueur conservé pour le jour où le WHOIS répondrait.
  studio: { free: [/^\s*Domain not found\.?\s*$/mi] },                         // Identity Digital
};

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// La réponse brute n'est loggée que pour REFUSAL et UNMAPPED_TLD (pas de
// données de titulaire dans ces réponses), tronquée à 1000 caractères. Les
// autres "unknown" (réponse non reconnue, erreur, timeout…) peuvent contenir
// des coordonnées de titulaire : domaine + raison + horodatage seulement.
function logUnknown(domain, reason, raw) {
  const tag = reason === 'unmapped_tld' ? 'UNMAPPED_TLD' : reason === 'refusal' ? 'REFUSAL' : 'UNKNOWN';
  const withRaw = tag !== 'UNKNOWN';
  console.warn(`[WHOIS][${tag}] ${new Date().toISOString()} ${domain} (raison : ${reason})` +
    (withRaw ? ` — réponse brute : ${JSON.stringify(String(raw ?? '').slice(0, 1000))}` : ''));
}

// Classe une réponse WHOIS brute (texte). Ne lève jamais.
function classifyWhois(domain, raw) {
  const unknown = (reason) => {
    logUnknown(domain, reason, raw);
    return { available: null, status: 'unknown', reason, expiry: null };
  };
  const text = String(raw ?? '');
  if (!text.trim()) return unknown('empty');

  // 1. Refus / maintenance — en premier. Cherché uniquement avant les mentions
  //    légales : celles d'Identity Digital (.io) contiennent "too many queries"
  //    et "maintenance periods" sur chaque réponse.
  const legalStart = text.search(/^\s*(>>> Last update|Terms of Use\s*:|TERMS OF USE\s*:|NOTICE\s*:)/m);
  const head = legalStart === -1 ? text : text.slice(0, legalStart);
  if (REFUSAL_PATTERNS.some(re => re.test(head))) return unknown('refusal');

  // 2. TLD non cartographié — tracé à part d'un refus dans les logs.
  const rules = TLD_RULES[tldOf(domain)];
  if (!rules) return unknown('unmapped_tld');

  // 3. Marqueur explicite de disponibilité, propre au TLD.
  if (rules.free.some(re => re.test(text))) {
    return { available: true, status: 'available', reason: 'free_marker', expiry: null };
  }

  // 4. Marqueur explicite d'enregistrement : la réponse nomme le domaine demandé.
  const takenRe = new RegExp(`^\\s*domain(\\s*name)?\\s*:\\s*${escapeRe(domain)}\\.?\\s*$`, 'mi');
  if (!takenRe.test(text)) return unknown('unrecognized');

  // Statuts EPP de fin de vie (grace period / redemption / pending delete),
  // pour alerter avant la libération effective du domaine.
  // autoRenewPeriod / renewPeriod ne sont PAS des statuts de fin de vie : ils
  // signalent que le domaine vient d'être renouvelé (fenêtre d'annulation du
  // registrar). Ils restent "taken" — auparavant classés gracePeriod à tort.
  const lower = text.toLowerCase();
  let status = 'taken';
  if (lower.includes('pendingdelete') || lower.includes('pending delete')) status = 'pendingDelete';
  else if (lower.includes('redemptionperiod') || lower.includes('redemption period')) status = 'redemptionPeriod';
  else if (lower.includes('grace period')) status = 'gracePeriod';

  const fields = parseWhoisFields(text);
  const expiryRaw =
    fields.registryExpiryDate || fields.expiresOn || fields.expirationDate ||
    fields.expiryDate || fields.paidTill || null;
  const expiry = expiryRaw ? new Date(expiryRaw) : null;

  return {
    available: false,
    status,
    reason: 'taken_marker',
    expiry: expiry && !isNaN(expiry) ? expiry.toLocaleDateString('fr-FR') : null,
  };
}

// Point d'entrée unique : requête (file par TLD) + classification. Ne lève
// jamais : erreur réseau, timeout ou file saturée → "unknown".
// cache: true uniquement pour les routes interactives.
async function checkWhois(domain, { cache = false, maxWaiting } = {}) {
  domain = String(domain).toLowerCase();
  let raw;
  try {
    raw = cache ? await getWhoisRawWithCache(domain, { maxWaiting })
                : await queuedWhois(domain, { maxWaiting });
  } catch (err) {
    const reason = err instanceof WhoisQueueFullError ? 'queue_full'
                 : /timeout/i.test(err.message) ? 'timeout' : 'error';
    logUnknown(domain, reason, `ERREUR : ${err.message}`);
    return { available: null, status: 'unknown', reason, expiry: null, raw: null };
  }
  return { ...classifyWhois(domain, raw), raw };
}

// Routes interactives : au-delà de 3 requêtes en attente sur le TLD → 503.
const INTERACTIVE = { cache: true, maxWaiting: 3 };

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
  const { available, status, expiry } = await checkWhois(domain, INTERACTIVE);
  if (status === 'unknown') {
    return res.status(503).json({ error: 'Service WHOIS temporairement indisponible, réessayez dans une minute' });
  }
  return res.json({ available, status, expiry });
});

// ─── Manifeste OpenAlert (standard labonnealerte.fr) ───────────────────────────
// GET /alert.json                  → manifeste broadcast (source globale, inactif :
//                                     une alerte DoomName n'a de sens que par domaine).
// GET /alert.json?domaine=x.fr      → manifeste évalué pour ce domaine, à partir de
//                                     l'état connu en base (maintenu par le cron).
// Léger et déterministe : une seule lecture indexée, jamais de WHOIS ni de 500.
// Conforme à OPENALERT.md v2 : le champ `params` déclare le schéma paramétré.
const OA_DOMAIN_RE = /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/;
const OA_PARAMS = [{ key: 'domaine', label: 'Nom de domaine', type: 'string', multiple: true, required: true }];

app.get('/alert.json', async (req, res) => {
  const base = {
    id: 'doomname', name: 'DoomName', url: 'https://doomname.com',
    checked_at: new Date().toISOString(), params: OA_PARAMS,
  };
  const inactive = (extra = {}) => res.json(Object.assign(
    { ...base, state: 'inactive', since: null, until: null, message: null }, extra));

  const raw = req.query.domaine;
  if (raw == null || raw === '') return inactive();               // broadcast : inactif neutre

  const domain = String(raw).toLowerCase().trim();
  if (!OA_DOMAIN_RE.test(domain)) return inactive();             // paramètre mal formé : réponse propre

  try {
    const { rows } = await db.query(
      `SELECT bool_or(last_status = 'available') AS available, max(last_change_at) AS last_change_at
         FROM subscriptions WHERE domain = $1`,
      [domain]
    );
    const r = rows[0] || {};
    const url = 'https://doomname.com/?domain=' + encodeURIComponent(domain);
    // Domaine inconnu en base (available = null) ou non disponible → inactif neutre.
    if (r.available === true) {
      return res.json({
        ...base, state: 'active',
        since: r.last_change_at ? new Date(r.last_change_at).toISOString() : null,
        until: null, message: `🟢 ${domain} est disponible`, url,
      });
    }
    return inactive({ url });
  } catch (err) {
    console.error('Erreur /alert.json :', err.message);
    return inactive(); // jamais de 500 : ne casse pas le poller labonnealerte
  }
});

// ─── Tracking interne (plateforme partenaire) ─────────────────────────────────
// POST /api/internal/track { domaine } — protégé par un secret partagé
// (DOOMNAME_INTERNAL_KEY). Fait entrer un domaine dans le cron SANS utilisateur
// ni e-mail (ligne système). Idempotent. Utilisé par labonnealerte quand un
// abonnement paramétré DoomName est créé, pour que le domaine soit réellement
// surveillé même s'il n'est suivi que depuis le kiosque.
app.post('/api/internal/track', async (req, res) => {
  const key = (process.env.DOOMNAME_INTERNAL_KEY || '').trim();
  if (!key) return res.status(503).json({ error: 'internal tracking disabled' });
  const provided = String(req.get('x-internal-key') || '');
  const a = Buffer.from(provided);
  const b = Buffer.from(key);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  const domaine = String((req.body && req.body.domaine) || '').toLowerCase().trim();
  if (!/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/.test(domaine)) {
    return res.status(400).json({ error: 'domaine invalide' });
  }
  try {
    await db.query(
      `INSERT INTO subscriptions (domain, email, active) VALUES ($1, $2, TRUE)
       ON CONFLICT (domain, email) DO UPDATE SET active = TRUE`,
      [domaine, PLATFORM_EMAIL]
    );
    // Détection immédiate du statut (jamais d'e-mail) pour que /alert.json soit à jour vite.
    detectAndStoreStatus(domaine, PLATFORM_EMAIL).catch(() => {});
    return res.json({ ok: true, domaine });
  } catch (err) {
    console.error('Erreur /api/internal/track :', err.message);
    return res.status(500).json({ error: 'server error' });
  }
});

// Détecte immédiatement le statut WHOIS d'un domaine à l'ajout et l'enregistre,
// sans attendre le cron horaire. Si le domaine est déjà disponible, on le marque
// 'available' (+ last_change_at) pour qu'il apparaisse aussitôt dans le filtre
// "Disponible". Un résultat "unknown" n'écrit rien (garde le dernier statut
// connu, 'taken' par défaut). notified_at n'est jamais touché ici (aucun envoi).
// N'interfère pas avec la confirmation différée : on ne fait qu'écrire last_status.
// IMPORTANT : ne JAMAIS envoyer d'e-mail ni de push ici. Les notifications ne
// partent que du cron et des routes de test — l'ajout d'une surveillance (même
// 'available') reste totalement silencieux.
async function detectAndStoreStatus(domain, email) {
  try {
    const { status } = await checkWhois(domain, INTERACTIVE);
    if (status === 'unknown') return null;
    await db.query(
      `UPDATE subscriptions
          SET last_status = $3::varchar,
              last_change_at = CASE WHEN last_status IS DISTINCT FROM $3::varchar THEN NOW() ELSE last_change_at END
        WHERE domain = $1 AND email = $2`,
      [domain, email, status]
    );
    return status;
  } catch (err) {
    console.warn(`Détection de statut immédiate échouée pour ${domain}:`, err.message);
    return null;
  }
}

// ─── Route POST /api/subscribe ─────────────────────────────────────────────────
app.post('/api/subscribe', async (req, res) => {
  const { domain, email, lang } = req.body;
  if (!domain || !email) return res.status(400).json({ error: 'Domaine et e-mail requis' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Adresse e-mail invalide' });
  if (!/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/.test(domain)) return res.status(400).json({ error: 'Nom de domaine invalide' });

  try {
    await db.query(`
      INSERT INTO subscriptions (domain, email, active, lang)
      VALUES ($1, $2, TRUE, $3)
      ON CONFLICT (domain, email)
      DO UPDATE SET active = TRUE, created_at = NOW(), lang = $3
    `, [domain.toLowerCase(), email.toLowerCase(), normLang(lang)]);
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
  const { email, lang } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Adresse e-mail invalide' });

  const token     = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 20 * 60 * 1000);
  // Langue du magic link : celle passée par le client, sinon celle déjà connue
  // pour ce compte (abonnements), sinon FR.
  const emailLang = lang ? normLang(lang) : await getUserLang(email);

  try {
    await db.query('INSERT INTO magic_links (email, token, expires_at) VALUES ($1, $2, $3)', [email.toLowerCase(), token, expiresAt]);
    await sendMagicLinkEmail(email.toLowerCase(), token, emailLang);
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
    let sessionToken = null;
    try { sessionToken = await createSession(res, rows[0].email); } catch (e) { console.error('createSession:', e.message); }

    return res.json({ success: true, email: rows[0].email, sessionToken });
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

// ─── OAuth Google / GitHub ─────────────────────────────────────────────────────
// Principe : quel que soit le canal (magic link, Google, GitHub), on aboutit à un
// email VÉRIFIÉ, puis on ouvre exactement la même session que le magic link
// (createSession → cookie httpOnly web) et on renvoie { success, email } (app).
// L'email reste l'identifiant unique : un même email via 2 canaux = même compte.
// Le flux magic link n'est jamais modifié — il reste le fallback universel.

// Client IDs Google acceptés comme audience du jeton (web + Android + iOS).
const GOOGLE_CLIENT_IDS = [
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_ID_ANDROID,
  process.env.GOOGLE_CLIENT_ID_IOS,
].filter(Boolean);
const googleClient = new OAuth2Client();

const GITHUB_CLIENT_ID     = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;

// Expose l'ID client Google au front web (bouton Google Identity Services).
app.get('/api/auth/config', (req, res) => {
  res.json({
    googleClientId: process.env.GOOGLE_CLIENT_ID || null,
    githubEnabled: !!GITHUB_CLIENT_ID,
  });
});

// Google : le front (web GIS ou app google-signin) envoie un ID token, on le
// vérifie côté serveur puis on établit la session.
app.post('/api/auth/google', async (req, res) => {
  const { idToken } = req.body || {};
  if (!idToken) return res.status(400).json({ error: 'idToken manquant' });
  if (GOOGLE_CLIENT_IDS.length === 0) return res.status(503).json({ error: 'Google Sign-In non configuré' });
  try {
    const ticket  = await googleClient.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_IDS });
    const payload = ticket.getPayload();
    if (!payload?.email || payload.email_verified !== true) {
      return res.status(401).json({ error: 'E-mail Google non vérifié' });
    }
    const email = payload.email.toLowerCase();
    let sessionToken = null;
    try { sessionToken = await createSession(res, email); } catch (e) { console.error('createSession(google):', e.message); }
    console.log(`🔐 Connexion Google : ${email}`);
    return res.json({ success: true, email, sessionToken });
  } catch (err) {
    console.error('Erreur auth Google:', err.message);
    return res.status(401).json({ error: 'Jeton Google invalide' });
  }
});

// ─── Sign in with Apple ────────────────────────────────────────────────────────
// Vérification de signature et client secret ES256 faits avec le module crypto
// natif de Node (JWK → KeyObject) : aucune dépendance ajoutée.
// Identité : le `sub` Apple (stable), PAS l'email, qui peut être un relais
// modifiable. Le nom et l'email ne sont envoyés par Apple qu'à la PREMIÈRE
// autorisation : on les persiste immédiatement.
const APPLE_ISSUER    = 'https://appleid.apple.com';
const APPLE_BUNDLE_ID = 'fr.dahuconcept.doomname';
const APPLE_ENV = ['APPLE_CLIENT_ID', 'APPLE_TEAM_ID', 'APPLE_KEY_ID', 'APPLE_PRIVATE_KEY'];
function appleConfigured() { return APPLE_ENV.every(k => (process.env[k] || '').trim()); }

const b64url = buf => Buffer.from(buf).toString('base64url');
function decodeJwtPart(part) { return JSON.parse(Buffer.from(part, 'base64url').toString('utf8')); }

// Clés publiques Apple en cache 24 h ; rechargées si un `kid` inconnu apparaît.
let appleKeysCache = { keys: null, at: 0 };
async function getApplePublicKey(kid) {
  const fresh = appleKeysCache.keys && Date.now() - appleKeysCache.at < 24 * 3600 * 1000;
  let jwk = fresh ? appleKeysCache.keys.find(k => k.kid === kid) : null;
  if (!jwk) {
    const r = await fetch(`${APPLE_ISSUER}/auth/keys`);
    if (!r.ok) throw new Error(`apple keys HTTP ${r.status}`);
    const { keys } = await r.json();
    appleKeysCache = { keys, at: Date.now() };
    jwk = keys.find(k => k.kid === kid);
  }
  if (!jwk) throw new Error('kid Apple inconnu');
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

async function verifyAppleIdentityToken(idToken) {
  const parts = String(idToken || '').split('.');
  if (parts.length !== 3) throw new Error('jeton mal formé');
  const header = decodeJwtPart(parts[0]);
  const data = Buffer.from(`${parts[0]}.${parts[1]}`);
  const sig  = Buffer.from(parts[2], 'base64url');
  // Les clés publiées par Apple sont RSA : identity token en RS256. ES256 est
  // accepté aussi ; tout autre alg (dont « none ») est refusé.
  let ok;
  if (header.alg === 'RS256') {
    ok = crypto.verify('sha256', data, await getApplePublicKey(header.kid), sig);
  } else if (header.alg === 'ES256') {
    ok = crypto.verify('sha256', data, { key: await getApplePublicKey(header.kid), dsaEncoding: 'ieee-p1363' }, sig);
  } else {
    throw new Error(`alg non supporté : ${header.alg}`);
  }
  if (!ok) throw new Error('signature invalide');
  const p = decodeJwtPart(parts[1]);
  if (p.iss !== APPLE_ISSUER) throw new Error('iss invalide');
  const aud = Array.isArray(p.aud) ? p.aud : [p.aud];
  if (!aud.includes(APPLE_BUNDLE_ID)) throw new Error('aud invalide');
  if (!p.exp || p.exp * 1000 < Date.now()) throw new Error('jeton expiré');
  if (!p.sub) throw new Error('sub manquant');
  return p;
}

// Client secret : JWT ES256 signé avec la clé .p8 (durée de vie courte : 5 min).
function appleClientSecret() {
  const now = Math.floor(Date.now() / 1000);
  const header  = { alg: 'ES256', kid: process.env.APPLE_KEY_ID.trim() };
  const payload = { iss: process.env.APPLE_TEAM_ID.trim(), iat: now, exp: now + 300, aud: APPLE_ISSUER, sub: process.env.APPLE_CLIENT_ID.trim() };
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  // Les variables d'env stockent souvent les retours à la ligne en « \n » littéraux.
  const pem = process.env.APPLE_PRIVATE_KEY.replace(/\\n/g, '\n');
  const sig = crypto.sign('sha256', Buffer.from(input), { key: pem, dsaEncoding: 'ieee-p1363' });
  return `${input}.${b64url(sig)}`;
}

// Échange l'authorizationCode contre un refresh token (nécessaire à la révocation).
async function exchangeAppleCode(code) {
  const r = await fetch(`${APPLE_ISSUER}/auth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: process.env.APPLE_CLIENT_ID.trim(), client_secret: appleClientSecret(),
      code, grant_type: 'authorization_code',
    }),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data.refresh_token || null;
}

// Révocation exigée par Apple à la suppression du compte. Neutralisée (no-op)
// si la configuration Apple est absente ou si aucun jeton n'est connu.
async function revokeAppleToken(refreshToken) {
  if (!refreshToken) return false;
  if (!appleConfigured()) { console.warn('⚠️  Révocation Apple ignorée : variables APPLE_* absentes'); return false; }
  try {
    const r = await fetch(`${APPLE_ISSUER}/auth/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.APPLE_CLIENT_ID.trim(), client_secret: appleClientSecret(),
        token: refreshToken, token_type_hint: 'refresh_token',
      }),
    });
    if (!r.ok) { console.error(`❌ Révocation Apple HTTP ${r.status}`); return false; }
    return true;
  } catch (err) {
    console.error('❌ Révocation Apple :', err.message);
    return false;
  }
}

app.post('/api/auth/apple', async (req, res) => {
  if (!appleConfigured()) return res.status(503).json({ error: 'Sign in with Apple non configuré sur ce serveur' });
  const { identityToken, authorizationCode, fullName } = req.body || {};
  if (!identityToken) return res.status(400).json({ error: 'identityToken manquant' });

  let payload;
  try { payload = await verifyAppleIdentityToken(identityToken); }
  catch (err) {
    console.error('Erreur jeton Apple:', err.message);
    return res.status(401).json({ error: 'Jeton Apple invalide' });
  }
  const sub = payload.sub;
  // L'email retenu est celui du jeton signé, jamais celui envoyé par le client
  // (le champ `email` du corps n'est pas utilisé pour l'identité).
  const tokenEmail = payload.email && (payload.email_verified === true || payload.email_verified === 'true')
    ? String(payload.email).toLowerCase() : null;
  const name = typeof fullName === 'string' ? (fullName.trim().slice(0, 255) || null) : null;

  try {
    let email;
    const known = await db.query('SELECT email FROM user_settings WHERE apple_sub = $1', [sub]);
    if (known.rows.length) {
      // 1. sub connu → ouverture de session sur ce compte.
      email = known.rows[0].email;
      if (name) await db.query('UPDATE user_settings SET display_name = COALESCE(display_name, $2) WHERE email = $1', [email, name]);
    } else {
      if (!tokenEmail) return res.status(400).json({ error: 'E-mail Apple indisponible' });
      email = tokenEmail;
      // 2. compte existant pour cet email → rattachement du sub ; 3. sinon création.
      // Les deux cas aboutissent à la même ligne user_settings (clé = email).
      await db.query(`
        INSERT INTO user_settings (email, apple_sub, display_name) VALUES ($1, $2, $3)
        ON CONFLICT (email) DO UPDATE SET apple_sub = $2, display_name = COALESCE(user_settings.display_name, $3)
      `, [email, sub, name]);
    }

    // Refresh token pour la révocation future : best effort, n'empêche pas la connexion.
    if (authorizationCode) {
      try {
        const rt = await exchangeAppleCode(authorizationCode);
        if (rt) await db.query('UPDATE user_settings SET apple_refresh_token = $2 WHERE email = $1', [email, rt]);
      } catch (e) { console.error('Échange code Apple :', e.message); }
    }

    let sessionToken = null;
    try { sessionToken = await createSession(res, email); } catch (e) { console.error('createSession(apple):', e.message); }
    console.log(`🔐 Connexion Apple : ${email}${isAppleRelayEmail(email) ? ' [apple-relay]' : ''}`);
    return res.json({ success: true, email, sessionToken });
  } catch (err) {
    console.error('Erreur auth Apple:', err.message);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GitHub : flux redirection (le secret ne quitte jamais le serveur).
//   ?platform=app  → à la fin, redirige vers un deep link doomname://auth?token=…
//                    (jeton magic-link éphémère consommé par /api/auth/verify).
//   sinon (web)    → createSession + redirige vers /manage.html.
// redirect_uri dérivé du host de la requête : le cookie d'état et le callback
// vivent ainsi sur le MÊME domaine (web = www.doomname.com, app = même host).
// → une seule URL de callback à enregistrer côté GitHub.
function githubCallbackUri(req) {
  return `https://${req.get('host')}/api/auth/github/callback`;
}

app.get('/api/auth/github', (req, res) => {
  if (!GITHUB_CLIENT_ID) return res.status(503).send('GitHub OAuth non configuré');
  const platform  = req.query.platform === 'app' ? 'app' : 'web';
  const rnd        = crypto.randomBytes(16).toString('hex');
  res.cookie('gh_oauth_state', rnd, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 10 * 60 * 1000, path: '/' });
  const redirectUri = githubCallbackUri(req);
  const url = 'https://github.com/login/oauth/authorize'
    + `?client_id=${encodeURIComponent(GITHUB_CLIENT_ID)}`
    + '&scope=user:email'
    + `&state=${rnd}.${platform}`
    + `&redirect_uri=${encodeURIComponent(redirectUri)}`;
  res.redirect(url);
});

app.get('/api/auth/github/callback', async (req, res) => {
  const { code, state } = req.query;
  const [stateRnd, platform] = String(state || '').split('.');
  const cookieState = req.cookies?.gh_oauth_state;
  if (!code || !stateRnd || stateRnd !== cookieState) return res.status(400).send('État OAuth invalide');
  res.clearCookie('gh_oauth_state', { path: '/' });
  try {
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: githubCallbackUri(req),
      }),
    });
    const tokenData   = await tokenRes.json();
    const accessToken = tokenData.access_token;
    if (!accessToken) return res.status(401).send('Échec de l’authentification GitHub');

    const emailsRes = await fetch('https://api.github.com/user/emails', {
      headers: { Authorization: `Bearer ${accessToken}`, 'User-Agent': 'DoomName', Accept: 'application/vnd.github+json' },
    });
    const emails  = await emailsRes.json();
    const primary = Array.isArray(emails)
      ? (emails.find(e => e.primary && e.verified) || emails.find(e => e.verified))
      : null;
    if (!primary) return res.status(401).send('Aucune adresse e-mail GitHub vérifiée');
    const email = primary.email.toLowerCase();
    console.log(`🔐 Connexion GitHub : ${email} (${platform})`);

    if (platform === 'app') {
      // Pont vers l'app : jeton éphémère (5 min) consommé par /api/auth/verify,
      // comme un magic link → l'app récupère l'email et ouvre sa session locale.
      const tok = crypto.randomBytes(32).toString('hex');
      await db.query('INSERT INTO magic_links (email, token, expires_at) VALUES ($1, $2, $3)', [email, tok, new Date(Date.now() + 5 * 60 * 1000)]);
      return res.redirect(`doomname://auth?token=${tok}`);
    }
    try { await createSession(res, email); } catch (e) { console.error('createSession(github):', e.message); }
    return res.redirect('/manage.html');
  } catch (err) {
    console.error('Erreur callback GitHub:', err.message);
    return res.status(500).send('Erreur serveur OAuth GitHub');
  }
});

// ─── Routes de gestion des abonnements ────────────────────────────────────────
app.get('/api/manage/subscriptions', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'E-mail requis' });
  try {
    const { rows } = await db.query('SELECT id, domain, active, created_at, last_status, notified_at, last_change_at FROM subscriptions WHERE email = $1 ORDER BY created_at DESC', [email.toLowerCase()]);
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
  const { email, domain, lang } = req.body;
  if (!email || !domain) return res.status(400).json({ error: 'E-mail et domaine requis' });
  if (!/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/.test(domain)) return res.status(400).json({ error: 'Nom de domaine invalide' });

  try {
    const { rows: activeRows } = await db.query('SELECT COUNT(*) FROM subscriptions WHERE email = $1 AND active = TRUE', [email.toLowerCase()]);
    if (parseInt(activeRows[0].count) >= 50) return res.status(400).json({ error: 'Limite de 50 surveillances actives atteinte' });

    const { rows: totalRows } = await db.query('SELECT COUNT(*) FROM subscriptions WHERE email = $1', [email.toLowerCase()]);
    if (parseInt(totalRows[0].count) >= 200) return res.status(400).json({ error: 'Limite de 200 domaines atteinte — supprimez des entrées pour en ajouter de nouvelles' });

    await db.query(`
      INSERT INTO subscriptions (domain, email, active, lang) VALUES ($1, $2, TRUE, $3)
      ON CONFLICT (domain, email) DO UPDATE SET active = TRUE, created_at = NOW(), lang = $3
    `, [domain.toLowerCase(), email.toLowerCase(), normLang(lang)]);

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

    const whoisRaw = await getWhoisRawWithCache(domain.toLowerCase(), { maxWaiting: INTERACTIVE.maxWaiting });
    const raw = String(whoisRaw || '').trim() || 'Aucune donnée WHOIS disponible.';
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

// Met à jour la langue préférée (colonne lang) de tous les abonnements du compte.
app.post('/api/manage/lang', async (req, res) => {
  const { email, lang } = req.body || {};
  if (!email) return res.status(400).json({ error: 'E-mail requis' });
  try {
    await db.query('UPDATE subscriptions SET lang = $2 WHERE email = $1', [email.toLowerCase(), normLang(lang)]);
    return res.json({ success: true });
  } catch (err) {
    console.error('Erreur maj lang:', err.message);
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

// ─── Suppression de compte ──────────────────────────────────────────────────────
// Suppression effective d'un compte (toutes les tables liées à l'email).
// Révoque d'abord le jeton Apple éventuel (exigence Apple, guideline 5.1.1(v)).
async function deleteAccount(email) {
  try {
    const { rows } = await db.query('SELECT apple_refresh_token FROM user_settings WHERE email = $1', [email]);
    if (rows[0]?.apple_refresh_token) await revokeAppleToken(rows[0].apple_refresh_token);
  } catch (e) { console.error('Lecture jeton Apple :', e.message); }
  await db.query('DELETE FROM subscriptions WHERE email = $1', [email]);
  await db.query('DELETE FROM api_keys WHERE email = $1', [email]);
  await db.query('DELETE FROM user_settings WHERE email = $1', [email]);
  await db.query('DELETE FROM push_tokens WHERE email = $1', [email]);
  await db.query('DELETE FROM sessions WHERE email = $1', [email]);
  // Purge tous les magic links de ce compte (dont les liens de suppression 7j
  // encore valides générés dans les footers d'e-mails).
  await db.query('DELETE FROM magic_links WHERE email = $1', [email]);
  console.log(`🗑️  Compte supprimé : ${email}`);
}

// Avec un jeton de session (Bearer app ou cookie web) : suppression IMMÉDIATE du
// seul compte de cette session (la confirmation a lieu côté client) ; l'email du
// corps est alors ignoré. Sans session : flux historique par e-mail de confirmation.
app.post('/api/account/delete-request', async (req, res) => {
  let sessionEmail = null;
  try { sessionEmail = await getSessionEmail(req); } catch (e) { console.error('getSessionEmail:', e.message); }
  if (sessionEmail) {
    try {
      await deleteAccount(sessionEmail);
      res.clearCookie(SESSION_COOKIE, { path: '/' });
      return res.json({ success: true, deleted: true });
    } catch (err) {
      console.error('Erreur suppression authentifiée:', err.message);
      return res.status(500).json({ error: 'Erreur serveur' });
    }
  }
  // Jeton fourni mais invalide/expiré : on ne retombe pas silencieusement sur l'email.
  if (req.get('authorization')) return res.status(401).json({ error: 'Session invalide ou expirée' });

  const { email } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Adresse e-mail invalide' });

  const token     = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 20 * 60 * 1000);

  try {
    await db.query(
      'INSERT INTO magic_links (email, token, expires_at, purpose) VALUES ($1, $2, $3, $4)',
      [email.toLowerCase(), token, expiresAt, 'delete']
    );
    await sendAccountDeleteEmail(email.toLowerCase(), token, await getUserLang(email));
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

    await deleteAccount(rows[0].email);
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
    const result = await checkWhois(domain, INTERACTIVE);
    if (result.status === 'unknown') {
      return res.status(503).json({ error: 'Registre WHOIS temporairement indisponible, réessayez plus tard' });
    }
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
    // "unknown" n'empêche pas l'abonnement : le cron déterminera le statut.
    const { available } = await checkWhois(domain, INTERACTIVE);
    if (available === true) return res.status(400).json({ error: 'Ce domaine est déjà disponible', available: true });

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

// ─── Notification "disponible" (après confirmation) ────────────────────────────
// notified_at est écrit pour chaque abonnement notifié, et n'est jamais remis à
// NULL : il date le dernier envoi d'alerte "disponible". La mise en évidence
// côté client s'appuie sur last_change_at.
async function notifyAvailable(domain, subs) {
  for (const { email, lang } of subs) {
    const l = normLang(lang);
    try {
      const settings = await getUserSettings(email);
      if (settings.email_alerts_enabled) {
        await sendAlertEmail(email, domain, l);
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
      title: l === 'en' ? `🟢 ${domain} is available!` : `🟢 ${domain} est disponible !`,
      body: l === 'en' ? 'This domain was just released!' : 'Super, ce domaine vient de se libérer !',
      data: { type: 'domain_available', domain, screen: 'manage', filter: 'available' },
    });
    // Écriture par abonné, isolée : un échec ici ne doit pas priver les
    // abonnés suivants de leur alerte (l'envoi a déjà eu lieu pour celui-ci).
    try {
      await db.query(
        'UPDATE subscriptions SET notified_at = NOW() WHERE domain = $1 AND email = $2',
        [domain, email]
      );
    } catch (dbErr) {
      console.error(`  ❌ Erreur écriture notified_at pour ${email} (${domain}):`, dbErr.message);
    }
  }
}

// ─── Disjoncteur par TLD ───────────────────────────────────────────────────────
// Une source en panne se reconnaît à une rafale de bascules pris→disponible
// simultanées, ou à une avalanche d'"unknown". Trois règles, par TLD et par run :
//  - rafale  : au moins 2 bascules NOUVELLES et plus de 30 % du TLD. Nouvelle =
//    domaine pas encore vu libre (whois_free_since NULL). Un domaine réellement
//    libéré n'est compté qu'une fois : sans ça, il restait "pris" en base,
//    rebasculait à chaque run et bloquait le disjoncteur ouvert pour toujours
//    (.io, 06/11/2026).
//  - masse   : plus de 60 % du TLD en bascule, en ne comptant que les bascules
//    nouvelles ou vues libres depuis moins de 6 h — panne durable. Au-delà de
//    6 h, une panne de registre se voit par ailleurs, alors qu'un TLD dont la
//    majorité des domaines est réellement libre resterait bloqué indéfiniment
//    (pending_confirmation_since n'étant jamais écrit disjoncteur ouvert).
//  - unknown : plus de 30 % du TLD en "unknown".
// Déclenché : aucun envoi ni écriture (hors whois_free_since) pour ce TLD dans
// ce run, log ERROR, e-mail à ADMIN_ALERT_EMAIL s'il est configuré.
// En dessous de BREAKER_MIN_SAMPLE domaines, un ratio n'a pas de sens : le
// disjoncteur ne s'applique pas.
const BREAKER_THRESHOLD       = 0.30;  // rafale et unknown
const BREAKER_MIN_NEW_FLIPS   = 2;
const BREAKER_MASS_THRESHOLD  = 0.60;
const BREAKER_MASS_WINDOW_MS  = 6 * 60 * 60 * 1000;
const BREAKER_MIN_SAMPLE      = 5;

// Au plus un e-mail admin par clé (ici : par TLD) toutes les 6 h, pour qu'un
// disjoncteur qui reste ouvert run après run n'envoie pas un e-mail par heure.
// Fenêtre en mémoire : remise à zéro à chaque redémarrage, ce qui est voulu.
const ADMIN_ALERT_SILENCE_MS = 6 * 60 * 60 * 1000;
const lastAdminAlertAt = new Map();

async function notifyAdmin(key, subject, text) {
  const to = (process.env.ADMIN_ALERT_EMAIL || '').trim();
  if (!to) return;
  const last = lastAdminAlertAt.get(key);
  if (last && Date.now() - last < ADMIN_ALERT_SILENCE_MS) {
    console.log(`  🔕 Alerte admin "${key}" déjà envoyée il y a ${Math.round((Date.now() - last) / 60000)} min — silence`);
    return;
  }
  lastAdminAlertAt.set(key, Date.now());
  try {
    await resend.emails.send({ from: EMAIL_FROM, to, subject, text });
  } catch (err) {
    console.error('  ❌ Erreur envoi alerte admin :', err.message);
  }
}

function evaluateBreakers(checks) {
  const byTld = new Map();
  for (const c of checks) {
    const tld = tldOf(c.domain);
    const s = byTld.get(tld) || { tld, total: 0, flips: 0, newFlips: 0, massFlips: 0, unknowns: 0 };
    s.total++;
    if (c.result.status === 'unknown') s.unknowns++;
    else if (c.result.available && !c.wasAvailable) {
      s.flips++;
      if (!c.freeSince) s.newFlips++;
      if (!c.freeSince || Date.now() - new Date(c.freeSince).getTime() < BREAKER_MASS_WINDOW_MS) s.massFlips++;
    }
    byTld.set(tld, s);
  }
  const tripped = new Map();
  for (const s of byTld.values()) {
    if (s.total < BREAKER_MIN_SAMPLE) continue;
    const flipRate = s.flips / s.total;
    const newFlipRate = s.newFlips / s.total;
    const massFlipRate = s.massFlips / s.total;
    const unknownRate = s.unknowns / s.total;
    const rules = [];
    if (s.newFlips >= BREAKER_MIN_NEW_FLIPS && newFlipRate > BREAKER_THRESHOLD) rules.push('rafale');
    if (massFlipRate > BREAKER_MASS_THRESHOLD) rules.push('masse');
    if (unknownRate > BREAKER_THRESHOLD) rules.push('unknown');
    if (rules.length) tripped.set(s.tld, { ...s, flipRate, newFlipRate, massFlipRate, unknownRate, rules });
  }
  return tripped;
}

// ─── Traitement d'un domaine après lecture WHOIS ──────────────────────────────
async function applyCheck(domain, result, subs) {
  const { status } = result;
  const wasAvailable = subs.some(s => s.last_status === 'available');
  const pendingSince = subs.map(s => s.pending_confirmation_since).filter(Boolean)
    .map(d => new Date(d).getTime()).sort((a, b) => a - b)[0];

  // "unknown" : rien n'est écrit, rien n'est envoyé (réponse brute déjà loggée).
  if (status === 'unknown') {
    console.log(`❔ ${domain} statut inconnu (${result.reason}) — dernier statut connu conservé`);
    return;
  }

  if (result.available) {
    if (wasAvailable) {
      // Déjà signalé disponible : on continue de surveiller (pour détecter
      // une reprise) mais on ne ré-alerte pas.
      console.log(`✅ ${domain} toujours disponible — déjà notifié, pas de nouvelle alerte`);
    } else if (!pendingSince) {
      console.log(`🕒 ${domain} semble disponible — confirmation au prochain run (≥ 1 h) avant alerte`);
      await db.query('UPDATE subscriptions SET pending_confirmation_since = NOW() WHERE domain = $1 AND active = TRUE', [domain]);
    } else if (Date.now() - pendingSince < CONFIRMATION_DELAY_MS) {
      console.log(`⏳ ${domain} en attente de confirmation (depuis ${Math.round((Date.now() - pendingSince) / 60000)} min)`);
    } else {
      console.log(`✅ ${domain} confirmé disponible (2e détection, ${Math.round((Date.now() - pendingSince) / 60000)} min après la 1re)`);
      // On garde l'alerte ACTIVE pour continuer à surveiller le domaine : s'il est
      // repris, on pourra envoyer la notification "Dommage".
      await db.query(
        "UPDATE subscriptions SET last_status = 'available', last_change_at = NOW(), pending_confirmation_since = NULL WHERE domain = $1",
        [domain]
      );
      await notifyAvailable(domain, subs);
    }
    return;
  }

  if (pendingSince) {
    console.log(`↩️  ${domain} pris avant la fin du délai de confirmation — alerte annulée (statut : ${status})`);
  } else {
    console.log(`⏳ ${domain} toujours pris (statut : ${status})`);
  }
  // Statut écrit AVANT tout envoi : si l'écriture échoue, rien n'est envoyé et
  // le run suivant ne peut pas renvoyer la même notification (régression du
  // 06/11/2026 : écriture en échec après envoi → "Dommage" renvoyé chaque heure).
  // last_change_at date le changement de statut (mise en évidence côté client) ;
  // notified_at n'est jamais touché ici. Les envois ci-dessous s'appuient sur
  // `subs`, lu avant cette écriture.
  await db.query(
    `UPDATE subscriptions
        SET last_status = $2::varchar,
            last_change_at = CASE WHEN last_status IS DISTINCT FROM $2::varchar THEN NOW() ELSE last_change_at END,
            pending_confirmation_since = NULL
      WHERE domain = $1`,
    [domain, status]
  );
  for (const { email, last_status, lang } of subs) {
    const l = normLang(lang);
    if (last_status === 'available') {
      // « Dommage » : le domaine était disponible et vient d'être repris.
      const settings = await getUserSettings(email);
      if (settings.email_alerts_enabled) {
        try {
          await sendMissedEmail(email, domain, l);
          console.log(`  📧 Notification "Dommage" (repris) envoyée à ${email}`);
        } catch (mailErr) {
          console.error(`  ❌ Erreur envoi mail à ${email}:`, mailErr.message);
        }
      }
      await sendMissedPush(email, domain, l);
    } else if (status !== last_status && ['gracePeriod', 'redemptionPeriod', 'pendingDelete'].includes(status)) {
      const settings = await getUserSettings(email);
      // La préférence "Période de grâce" pilote toute cette catégorie
      // (grâce / rédemption / suppression), e-mail comme push.
      if (settings.grace_alerts_enabled) {
        if (settings.email_alerts_enabled) {
          try {
            await sendStatusChangeEmail(email, domain, status, l);
            console.log(`  📧 Alerte de changement d'état (${status}) envoyée à ${email}`);
          } catch (mailErr) {
            console.error(`  ❌ Erreur envoi mail à ${email}:`, mailErr.message);
          }
        }
        await sendStatusChangePush(email, domain, status, l);
      } else {
        console.log(`  🔕 Alertes de grâce/rédemption désactivées pour ${email}, envoi ignoré`);
      }
    }
  }
}

// Mémorise ce que le WHOIS a vu, disjoncteur ouvert ou non : libre →
// whois_free_since posé (s'il ne l'est pas déjà) ; pris → remis à NULL ;
// unknown → rien (aucune information). Ne déclenche jamais d'envoi.
async function recordWhoisObservation(domain, result) {
  if (result.status === 'unknown') return;
  if (result.available) {
    await db.query('UPDATE subscriptions SET whois_free_since = COALESCE(whois_free_since, NOW()) WHERE domain = $1', [domain]);
  } else {
    await db.query('UPDATE subscriptions SET whois_free_since = NULL WHERE domain = $1 AND whois_free_since IS NOT NULL', [domain]);
  }
}

// Un run du cron :
// 1. Lecture WHOIS de tous les domaines, regroupés par TLD : en série au sein
//    d'un TLD (file globale), en parallèle entre TLDs.
// 2. Disjoncteur par TLD sur l'ensemble des résultats du run.
// 3. whois_free_since mis à jour pour tous les domaines (même TLD disjoncté).
// 4. Application (écritures + envois) pour les TLDs sains uniquement.
async function runCron() {
  let rows;
  try {
    const result = await db.query(
      `SELECT domain, bool_or(last_status = 'available') AS was_available,
              min(whois_free_since) AS free_since
         FROM subscriptions WHERE active = TRUE
        GROUP BY domain
        ORDER BY split_part(domain, '.', array_length(string_to_array(domain, '.'), 1)), domain`
    );
    rows = result.rows;
  } catch (err) {
    console.error('Erreur lecture DB (cron):', err.message);
    return;
  }

  const checks = await Promise.all(rows.map(async ({ domain, was_available, free_since }) => ({
    domain,
    wasAvailable: was_available === true,
    freeSince: free_since || null,
    result: await checkWhois(domain),   // jamais de cache ici
  })));

  const tripped = evaluateBreakers(checks);
  for (const s of tripped.values()) {
    const msg = `[DISJONCTEUR] .${s.tld} (${s.rules.join(' + ')}) : ` +
      `${s.newFlips}/${s.total} bascules nouvelles (${Math.round(s.newFlipRate * 100)} %), ` +
      `${s.flips}/${s.total} bascules au total (${Math.round(s.flipRate * 100)} %), ` +
      `${s.massFlips}/${s.total} de moins de 6 h (${Math.round(s.massFlipRate * 100)} %), ` +
      `${s.unknowns}/${s.total} unknown (${Math.round(s.unknownRate * 100)} %) — ` +
      `seuils : rafale ≥ ${BREAKER_MIN_NEW_FLIPS} et > ${BREAKER_THRESHOLD * 100} %, ` +
      `masse > ${BREAKER_MASS_THRESHOLD * 100} % (< 6 h), unknown > ${BREAKER_THRESHOLD * 100} %. ` +
      `Envois et écritures suspendus pour .${s.tld} sur ce run.`;
    console.error(`🛑 ${new Date().toISOString()} ${msg}`);
    await notifyAdmin(`disjoncteur:${s.tld}`, `🛑 DoomName — disjoncteur .${s.tld} déclenché`, msg);
  }

  for (const { domain, result } of checks) {
    try {
      await recordWhoisObservation(domain, result);
    } catch (err) {
      console.error(`Erreur écriture whois_free_since pour ${domain}:`, err.message);
    }
    if (tripped.has(tldOf(domain))) {
      console.log(`🛑 ${domain} ignoré (disjoncteur .${tldOf(domain)}) — résultat brut : ${result.status}`);
      continue;
    }
    try {
      const { rows: subs } = await db.query("SELECT email, last_status, pending_confirmation_since, COALESCE(lang,'fr') AS lang FROM subscriptions WHERE domain = $1 AND active = TRUE", [domain]);
      await applyCheck(domain, result, subs);
    } catch (err) {
      console.error(`Erreur cron pour ${domain}:`, err.message);
    }
  }
}

// ─── Cron job — vérification toutes les heures ─────────────────────────────────
let cronRunning = false;
cron.schedule('0 * * * *', async () => {
  if (cronRunning) {
    console.warn('⚠️  Run précédent encore en cours — run ignoré');
    return;
  }
  cronRunning = true;
  console.log(`\n🔄 [${new Date().toISOString()}] Lancement du cron job…`);
  try {
    await runCron();
  } finally {
    cronRunning = false;
    console.log('✔️  Cron job terminé\n');
  }
});

// ─── Démarrage ─────────────────────────────────────────────────────────────────
async function start() {
  await initDB();
  await ensureReviewToken();
  app.listen(port, () => {
    console.log(`🚀 DoomName en ligne sur http://localhost:${port}`);
    console.log(`   Cron job actif — vérification toutes les heures`);
  });
}

start();