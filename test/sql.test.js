// Tests SQL du cron (régression du 06/11/2026 : "inconsistent types deduced
// for parameter $2" → last_status jamais écrit → "Dommage" renvoyé à chaque run).
// Exécute applyCheck et detectAndStoreStatus tels qu'écrits dans server.js
// contre un vrai PostgreSQL, sur une table TEMPORAIRE (rien n'est persisté).
// Lancer : TEST_DATABASE_URL=postgres://… npm run test:sql
const path = require('path');
const fs = require('fs');
const { Client } = require('pg');

const url = process.env.TEST_DATABASE_URL;
if (!url) {
  console.error('TEST_DATABASE_URL requis (PostgreSQL de test).');
  process.exit(2);
}

const src = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const slice = (from, to) => {
  const a = src.indexOf(from), b = src.indexOf(to, a);
  if (a === -1 || b === -1) throw new Error(`bloc introuvable : ${from}`);
  return src.slice(a, b);
};
const applyCheckSrc = slice("// ─── Traitement d'un domaine après lecture WHOIS", '// ─── Cron job');
const detectSrc = slice('async function detectAndStoreStatus', '// ─── Route POST /api/subscribe');

let fail = 0, n = 0;
const expect = (name, got, want) => {
  n++;
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}: ${JSON.stringify(got)}${ok ? '' : ` (attendu ${JSON.stringify(want)})`}`);
};

(async () => {
  const client = new Client({ connectionString: url });
  await client.connect();
  // Mêmes types de colonnes qu'en production (initDB).
  await client.query(`
    CREATE TEMP TABLE subscriptions (
      id SERIAL PRIMARY KEY, domain VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL,
      active BOOLEAN DEFAULT TRUE, created_at TIMESTAMPTZ DEFAULT NOW(),
      last_status VARCHAR(32) DEFAULT 'taken', pending_confirmation_since TIMESTAMPTZ,
      notified_at TIMESTAMPTZ, lang VARCHAR(2) DEFAULT 'fr', last_change_at TIMESTAMPTZ,
      UNIQUE(domain, email))`);

  const sent = [];
  const deps = {
    normLang: (l) => (l === 'en' ? 'en' : 'fr'),
    getUserSettings: async () => ({ email_alerts_enabled: true, grace_alerts_enabled: true }),
    sendMissedEmail: async (e, d) => sent.push(`missed-mail:${d}`),
    sendMissedPush: async (e, d) => sent.push(`missed-push:${d}`),
    sendStatusChangeEmail: async (e, d, s) => sent.push(`status-mail:${d}:${s}`),
    sendStatusChangePush: async (e, d, s) => sent.push(`status-push:${d}:${s}`),
    notifyAvailable: async (d) => sent.push(`available:${d}`),
    CONFIRMATION_DELAY_MS: 60 * 60 * 1000,
    INTERACTIVE: {},
  };
  const load = (db, checkWhois = async () => ({ status: 'taken' })) => new Function(
    'db', 'checkWhois', ...Object.keys(deps),
    `${applyCheckSrc}\n${detectSrc}\nreturn { applyCheck, detectAndStoreStatus };`
  )(db, checkWhois, ...Object.values(deps));

  const subsOf = async (domain) => (await client.query(
    "SELECT email, last_status, pending_confirmation_since, COALESCE(lang,'fr') AS lang FROM subscriptions WHERE domain = $1 AND active = TRUE",
    [domain])).rows;
  const row = async (domain) => (await client.query(
    'SELECT last_status, last_change_at IS NOT NULL AS changed, notified_at FROM subscriptions WHERE domain = $1', [domain])).rows[0];
  // Un run du cron pour un domaine : relit les abonnements comme le cron, puis applyCheck.
  const run = async (fns, domain, result) => {
    sent.length = 0;
    let error = null;
    try { await fns.applyCheck(domain, result, await subsOf(domain)); } catch (e) { error = e.message; }
    return { sent: [...sent], error };
  };

  const fns = load(client);

  // 1. « Dommage » : disponible en base, pris au WHOIS → 1 envoi, puis plus rien.
  await client.query("INSERT INTO subscriptions (domain, email, last_status) VALUES ('repris.com', 'a@x.test', 'available')");
  let r = await run(fns, 'repris.com', { status: 'taken', available: false });
  expect('Dommage run 1 : erreur SQL', r.error, null);
  expect('Dommage run 1 : envois', r.sent, ['missed-mail:repris.com', 'missed-push:repris.com']);
  expect('Dommage run 1 : statut écrit', await row('repris.com'), { last_status: 'taken', changed: true, notified_at: null });
  r = await run(fns, 'repris.com', { status: 'taken', available: false });
  expect('Dommage run 2 : aucun renvoi', r.sent, []);

  // 2. Changement d'état : pris en base, redemptionPeriod au WHOIS → 1 envoi, puis plus rien.
  await client.query("INSERT INTO subscriptions (domain, email, last_status) VALUES ('redemption.com', 'b@x.test', 'taken')");
  r = await run(fns, 'redemption.com', { status: 'redemptionPeriod', available: false });
  expect('Statut run 1 : erreur SQL', r.error, null);
  expect('Statut run 1 : envois', r.sent, ['status-mail:redemption.com:redemptionPeriod', 'status-push:redemption.com:redemptionPeriod']);
  expect('Statut run 1 : statut écrit', (await row('redemption.com')).last_status, 'redemptionPeriod');
  r = await run(fns, 'redemption.com', { status: 'redemptionPeriod', available: false });
  expect('Statut run 2 : aucun renvoi', r.sent, []);

  // 3. Inchangé : pris → pris, last_change_at non touché.
  await client.query("INSERT INTO subscriptions (domain, email, last_status) VALUES ('stable.com', 'c@x.test', 'taken')");
  r = await run(fns, 'stable.com', { status: 'taken', available: false });
  expect('Stable : erreur SQL', r.error, null);
  expect('Stable : last_change_at inchangé', (await row('stable.com')).changed, false);

  // 4. Écriture en échec → AUCUN envoi (l'écriture précède les envois).
  await client.query("INSERT INTO subscriptions (domain, email, last_status) VALUES ('echec.com', 'd@x.test', 'available')");
  const failingDb = { query: (sql, params) => (/^\s*UPDATE/i.test(sql) ? Promise.reject(new Error('écriture simulée en échec')) : client.query(sql, params)) };
  r = await run(load(failingDb), 'echec.com', { status: 'taken', available: false });
  expect('Écriture en échec : erreur remontée', r.error, 'écriture simulée en échec');
  expect('Écriture en échec : aucun envoi', r.sent, []);

  // 5. detectAndStoreStatus (ajout d'une surveillance) : statut écrit sans erreur.
  await client.query("INSERT INTO subscriptions (domain, email, last_status) VALUES ('ajout.com', 'e@x.test', 'taken')");
  const warns = [];
  const origWarn = console.warn;
  console.warn = (...a) => warns.push(a.join(' '));
  const detected = await load(client, async () => ({ status: 'gracePeriod' })).detectAndStoreStatus('ajout.com', 'e@x.test');
  console.warn = origWarn;
  expect('detectAndStoreStatus : erreur SQL', warns.join(' ') || null, null);
  expect('detectAndStoreStatus : retour', detected, 'gracePeriod');
  expect('detectAndStoreStatus : statut écrit', await row('ajout.com'), { last_status: 'gracePeriod', changed: true, notified_at: null });

  await client.end();
  console.log(fail ? `${fail}/${n} ÉCHEC(S)` : `TOUT OK (${n} cas)`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('ERREUR', e); process.exit(1); });
