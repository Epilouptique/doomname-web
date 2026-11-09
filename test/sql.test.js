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
// Notification "disponible" + disjoncteur (evaluateBreakers, notifyAdmin).
const notifySrc = slice('// ─── Notification "disponible"', "// ─── Traitement d'un domaine après lecture WHOIS");
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
      whois_free_since TIMESTAMPTZ,
      UNIQUE(domain, email))`);

  const sent = [];
  const deps = {
    normLang: (l) => (l === 'en' ? 'en' : 'fr'),
    getUserSettings: async () => ({ email_alerts_enabled: true, grace_alerts_enabled: true }),
    sendMissedEmail: async (e, d) => sent.push(`missed-mail:${d}`),
    sendMissedPush: async (e, d) => sent.push(`missed-push:${d}`),
    sendStatusChangeEmail: async (e, d, s) => sent.push(`status-mail:${d}:${s}`),
    sendStatusChangePush: async (e, d, s) => sent.push(`status-push:${d}:${s}`),
    sendAlertEmail: async (e, d) => sent.push(`available-mail:${e}`),
    sendPushNotification: async (e) => sent.push(`available-push:${e}`),
    CONFIRMATION_DELAY_MS: 60 * 60 * 1000,
    INTERACTIVE: {},
    tldOf: (d) => String(d).toLowerCase().split('.').pop(),
    resend: { emails: { send: async () => ({}) } },
    EMAIL_FROM: 'test@x.test',
  };
  const load = (db, checkWhois = async () => ({ status: 'taken' })) => new Function(
    'db', 'checkWhois', ...Object.keys(deps),
    `${notifySrc}\n${applyCheckSrc}\n${detectSrc}\nreturn { notifyAvailable, applyCheck, detectAndStoreStatus, evaluateBreakers, runCron: typeof runCron === 'function' ? runCron : null };`
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

  // 6. Ancien gracePeriod (en réalité autoRenewPeriod) reclassé pris → aucune alerte.
  await client.query("INSERT INTO subscriptions (domain, email, last_status) VALUES ('renouvele.fr', 'f@x.test', 'gracePeriod')");
  r = await run(fns, 'renouvele.fr', { status: 'taken', available: false });
  expect('Ex-gracePeriod → pris : aucun envoi', r.sent, []);
  expect('Ex-gracePeriod → pris : statut écrit', (await row('renouvele.fr')).last_status, 'taken');

  // 7. notifyAvailable : l'écriture de notified_at échoue pour le 1er abonné →
  //    le 2e reçoit quand même son alerte, et son notified_at est écrit.
  await client.query("INSERT INTO subscriptions (domain, email, last_status) VALUES ('libre.com', 'g1@x.test', 'available'), ('libre.com', 'g2@x.test', 'available')");
  const notifiedFailDb = { query: (sql, params) => (/notified_at = NOW/.test(sql) && params[1] === 'g1@x.test' ? Promise.reject(new Error('notified_at en échec')) : client.query(sql, params)) };
  sent.length = 0;
  const errs = [];
  const origErr = console.error;
  console.error = (...a) => errs.push(a.join(' '));
  let thrown = null;
  try { await load(notifiedFailDb).notifyAvailable('libre.com', [{ email: 'g1@x.test', lang: 'fr' }, { email: 'g2@x.test', lang: 'fr' }]); } catch (e) { thrown = e.message; }
  console.error = origErr;
  expect('notifyAvailable : aucune exception remontée', thrown, null);
  expect('notifyAvailable : 2e abonné notifié', sent, ['available-mail:g1@x.test', 'available-push:g1@x.test', 'available-mail:g2@x.test', 'available-push:g2@x.test']);
  expect('notifyAvailable : notified_at du 2e écrit', (await client.query("SELECT notified_at IS NOT NULL AS ok FROM subscriptions WHERE email = 'g2@x.test'")).rows[0].ok, true);
  expect('notifyAvailable : échec loggé', errs.some(e => e.includes('notified_at en échec')), true);

  // 8. Disjoncteur .io bloqué ouvert (deadlock du 06/11/2026) : 5 domaines .io,
  //    3 réellement libres. Run 1 : bascules nouvelles → disjoncteur. Run 2 :
  //    plus nouvelles (whois_free_since) → passe, confirmation en attente.
  //    Run 3 (≥ 1 h) : confirmé, alerte "disponible".
  await client.query('DELETE FROM subscriptions');   // runCron lit toute la table
  const free = new Set(['l1.io', 'l2.io', 'l3.io']);
  await client.query(`INSERT INTO subscriptions (domain, email) VALUES
    ('l1.io','h1@x.test'),('l2.io','h2@x.test'),('l3.io','h3@x.test'),('p1.io','h4@x.test'),('p2.io','h5@x.test')`);
  const whoisIo = async (d) => (free.has(d) ? { status: 'available', available: true } : { status: 'taken', available: false });
  // Un run complet du cron sur les .io. Avec runCron (code corrigé) : la vraie
  // fonction. Sans (code actuel) : copie conforme de la boucle du cron actuel.
  const cronIo = async () => {
    const f = load(client, whoisIo);
    sent.length = 0;
    const logs = [];
    const oe = console.error, ol = console.log;
    console.error = (...a) => logs.push(a.join(' '));
    console.log = (...a) => logs.push(a.join(' '));
    try {
      if (f.runCron) await f.runCron();
      else {
        const { rows } = await client.query(`SELECT domain, bool_or(last_status = 'available') AS was_available
          FROM subscriptions WHERE active = TRUE AND domain LIKE '%.io' GROUP BY domain`);
        const checks = await Promise.all(rows.map(async ({ domain, was_available }) => ({
          domain, wasAvailable: was_available === true, result: await whoisIo(domain) })));
        const tripped = f.evaluateBreakers(checks);
        for (const s of tripped.values()) logs.push(`[DISJONCTEUR] .${s.tld}`);
        for (const { domain, result } of checks) {
          if (tripped.has(f.tldOf ? f.tldOf(domain) : domain.split('.').pop())) continue;
          await f.applyCheck(domain, result, await subsOf(domain));
        }
      }
    } finally { console.error = oe; console.log = ol; }
    return { tripped: logs.some(l => l.includes('[DISJONCTEUR]')), sent: [...sent].sort() };
  };
  const ioState = async () => (await client.query(`SELECT domain, last_status,
      pending_confirmation_since IS NOT NULL AS pending, whois_free_since IS NOT NULL AS seen_free
      FROM subscriptions WHERE domain LIKE 'l_.io' ORDER BY domain`)).rows
    .map(r => `${r.domain}:${r.last_status}:${r.pending ? 'pending' : '-'}:${r.seen_free ? 'vu-libre' : '-'}`);

  let c = await cronIo();
  expect('Deadlock run 1 : disjoncteur (3 bascules nouvelles / 5)', c.tripped, true);
  expect('Deadlock run 1 : aucun envoi', c.sent, []);
  expect('Deadlock run 1 : vu libre noté, pas de pending', await ioState(), ['l1.io:taken:-:vu-libre', 'l2.io:taken:-:vu-libre', 'l3.io:taken:-:vu-libre']);
  c = await cronIo();
  expect('Deadlock run 2 : disjoncteur fermé (0 nouvelle, 60 % pas > 60 %)', c.tripped, false);
  expect('Deadlock run 2 : aucun envoi', c.sent, []);
  expect('Deadlock run 2 : confirmation en attente', await ioState(), ['l1.io:taken:pending:vu-libre', 'l2.io:taken:pending:vu-libre', 'l3.io:taken:pending:vu-libre']);
  await client.query("UPDATE subscriptions SET pending_confirmation_since = NOW() - INTERVAL '61 minutes' WHERE domain LIKE 'l_.io'");
  c = await cronIo();
  expect('Deadlock run 3 : disjoncteur fermé', c.tripped, false);
  expect('Deadlock run 3 : alertes disponibles', c.sent, ['available-mail:h1@x.test', 'available-mail:h2@x.test', 'available-mail:h3@x.test', 'available-push:h1@x.test', 'available-push:h2@x.test', 'available-push:h3@x.test']);
  free.delete('l1.io');
  await cronIo();
  expect('Vu pris à nouveau : whois_free_since remis à NULL', (await client.query("SELECT whois_free_since FROM subscriptions WHERE domain = 'l1.io'")).rows[0].whois_free_since, null);

  // 9. Panne durable (tous les .io faussement libres) : run 1 rafale, run 2
  //    règle de masse (5 domaines, 100 % > 60 %) → toujours bloqué, rien écrit
  //    hors whois_free_since.
  await client.query("DELETE FROM subscriptions WHERE domain LIKE '%.io'");
  ['l1.io', 'l2.io', 'l3.io', 'p1.io', 'p2.io'].forEach(d => free.add(d));
  await client.query(`INSERT INTO subscriptions (domain, email) VALUES
    ('l1.io','h1@x.test'),('l2.io','h2@x.test'),('l3.io','h3@x.test'),('p1.io','h4@x.test'),('p2.io','h5@x.test')`);
  c = await cronIo();
  expect('Panne run 1 : disjoncteur', c.tripped, true);
  c = await cronIo();
  expect('Panne run 2 : disjoncteur (règle de masse)', c.tripped, true);
  expect('Panne run 2 : aucun envoi', c.sent, []);
  expect('Panne : pending jamais écrit disjoncteur ouvert', (await client.query("SELECT count(*)::int n FROM subscriptions WHERE domain LIKE '%.io' AND pending_confirmation_since IS NOT NULL")).rows[0].n, 0);

  // 10. Règle de masse limitée à 6 h : ne compte que les bascules vues libres
  //     depuis moins de 6 h (ou nouvelles). Un TLD dont la majorité des domaines
  //     est réellement libre ne reste pas bloqué indéfiniment.
  const resetIo = async (freeList, freeSinceSql) => {
    await client.query("DELETE FROM subscriptions WHERE domain LIKE '%.io'");
    free.clear(); freeList.forEach(d => free.add(d));
    await client.query(`INSERT INTO subscriptions (domain, email) VALUES
      ('l1.io','h1@x.test'),('l2.io','h2@x.test'),('l3.io','h3@x.test'),('p1.io','h4@x.test'),('p2.io','h5@x.test')`);
    for (const [d, since] of Object.entries(freeSinceSql)) {
      await client.query(`UPDATE subscriptions SET whois_free_since = ${since} WHERE domain = $1`, [d]);
    }
  };
  // 3 vus libres il y a plus de 6 h + 1 nouveau : 4/5 = 80 %, mais 1/5 récent.
  await resetIo(['l1.io', 'l2.io', 'l3.io', 'p1.io'], {
    'l1.io': "NOW() - INTERVAL '7 hours'", 'l2.io': "NOW() - INTERVAL '7 hours'", 'l3.io': "NOW() - INTERVAL '7 hours'" });
  c = await cronIo();
  expect('Masse 6 h : 3 vus libres > 6 h + 1 nouveau → pas de déclenchement', c.tripped, false);
  // Panne durable de moins de 6 h : tous vus libres il y a 2 h → masse.
  await resetIo(['l1.io', 'l2.io', 'l3.io', 'p1.io', 'p2.io'], Object.fromEntries(
    ['l1.io', 'l2.io', 'l3.io', 'p1.io', 'p2.io'].map(d => [d, "NOW() - INTERVAL '2 hours'"])));
  c = await cronIo();
  expect('Masse 6 h : panne durable < 6 h → déclenchement', c.tripped, true);
  expect('Masse 6 h : panne durable < 6 h → aucun envoi', c.sent, []);

  await client.end();
  console.log(fail ? `${fail}/${n} ÉCHEC(S)` : `TOUT OK (${n} cas)`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('ERREUR', e); process.exit(1); });
