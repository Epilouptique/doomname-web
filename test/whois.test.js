// Tests du classifieur et de la file WHOIS (incident AFNIC du 13/10/2026).
// Charge le bloc WHOIS de server.js tel quel, sans DB ni serveur ni réseau.
// Lancer : npm test
const path = require('path');
const util = require('util');
const fs = require('fs');
const root = path.join(__dirname, '..');
const src = fs.readFileSync(path.join(root, 'server.js'), 'utf8');
const parseWhoisFields = require(path.join(root, 'node_modules', 'whois-json', 'parse-raw-data.js'));
const a = src.indexOf("// ─── WHOIS : file d'attente globale par TLD");
const b = src.indexOf('// ─── Middleware API Key');
const warns = [];
const out = console.log;
console.warn = (m) => warns.push(m);
const load = (lib) => new Function('whoisLib', 'parseWhoisFields', 'util',
  src.slice(a, b) + '\nreturn { classifyWhois, checkWhois };')(lib, parseWhoisFields, util);
const { classifyWhois } = load(require(path.join(root, 'node_modules', 'whois')));

let fail = 0, n = 0;
const expect = (name, got, want) => { n++; if (got !== want) { fail++; out(`FAIL ${name}: ${got} (attendu ${want})`); } };
const st = (d, t) => classifyWhois(d, t).status;

expect('fr vide', st('google.fr', ''), 'unknown');
expect('fr refus', st('google.fr', '%% Too many requests, please try again later'), 'unknown');
expect('fr refus + NOT FOUND', st('x.fr', '%% NOT FOUND\n%% Query rate limit exceeded'), 'unknown');
expect('fr raison refusal', classifyWhois('x.fr', 'Rate limit exceeded').reason, 'refusal');
expect('fr non reconnu', st('google.fr', 'foo: bar\nbaz: qux'), 'unknown');
expect('fr libre %%', st('zz.fr', '%%\n%% This is the AFNIC Whois server.\n%%\n\n%% NOT FOUND\n'), 'available');
expect('fr libre No entries', st('zz.fr', 'No entries found in the AFNIC Database.\n'), 'available');
expect('fr pris', st('google.fr', 'domain:      google.fr\nstatus:      ACTIVE\n'), 'taken');
expect('fr pris autre domaine', st('google.fr', 'domain:      autre.fr\n'), 'unknown');
expect('com libre', st('zz.com', 'No match for domain "ZZ.COM".\n'), 'available');
expect('com not found générique', st('zz.com', 'Domain not found.'), 'unknown');
expect('com pris', st('google.com', '   Domain Name: GOOGLE.COM\n   Registry Expiry Date: 2028-09-14T04:00:00Z\n'), 'taken');
expect('com pendingDelete', st('x.com', 'Domain Name: X.COM\nDomain Status: pendingDelete'), 'pendingDelete');
expect('io libre + mentions légales', st('zz.io', 'Domain not found.\r\n>>> Last update of WHOIS database: x <<<\r\n\r\nTerms of Use: maintenance periods. If too many queries are received'), 'available');
expect('refus en tête + mentions', st('zz.io', 'Rate limit exceeded\r\n>>> Last update of WHOIS database: x <<<\r\nTerms of Use: ...'), 'unknown');
expect('studio non supporté', st('zz.studio', 'TLD is not supported.\r\n>>> Last update of WHOIS database: x <<<'), 'unknown');
expect('TLD non cartographié', classifyWhois('zz.eu', 'Status: AVAILABLE').reason, 'unmapped_tld');
expect('log UNMAPPED_TLD avec brut', warns.some(w => w.includes('[WHOIS][UNMAPPED_TLD]') && w.includes('réponse brute')), true);
expect('log REFUSAL avec brut', warns.some(w => w.includes('[WHOIS][REFUSAL]') && w.includes('réponse brute')), true);
classifyWhois('x.fr', 'holder: Jean Dupont');
expect('log UNKNOWN sans brut', warns.filter(w => w.includes('[WHOIS][UNKNOWN]')).every(w => !w.includes('réponse brute')), true);
classifyWhois('x.fr', 'Rate limit ' + 'A'.repeat(3000));
expect('brut tronqué ≤ 1000', warns[warns.length - 1].length < 1200, true);

(async () => {
  const starts = [];
  const fake = { lookup: (d, o, cb) => { starts.push(Date.now()); setTimeout(() => cb(null, '%% NOT FOUND'), 200); } };
  const { checkWhois: cw } = load(fake);
  await Promise.all(['a.fr', 'b.fr', 'c.fr', 'd.com'].map(d => cw(d)));
  const s = starts.slice().sort((x, y) => x - y);
  expect('fr espacés ≥ 1,7 s, .com en parallèle', s[2] - s[1] >= 1650 && s[3] - s[2] >= 1650, true);
  expect('file saturée → unknown', (await cw('e.fr', { maxWaiting: 0 })).reason, 'queue_full');
  out(fail ? `${fail}/${n} ÉCHEC(S)` : `TOUT OK (${n} cas)`);
  process.exit(fail ? 1 : 0);
})();
