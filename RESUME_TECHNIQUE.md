# DoomName — Résumé technique

## Points connus à corriger

- **notifyAvailable (server.js) — envoi avant écriture de `notified_at`.** Pour
  chaque abonné, l'e-mail et le push partent, puis `notified_at` est écrit. Si
  cette écriture échoue, l'exception interrompt la boucle et les abonnés
  suivants ne reçoivent pas leur alerte « disponible ». Pas de risque de boucle
  (`last_status = 'available'` est écrit avant l'appel). À corriger par un
  try/catch par abonné. Relevé le 09/11/2026, non corrigé dans cfe761d.

## Décisions et limites connues

- **autoRenewPeriod / renewPeriod classés "taken" (09/11/2026).** Ces statuts
  EPP signifient que le domaine vient d'être renouvelé ; ils étaient classés
  gracePeriod à tort (4 domaines .fr concernés, dont orange.fr). Limite
  acceptée : en .com (gTLD), un domaine qui vient d'expirer passe aussi en
  autoRenewPeriod, ce signal d'alerte précoce est donc perdu. Faux positif
  actuel certain contre signal perdu hypothétique.

## Sign in with Apple et session app (11/11/2026)

- **Identité Apple = `sub`, pas l'e-mail.** Il n'existe pas de table
  utilisateurs : le compte est l'e-mail. `apple_sub` (UNIQUE),
  `apple_refresh_token` et `display_name` sont stockés dans `user_settings`
  (clé primaire = email). sub connu → session ; sinon l'e-mail du jeton signé
  (jamais celui du client) rattache ou crée la ligne.
- **Nom et e-mail ne sont envoyés par Apple qu'à la première autorisation.**
  Persistés immédiatement ; l'app garde le nom en local tant que l'appel
  backend n'a pas réussi.
- **Identity token Apple signé en RS256** (clés RSA de `/auth/keys`, cache
  24 h). Vérification et client secret ES256 faits avec `crypto` natif, sans
  dépendance.
- **Révocation obligatoire à la suppression** : l'`authorizationCode` est
  échangé contre un refresh token à la connexion, révoqué dans
  `deleteAccount()`. No-op si les variables `APPLE_*` manquent.
- **Jeton de session renvoyé dans le JSON** (`sessionToken`) de
  `/api/auth/verify`, `/google`, `/apple` : l'app l'envoie en
  `Authorization: Bearer` pour la suppression immédiate. Les autres endpoints
  `/api/manage/*` restent authentifiés par e-mail seul (dette connue).
- **Adresses relais `@privaterelay.appleid.com`** : rejetées si l'expéditeur
  n'est pas enregistré chez Apple (domaine `alert.doomname.com` par défaut).
  Les erreurs d'API Resend sont logguées `[apple-relay]`, mais un rejet Apple
  arrive en bounce asynchrone : il n'est visible que côté Resend.

## Piège Bearer / cookie (11/11/2026)

- **Le cookie `dw_session` ne doit JAMAIS autoriser une action destructrice.**
  Il part automatiquement avec toute requête émise par nos propres pages : le
  formulaire de suppression de `cgv.html` (e-mail saisi à la main) supprimait
  le compte du visiteur connecté, quel que soit l'e-mail tapé, sans
  confirmation. Le stockage de cookies natif de React Native peut aussi
  rejouer ce cookie depuis l'app.
- Règle : `getSessionEmail(req)` (Bearer puis cookie) pour la LECTURE ;
  `getSessionEmail(req, { bearerOnly: true })` pour tout endpoint qui supprime
  ou modifie un compte. Sans Bearer, retour au parcours par e-mail.
- `SameSite=Lax` empêche l'envoi du cookie sur un POST venu d'un site tiers,
  mais ne protège pas contre une requête émise par nos propres pages.
- `/api/auth/logout` révoque le Bearer et le cookie ; l'app l'appelle avant
  d'effacer son stockage local. Les sessions expirées sont purgées par le
  cron horaire.
