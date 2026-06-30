# DoomName

Surveillance de noms de domaine — vérifie la disponibilité d'un domaine via WHOIS et envoie une alerte e-mail dès qu'il se libère.

Site : [doomname.com](https://www.doomname.com)

## Fonctionnalités

- **Vérification WHOIS** en temps réel, avec cache 60s pour éviter le rate-limiting des registrars
- **Détection des statuts de fin de vie** d'un domaine (grâce, rédemption, suppression imminente) en plus de disponible/pris, avec e-mail dédié dès qu'un domaine surveillé change d'état
- **Confirmation différée de 10 minutes** avant d'envoyer l'alerte "disponible" : certains domaines à forte valeur sont recapturés en quelques secondes par des bots de drop-catching ; le domaine est revérifié 10 min plus tard avant de notifier, sans changer la fréquence du cron principal (1h)
- **Authentification par magic link** (pas de mot de passe), valable 20 minutes
- **"Mes alertes"** : gestion des domaines surveillés (filtres, pagination 20/page, recherche), import/export CSV, consultation du WHOIS complet en modale, préférences d'alertes (e-mail / période de grâce) par utilisateur
- **Suppression de compte** (RGPD) : un e-mail de confirmation déclenche l'effacement définitif de toutes les données liées à une adresse e-mail
- **API publique v1** avec clé développeur (`dk_...`), 100 requêtes/jour, 3 clés max par e-mail
- **PWA** installable avec notifications push (Firebase)
- Limites : 50 surveillances actives / 200 au total par e-mail

## Stack

- Node.js + Express (fichier unique `server.js`, pas de framework front — pages HTML statiques avec JS vanilla)
- PostgreSQL (`pg`)
- [Resend](https://resend.com) pour l'envoi d'e-mails
- `node-cron` pour la vérification horaire des domaines surveillés
- `whois-json` pour les requêtes WHOIS
- CSS partagé dans `css/common.css`, repris par toutes les pages

## Pages

| Fichier | Description |
|---|---|
| `index.html` | Accueil — vérification de domaine, suggestions d'extensions |
| `manage.html` | "Mes alertes" — connexion par magic link et gestion des surveillances |
| `developer.html` / `docs.html` | API publique et documentation |
| `cgv.html` | CGU/CGV, suppression de compte |
| `politique-confidentialite.html` | Politique de confidentialité |
| `open-app.html` | Page de redirection intelligente (app mobile → site, voir mails) |

## Lancer en local

```bash
npm install
cp .env.example .env   # puis renseigner les variables (voir ci-dessous)
npm run dev             # avec rechargement automatique (nodemon)
# ou
npm start
```

## Variables d'environnement

| Variable | Description |
|---|---|
| `PORT` | Port d'écoute du serveur (optionnel, défaut 3000) |
| `NODE_ENV` | `production` active le SSL pour PostgreSQL |
| `DATABASE_URL` | Chaîne de connexion PostgreSQL |
| `RESEND_API_KEY` | Clé API [Resend](https://resend.com) |
| `EMAIL_FROM` | Adresse d'expédition des e-mails |
| `APP_URL` | URL publique du site (utilisée dans les liens des e-mails) |

## Déploiement

Hébergé sur [Railway](https://railway.app) (`Procfile` : `web: node server.js`). Le déploiement relance le processus Node, ce qui réinitialise les `setTimeout` en mémoire des confirmations différées — `recoverPendingConfirmations()` les reprogramme automatiquement au démarrage à partir de la base de données.

## Application mobile

Le pendant Android de ce service vit dans [doomname-app](https://github.com/Epilouptique/doomname-app) (Expo / React Native), qui consomme la même API.

---

Développé par Hugo Vial-Jaime — Agence [Dahu-Concept](https://dahu-concept.fr)
