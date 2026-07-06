/* i18n partagé DoomName (FR par défaut / EN). Ne pas traduire "DoomName"/"Dahu-Concept".
   Usage : data-i18n="clé" (textContent), data-i18n-html="clé" (innerHTML),
   data-i18n-ph="clé" (placeholder). window.t('clé') pour le JS. */
(function () {
  const DICT = {
    fr: {
      'nav.lang': 'FR',
      // Accueil
      'home.h1': 'Surveillance de <em>nom de domaine</em>',
      'home.subtitle': 'Vérifiez la disponibilité et soyez alerté dès qu\'un domaine se libère',
      'home.tag_check': 'Vérifier un domaine',
      'home.check_btn': 'Surveiller',
      'home.tag_alert': 'Recevoir une alerte',
      'home.subscribe_btn': 'M\'alerter',
      'home.watch_btn': 'Surveiller',
      'home.subscribe_confirm': 'Alerte activée — vous serez notifié dès que ce domaine sera libre.',
      'home.pill_hourly': 'Vérifié toutes les heures',
      'home.pill_free': 'Alerte e-mail gratuite',
      'home.pill_whois': 'WHOIS en temps réel',
      'home.install': 'Installer l\'app',
      'home.enable_notifs': 'Activer les notifications',
      'home.manage_link': 'Gérer mes alertes →',
      'header.login': 'Se connecter',
      'header.logout': 'Se déconnecter',
      'header.download': 'Télécharger',
      'hero.h1': 'Surveillez la <em>disponibilité</em> de vos noms de domaine',
      'col.need_h2': 'Le besoin',
      'col.need_p': 'Le domaine parfait est déjà pris ? La plupart des domaines expirés ne sont jamais renouvelés — encore faut-il être là au bon moment.',
      'col.sol_h2': 'La solution',
      'col.sol_p': 'DoomName surveille pour vous, 24h/24. Email + notification push dès la libération, avec double vérification anti-faux-positifs.',
      'col.free_h2': 'Libre et pratique',
      'col.free_p': 'Gratuit et open-source. Aucune donnée revendue. <a href="/docs.html">API REST &amp; webhooks</a> pour les développeurs.',
      // Section SEO
      'about.h2': 'Surveillez la disponibilité d\'un nom de domaine, gratuitement',
      'about.p1': 'DoomName est un service gratuit qui surveille en continu la disponibilité des noms de domaine qui vous intéressent. Saisissez un domaine : nous interrogeons les serveurs WHOIS en temps réel pour savoir s\'il est libre, enregistré, ou en cours d\'expiration. S\'il est déjà pris, activez une alerte et nous vous préviendrons automatiquement, par e-mail et par notification, dès qu\'il se libère.',
      'about.p2': 'De nombreux domaines expirent chaque jour sans être renouvelés. DoomName vérifie leur statut toutes les heures et suit leur cycle de vie complet — période de grâce, rédemption, suppression — pour vous alerter au bon moment. Le service est utilisable depuis le web comme depuis l\'application mobile Android, et une API publique permet aux développeurs d\'automatiser leurs surveillances.',
      'about.h3': 'Pourquoi utiliser DoomName ?',
      'about.li1': 'Alertes automatiques par e-mail et notification push dès qu\'un domaine devient disponible.',
      'about.li2': 'Vérification WHOIS en temps réel et suivi horaire des domaines surveillés.',
      'about.li3': 'Suivi du cycle d\'expiration : grâce, rédemption et suppression imminente.',
      'about.li4': '100 % gratuit, sans publicité, avec une API pour les développeurs.',
      // Résultats / messages JS
      'res.available_title': '%{d} est disponible !',
      'res.available_sub': 'Ce domaine peut être enregistré maintenant.',
      'res.taken_title': '%{d} est déjà pris',
      'res.taken_sub_expiry': 'Expiration : %{e}',
      'res.taken_sub': 'Activez une alerte pour être notifié.',
      'res.invalid_title': 'Domaine invalide',
      'res.invalid_sub': 'Ex : exemple.com, monsite.fr',
      'res.err_title': 'Erreur de connexion',
      'res.err_sub': 'Le serveur est inaccessible.',
      'intro.taken': '<strong>%{d}</strong> est actuellement pris. Entrez votre e-mail pour être alerté dès qu\'il sera disponible.',
      'intro.available': '<strong>%{d}</strong> est disponible. Surveillez-le pour être prévenu s\'il est enregistré, puis à nouveau libéré.',
      'msg.sub_error': 'Une erreur est survenue. Veuillez réessayer.',
      'msg.conn_error': 'Erreur de connexion au serveur.',
      // manage.html
      'manage.h1': 'Mes <em>alertes</em>',
      'manage.subtitle': 'Gérez vos domaines surveillés',
      'manage.login_tag': 'Connexion',
      'manage.login_intro': 'Entrez votre adresse e-mail pour recevoir un lien de connexion. Aucun mot de passe requis.',
      'manage.login_send': 'Envoyer le lien',
      'manage.login_success': '📬 Vérifiez votre boîte mail — un lien de connexion vient d\'être envoyé.',
      'manage.expired_title': 'Lien expiré',
      'manage.expired_text': 'Ce lien a expiré ou a déjà été utilisé.<br/>Les liens sont valables 20 minutes.',
      'manage.expired_btn': 'Demander un nouveau lien',
      'manage.del_title': 'Supprimer votre compte',
      'manage.del_btn': 'Supprimer définitivement',
      'manage.cancel': 'Annuler',
      'manage.watched': 'Domaines surveillés',
      'manage.f_all': 'Tous',
      'manage.f_active': 'Actifs',
      'manage.f_inactive': 'Désactivés',
      'manage.f_available': 'Disponible',
      'manage.search': 'Rechercher',
      'manage.search_ph': 'Rechercher un domaine…',
      'manage.add_domain': 'Ajouter un domaine',
      'manage.add_btn': 'Surveiller',
      'manage.impexp': 'Importer / exporter',
      'manage.export': 'Exporter en CSV',
      'manage.import': 'Importer un CSV',
      'manage.alerts': 'Alertes',
      'manage.email_alerts': 'Alertes e-mail',
      'manage.email_alerts_desc': 'Recevoir un e-mail quand un domaine surveillé devient disponible',
      'manage.grace': 'Période de grâce',
      'manage.grace_desc': 'Être alerté quand un domaine entre en grâce, rédemption ou suppression',
      'manage.logout': 'Se déconnecter',
      'manage.loading': 'Chargement…',
      'manage.empty_search': 'Aucun domaine ne correspond à votre recherche.',
      'manage.empty_active': 'Aucune surveillance active.',
      'manage.empty_inactive': 'Aucun domaine désactivé.',
      'manage.empty_available': 'Aucun domaine disponible pour le moment.',
      'manage.empty_all': 'Aucun domaine dans votre liste.',
      'manage.badge_grace': 'Grâce',
      'manage.badge_redemption': 'Rédemption',
      'manage.badge_pending': 'Bientôt libre',
      'manage.badge_available': 'Disponible',
      'manage.err_generic': 'Une erreur est survenue.',
      'manage.err_conn': 'Erreur de connexion.',
      'manage.err_delete': 'Erreur lors de la suppression.',
      'manage.err_email': 'Adresse e-mail invalide.',
      'manage.whois_empty': 'Aucune donnée disponible.',
      'manage.added_on': 'Ajouté le',
      // Pages docs / légales
      'legal.notice': 'Traduction de courtoisie — seule la version française fait foi.',
      'legal.back': '← Retour à l\'accueil',
      'manage.tt_whois': 'Voir le WHOIS complet',
      'manage.tt_disable': 'Désactiver',
      'manage.tt_reactivate': 'Réactiver',
      'manage.tt_delete': 'Supprimer',
      'manage.tt_prev': 'Page précédente',
      'manage.tt_next': 'Page suivante',
      'manage.tt_close': 'Fermer',
      'manage.add_success': '✓ %{d} ajouté à votre surveillance.',
      'manage.add_available': '%{d} est déjà disponible !',
      'manage.register_now': 'L\'enregistrer maintenant →',
      'manage.load_error': 'Erreur de chargement.',
    },
    en: {
      'nav.lang': 'EN',
      'home.h1': 'Domain name <em>monitoring</em>',
      'home.subtitle': 'Check availability and get alerted as soon as a domain is released',
      'home.tag_check': 'Check a domain',
      'home.check_btn': 'Watch',
      'home.tag_alert': 'Get an alert',
      'home.subscribe_btn': 'Alert me',
      'home.watch_btn': 'Watch',
      'home.subscribe_confirm': 'Alert enabled — you will be notified as soon as this domain is free.',
      'home.pill_hourly': 'Checked every hour',
      'home.pill_free': 'Free email alerts',
      'home.pill_whois': 'Real-time WHOIS',
      'home.install': 'Install the app',
      'home.enable_notifs': 'Enable notifications',
      'home.manage_link': 'Manage my alerts →',
      'header.login': 'Log in',
      'header.logout': 'Log out',
      'header.download': 'Download',
      'hero.h1': 'Monitor domain name <em>availability</em>',
      'col.need_h2': 'The need',
      'col.need_p': 'The perfect domain is already taken? Most expired domains are never renewed — you just need to be there at the right moment.',
      'col.sol_h2': 'The solution',
      'col.sol_p': 'DoomName watches for you, 24/7. Email + push notification the moment it is released, with double-check anti-false-positives.',
      'col.free_h2': 'Free &amp; practical',
      'col.free_p': 'Free and open-source. No data resold. <a href="/docs.html">REST API &amp; webhooks</a> for developers.',
      'about.h2': 'Monitor a domain name\'s availability, for free',
      'about.p1': 'DoomName is a free service that continuously monitors the availability of the domain names you care about. Enter a domain: we query WHOIS servers in real time to know whether it is free, registered, or expiring. If it is taken, enable an alert and we will notify you automatically, by email and notification, as soon as it is released.',
      'about.p2': 'Many domains expire every day without being renewed. DoomName checks their status every hour and follows their full life cycle — grace period, redemption, deletion — to alert you at the right time. It works from the web and the Android app, and a public API lets developers automate their own monitoring.',
      'about.h3': 'Why use DoomName?',
      'about.li1': 'Automatic email and push alerts as soon as a domain becomes available.',
      'about.li2': 'Real-time WHOIS checks and hourly monitoring of watched domains.',
      'about.li3': 'Expiration cycle tracking: grace, redemption and imminent deletion.',
      'about.li4': '100% free, no ads, with an API for developers.',
      'res.available_title': '%{d} is available!',
      'res.available_sub': 'This domain can be registered now.',
      'res.taken_title': '%{d} is already taken',
      'res.taken_sub_expiry': 'Expires: %{e}',
      'res.taken_sub': 'Enable an alert to be notified.',
      'res.invalid_title': 'Invalid domain',
      'res.invalid_sub': 'e.g. example.com, mysite.fr',
      'res.err_title': 'Connection error',
      'res.err_sub': 'The server is unreachable.',
      'intro.taken': '<strong>%{d}</strong> is currently taken. Enter your email to be alerted as soon as it becomes available.',
      'intro.available': '<strong>%{d}</strong> is available. Watch it to be notified if it gets registered, then released again.',
      'msg.sub_error': 'Something went wrong. Please try again.',
      'msg.conn_error': 'Connection error.',
      // manage.html
      'manage.h1': 'My <em>alerts</em>',
      'manage.subtitle': 'Manage your watched domains',
      'manage.login_tag': 'Sign in',
      'manage.login_intro': 'Enter your email address to receive a sign-in link. No password required.',
      'manage.login_send': 'Send the link',
      'manage.login_success': '📬 Check your inbox — a sign-in link was just sent.',
      'manage.expired_title': 'Link expired',
      'manage.expired_text': 'This link has expired or has already been used.<br/>Links are valid for 20 minutes.',
      'manage.expired_btn': 'Request a new link',
      'manage.del_title': 'Delete your account',
      'manage.del_btn': 'Delete permanently',
      'manage.cancel': 'Cancel',
      'manage.watched': 'Watched domains',
      'manage.f_all': 'All',
      'manage.f_active': 'Active',
      'manage.f_inactive': 'Disabled',
      'manage.f_available': 'Available',
      'manage.search': 'Search',
      'manage.search_ph': 'Search a domain…',
      'manage.add_domain': 'Add a domain',
      'manage.add_btn': 'Watch',
      'manage.impexp': 'Import / export',
      'manage.export': 'Export as CSV',
      'manage.import': 'Import a CSV',
      'manage.alerts': 'Alerts',
      'manage.email_alerts': 'Email alerts',
      'manage.email_alerts_desc': 'Receive an email when a watched domain becomes available',
      'manage.grace': 'Grace period',
      'manage.grace_desc': 'Be alerted when a domain enters grace, redemption or deletion',
      'manage.logout': 'Sign out',
      'manage.loading': 'Loading…',
      'manage.empty_search': 'No domain matches your search.',
      'manage.empty_active': 'No active watch.',
      'manage.empty_inactive': 'No disabled domain.',
      'manage.empty_available': 'No available domain right now.',
      'manage.empty_all': 'No domain in your list.',
      'manage.badge_grace': 'Grace',
      'manage.badge_redemption': 'Redemption',
      'manage.badge_pending': 'Soon free',
      'manage.badge_available': 'Available',
      'manage.err_generic': 'Something went wrong.',
      'manage.err_conn': 'Connection error.',
      'manage.err_delete': 'Error while deleting.',
      'manage.err_email': 'Invalid email address.',
      'manage.whois_empty': 'No data available.',
      'manage.added_on': 'Added on',
      // Docs / legal pages
      'legal.notice': 'Courtesy translation — only the French version prevails.',
      'legal.back': '← Back to home',
      'manage.tt_whois': 'View full WHOIS',
      'manage.tt_disable': 'Disable',
      'manage.tt_reactivate': 'Re-enable',
      'manage.tt_delete': 'Delete',
      'manage.tt_prev': 'Previous page',
      'manage.tt_next': 'Next page',
      'manage.tt_close': 'Close',
      'manage.add_success': '✓ %{d} added to your watches.',
      'manage.add_available': '%{d} is already available!',
      'manage.register_now': 'Register it now →',
      'manage.load_error': 'Loading error.',
    },
  };

  function detect() {
    const q = new URLSearchParams(location.search).get('lang');
    if (q === 'fr' || q === 'en') { localStorage.setItem('dw-lang', q); return q; }
    const saved = localStorage.getItem('dw-lang');
    if (saved === 'fr' || saved === 'en') return saved;
    return (navigator.language || 'fr').toLowerCase().startsWith('fr') ? 'fr' : 'en';
  }

  let lang = detect();

  function interp(str, params) {
    return params ? str.replace(/%\{(\w+)\}/g, (_, k) => (params[k] != null ? params[k] : '')) : str;
  }
  function t(key, params) {
    const d = DICT[lang] || DICT.fr;
    return interp(d[key] != null ? d[key] : (DICT.fr[key] != null ? DICT.fr[key] : key), params);
  }

  function apply(root) {
    (root || document).querySelectorAll('[data-i18n]').forEach(el => { el.textContent = t(el.getAttribute('data-i18n')); });
    (root || document).querySelectorAll('[data-i18n-html]').forEach(el => { el.innerHTML = t(el.getAttribute('data-i18n-html')); });
    (root || document).querySelectorAll('[data-i18n-ph]').forEach(el => { el.setAttribute('placeholder', t(el.getAttribute('data-i18n-ph'))); });
    (root || document).querySelectorAll('[data-i18n-title]').forEach(el => { el.setAttribute('title', t(el.getAttribute('data-i18n-title'))); });
    // Éléments affichés uniquement en anglais (ex. mention de traduction légale).
    (root || document).querySelectorAll('[data-en-only]').forEach(el => { el.style.display = (lang === 'en') ? '' : 'none'; });
    document.documentElement.setAttribute('lang', lang);
  }

  function setLang(l) {
    lang = (l === 'en') ? 'en' : 'fr';
    localStorage.setItem('dw-lang', lang);
    apply();
    const badge = document.getElementById('lang-btn');
    if (badge) badge.textContent = lang.toUpperCase();
    document.dispatchEvent(new CustomEvent('langchange', { detail: lang }));
  }

  // Expose l'API + initialise au chargement.
  window.i18n = { t, setLang, apply, get lang() { return lang; } };
  window.t = t;
  document.addEventListener('DOMContentLoaded', () => {
    const badge = document.getElementById('lang-btn');
    if (badge) { badge.textContent = lang.toUpperCase(); badge.addEventListener('click', () => setLang(lang === 'fr' ? 'en' : 'fr')); }
    apply();
  });
})();
