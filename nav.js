/* Header commun DoomName : gère le bouton "Se connecter/Se déconnecter" (selon
   la présence de dw-email) et le bouton "Télécharger" (installation PWA, sinon
   repli vers l'accueil). Le badge langue (#lang-btn) et le thème (toggleTheme)
   restent gérés par i18n.js et le script de chaque page. */
(function () {
  let deferredPrompt = null;
  window.addEventListener('beforeinstallprompt', (e) => { e.preventDefault(); deferredPrompt = e; });

  async function logout() {
    try { await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' }); } catch {}
    localStorage.removeItem('dw-email');
    window.location.href = '/';
  }

  function label(key, fallback) {
    return (window.t ? window.t(key) : fallback);
  }

  function wire() {
    const login = document.getElementById('nav-login');
    if (login) {
      const email = localStorage.getItem('dw-email');
      if (email) {
        // Connecté → transformer en "Se déconnecter".
        login.setAttribute('data-i18n', 'header.logout');
        login.textContent = label('header.logout', 'Se déconnecter');
        login.removeAttribute('href');
        login.style.cursor = 'pointer';
        login.addEventListener('click', logout);
      }
      // Sinon : garde href="/manage.html" + data-i18n="header.login".
    }

    const dl = document.getElementById('nav-download');
    if (dl) {
      dl.addEventListener('click', () => {
        if (deferredPrompt) {
          deferredPrompt.prompt();
          deferredPrompt.userChoice.then(() => { deferredPrompt = null; });
        } else {
          // Pas d'invite d'installation → renvoyer vers l'accueil (badge Play).
          window.location.href = '/';
        }
      });
    }
  }

  document.addEventListener('DOMContentLoaded', wire);
})();
