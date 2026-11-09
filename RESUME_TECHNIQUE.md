# DoomName — Résumé technique

## Points connus à corriger

- **notifyAvailable (server.js) — envoi avant écriture de `notified_at`.** Pour
  chaque abonné, l'e-mail et le push partent, puis `notified_at` est écrit. Si
  cette écriture échoue, l'exception interrompt la boucle et les abonnés
  suivants ne reçoivent pas leur alerte « disponible ». Pas de risque de boucle
  (`last_status = 'available'` est écrit avant l'appel). À corriger par un
  try/catch par abonné. Relevé le 09/11/2026, non corrigé dans cfe761d.
