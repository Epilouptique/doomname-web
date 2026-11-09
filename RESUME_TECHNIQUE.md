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
