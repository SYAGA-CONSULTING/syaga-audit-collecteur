# SYAGA Audit - Collecteur vérifiable

**Langues :** [English](README.md) &middot; Français (ce fichier)

Ce dépôt contient **l'intégralité du code qui s'exécute sur votre poste** lorsque vous
utilisez SYAGA Audit pour Microsoft 365. Il est public pour une seule raison : vous
permettre de **vérifier par vous-même** qu'aucune de vos données ne nous est transmise.

## Le principe : zéro-knowledge

1. L'extension lit la configuration de sécurité de votre tenant Microsoft 365, **en lecture seule**,
   après votre consentement sur l'écran officiel Microsoft.
2. Elle **pseudonymise sur votre poste** : vos noms, adresses e-mail et identifiants sont
   remplacés par des jetons, **avant** tout envoi. La clé de pseudonymisation est générée
   localement et ne sort jamais.
3. Seuls ces **jetons** sont envoyés au service d'analyse. Vos données réelles ne quittent
   jamais votre navigateur.
4. Le rapport est **re-contextualisé localement** avec vos vrais libellés.

Le mécanisme est **fail-closed** : par défaut tout est tokenisé ; seule une liste de valeurs
de configuration Microsoft **publiques** (ex. `Enabled`, `ExternalUserAndGuestSharing`) reste
en clair, car nécessaire à l'évaluation. Une valeur inconnue est tokenisée, jamais l'inverse.

## Comment vérifier

- **`SHA256SUMS`** : l'empreinte de chacun des 11 fichiers livrés. Le code publié ici EST
  le code qui s'exécute chez vous.
- **`REPRODUCIBLE.md`** : comment reconstruire et recalculer ces empreintes.
- **Point de sortie unique** : une seule destination réseau applicative (le service SYAGA Audit),
  déclarée dans le `manifest.json` (`host_permissions` + CSP `connect-src`). Tout le reste est
  Microsoft (graph.microsoft.com, outlook.office365.com, compliance).
- **`pseudonymize.mjs` + `pseudo_whitelist.mjs`** : la frontière. Lisez `keepClear()` : c'est
  la fonction qui décide, valeur par valeur, ce qui reste en clair (jamais une identité).

## Ce qui n'est PAS ici

Le **catalogue de règles**, le **scoring** et le **moteur de rapport** vivent côté serveur et
ne sont pas nécessaires pour vérifier la promesse de confidentialité : quoi que fasse le serveur,
il ne reçoit que des jetons. C'est précisément ce que ce dépôt vous permet de contrôler.

## Les 11 fichiers

`auth.js` &middot; `auth-ok.html` &middot; `background.js` &middot; `collect.js` &middot; `manifest.json` &middot; `popup.html` &middot;
`popup.js` &middot; `pseudonymize.mjs` &middot; `pseudo_whitelist.mjs` &middot; `recontextualize.mjs` &middot;
`render_reproducible.mjs`

---

© 2026 SYAGA CONSULTING. Code publié pour vérification et transparence.
