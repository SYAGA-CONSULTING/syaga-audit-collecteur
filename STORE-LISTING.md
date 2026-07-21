# Fiche de soumission store (Chrome Web Store / Edge Add-ons)

Paquet à uploader : `syaga-audit-collecteur-v0.0.4.zip` (les 15 fichiers (dont icônes) livrés).
Compte éditeur : ton compte développeur (Chrome Web Store : ~5 USD une fois ; Edge Add-ons : gratuit).

## Nom (max 45 car.)
SYAGA Audit - Collecteur vérifiable

## Résumé court (max 132 car.)
Auditez la sécurité de votre Microsoft 365 sans jamais nous confier vos données : la collecte est pseudonymisée sur votre poste.

## Description détaillée
SYAGA Audit évalue la configuration de sécurité de votre tenant Microsoft 365 (identité, messagerie, partage, appareils, conformité) et la croise avec NIS2, RGPD, DORA, CIS et MITRE.

Sa particularité : le zero-knowledge. L'extension collecte votre configuration en LECTURE SEULE, la pseudonymise SUR VOTRE POSTE (vos noms, adresses et identifiants sont remplacés par des jetons), et n'envoie à SYAGA que ces jetons. Vos données réelles ne quittent jamais votre navigateur. Le rapport est re-contextualisé localement avec vos vrais libellés.

Vous n'avez pas à nous croire, tout est vérifiable :
- Microsoft affiche à l'installation que l'accès est en lecture seule ; vous le révoquez d'un clic depuis votre console.
- Le code de l'extension est lisible, non minifié, et son empreinte est publiée (le code qui tourne EST le code publié).
- Un seul point de sortie réseau, avec un détecteur qui bloque l'envoi si une donnée en clair tentait de sortir (fail-closed).

Auditer votre sécurité ne doit pas créer un nouveau risque de sécurité.

## Catégorie
Outils pour développeurs (ou Productivité)

## Langue
Français

## Politique de confidentialité (URL requise)
https://m365.audit.syaga.fr/confidentialite.html

## Objectif unique (single purpose)
Collecter en lecture seule la configuration de sécurité Microsoft 365 de l'utilisateur, la pseudonymiser localement, et l'envoyer sous forme de jetons au service d'analyse SYAGA Audit.

## Justification des permissions
- identity : ouvrir la connexion Microsoft (OAuth) pour obtenir un accès LECTURE SEULE au tenant, après consentement explicite de l'utilisateur.
- storage : conserver localement (chrome.storage.local) le jeton de session Exchange/Purview le temps du scan et la table de re-contextualisation ; rien n'est transmis à SYAGA.
- tabs : ouvrir la page de retour d'authentification et le rapport.
- webRequest : suivre le flux d'authentification Microsoft.
- host_permissions : uniquement les API Microsoft (graph.microsoft.com, outlook.office365.com, compliance) et le service SYAGA Audit (m365.audit.syaga.fr) déclaré dans le CSP.

## À fournir par SQ (le store l'exige)
- Captures d'écran (1280x800) : la popup, un scan, le score gratuit, le rapport.
- Icône 128x128.
- Compte éditeur vérifié.

## Étapes de soumission
1. Chrome Web Store : https://chrome.google.com/webstore/devconsole -> Nouvel élément -> uploader le zip -> remplir avec ce fichier -> Soumettre pour revue.
2. Edge Add-ons : https://partner.microsoft.com/dashboard/microsoftedge -> idem.
Note : la revue store peut prendre quelques jours. L'ID d'extension reste stable (champ `key` du manifest) -> pas de re-câblage du site.
