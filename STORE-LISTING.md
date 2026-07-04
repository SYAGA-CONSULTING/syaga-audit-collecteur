# Fiche de soumission store (Chrome Web Store / Edge Add-ons)

Paquet a uploader : `syaga-audit-collecteur-v0.0.4.zip` (les 11 fichiers livres).
Compte editeur : ton compte developpeur (Chrome Web Store : ~5 USD une fois ; Edge Add-ons : gratuit).

## Nom (max 45 car.)
SYAGA Audit - Collecteur verifiable

## Resume court (max 132 car.)
Auditez la securite de votre Microsoft 365 sans jamais nous confier vos donnees : la collecte est pseudonymisee sur votre poste.

## Description detaillee
SYAGA Audit evalue la configuration de securite de votre tenant Microsoft 365 (identite, messagerie, partage, appareils, conformite) et la croise avec NIS2, RGPD, DORA, CIS et MITRE.

Sa particularite : le zero-knowledge. L'extension collecte votre configuration en LECTURE SEULE, la pseudonymise SUR VOTRE POSTE (vos noms, adresses et identifiants sont remplaces par des jetons), et n'envoie a SYAGA que ces jetons. Vos donnees reelles ne quittent jamais votre navigateur. Le rapport est re-contextualise localement avec vos vrais libelles.

Vous n'avez pas a nous croire, tout est verifiable :
- Microsoft affiche a l'installation que l'acces est en lecture seule ; vous le revoquez d'un clic depuis votre console.
- Le code de l'extension est lisible, non minifie, et son empreinte est publiee (le code qui tourne EST le code publie).
- Un seul point de sortie reseau, avec un detecteur qui bloque l'envoi si une donnee en clair tentait de sortir (fail-closed).

Auditer votre securite ne doit pas creer un nouveau risque de securite.

## Categorie
Outils pour developpeurs (ou Productivite)

## Langue
Francais

## Politique de confidentialite (URL requise)
https://m365.audit.syaga.fr/confidentialite.html

## Objectif unique (single purpose)
Collecter en lecture seule la configuration de securite Microsoft 365 de l'utilisateur, la pseudonymiser localement, et l'envoyer sous forme de jetons au service d'analyse SYAGA Audit.

## Justification des permissions
- identity : ouvrir la connexion Microsoft (OAuth) pour obtenir un acces LECTURE SEULE au tenant, apres consentement explicite de l'utilisateur.
- storage : conserver localement (chrome.storage.local) le jeton de session Exchange/Purview le temps du scan et la table de re-contextualisation ; rien n'est transmis a SYAGA.
- tabs : ouvrir la page de retour d'authentification et le rapport.
- webRequest : suivre le flux d'authentification Microsoft.
- host_permissions : uniquement les API Microsoft (graph.microsoft.com, outlook.office365.com, compliance) et le service SYAGA Audit (m365.audit.syaga.fr) declare dans le CSP.

## A fournir par SQ (le store l'exige)
- Captures d'ecran (1280x800) : la popup, un scan, le score gratuit, le rapport.
- Icone 128x128.
- Compte editeur verifie.

## Etapes de soumission
1. Chrome Web Store : https://chrome.google.com/webstore/devconsole -> Nouvel element -> uploader le zip -> remplir avec ce fichier -> Soumettre pour revue.
2. Edge Add-ons : https://partner.microsoft.com/dashboard/microsoftedge -> idem.
Note : la revue store peut prendre quelques jours. L'ID d'extension reste stable (champ `key` du manifest) -> pas de re-cablage du site.
