# Reproductibilité de l'extension SYAGA Audit - "le code qui tourne EST le code publié"

**Langues :** [English](REPRODUCIBLE.md) &middot; Français (ce fichier)

## Le point fort : il n'y a RIEN à reconstruire
L'extension est écrite en JavaScript LISIBLE, **non bundlé, non minifié, sans étape de build**. Le fichier
livré dans le paquet est, octet pour octet, le fichier source de ce dépôt. La "reproductibilité" est donc
triviale et maximale : on ne compare pas une source à un binaire minifié généré (le cas difficile habituel),
on compare deux fichiers identiques. C'est le meilleur scénario de preuve possible.

C'est aussi pour ça qu'on reste en JS et pas en WebAssembly : un binaire WASM serait opaque et romprait
cette égalité source == livré.

## Ce que le client / l'auditeur peut vérifier LUI-MÊME
1. Lire le code (5 fichiers, tout est ouvert) : manifest.json, background.js, auth.js, collect.js, pseudonymize.mjs.
2. Recalculer les empreintes et comparer aux empreintes publiées :
   ```bash
   ./verify.sh        # ou : sha256sum -c SHA256SUMS
   ```
   Toutes les lignes doivent afficher OK. Une seule différence = le code livré n'est pas le code publié.
3. Vérifier l'egress en live (onglet réseau) : seuls des jetons sortent (voir README.fr.md).

## Empreintes (SHA-256) des fichiers LIVRÉS
Voir `SHA256SUMS`. Régénérées à chaque version. Le client compare ce qu'il a reçu à ce hash.

## Chaîne de preuve CONTINUE (à chaque version) - voir p0_research/repro_update_trust
- Build (ici : copie verbatim) exécuté en CI PUBLIQUE -> attestation SLSA + signature keyless sigstore
  (Fulcio) + entrée append-only dans le log de transparence Rekor. Vérifiable via `gh attestation verify`.
- Le hash de CHAQUE version est publié à un endroit inviolable (Rekor) + en façade utilisateur façon
  Code Verify -> une mise à jour malveillante ne peut pas passer en douce.

## Limites honnêtes (preuve avant slogan)
- **Firefox AMO** impose déjà la revue de source + le diff "no differences" par version : canal de preuve
  fort. **Chrome Web Store ne vérifie AUCUNE source** -> sur Chrome on s'appuie uniquement sur ces
  empreintes + l'attestation, et on le DIT.
- Le store ré-emballe le paquet (`_metadata/`, signatures du store) -> le .zip/.xpi n'est pas byte-identique
  à l'archive d'origine. On prouve l'égalité des FICHIERS JS exécutés (ce qui compte), pas de l'enveloppe.
- SLSA/sigstore prouvent l'ORIGINE du build, pas l'absence de faille dans la source : la lecture du code
  (rendue facile par l'absence de minification) reste nécessaire. C'est justement pour ça qu'on l'ouvre.
