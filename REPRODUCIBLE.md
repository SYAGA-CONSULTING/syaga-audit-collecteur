# Reproductibilite de l'extension SYAGA Audit - "le code qui tourne EST le code publie"

## Le point fort : il n'y a RIEN a reconstruire
L'extension est ecrite en JavaScript LISIBLE, **non bundle, non minifie, sans etape de build**. Le fichier
livre dans le paquet est, octet pour octet, le fichier source de ce depot. La "reproductibilite" est donc
triviale et maximale : on ne compare pas une source a un binaire minifie genere (le cas difficile habituel),
on compare deux fichiers identiques. C'est le meilleur scenario de preuve possible.

C'est aussi pour ca qu'on reste en JS et pas en WebAssembly : un binaire WASM serait opaque et romprait
cette egalite source == livre.

## Ce que le client / l'auditeur peut verifier LUI-MEME
1. Lire le code (5 fichiers, tout est ouvert) : manifest.json, background.js, auth.js, collect.js, pseudonymize.mjs.
2. Recalculer les empreintes et comparer aux empreintes publiees :
   ```bash
   ./verify.sh        # ou : sha256sum -c SHA256SUMS
   ```
   Toutes les lignes doivent afficher OK. Une seule difference = le code livre n'est pas le code publie.
3. Verifier l'egress en live (onglet reseau) : seuls des jetons sortent (voir README.md).

## Empreintes (SHA-256) des fichiers LIVRES
Voir `SHA256SUMS`. Regenerees a chaque version. Le client compare ce qu'il a recu a ce hash.

## Chaine de preuve CONTINUE (a chaque version) - voir p0_research/repro_update_trust
- Build (ici : copie verbatim) execute en CI PUBLIQUE -> attestation SLSA + signature keyless sigstore
  (Fulcio) + entree append-only dans le log de transparence Rekor. Verifiable via `gh attestation verify`.
- Le hash de CHAQUE version est publie a un endroit inviolable (Rekor) + en facade utilisateur facon
  Code Verify -> une mise a jour malveillante ne peut pas passer en douce.

## Limites honnetes (preuve avant slogan)
- **Firefox AMO** impose deja la revue de source + le diff "no differences" par version : canal de preuve
  fort. **Chrome Web Store ne verifie AUCUNE source** -> sur Chrome on s'appuie uniquement sur ces
  empreintes + l'attestation, et on le DIT.
- Le store re-emballe le paquet (`_metadata/`, signatures du store) -> le .zip/.xpi n'est pas byte-identique
  a l'archive d'origine. On prouve l'egalite des FICHIERS JS executes (ce qui compte), pas de l'enveloppe.
- SLSA/sigstore prouvent l'ORIGINE du build, pas l'absence de faille dans la source : la lecture du code
  (rendue facile par l'absence de minification) reste necessaire. C'est justement pour ca qu'on l'ouvre.
