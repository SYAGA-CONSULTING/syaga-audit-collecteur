# Reproducibility of the SYAGA Audit extension - "the code that runs IS the code published"

**Languages:** English (this file) &middot; [Français](REPRODUCIBLE.fr.md)

## The key point: there is NOTHING to rebuild
The extension is written in READABLE JavaScript, **unbundled, unminified, with no build step**. The file
delivered in the package is, byte for byte, the source file in this repository. "Reproducibility" is therefore
trivial and maximal: we do not compare a source to a generated minified binary (the usual hard case),
we compare two identical files. It is the best possible proof scenario.

That is also why we stay in JS and not WebAssembly: a WASM binary would be opaque and would break
this source == delivered equality.

## What the client / auditor can verify THEMSELVES
1. Read the code (5 files, everything is open): manifest.json, background.js, auth.js, collect.js, pseudonymize.mjs.
2. Recompute the fingerprints and compare them to the published ones:
   ```bash
   ./verify.sh        # or: sha256sum -c SHA256SUMS
   ```
   Every line must show OK. A single difference = the delivered code is not the published code.
3. Verify the egress live (network tab): only tokens leave (see README.md).

## Fingerprints (SHA-256) of the DELIVERED files
See `SHA256SUMS`. Regenerated at each version. The client compares what they received against this hash.

## CONTINUOUS chain of proof (at each version) - see p0_research/repro_update_trust
- Build (here: verbatim copy) run in PUBLIC CI -> SLSA attestation + keyless sigstore signature
  (Fulcio) + append-only entry in the Rekor transparency log. Verifiable via `gh attestation verify`.
- The hash of EACH version is published in a tamper-proof place (Rekor) + user-facing, Code Verify
  style -> a malicious update cannot slip through unnoticed.

## Honest limits (proof before slogan)
- **Firefox AMO** already requires source review + the "no differences" diff per version: a strong proof
  channel. **Chrome Web Store verifies NO source** -> on Chrome we rely solely on these fingerprints
  + the attestation, and we SAY so.
- The store re-packages the bundle (`_metadata/`, store signatures) -> the .zip/.xpi is not byte-identical
  to the original archive. We prove the equality of the EXECUTED JS FILES (what matters), not the wrapper.
- SLSA/sigstore prove the ORIGIN of the build, not the absence of a flaw in the source: reading the code
  (made easy by the lack of minification) remains necessary. That is exactly why we open it.
