# SYAGA Audit - Verifiable collector

**Languages:** English (this file) &middot; [Français](README.fr.md)

This repository contains **the entire code that runs on your own machine** when you use SYAGA
Audit for Microsoft 365. It is public for one reason only: to let you **check for yourself**
that none of your data is ever sent to us.

## The principle: zero-knowledge

1. The extension reads your Microsoft 365 tenant security configuration, **read-only**, after
   your consent on the official Microsoft screen.
2. It **pseudonymizes on your machine**: your names, e-mail addresses and identifiers are
   replaced by tokens **before** anything is sent. The pseudonymization key is generated
   locally and never leaves your machine.
3. Only those **tokens** are sent to the analysis service. Your real data never leaves your
   browser.
4. The report is **re-contextualized locally** with your real labels.

The mechanism is **fail-closed**: by default everything is tokenized; only a list of **public**
Microsoft configuration values (e.g. `Enabled`, `ExternalUserAndGuestSharing`) stays in clear,
because it is required for the assessment. An unknown value is tokenized, never the other way around.

## How to verify

- **`SHA256SUMS`**: the fingerprint of each of the 11 delivered files. The code published here
  IS the code that runs on your machine.
- **`REPRODUCIBLE.md`**: how to rebuild and recompute those fingerprints.
- **Single egress point**: one single application network destination (the SYAGA Audit service),
  declared in `manifest.json` (`host_permissions` + CSP `connect-src`). Everything else is
  Microsoft (graph.microsoft.com, outlook.office365.com, compliance).
- **`pseudonymize.mjs` + `pseudo_whitelist.mjs`**: the boundary. Read `keepClear()`: the function
  that decides, value by value, what stays in clear (never an identity).

## What is NOT here

The **rule catalogue**, the **scoring** and the **report engine** live server-side and are not
needed to verify the confidentiality promise: whatever the server does, it only ever receives
tokens. That is exactly what this repository lets you check.

## The 11 files

`auth.js` &middot; `auth-ok.html` &middot; `background.js` &middot; `collect.js` &middot; `manifest.json` &middot; `popup.html` &middot;
`popup.js` &middot; `pseudonymize.mjs` &middot; `pseudo_whitelist.mjs` &middot; `recontextualize.mjs` &middot;
`render_reproducible.mjs`

---

© 2026 SYAGA CONSULTING. Code published for verification and transparency.
