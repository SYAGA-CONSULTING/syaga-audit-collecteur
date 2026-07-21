# Store submission sheet (Chrome Web Store / Edge Add-ons)

**Languages:** English (this file) &middot; [Français](STORE-LISTING.fr.md)

Package to upload: `syaga-audit-collecteur-v0.0.4.zip` (the 15 delivered files, icons included).
Publisher account: your developer account (Chrome Web Store: ~5 USD one-time; Edge Add-ons: free).

## Name (max 45 chars)
SYAGA Audit - Verifiable collector

## Short summary (max 132 chars)
Audit your Microsoft 365 security without ever entrusting us your data: collection is pseudonymized on your own machine.

## Detailed description
SYAGA Audit assesses the security configuration of your Microsoft 365 tenant (identity, mail, sharing, devices, compliance) and cross-references it with NIS2, GDPR, DORA, CIS and MITRE.

Its distinctive trait: zero-knowledge. The extension collects your configuration READ-ONLY, pseudonymizes it ON YOUR MACHINE (your names, addresses and identifiers are replaced by tokens), and sends SYAGA only those tokens. Your real data never leaves your browser. The report is re-contextualized locally with your real labels.

You do not have to trust us, everything is verifiable:
- Microsoft shows at install time that access is read-only; you revoke it in one click from your console.
- The extension code is readable, unminified, and its fingerprint is published (the code that runs IS the published code).
- A single network egress point, with a detector that blocks the send if any clear data tried to leave (fail-closed).

Auditing your security must not create a new security risk.

## Category
Developer tools (or Productivity)

## Language
English

## Privacy policy (URL required)
https://m365.audit.syaga.fr/confidentialite.html

## Single purpose
Collect read-only the user's Microsoft 365 security configuration, pseudonymize it locally, and send it as tokens to the SYAGA Audit analysis service.

## Permission justification
- identity: open the Microsoft sign-in (OAuth) to obtain READ-ONLY access to the tenant, after the user's explicit consent.
- storage: keep locally (chrome.storage.local) the Exchange/Purview session token for the duration of the scan and the re-contextualization table; nothing is sent to SYAGA.
- tabs: open the authentication return page and the report.
- webRequest: follow the Microsoft authentication flow.
- host_permissions: only the Microsoft APIs (graph.microsoft.com, outlook.office365.com, compliance) and the SYAGA Audit service (m365.audit.syaga.fr) declared in the CSP.

## To be provided by SQ (the store requires it)
- Screenshots (1280x800): the popup, a scan, the free score, the report.
- 128x128 icon.
- Verified publisher account.

## Submission steps
1. Chrome Web Store: https://chrome.google.com/webstore/devconsole -> New item -> upload the zip -> fill in with this file -> Submit for review.
2. Edge Add-ons: https://partner.microsoft.com/dashboard/microsoftedge -> same.
Note: store review can take a few days. The extension ID stays stable (`key` field of the manifest) -> no site re-wiring.
