// SYAGA Audit extension - couche AUTH. Authorization code + PKCE delegue (ADR-004).
// Client PUBLIC : aucun client secret. Device code PROSCRIT. Token delegue (role de l'utilisateur).
// Deux ressources = deux tokens : Graph (graph.microsoft.com) et EXO (outlook.office365.com).
// Helpers PKCE/URL = purs et testables (Web Crypto natif). launchInteractive/exchange = runtime navigateur.

const LOGIN = "https://login.microsoftonline.com";

// base64url d'un Uint8Array (RFC 7636 : pas de '+', '/', '=')
function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// code_verifier = 43-128 caracteres [A-Za-z0-9-._~]. On genere 32 octets -> 43 chars base64url.
export function makeVerifier(nBytes = 32) {
  return b64url(crypto.getRandomValues(new Uint8Array(nBytes)));
}

// code_challenge = base64url( SHA-256( code_verifier ) ), methode S256.
export async function makeChallenge(verifier) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return b64url(new Uint8Array(digest));
}

export async function generatePkce() {
  const verifier = makeVerifier();
  const challenge = await makeChallenge(verifier);
  return { verifier, challenge, method: "S256" };
}

// URL d'autorisation (authorization code). state = anti-CSRF (genere par l'appelant).
export function buildAuthUrl({ tenant, clientId, redirectUri, scope, challenge, state }) {
  const p = new URLSearchParams({
    client_id: clientId,
    response_type: "code",
    redirect_uri: redirectUri,
    response_mode: "query",
    scope,                                  // ex: "https://graph.microsoft.com/.default offline_access"
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    prompt: "consent",   // force le VRAI ecran de consentement admin (grand consentement org-wide)
  });
  return `${LOGIN}/${tenant}/oauth2/v2.0/authorize?${p.toString()}`;
}

// --- Runtime navigateur (non teste hors extension) ---
// Lance le flux interactif (fenetre Microsoft : login + consentement + MFA), retourne le code.
export async function launchInteractive(authUrl) {
  const redirect = await chrome.identity.launchWebAuthFlow({ url: authUrl, interactive: true });
  const u = new URL(redirect);
  const code = u.searchParams.get("code");
  if (!code) throw new Error("auth: pas de code dans le redirect (" + (u.searchParams.get("error") || "?") + ")");
  return code;
}

// Echange code -> access_token (client public : pas de secret, on renvoie le code_verifier).
export async function exchangeCode({ tenant, clientId, redirectUri, code, verifier, scope }) {
  const body = new URLSearchParams({
    client_id: clientId,
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
    scope,
  });
  const resp = await fetch(`${LOGIN}/${tenant}/oauth2/v2.0/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  if (resp.status >= 400) throw new Error("token exchange " + resp.status + ": " + (await resp.text()).slice(0, 300));
  return resp.json(); // { access_token, expires_in, ... } - garde en MEMOIRE, jamais persiste en clair
}

// --- EXO : app built-in Microsoft fb78d390 (la seule autorisee sur l'adminapi profond).
// C'est un PUBLIC CLIENT (aucun secret) qui accepte la redirection http://localhost. En delegue
// (droits de l'admin connecte), PKCE, ZERO secret, ZERO device-code. Prouve 01/07 : 9/9 endpoints securite.
export const EXO_CLIENT_ID = "fb78d390-0c51-40cd-8e17-fdbfab77341b";
export const EXO_REDIRECT = "http://localhost";  // loopback accepte par fb78d390 (public client)

// URL d'autorisation pour EXO (redirection localhost, interceptee par l'extension via chrome.tabs).
export function buildLocalhostAuthUrl({ tenant, scope, challenge, state }) {
  const p = new URLSearchParams({
    client_id: EXO_CLIENT_ID, response_type: "code", redirect_uri: EXO_REDIRECT,
    response_mode: "query", scope, code_challenge: challenge, code_challenge_method: "S256", state,
  });
  return `${LOGIN}/${tenant}/oauth2/v2.0/authorize?${p.toString()}`;
}

// [device-code SUPPRIME le 02/07/2026] Le flow device-code est PROSCRIT (vecteur de phishing, exigence SQ).
// L'auth EXO passe UNIQUEMENT par le flow interactif localhost (getExoToken, background.js), jamais device-code.

// Refresh silencieux (aucune interaction) tant que le refresh token est valide (~90j public client).
export async function refreshAccessToken({ tenant, clientId, refreshToken, scope }) {
  const resp = await fetch(`${LOGIN}/${tenant}/oauth2/v2.0/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token", client_id: clientId, refresh_token: refreshToken, scope,
    }).toString(),
  });
  if (resp.status >= 400) throw new Error("refresh " + resp.status);
  return resp.json();
}

// Orchestration d'un token delegue pour une ressource donnee (Graph OU EXO).
export async function getDelegatedToken({ tenant, clientId, redirectUri, scope }) {
  const { verifier, challenge } = await generatePkce();
  const state = b64url(crypto.getRandomValues(new Uint8Array(16)));
  const authUrl = buildAuthUrl({ tenant, clientId, redirectUri, scope, challenge, state });
  const code = await launchInteractive(authUrl);
  const tok = await exchangeCode({ tenant, clientId, redirectUri, code, verifier, scope });
  return tok.access_token;
}
