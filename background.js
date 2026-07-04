// SYAGA Audit extension - service worker (orchestration). 100% JS lisible (auditabilite).
// Flux : auth PKCE delegue -> collecte read-only (Graph + EXO InvokeCommand) -> pseudonymisation
// locale -> envoi des JETONS a UNE seule origine SYAGA Audit. Le clair et la cle ne sortent jamais.
import { getDelegatedToken, generatePkce, buildLocalhostAuthUrl, exchangeCode, refreshAccessToken,
         EXO_CLIENT_ID, EXO_REDIRECT } from "./auth.js";
import { graphGet, invoke, GRAPH_ENDPOINTS, EXO_COLLECTORS, COMPLIANCE_COLLECTORS,
         EXO_HOST, PURVIEW_HOST, EXO_SCOPE, getComplianceHost, COMPLIANCE_SYS_MBX } from "./collect.js";
import { pseudonymize, generateEphemeralKey, newStableKey, keyFromSecret } from "./pseudonymize.mjs";
import { recontextualize } from "./recontextualize.mjs";

// --- Config (a brancher sur l'app Entra SYAGA + l'origine de prod ; placeholders honnetes) ---
const CONFIG = {
  clientId: "6ca99dee-6a03-49d2-9c57-40ec58f2e4ce",   // app PUBLIQUE SYAGA (creee 01/07, redirect = ext ID)
  tenantSegment: "organizations",                      // le tenant reel = celui ou l'utilisateur se connecte
  apiOrigin: "https://m365.audit.syaga.fr",              // preprod live (route seam /api/v1/audit deployee 01/07)
  graphScope: [
    "https://graph.microsoft.com/User.Read",
    "https://graph.microsoft.com/Directory.Read.All",
    "https://graph.microsoft.com/Policy.Read.All",
    "https://graph.microsoft.com/AuditLog.Read.All",
    "https://graph.microsoft.com/RoleManagement.Read.Directory",
    "https://graph.microsoft.com/AccessReview.Read.All",
    "https://graph.microsoft.com/EntitlementManagement.Read.All",
    "https://graph.microsoft.com/DeviceManagementManagedDevices.Read.All",
    "https://graph.microsoft.com/DeviceManagementConfiguration.Read.All",
    "https://graph.microsoft.com/DeviceManagementServiceConfig.Read.All",
    "https://graph.microsoft.com/SharePointTenantSettings.Read.All",
    "https://graph.microsoft.com/DeviceLocalCredential.ReadBasic.All",
    "https://graph.microsoft.com/NetworkAccess.Read.All",
    "https://graph.microsoft.com/RoleManagementAlert.Read.Directory",
    "offline_access",
  ].join(" "),   // scopes verifies Microsoft Learn par endpoint (agent 01/07)
  exoScope: EXO_SCOPE + " offline_access",
};

function redirectUri() { return chrome.identity.getRedirectURL(); } // https://<id>.chromiumapp.org/

// L'adminapi Exchange exige l'ID de tenant (GUID) dans l'URL, pas un domaine vanity (syaga.fr).
// On le lit dans le claim `tid` du token (valeur canonique, jamais une supposition).
function tidFromToken(jwt) {
  try {
    const seg = String(jwt).split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(seg)).tid || null;
  } catch (e) { return null; }
}

// L'adminapi delegue s'ancre (X-AnchorMailbox) sur le mailbox de l'APPELANT, pas un mailbox systeme.
// On lit l'UPN dans le token (claim upn / preferred_username), sinon 403 (acces refuse au mailbox systeme).
function upnFromToken(jwt) {
  try {
    const seg = String(jwt).split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    const p = JSON.parse(atob(seg));
    return p.upn || p.preferred_username || null;
  } catch (e) { return null; }
}

// Token EXO via l'app built-in fb78d390 (la seule autorisee sur l'adminapi profond), en DELEGUE,
// PKCE, ZERO secret, ZERO device-code. D'abord refresh silencieux ; sinon flow interactif :
// on ouvre l'URL d'auth, Microsoft redirige vers http://localhost/?code=... (page "inaccessible" = normal),
// et on INTERCEPTE le code dans l'URL de l'onglet via chrome.tabs.onUpdated (aucun serveur local requis).
const EXO_STORE_KEY = "vigil_exo_refresh";

function captureCodeViaTab(authUrl, expectedState) {
  return new Promise((resolve, reject) => {
    chrome.tabs.create({ url: authUrl, active: true }, (tab) => {
      const tabId = tab.id;
      const timer = setTimeout(() => { cleanup(); reject(new Error("auth localhost: timeout")); }, 300000);
      function cleanup() { clearTimeout(timer); chrome.tabs.onUpdated.removeListener(onUpdated); }
      function onUpdated(id, info) {
        if (id !== tabId || !info.url || !info.url.startsWith(EXO_REDIRECT)) return;  // attend la redirection localhost
        let code = null, err = null, st = null;
        try { const u = new URL(info.url); code = u.searchParams.get("code"); err = u.searchParams.get("error"); st = u.searchParams.get("state"); } catch (e) { /* url non parsable */ }
        cleanup();
        if (code && st === expectedState) {
          // remplace la page "localhost inaccessible" par une page SYAGA Audit rassurante
          try { chrome.tabs.update(tabId, { url: chrome.runtime.getURL("auth-ok.html") }); } catch (e) { /* onglet ferme */ }
          resolve(code);
        } else {
          try { chrome.tabs.remove(tabId); } catch (e) { /* deja ferme */ }
          reject(new Error("auth localhost: " + (err || (st !== expectedState ? "state mismatch" : "no code"))));
        }
      }
      chrome.tabs.onUpdated.addListener(onUpdated);
    });
  });
}

async function getExoToken(tenant) {
  const scope = "https://outlook.office365.com/.default offline_access";
  // 1. silencieux via refresh token stocke (MFA une fois, puis ~90j sans interaction)
  try {
    const stored = (await chrome.storage.local.get(EXO_STORE_KEY))[EXO_STORE_KEY];
    if (stored) {
      const t = await refreshAccessToken({ tenant, clientId: EXO_CLIENT_ID, refreshToken: stored, scope });
      if (t && t.access_token) {
        if (t.refresh_token) await chrome.storage.local.set({ [EXO_STORE_KEY]: t.refresh_token });
        return t.access_token;
      }
    }
  } catch (e) { /* refresh expire -> flow interactif */ }
  // 2. interactif : fb78d390 + redirection localhost interceptee (PKCE, zero secret, zero device-code)
  const { verifier, challenge } = await generatePkce();
  const state = crypto.getRandomValues(new Uint32Array(2)).join("");  // anti-CSRF, verifie au retour
  const authUrl = buildLocalhostAuthUrl({ tenant, scope, challenge, state });
  const code = await captureCodeViaTab(authUrl, state);
  const tok = await exchangeCode({ tenant, clientId: EXO_CLIENT_ID, redirectUri: EXO_REDIRECT, code, verifier, scope });
  if (tok.refresh_token) await chrome.storage.local.set({ [EXO_STORE_KEY]: tok.refresh_token });
  return tok.access_token;
}

async function collectGraph(token, onEach = () => {}) {
  const out = {};
  const entries = Object.entries(GRAPH_ENDPOINTS);
  let done = 0;
  // PARALLELE : les 38 sources en meme temps -> la phase dure ~ la plus lente (timeout 10s),
  // pas la somme. Les sources Governance/P2 qui pendent ne bloquent plus les autres.
  await Promise.all(entries.map(async ([label, path]) => {
    // deballe {value:[...]} en tableau (ce qu'attend normalize) ; garde l'objet pour les singletons
    try { const r = await graphGet(path, token); out["graph_" + label] = (r && r.value !== undefined) ? r.value : r; }
    catch (e) { out["graph_" + label] = { _error: String(e).slice(0, 200) }; }
    onEach(++done, entries.length, label);
  }));
  return out;
}

async function collectExo(token, tenant, anchor, onEach = () => {}) {
  const out = {};
  const entries = Object.entries(EXO_COLLECTORS);
  let i = 0;
  for (const [label, [cmdlet, params]] of entries) {
    onEach(++i, entries.length, label);
    try { out["exo_" + label] = await invoke(cmdlet, { tenant, token, params, host: EXO_HOST, anchor }); }
    catch (e) { out["exo_" + label] = { _error: String(e).slice(0, 200) }; }
  }
  return out;
}

// Token compliance (ressource ps.compliance, distincte d'EXO) : silencieux depuis le refresh fb78d390.
const COMP_STORE_KEY = "vigil_comp_refresh";
async function getComplianceToken(tenant) {
  const scope = "https://ps.compliance.protection.outlook.com/.default offline_access";
  const s = await chrome.storage.local.get([COMP_STORE_KEY, EXO_STORE_KEY]);
  const rt = s[COMP_STORE_KEY] || s[EXO_STORE_KEY];   // RT compliance, sinon RT EXO (multi-ressource)
  if (!rt) return null;
  try {
    const t = await refreshAccessToken({ tenant, clientId: EXO_CLIENT_ID, refreshToken: rt, scope });
    if (t && t.refresh_token) await chrome.storage.local.set({ [COMP_STORE_KEY]: t.refresh_token });
    return t && t.access_token ? t.access_token : null;
  } catch (e) { return null; }
}

// Purview : host backend derive via AutogenSession (recette CIPP), ancre systeme, InvokeCommand.
async function collectCompliance(complianceToken, tenant, initialDomain) {
  const out = {};
  const anchor = COMPLIANCE_SYS_MBX + initialDomain;
  let host;
  try { host = await getComplianceHost(tenant, complianceToken, initialDomain); }
  catch (e) {
    for (const k of Object.keys(COMPLIANCE_COLLECTORS)) out["purview_" + k] = { _error: "autogen: " + String(e).slice(0, 80) };
    return out;
  }
  for (const [label, [cmdlet, params]] of Object.entries(COMPLIANCE_COLLECTORS)) {
    try { out["purview_" + label] = await invoke(cmdlet, { tenant, token: complianceToken, params, host: "https://" + host, anchor }); }
    catch (e) { out["purview_" + label] = { _error: String(e).slice(0, 200) }; }
  }
  return out;
}

// --- Point de sortie reseau SCELLE (P0 modele de menace) : detecteur de clair, defense en profondeur.
// Si un email en clair a echappe a la pseudonymisation, on BLOQUE l'envoi (fail-closed). Les enregistrements
// DNS publics (SPF/DMARC/DKIM) contiennent des adresses legitimement claires -> exclus pour eviter un faux positif.
const EMAIL_LEAK_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;
const DNS_RECORD_RE = /v=spf1|v=dmarc1|mailto:|include:|_domainkey|dkim/i;
export function detectClearLeak(node, out = []) {
  if (Array.isArray(node)) { for (const x of node) detectClearLeak(x, out); return out; }
  if (node && typeof node === "object") { for (const v of Object.values(node)) detectClearLeak(v, out); return out; }
  if (typeof node === "string" && EMAIL_LEAK_RE.test(node) && !DNS_RECORD_RE.test(node)) out.push(node.slice(0, 60));
  return out;
}
async function sealedSend(payload, diag, apiOrigin) {
  const leaks = detectClearLeak(payload);
  if (leaks.length) {
    console.error("[SYAGA Audit] SEAL: envoi BLOQUE, clair detecte:", leaks.slice(0, 5));
    throw new Error("seal: clair detecte dans le payload (" + leaks.length + " valeur(s)), envoi bloque");
  }
  const resp = await fetch(apiOrigin + "/api/v1/audit", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ payload, _diag: diag }),
  });
  if (resp.status >= 400) throw new Error("egress " + resp.status);
  return resp.json();
}

// Selection de la cle de pseudonymisation selon la formule (2 modes, decision SQ 02/07).
const STABLE_SECRET_KEY = "vigil_pseudo_secret";
async function getPseudoKey(mode) {
  if (mode !== "subscription") return { key: await generateEphemeralKey(), newSecret: null }; // ponctuel = cle jetable
  const stored = (await chrome.storage.local.get(STABLE_SECRET_KEY))[STABLE_SECRET_KEY];
  if (stored) return { key: await keyFromSecret(stored), newSecret: null };                    // abo : cle deja etablie
  const { secret, key } = await newStableKey();                                                 // 1er run abo : nouveau secret
  await chrome.storage.local.set({ [STABLE_SECRET_KEY]: secret });
  return { key, newSecret: secret };   // newSecret != null -> l'UI DOIT l'afficher UNE FOIS (pattern secret API)
}

// Pipeline complet d'un audit. mode = "oneshot" (cle jetable) | "subscription" (cle stable conservee par le client).
async function runAudit(tenant, mode = "oneshot", onProgress = () => {}) {
  const p = (pct, label) => { try { onProgress({ pct, label }); } catch (e) { /* best-effort */ } };
  const ru = redirectUri();
  // 1. deux tokens delegues (Graph + EXO), via PKCE (consentement + MFA cote utilisateur)
  p(5, "Connexion Microsoft (lecture seule)...");
  const graphTok = await getDelegatedToken({ tenant, clientId: CONFIG.clientId, redirectUri: ru, scope: CONFIG.graphScope });
  // 2. collecte read-only. Graph = coeur ; EXO (SPF/DMARC/DKIM) = separe et NON bloquant
  // (token + consentement distincts pour outlook.office365.com ; s'il manque, on continue sur Graph).
  p(20, "Collecte Entra / Microsoft Graph (38 sources)...");
  const graphData = await collectGraph(graphTok, (i, n, label) => p(20 + Math.round((i / n) * 24), `Microsoft Graph ${i}/${n} : ${label}`));
  let exoData = {};
  let tokenDiag = null;
  try {
    p(45, "Connexion Exchange Online...");
    const exoTok = await getExoToken(tenant);   // app built-in fb78d390 (refresh silencieux, sinon device-code)
    // DIAG temporaire (recon token, NON-PII) : envoye au serveur pour trancher le 403 sans console.
    // aud/scp = ressource+scope ; wids = roles annuaire actifs (Global Admin = 62e90394-...) ; upnPresent = bool.
    try {
      const _c = JSON.parse(atob(exoTok.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
      tokenDiag = { aud: _c.aud, scp: _c.scp, roles: _c.roles, wids: _c.wids, upnPresent: !!(_c.upn || _c.preferred_username) };
    } catch (e) { /* diag best-effort */ }
    const exoTenant = tidFromToken(exoTok) || tenant;  // GUID pour l'adminapi (pas le domaine vanity)
    const exoAnchor = upnFromToken(exoTok);              // X-AnchorMailbox = mailbox de l'appelant
    p(55, "Collecte Exchange Online (27 sources)...");
    exoData = await collectExo(exoTok, exoTenant, exoAnchor, (i, n, label) => p(55 + Math.round((i / n) * 14), `Exchange Online ${i}/${n} : ${label}`));
    // Purview : ressource compliance (silencieuse depuis le meme refresh), host backend via AutogenSession
    try {
      p(70, "Collecte Purview (conformite)...");
      const initial = ((graphData.graph_domains || []).find((d) => d && d.isInitial) || {}).id;
      const compTok = await getComplianceToken(exoTenant);
      if (compTok && initial) Object.assign(exoData, await collectCompliance(compTok, exoTenant, initial));
    } catch (e) { console.warn("[SYAGA Audit] Purview ignore:", String(e).slice(0, 120)); }
  } catch (e) { console.warn("[SYAGA Audit] collecte EXO ignoree (consentement/token distinct manquant):", String(e).slice(0, 160)); }
  const collected = { ...graphData, ...exoData };
  console.log("[SYAGA Audit] cles collectees:", Object.keys(collected), "| items:", Object.values(collected).map(v => Array.isArray(v) ? v.length : typeof v));
  // 2bis. Reduction client-side des champs RE-IDENTIFIANTS inutiles au scoring (Bucket C, red-team 02/07).
  // Les cles publiques DKIM (Selector*PublicKey) sont une empreinte DNS publique (publiees a
  // selectorN._domainkey.<domaine>) et ne sont lues par AUCUN predicat des 589 (verifie : 0 usage py).
  // On ne transmet donc que leur LONGUEUR (force indicative de la cle), jamais le modulus, et AVANT
  // pseudonymisation -> le champ re-identifiant n'entre jamais dans le payload. Extensible a *Thumbprint/*KeyId.
  const reduceReidentifying = (node) => {
    if (Array.isArray(node)) { for (const it of node) reduceReidentifying(it); return; }
    if (node && typeof node === "object") {
      for (const [k, v] of Object.entries(node)) {
        if (/publickey$/i.test(k) && typeof v === "string") node[k] = v.length;   // modulus -> longueur
        else reduceReidentifying(v);
      }
    }
  };
  reduceReidentifying(collected);
  // 3. pseudonymisation LOCALE (cle generee ici, jamais transmise)
  p(82, "Pseudonymisation locale (vos donnees ne partent pas en clair)...");
  const { key: pseudoKey, newSecret } = await getPseudoKey(mode);   // 2 modes : jetable (ponctuel) / stable (abo)
  const { payload, mapping } = await pseudonymize(collected, pseudoKey);
  // 4. egress SCELLE : point de sortie reseau UNIQUE + detecteur de clair (fail-closed). Voir sealedSend.
  p(90, "Envoi des jetons + evaluation des 589 controles...");
  const report = await sealedSend(payload, tokenDiag, CONFIG.apiOrigin);   // rapport indexe par jetons
  // P2 : on garde le mapping (jeton->clair) EN LOCAL, cle par audit_id, pour re-contextualiser le rapport
  // COMPLET livre APRES paiement. Il ne quitte JAMAIS le poste (chrome.storage.local, isole a l'extension) ->
  // zero-knowledge intact. S'il est perdu (crash), c'est le cas RECUPERATION (re-scan), pas un drame.
  try { if (report && report.audit_id) await chrome.storage.local.set({ ["vigil_map_" + report.audit_id]: mapping }); }
  catch (e) { /* best-effort : sinon le complet retombe sur le jetonise cote serveur */ }
  // 5. re-contextualisation cote client : remplace les jetons par les vrais noms (table locale)
  p(97, "Restitution de vos vrais noms (local)...");
  const reportLisible = recontextualize(report, mapping);
  p(100, "Termine.");
  return { reportLisible, mapping, newSecret };   // newSecret non-null (1er run abo) -> l'UI l'affiche UNE fois
}

// Le popup (popup.js) demande l'audit avec le tenant saisi par l'utilisateur.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "run-audit") {
    runAudit(msg.tenant || CONFIG.tenantSegment, msg.mode || "oneshot")
      .then((r) => sendResponse({ ok: true, report: r.reportLisible, newSecret: r.newSecret || null }))
      .catch((e) => sendResponse({ ok: false, error: String(e).slice(0, 200) }));
    return true; // reponse asynchrone
  }
  if (msg && msg.type === "import-secret") {   // restaurer une cle de suivi existante (mode abonnement)
    const secret = String(msg.secret || "").trim();
    if (!secret) { sendResponse({ ok: false, error: "clé vide" }); return true; }
    chrome.storage.local.set({ [STABLE_SECRET_KEY]: secret })
      .then(() => sendResponse({ ok: true }))
      .catch((e) => sendResponse({ ok: false, error: String(e).slice(0, 120) }));
    return true;
  }
});

// --- PONT SITE <-> EXTENSION (integration funnel) ---
// SECURITE (durci suite review 02/07) : le canal externe est un vecteur d'exfiltration si mal garde.
// 1) origine STRICTE (le manifest externally_connectable est un filtre grossier ; on revalide ici l'origine
//    exacte, port compris). 2) JAMAIS renvoyer newSecret (cle de suivi = cle de de-pseudonymisation) par ce
//    canal -> mode oneshot IMPOSE (cle ephemere, aucun secret genere). 3) tenant valide (format domaine).
// Le rapport renvoye est DEJA recontextualise LOCALEMENT ; il ne quitte pas le poste (site = meme machine).
// NB build STORE (prod) : retirer les origines localhost (dev only) via prod_build_guard.
const EXTERNAL_ALLOWED_ORIGINS = new Set([
  "https://m365.audit.syaga.fr",         // domaine canonique du site (prod)
  "https://m365.audit.syaga.fr",
  "https://m365.audit.syaga.fr",   // alias (redirige vers m365.audit.syaga.fr)
  "http://localhost:8899",       // banc de test LOCAL du PC de SQ uniquement (port fixe)
]);
const TENANT_RE = /^([a-z0-9-]+\.)+[a-z]{2,}$/;   // domaine ou tenant.onmicrosoft.com

chrome.runtime.onMessageExternal.addListener((msg, sender, sendResponse) => {
  const origin = sender && sender.origin;
  if (!origin || !EXTERNAL_ALLOWED_ORIGINS.has(origin)) {   // garde-fou #1 : origine exacte
    sendResponse({ ok: false, error: "origine non autorisee" });
    return true;
  }
  if (msg && msg.type === "vigil-ping") {                    // detection de presence (aucune donnee sensible)
    sendResponse({ ok: true, ext: "syaga-audit", version: chrome.runtime.getManifest().version });
    return true;
  }
  if (msg && msg.type === "run-audit") {
    const tenant = String(msg.tenant || "").trim().toLowerCase();
    if (!TENANT_RE.test(tenant)) {                           // garde-fou #3 : format tenant
      sendResponse({ ok: false, error: "domaine invalide" });
      return true;
    }
    runAudit(tenant, "oneshot")                              // garde-fou #2 : oneshot force, jamais d'abonnement
      .then((r) => sendResponse({ ok: true, report: r.reportLisible }))   // PAS de newSecret via ce canal
      .catch((e) => sendResponse({ ok: false, error: String(e).slice(0, 200) }));
    return true;
  }
  if (msg && msg.type === "recontextualize") {
    // P2 : re-contextualise le rapport COMPLET post-paiement, SANS jamais exposer le mapping. SECURITE :
    // l'extension RE-FETCHE elle-meme le /result authentique (gate paye cote serveur) au lieu d'accepter un
    // rapport fourni par l'appelant -> pas d'ORACLE de de-pseudonymisation. On ne renvoie QUE le clair.
    const auditId = String(msg.audit_id || "").trim();
    const token = String(msg.token || "").trim();
    if (!auditId || !token) { sendResponse({ ok: false, error: "audit_id/token requis" }); return true; }
    (async () => {
      try {
        const stored = (await chrome.storage.local.get("vigil_map_" + auditId))["vigil_map_" + auditId];
        if (!stored) { sendResponse({ ok: false, error: "mapping absent (autre poste/expire) -> relancer un audit" }); return; }
        const r = await fetch(CONFIG.apiOrigin + "/api/v1/secure-audit/result/" + encodeURIComponent(auditId), { headers: { "X-Audit-Token": token } });
        if (!r.ok) { sendResponse({ ok: false, error: "result " + r.status }); return; }
        sendResponse({ ok: true, report: recontextualize(await r.json(), stored) });   // JAMAIS le mapping
      } catch (e) { sendResponse({ ok: false, error: String(e).slice(0, 120) }); }
    })();
    return true;
  }
  if (msg && msg.type === "recontextualize_html") {
    // A2 (moteur unique sur le site) : re-contextualise le HTML du rapport (report_engine) post-paiement. MEME
    // securite que "recontextualize" : l'extension RE-FETCHE elle-meme le HTML authentique (gate paye serveur),
    // applique le mapping LOCAL, ne renvoie QUE le HTML clair -> pas d'oracle, mapping jamais expose.
    const auditId = String(msg.audit_id || "").trim();
    const token = String(msg.token || "").trim();
    const path = msg.audience === "technique" ? "report-technique" : "report";
    if (!auditId || !token) { sendResponse({ ok: false, error: "audit_id/token requis" }); return true; }
    (async () => {
      try {
        const stored = (await chrome.storage.local.get("vigil_map_" + auditId))["vigil_map_" + auditId];
        if (!stored) { sendResponse({ ok: false, error: "mapping absent (autre poste/expire) -> relancer un audit" }); return; }
        const r = await fetch(CONFIG.apiOrigin + "/api/v1/secure-audit/" + path + "/" + encodeURIComponent(auditId), { headers: { "X-Audit-Token": token } });
        if (!r.ok) { sendResponse({ ok: false, error: path + " " + r.status }); return; }
        sendResponse({ ok: true, html: recontextualize(await r.text(), stored) });   // JAMAIS le mapping
      } catch (e) { sendResponse({ ok: false, error: String(e).slice(0, 120) }); }
    })();
    return true;
  }
  sendResponse({ ok: false, error: "type inconnu" });
  return true;
});

// Canal TEMPS-REEL de progression : le site ouvre un port long-lived "vigil-audit", envoie run-audit,
// et recoit les jalons {type:"progress", pct, label} puis {type:"report"} ou {type:"error"}.
// Memes garde-fous que onMessageExternal (origine stricte, oneshot impose, tenant valide).
chrome.runtime.onConnectExternal.addListener((port) => {
  const origin = port.sender && port.sender.origin;
  if (port.name !== "vigil-audit" || !origin || !EXTERNAL_ALLOWED_ORIGINS.has(origin)) {
    try { port.disconnect(); } catch (e) { /* noop */ }
    return;
  }
  port.onMessage.addListener((msg) => {
    if (!msg || msg.type !== "run-audit") return;
    const tenant = String(msg.tenant || "").trim().toLowerCase();
    if (!TENANT_RE.test(tenant)) { try { port.postMessage({ type: "error", error: "domaine invalide" }); } catch (e) {} return; }
    runAudit(tenant, "oneshot", (prog) => { try { port.postMessage({ type: "progress", ...prog }); } catch (e) {} })
      .then((r) => { try { port.postMessage({ type: "report", report: r.reportLisible }); } catch (e) {} })
      .catch((e) => { try { port.postMessage({ type: "error", error: String(e).slice(0, 200) }); } catch (e) {} });
  });
});

export { runAudit }; // pour tests/orchestration
