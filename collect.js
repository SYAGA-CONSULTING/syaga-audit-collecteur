// SYAGA Audit extension - couche COLLECTE (port JS fidele de m365-rest-collector/m365rest/exo.py).
// Approche Vasil Michev : on rejoue les cmdlets EXO/Purview en REST via InvokeCommand. ZERO PowerShell.
// Source des constantes : exo.py (verifie 30/06). Aucun endpoint invente ici.
// Auth = authorization code + PKCE delegue (ADR-004), gere ailleurs ; ici on recoit un access_token.

// ---- Constantes EXO/Purview (copiees telles quelles depuis exo.py) ----
export const EXO_HOST = "https://outlook.office365.com";
export const PURVIEW_HOST = "https://ps.compliance.protection.outlook.com";
export const COMPLIANCE_SYS_MBX = "UPN:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@";  // + domaine .onmicrosoft

// Purview : l'adminapi compliance route via AutogenSession vers un backend REGIONAL. En PowerShell on lit
// l'en-tete Location du 302 ; en fetch navigateur c'est opaque/illisible (redirect vers :446 = Failed to fetch).
// SOLUTION : chrome.webRequest.onBeforeRedirect OBSERVE la redirection et expose redirectUrl (que fetch cache).
// On declenche l'AutogenSession (le fetch echouera en suivant :446, on s'en fiche), on capte le host regional
// via le listener, on derive {region}.ps.compliance.protection.outlook.com (443, sans redirection).
export function getComplianceHost(tenant, token, initialDomain) {
  const anchor = COMPLIANCE_SYS_MBX + initialDomain;
  const url = `${PURVIEW_HOST}/adminapi/beta/${tenant}/EXOBanner('AutogenSession')`;
  return new Promise((resolve, reject) => {
    let done = false;
    const filter = { urls: ["https://ps.compliance.protection.outlook.com/*", "https://*.admin.protection.outlook.com/*"] };
    const cleanup = () => { try { chrome.webRequest.onBeforeRedirect.removeListener(onRedirect); } catch (e) {} };
    function onRedirect(d) {
      if (done || !d.redirectUrl) return;
      let host;
      try { host = new URL(d.redirectUrl).host.split(":")[0]; } catch (e) { return; }   // sans le port :446
      if (!/\.(admin\.protection|ps\.compliance\.protection)\.outlook\.com$/.test(host)) return;
      done = true; cleanup();
      resolve(`${host.split(".")[0]}.ps.compliance.protection.outlook.com`);             // {region}.ps.compliance...
    }
    chrome.webRequest.onBeforeRedirect.addListener(onRedirect, filter);
    setTimeout(() => { if (!done) { cleanup(); reject(new Error("AutogenSession: aucune redirection captee (20s)")); } }, 20000);
    // declenche la requete ; onBeforeRedirect capte le host AVANT que le saut vers :446 n'echoue
    fetch(url, { headers: { "Authorization": `Bearer ${token}`, "X-AnchorMailbox": anchor } }).catch(() => {});
  });
}
export const EXO_SCOPE = "https://outlook.office365.com/.default";
export const PURVIEW_SCOPE = "https://ps.compliance.protection.outlook.com/.default";
const INVOKE_PATH = "/adminapi/beta/{tenant}/InvokeCommand";
const SYSTEM_MBX = "SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@{tenant}";
const DEFAULT_MAXPAGESIZE = 1000;
const DEFAULT_MAX_PAGES = 10000;

// label -> [cmdlet, parameters]. Copie fidele de EXO_COLLECTORS (exo.py), tout read-only org-level.
export const EXO_COLLECTORS = {
  OrganizationConfig: ["Get-OrganizationConfig", {}],
  AcceptedDomain: ["Get-AcceptedDomain", {}],
  RemoteDomain: ["Get-RemoteDomain", {}],
  SharingPolicy: ["Get-SharingPolicy", {}],
  TransportConfig: ["Get-TransportConfig", {}],
  TransportRule: ["Get-TransportRule", {}],
  InboundConnector: ["Get-InboundConnector", {}],
  OutboundConnector: ["Get-OutboundConnector", {}],
  AuthenticationPolicy: ["Get-AuthenticationPolicy", {}],
  OwaMailboxPolicy: ["Get-OwaMailboxPolicy", {}],
  DkimSigningConfig: ["Get-DkimSigningConfig", {}],
  HostedConnectionFilterPolicy: ["Get-HostedConnectionFilterPolicy", {}],
  HostedContentFilterPolicy: ["Get-HostedContentFilterPolicy", {}],
  MalwareFilterPolicy: ["Get-MalwareFilterPolicy", {}],
  AntiPhishPolicy: ["Get-AntiPhishPolicy", {}],
  QuarantinePolicy: ["Get-QuarantinePolicy", {}],
  SafeLinksPolicy: ["Get-SafeLinksPolicy", {}],
  SafeAttachmentPolicy: ["Get-SafeAttachmentPolicy", {}],
  AdminAuditLogConfig: ["Get-AdminAuditLogConfig", {}],
  // --- ajouts 01/07 (verifies Microsoft Learn, meme contrat InvokeCommand valide) ---
  HostedOutboundSpamFilterPolicy: ["Get-HostedOutboundSpamFilterPolicy", {}],
  EOPProtectionPolicyRule: ["Get-EOPProtectionPolicyRule", {}],
  ATPProtectionPolicyRule: ["Get-ATPProtectionPolicyRule", {}],
  AtpPolicyForO365: ["Get-AtpPolicyForO365", {}],
  ReportSubmissionPolicy: ["Get-ReportSubmissionPolicy", {}],
  ExternalInOutlook: ["Get-ExternalInOutlook", {}],
  MailboxAuditBypassAssociation: ["Get-MailboxAuditBypassAssociation", {}],
  IRMConfiguration: ["Get-IRMConfiguration", {}],
};
export const COMPLIANCE_COLLECTORS = {
  RetentionCompliancePolicy: ["Get-RetentionCompliancePolicy", {}],
  // --- ajouts 01/07 (verifies Microsoft Learn) : DLP + etiquettes + alertes Purview ---
  DlpCompliancePolicy: ["Get-DlpCompliancePolicy", {}],
  DlpComplianceRule: ["Get-DlpComplianceRule", {}],
  LabelPolicy: ["Get-LabelPolicy", {}],
  Label: ["Get-Label", {}],
  ProtectionAlert: ["Get-ProtectionAlert", {}],
};

// ---- Surfaces Graph v1.0 (CORS OK) verifiees dans SYNTHESE-couverture-graph-vs-adminapi.md ----
export const GRAPH_BASE = "https://graph.microsoft.com/v1.0";
export const GRAPH_ENDPOINTS = {
  organization: "/organization",
  users: "/users",
  groups: "/groups",
  applications: "/applications",
  servicePrincipals: "/servicePrincipals",
  directoryRoles: "/directoryRoles",
  conditionalAccess: "/identity/conditionalAccess/policies",
  authenticationMethodsPolicy: "/policies/authenticationMethodsPolicy",
  authorizationPolicy: "/policies/authorizationPolicy",
  riskyUsers: "/identityProtection/riskyUsers",
  secureScores: "/security/secureScores",
  // --- ajouts 01/07 (verifies Microsoft Learn, v1.0, GET delegue navigateur) ---
  signInLogs: "/auditLogs/signIns",
  subscribedSkus: "/subscribedSkus",
  domains: "/domains",
  securityDefaults: "/policies/identitySecurityDefaultsEnforcementPolicy",
  adminConsentRequestPolicy: "/policies/adminConsentRequestPolicy",
  directorySettings: "/groupSettings",
  accessReviews: "/identityGovernance/accessReviews/definitions",
  roleAssignmentScheduleInstances: "/roleManagement/directory/roleAssignmentScheduleInstances",
  roleAssignments: "/roleManagement/directory/roleAssignments",
  roleEligibilityScheduleInstances: "/roleManagement/directory/roleEligibilityScheduleInstances",
  oauth2PermissionGrants: "/oauth2PermissionGrants",
  entitlementManagementAccessPackages: "/identityGovernance/entitlementManagement/accessPackages",
  roleManagementPolicies: "/policies/roleManagementPolicies?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'",
  sharepointSettings: "/admin/sharepoint/settings",
  managedDevices: "/deviceManagement/managedDevices",
  deviceCompliancePolicies: "/deviceManagement/deviceCompliancePolicies",
  deviceConfigurations: "/deviceManagement/deviceConfigurations",
  detectedApps: "/deviceManagement/detectedApps",
  deviceEnrollmentConfigurations: "/deviceManagement/deviceEnrollmentConfigurations",
  deviceCompliancePolicyDeviceStateSummary: "/deviceManagement/deviceCompliancePolicyDeviceStateSummary",
  deviceLocalCredentials: "/directory/deviceLocalCredentials",
  emailAuthenticationMethodConfig: "/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/email",
  // --- beta (URL complete, base beta distincte ; graphGet accepte les URL http) ---
  roleManagementAlerts: "https://graph.microsoft.com/beta/identityGovernance/roleManagementAlerts/alerts?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'",
  deviceRegistrationPolicy: "https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy",
  forwardingProfiles: "https://graph.microsoft.com/beta/networkAccess/forwardingProfiles",
  endpointSecurityIntents: "https://graph.microsoft.com/beta/deviceManagement/intents",
  configurationPolicies: "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies",
};

// ---- Constructeur de requete InvokeCommand (PUR, testable sans reseau) ----
// Retourne {url, headers, body} STRICTEMENT identique au contrat exo.py.
export function buildInvokeRequest(cmdlet, { tenant, token, params = {}, select = null, anchor = null,
                                             host = EXO_HOST, maxpagesize = DEFAULT_MAXPAGESIZE } = {}) {
  let url = host.replace(/\/$/, "") + INVOKE_PATH.replace("{tenant}", tenant);
  if (select && select.length) url += "?$select=" + select.join(",");
  // Appel DELEGUE : ancre AAD-UPN (EXO) ; si un prefixe est deja present (ex: compliance "UPN:SystemMailbox..."), on garde tel quel.
  const anchorMbx = anchor ? (anchor.includes(":") ? anchor : "AAD-UPN:" + anchor) : SYSTEM_MBX.replace("{tenant}", tenant);
  const headers = {
    "Authorization": `Bearer ${token}`,
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-ResponseFormat": "json",
    "X-ClientApplication": "ExoManagementModule",   // requis par l'adminapi (recette validee 01/07)
    "X-AnchorMailbox": anchorMbx,
    "Prefer": `odata.maxpagesize=${maxpagesize}`,
  };
  const body = { CmdletInput: { CmdletName: cmdlet, Parameters: params || {} } };
  return { url, headers, body };
}

// ---- Execution reelle (reseau : tourne dans le service worker de l'extension) ----
// invoke() suit @odata.nextLink en GET, POST sur la 1ere page (comme exo.py).
export async function invoke(cmdlet, opts) {
  const { url, headers, body } = buildInvokeRequest(cmdlet, opts);
  const out = [];
  let nextUrl = url, first = true, pages = 0;
  while (nextUrl) {
    if (++pages > (opts.maxPages || DEFAULT_MAX_PAGES))
      throw new Error(`EXO ${cmdlet}: max_pages exceeded (${out.length} rows)`);
    const resp = first
      ? await fetch(nextUrl, { method: "POST", headers, body: JSON.stringify(body), signal: AbortSignal.timeout(15000) })
      : await fetch(nextUrl, { method: "GET", headers, signal: AbortSignal.timeout(15000) });
    first = false;
    if (resp.status >= 400) throw new Error(`EXO ${resp.status} on ${cmdlet}: ${(await resp.text()).slice(0,500)}`);
    const data = await resp.json();
    out.push(...(data.value || data.Value || []));
    nextUrl = data["@odata.nextLink"] || null;
  }
  return out;
}

export async function graphGet(path, token, { consistencyEventual = false } = {}) {
  const headers = { "Authorization": `Bearer ${token}`, "Accept": "application/json" };
  if (consistencyEventual) headers["ConsistencyLevel"] = "eventual"; // requis pour $count (ADR-004)
  const url = path.startsWith("http") ? path : GRAPH_BASE + path;  // beta = URL complete
  const resp = await fetch(url, { headers, signal: AbortSignal.timeout(10000) }); // timeout : une source lente n'fige pas tout
  if (resp.status >= 400) throw new Error(`Graph ${resp.status} on ${path}`);
  return resp.json();
}
