// SYAGA Audit extension - RENDU REPRODUCTIBLE (cote client).
// Objectif : garantir que le PDF final est (1) fabrique par un moteur EMBARQUE dans l'artefact
// (jamais le print-to-PDF du navigateur du client, non maitrise), et (2) REPRODUCTIBLE au bit pres,
// pour que quiconque puisse verifier "meme entree -> meme PDF". Preuve : test_render_reproducible.mjs.
//
// Deux non-determinismes a neutraliser (prouve empiriquement le 01/07) :
//   a) l'horodatage embarque (/CreationDate, /ModDate) : varie a chaque rendu -> on le fige.
//   b) l'identifiant de document (/ID) : a fixer a la generation (option du moteur epingle).
// La mise en page, elle, est deterministe pour un meme moteur (prouve : 2 rendus Edge identiques
// hors horodatage). Donc moteur embarque + horodatage fige = qualite garantie + reproductibilite.

// Fige les horodatages PDF a une valeur canonique. Remplacement de MEME LONGUEUR (23 car.)
// -> ne decale PAS la table xref (offsets preserves), le PDF reste valide.
const PDF_DATE_RE = /D:\d{14}\+\d\d'\d\d'/g;
const CANONICAL_DATE = "D:00000000000000+00'00'"; // meme longueur que "D:AAAAMMJJHHMMSS+ZZ'ZZ'"

export function normalizePdfBytes(bytes) {
  // bytes: Uint8Array. On travaille en latin1 (1 octet <-> 1 caractere) pour un remplacement binaire sur.
  let s = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  s = s.replace(PDF_DATE_RE, CANONICAL_DATE);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

// Assemble le rapport final PRET A RENDRE : recontextualise les jetons (vrais noms via la table locale)
// PUIS applique les valeurs calculees cote client (ex: KPI de volume, qui depend de la taille reelle
// des donnees et n'est donc pas invariant sous pseudonymisation). Le rendu se fait ENSUITE, localement,
// par le moteur embarque -> le PDF ne contient jamais de jeton et n'a jamais quitte le poste en clair.
export function assembleFinalReportHtml(serverHtmlWithTokens, recontextualizeFn, mapping, clientPatches = []) {
  let html = recontextualizeFn(serverHtmlWithTokens, mapping); // jetons -> vrais noms
  for (const { find, replace } of clientPatches) {
    html = html.split(find).join(replace); // remplacement litteral, valeurs calculees cote client
  }
  return html;
}
