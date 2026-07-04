// SYAGA Audit - pseudonymiseur de la frontiere (cote CLIENT). Edite par SYAGA.
// Principe prouve (402/402 predicats) : aucun verdict ne depend d'un identifiant en clair.
// Donc on garde EN CLAIR uniquement les champs de config lus par les predicats (whitelist),
// et on TOKENISE tout le reste PAR DEFAUT (fail-safe). Un champ inconnu = tokenise, jamais l'inverse.
//
// Web Crypto natif (navigateur ET Node 18+). La cle est generee ICI et ne sort JAMAIS.

// --- Whitelist GENEREE depuis le serveur (catalogue_pseudonymizer). Defaut = CLAIR, on ne
// tokenise QUE la vraie PII. Identique au serveur -> tokenisation invariante (analyse + 589 prouves).
import { CLEAR_KEYS, CONST_VALUES, PII_FIELDS, PII_RE } from "./pseudo_whitelist.mjs";

// Cles structurelles a NE PAS tokeniser (sinon on perd la forme de l'objet).
const STRUCTURAL_KEYS = new Set(["@odata.type", "@odata.context"]);

// Detection PII robuste par NOM DE CHAMP, insensible a la casse. Indispensable : EXO/Purview renvoient
// des champs en PascalCase (DisplayName, Name, Identity, PrimarySmtpAddress) absents de PII_FIELDS (camelCase).
// Un nom de personne sous ces champs ne matche AUCUN motif de valeur -> fuyait en clair (seal 02/07).
// Fail-safe : tout champ identite/contact tokenise. Les CONSTANTES de config (CONST_VALUES) restent claires
// car testees AVANT dans keepClear. Les valeurs tokenisees sont recontextualisees cote client (mapping local).
// Inclut les champs IDENTITE/CONTACT + les champs TEXTE LIBRE (une phrase peut contenir un nom sans
// motif email/IP -> fuite, cf. seal adversarial 02/07). Texte libre tokenise en bloc (sur pour l'eval
// et recontextualise cote client). Les constantes de config (CONST_VALUES) restent claires (testees avant).
const PII_FIELD_RE = /name|principal|smtp|email|mail|address|street|location|city|phone|telephone|fax|owner|managed|manager|identity|surname|proxy|postal|createdby|modifiedby|upn|alias|nickname|description|comment|note|justification|reason|remark|memo|message|body|subject/;
function isPiiField(key) { return PII_FIELD_RE.test(String(key).toLowerCase()); }

// --- GESTION DES CLES : 2 MODES (decision SQ 02/07) ---
// PONCTUEL   : cle EPHEMERE, jetable, jamais montree ni persistee (rien a garder, confidentialite max).
// ABONNEMENT : cle STABLE derivee d'un SECRET que le client conserve (pattern secret API : genere+montre
//   une seule fois, jamais re-affichable, jamais cote serveur). Meme secret -> memes jetons d'un run a
//   l'autre -> comparaison dans le temps possible. La cle HMAC importee est non-extractible.
function b64urlBytes(bytes) { let s = ""; for (const b of bytes) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function bytesFromB64url(str) { const s = str.replace(/-/g, "+").replace(/_/g, "/"); const bin = atob(s + "=".repeat((4 - s.length % 4) % 4)); const o = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) o[i] = bin.charCodeAt(i); return o; }
async function importHmac(raw) { return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]); }

// PONCTUEL : cle jetable, non-extractible.
export async function generateEphemeralKey() { return importHmac(crypto.getRandomValues(new Uint8Array(32))); }
// ABONNEMENT : genere un nouveau secret a MONTRER UNE FOIS (le client le conserve). Retourne { secret, key }.
export async function newStableKey() { const raw = crypto.getRandomValues(new Uint8Array(32)); return { secret: b64urlBytes(raw), key: await importHmac(raw) }; }
// ABONNEMENT : re-derive la cle depuis le secret conserve par le client (re-import / autre poste).
export async function keyFromSecret(secret) { return importHmac(bytesFromB64url(secret)); }
// Compat : ancien nom = cle ephemere (defaut de pseudonymize()).
async function generateKey() { return generateEphemeralKey(); }

async function hmacToken(value, key, prefix) {
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(String(value)));
  const hex = [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
  return `${prefix}-${hex.slice(0, 12).toUpperCase()}`;
}

// FAIL-CLOSED (decision SQ 02/07) : tokeniser PAR DEFAUT, garder clair UNIQUEMENT le whitelist
// (CONST_VALUES + CLEAR_KEYS + booleens/nombres/forme). Rend la confidentialite prouvable PAR CONSTRUCTION :
// un champ/valeur inconnu = tokenise, JAMAIS une fuite. Cout : une valeur de config absente du whitelist est
// tokenisee -> le whitelist doit etre COMPLET pour l'eval. GARANTIE requise avant deploiement : miroir serveur
// (meme logique) + re-verif d'invariance des 589 (score/verdicts identiques). Tant que non fait : NE PAS
// deployer en prod (casserait l'eval des valeurs config manquantes). Le mode fail-open historique reste
// disponible (FAIL_CLOSED=false) pour reference / rollback.
const FAIL_CLOSED = true;

function keepClear(key, value) {
  if (value === null || typeof value === "boolean" || typeof value === "number") return true; // etats/seuils = eval
  if (typeof value === "string") {
    if (STRUCTURAL_KEYS.has(key)) return true;                       // forme odata, pas une identite
    if (CLEAR_KEYS.has(key) || CONST_VALUES.has(value)) return true; // whitelist config = le SEUL clair autorise
    if (FAIL_CLOSED) return false;                                   // DEFAUT fail-closed : tout le reste tokenise
    // --- mode fail-open historique (reference) : ne tokenise QUE la PII detectee ---
    if (PII_FIELDS.has(key) || isPiiField(key) || PII_RE.test(value)) return false;
    return true;
  }
  return false;
}

function prefixFor(key) {
  const k = key.toLowerCase();
  if (k.includes("principalname") || k.includes("upn")) return "UPN";
  if (k.includes("mail") || k.includes("email")) return "MAIL";
  if (k.includes("domain")) return "DOM";
  if (k.includes("displayname") || k.includes("name")) return "NAME";
  if (k === "id" || k.endsWith("id")) return "ID";
  if (k.includes("ip") || k.includes("location")) return "NET";
  return "TOK";
}

// Pseudonymise un objet/arbre. Retourne { payload, mapping }.
// payload = ce qui PART vers SYAGA Audit. mapping = jeton->valeur, reste CHEZ LE CLIENT.
export async function pseudonymize(input, key) {
  key = key || (await generateKey());
  const mapping = {};
  const seen = new Map(); // valeur->jeton : consistance (meme valeur -> meme jeton, pour la correlation)

  async function walk(node, parentKey) {
    if (Array.isArray(node)) {
      const out = [];
      for (const item of node) out.push(await walk(item, parentKey));
      return out;
    }
    if (node && typeof node === "object") {
      const out = {};
      for (const [k, v] of Object.entries(node)) out[k] = await walk(v, k);
      return out;
    }
    // feuille
    if (keepClear(parentKey, node)) return node;
    const v = String(node);
    if (seen.has(v)) return seen.get(v);
    const tok = await hmacToken(v, key, prefixFor(parentKey));
    seen.set(v, tok);
    mapping[tok] = v;
    return tok;
  }

  const payload = await walk(input, "$root");
  return { payload, mapping, key };
}

export { generateKey };
