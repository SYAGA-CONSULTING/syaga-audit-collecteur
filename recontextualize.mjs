// SYAGA Audit extension - RE-CONTEXTUALISATION (cote client). Le serveur renvoie un rapport indexe par
// JETONS (il n'a jamais vu les vrais noms). Ici, avec la table 'mapping' restee sur le poste, on
// remplace les jetons par les vraies valeurs pour AFFICHER un rapport lisible au client.
// Le serveur ne peut pas faire ca (il n'a pas la table). C'est le retour de la frontiere.

const TOKEN_RE = /\b[A-Z]+-[0-9A-F]{8,12}\b/g;

// Remplace, dans n'importe quelle structure (string/array/objet), les jetons par mapping[jeton].
export function recontextualize(node, mapping) {
  if (typeof node === "string") {
    return node.replace(TOKEN_RE, (tok) => (tok in mapping ? mapping[tok] : tok));
  }
  if (Array.isArray(node)) return node.map((n) => recontextualize(n, mapping));
  if (node && typeof node === "object") {
    const out = {};
    for (const [k, v] of Object.entries(node)) out[recontextualize(k, mapping)] = recontextualize(v, mapping);
    return out;
  }
  return node;
}
