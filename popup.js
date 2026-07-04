// SYAGA Audit extension - popup (entree utilisateur). Envoie l'ordre au service worker (background.js)
// et affiche le rapport recontextualise (vrais noms, restitues sur ce poste) dans la page.
const $ = (id) => document.getElementById(id);

function colVerdict(v) {
  v = (v || "").toUpperCase();
  if (["COUVERT", "PROPRE", "MAITRISE", "TENU", "NATIF"].some((x) => v.includes(x))) return "#16a34a";
  if (["EXPOSE", "INVESTIGUER"].some((x) => v.includes(x))) return "#dc2626";
  if (v.includes("NON DISPONIBLE")) return "#94a3b8";
  if (v.includes("SOUS-EXPLOIT")) return "#0284c7";
  return "#ca8a04";
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function renderReport(report) {
  const outcomes = (report && report.outcomes) || [];
  const rows = outcomes.map((o) => {
    const c = colVerdict(o.verdict);
    const preuve = (o.preuve || []).slice(0, 4).map(esc).join(" &middot; ");
    return `<div style="padding:11px 0;border-top:1px solid #eef2f7">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px">
        <span style="font-weight:700;font-size:13.5px;color:#1e293b">${esc(o.outcome)}</span>
        <span style="font-size:10.5px;font-weight:800;color:${c};border:1.5px solid ${c};border-radius:999px;padding:3px 10px;white-space:nowrap">${esc(o.verdict)}</span>
      </div>
      <div style="font-size:12.5px;color:#475569;margin-top:4px">${esc(o.recoupement)}</div>
      ${preuve ? `<div style="font-size:11px;color:#94a3b8;margin-top:3px">${preuve}</div>` : ""}
    </div>`;
  }).join("");
  const score = report && report.score != null ? report.score : "-";
  return `<div style="margin-top:14px;text-align:left">
    <div style="font-size:11px;letter-spacing:1px;text-transform:uppercase;color:#16a34a;font-weight:800">Analyse recoupee</div>
    <div style="font-size:13px;color:#475569;margin:4px 0 8px">Score technique : <b>${esc(score)}</b>/100. Vrais noms restitues sur ce poste ; le serveur n'a jamais vu le clair.</div>
    <div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:2px 14px">${rows || "<div style='padding:12px'>Aucun outcome.</div>"}</div>
  </div>`;
}

// Mode abonnement, 1er run : afficher la clé de suivi UNE seule fois (pattern secret API).
function showSecret(secret) {
  let box = $("secret");
  if (!box) { box = document.createElement("div"); box.id = "secret"; $("status").after(box); }
  box.innerHTML = `<div style="margin-top:12px;border:2px solid #ca8a04;background:#fffbeb;border-radius:10px;padding:12px;text-align:left">
    <div style="font-weight:800;color:#b45309;font-size:13px">Votre clé de suivi - à conserver MAINTENANT</div>
    <div style="font-size:12px;color:#78350f;margin:4px 0 8px">Elle permet de comparer vos audits dans le temps. Nous ne la voyons jamais et <b>ne pourrons pas vous la redonner</b> : elle ne s'affichera plus. Perdue = vous repartez d'une nouvelle base.</div>
    <code style="display:block;word-break:break-all;background:#fff;border:1px solid #e2e8f0;border-radius:6px;padding:8px;font-size:12px">${esc(secret)}</code>
    <button id="dlkey" style="margin-top:8px;background:#b45309">Télécharger la clé (.txt)</button>
  </div>`;
  $("dlkey").addEventListener("click", () => {
    const blob = new Blob([secret], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = "syaga-audit-cle-de-suivi.txt"; a.click();
    URL.revokeObjectURL(a.href);
  });
}

$("run").addEventListener("click", () => {
  const tenant = $("tenant").value.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  if (!tenant) { $("status").textContent = "Indiquez votre domaine ou tenant."; return; }
  const mode = $("mode-abo") && $("mode-abo").checked ? "subscription" : "oneshot";
  $("status").textContent = "Connexion Microsoft (consentement + MFA), puis collecte...";
  chrome.runtime.sendMessage({ type: "run-audit", tenant, mode }, (res) => {
    if (chrome.runtime.lastError) { $("status").textContent = "Erreur : " + chrome.runtime.lastError.message; return; }
    if (res && res.ok) {
      if (res.newSecret) showSecret(res.newSecret);   // 1er run abonnement : la clé s'affiche UNE fois
      $("status").textContent = "Audit terminé. Rapport ci-dessous (vrais noms restitués sur ce poste).";
      let box = $("report");
      if (!box) { box = document.createElement("div"); box.id = "report"; document.body.appendChild(box); }
      box.innerHTML = renderReport(res.report);
    } else {
      $("status").textContent = "Échec : " + (res && res.error ? res.error : "inconnu");
    }
  });
});

// Restaurer une clé de suivi existante (réinstallation / autre poste). La clé ne quitte jamais ce navigateur.
if ($("dorestore")) $("dorestore").addEventListener("click", () => {
  const secret = ($("restore").value || "").trim();
  if (!secret) { $("status").textContent = "Collez d'abord votre clé de suivi."; return; }
  chrome.runtime.sendMessage({ type: "import-secret", secret }, (res) => {
    if (chrome.runtime.lastError) { $("status").textContent = "Erreur : " + chrome.runtime.lastError.message; return; }
    $("status").textContent = (res && res.ok) ? "Clé de suivi restaurée. Vos prochains audits seront comparables." : "Échec restauration : " + ((res && res.error) || "inconnu");
  });
});
