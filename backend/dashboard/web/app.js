"use strict";

// GuardianOS-AI web dashboard: live view, threat timeline, chain DAG,
// approval / rollback controls and analyst feedback.

const $ = (id) => document.getElementById(id);

const state = {
  reports: [],
  selectedId: null,
  health: null,
  token: localStorage.getItem("guardian_token") || "",
  ws: null,
};

// -- helpers -----------------------------------------------------------
function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function fmtTime(ts) {
  const d = new Date((ts || 0) * 1000);
  return d.toLocaleTimeString();
}

function headers(json) {
  const h = {};
  if (state.token) h["X-GUARDIAN-TOKEN"] = state.token;
  if (json) h["Content-Type"] = "application/json";
  return h;
}

async function api(path, opts = {}) {
  const res = await fetch(path, { headers: headers(opts.body != null), ...opts });
  if (res.status === 401 || res.status === 403) {
    throw new Error(`HTTP ${res.status}: ${await res.text()}`);
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
  return res.json();
}

// -- data loading ------------------------------------------------------
async function refreshHealth() {
  try {
    state.health = await api("/api/health");
  } catch (err) {
    state.health = null;
  }
  renderStats();
}

async function refreshThreats() {
  try {
    state.reports = await api("/api/threats");
  } catch (err) {
    state.reports = [];
  }
  if (state.reports.length && !state.reports.some((r) => r.report_id === state.selectedId)) {
    state.selectedId = state.reports[0].report_id;
  }
  renderThreats();
  renderDetail();
}

async function refreshEvents() {
  try {
    const events = await api("/api/events?limit=40");
    renderEvents(events);
  } catch (err) {
    // ignore; events are best-effort
  }
}

// -- render ------------------------------------------------------------
function renderStats() {
  const h = state.health || {};
  const status = $("stat-status");
  if (!h.status) {
    status.textContent = "offline";
    status.className = "pill pill-idle";
  } else if (h.learning) {
    status.textContent = `LEARNING (baseline ${h.baseline})`;
    status.className = "pill pill-learning";
  } else {
    status.textContent = "DETECTING";
    status.className = h.threats ? "pill pill-alert" : "pill pill-active";
  }
  $("stat-baseline").innerHTML = `baseline <b>${h.baseline ?? 0}</b>`;
  $("stat-threats").innerHTML = `threats <b>${h.threats ?? 0}</b>`;
  $("stat-events").innerHTML = `events <b>${h.events_in_window ?? 0}</b>`;
}

function severityClass(sev) {
  return `sev-${sev || "low"}`;
}

function renderThreats() {
  const list = $("threat-list");
  if (!state.reports.length) {
    list.innerHTML = '<li class="empty">No threats detected yet. Baseline learning builds a profile of normal behaviour…</li>';
    return;
  }
  list.innerHTML = state.reports.map((report) => {
    const d = report.detection;
    const mitre = (report.explanation.mitre || []).map((m) => m.technique_id).join(", ") || "-";
    const selected = report.report_id === state.selectedId ? " selected" : "";
    return `<li class="${selected}" data-id="${esc(report.report_id)}">
      <div class="row">
        <span class="exe">${esc(d.exe)}</span>
        <span class="sev ${severityClass(d.severity)}">${esc(d.severity)}</span>
      </div>
      <div class="row">
        <span class="meta">${fmtTime(report.timestamp)} · pid ${d.pid} · score ${d.anomaly_score.toFixed(2)}</span>
        <span class="meta">${esc(mitre)}</span>
      </div>
    </li>`;
  }).join("");
  list.querySelectorAll("li[data-id]").forEach((li) => {
    li.addEventListener("click", () => {
      state.selectedId = li.dataset.id;
      renderThreats();
      renderDetail();
    });
  });
}

function dagLines(dag) {
  if (!dag || !dag.nodes || !dag.nodes.length) return ["No behaviour-chain DAG available."];
  const byId = new Map(dag.nodes.map((n) => [n.id, n]));
  const spawn = new Map();
  const attach = new Map();
  for (const edge of dag.edges) {
    const bucket = edge.kind === "spawn" ? spawn : attach;
    if (!bucket.has(edge.source)) bucket.set(edge.source, []);
    bucket.get(edge.source).push(edge.target);
  }
  const label = (nodeId) => {
    const node = byId.get(nodeId);
    const exe = String(node.exe).split(/[\\/]/).pop() || node.exe;
    const text = `${exe} (pid ${node.pid})`;
    return node.suspicious ? `<span class="susp">${esc(text)}</span>` : esc(text);
  };
  const out = [];
  const walk = (nodeId, prefix, last) => {
    out.push(`${prefix}${last ? "└─ " : "├─ "}${label(nodeId)}`);
    const childPrefix = prefix + (last ? "   " : "│  ");
    const children = (spawn.get(nodeId) || []).concat(attach.get(nodeId) || []);
    children.forEach((childId, index) => {
      const childLast = index === children.length - 1;
      if (byId.has(childId) && !spawn.has(childId)) {
        const leaf = byId.get(childId);
        const glyph = childLast ? "└─ " : "├─ ";
        const text = leaf.suspicious
          ? `<span class="susp">${esc(leaf.description)}</span>`
          : esc(leaf.description);
        out.push(`${childPrefix}${glyph}${text}`);
      } else {
        walk(childId, childPrefix, childLast);
      }
    });
  };
  const roots = dag.roots.length
    ? dag.roots
    : dag.nodes.filter((n) => ["process_created", "exec"].includes(n.kind)).map((n) => n.id);
  roots.forEach((root, index) => walk(root, "", index === roots.length - 1));
  return out;
}

function renderDetail() {
  const el = $("detail");
  const report = state.reports.find((r) => r.report_id === state.selectedId);
  if (!report) {
    el.innerHTML = '<p class="empty">Select a threat to see the AI analysis, behaviour chain and response actions.</p>';
    return;
  }
  const exp = report.explanation;
  const html = [
    `<p class="summary">${esc(exp.summary)}</p>`,
    exp.reasons.length
      ? `<h3>Why</h3><ul>${exp.reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>`
      : "",
    exp.mitre.length
      ? `<h3>MITRE ATT&amp;CK</h3><ul>${exp.mitre
          .map((m) => `<li class="mitre">${esc(m.technique_id)} ${esc(m.name)} · ${esc(m.tactic)} (${(m.confidence * 100).toFixed(0)}%)</li>`)
          .join("")}</ul>`
      : "",
    `<h3>Behaviour chain DAG</h3><pre class="dag">${dagLines(exp.dag).join("\n")}</pre>`,
    `<h3>Recommended response</h3>${renderActions(report)}`,
    `<h3>Analyst feedback</h3><div class="action"><button data-label="benign" class="approve">Mark benign</button><button data-label="malicious" class="reject">Mark malicious</button></div>`,
  ].join("");
  el.innerHTML = html;
  bindDetailActions(report);
}

function renderActions(report) {
  if (!report.actions.length) return '<p class="empty">No actions recommended.</p>';
  return report.actions.map((action, index) => {
    const status = `status-${action.status}`;
    const canApprove = action.status === "pending_approval" || action.status === "recommended";
    return `<div class="action">
      <span class="desc">${esc(action.action_type)}: ${esc(action.description)}</span>
      <span class="status ${status}">${esc(action.status)}</span>
      <button data-approve="${index}" class="approve" ${canApprove ? "" : "disabled"}>Approve</button>
      <button data-reject="${index}" class="reject" ${canApprove ? "" : "disabled"}>Reject</button>
    </div>`;
  }).join("");
}

function bindDetailActions(report) {
  $("detail").querySelectorAll("[data-approve]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await api(`/api/threats/${report.report_id}/actions/${btn.dataset.approve}/approve`, { method: "POST" });
      refreshThreats();
    });
  });
  $("detail").querySelectorAll("[data-reject]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await api(`/api/threats/${report.report_id}/actions/${btn.dataset.reject}/reject`, { method: "POST" });
      refreshThreats();
    });
  });
  $("detail").querySelectorAll("[data-label]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await api(`/api/threats/${report.report_id}/label`, {
        method: "POST",
        body: JSON.stringify({ verdict: btn.dataset.label }),
      });
      refreshThreats();
    });
  });
  const rollback = document.querySelector(".action [data-rollback]");
  if (rollback) {
    rollback.addEventListener("click", async () => {
      await api(`/api/threats/${report.report_id}/rollback`, { method: "POST" });
      refreshThreats();
    });
  }
}

function renderEvents(events) {
  const body = $("events-table").querySelector("tbody");
  if (!events.length) {
    body.innerHTML = "";
    return;
  }
  body.innerHTML = events.map((e) => {
    const detail = e.details && (e.details.remote_ip || e.details.path)
      ? `→ ${e.details.remote_ip || e.details.path}`
      : "";
    return `<tr>
      <td>${fmtTime(e.timestamp)}</td>
      <td class="kind">${esc(e.kind)}</td>
      <td>${e.pid}</td>
      <td>${esc(e.exe)}</td>
      <td>${esc((e.cmdline || []).slice(0, 3).join(" "))} ${esc(detail)}</td>
    </tr>`;
  }).join("");
}

// -- websocket live stream ---------------------------------------------
function connectWS() {
  if (state.ws) { try { state.ws.close(); } catch (e) { /* ignore */ } }
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const url = `${proto}://${location.host}/api/ws${state.token ? `?token=${encodeURIComponent(state.token)}` : ""}`;
  const ws = new WebSocket(url);
  state.ws = ws;
  ws.onopen = () => refreshHealth();
  ws.onmessage = (evt) => {
    const msg = JSON.parse(evt.data);
    let newReports = 0;
    for (const item of msg.items || []) {
      if (item.kind === "report") {
        newReports += 1;
        state.selectedId = item.data.report.report_id;
      } else if (item.kind === "health") {
        state.health = item.data.health;
        renderStats();
      }
    }
    if (newReports > 0) refreshThreats();
    renderStats();
  };
  ws.onclose = () => {
    setTimeout(() => { if (state.ws === ws) connectWS(); }, 2000);
  };
}

// -- init ---------------------------------------------------------------
$("token-input").value = state.token;
$("token-input").addEventListener("input", (evt) => {
  state.token = evt.target.value.trim();
  localStorage.setItem("guardian_token", state.token);
  refreshHealth();
  refreshThreats();
  refreshEvents();
  connectWS();
});

async function boot() {
  await refreshHealth();
  await refreshThreats();
  await refreshEvents();
  connectWS();
  setInterval(refreshEvents, 5000);
  setInterval(refreshHealth, 10000);
}

boot();
