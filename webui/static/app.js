/* fabric topology UI. No build step, no dependencies: poll /api/overview,
   render an SVG star graph of this node's view of the mesh, and drive the
   admission/revocation lifecycle (signing happens server-side in the
   `fabric ui` process — the passphrase field here unlocks one operation). */

const POLL_MS = 3000;
const SVG = "http://www.w3.org/2000/svg";

const state = {
  data: null,       // last /api/overview payload
  selected: null,   // selected node id ('self' or peer id)
  form: null,       // {kind:'approve'|'deny'|'revoke', fp, error, busy}
  failing: false,
};

/* ---------- theme ---------- */

function initTheme() {
  const urlTheme = new URLSearchParams(location.search).get("theme");
  const saved = urlTheme || localStorage.getItem("fabric-theme");
  const dark = saved ? saved === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  document.getElementById("theme-toggle").onclick = () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    localStorage.setItem("fabric-theme", next);
  };
}

/* ---------- data ---------- */

async function poll() {
  try {
    const r = await fetch("/api/overview");
    if (!r.ok) throw new Error((await r.json()).error || r.statusText);
    state.data = await r.json();
    state.failing = false;
  } catch (err) {
    state.failing = String(err.message || err);
  }
  render();
}

/* Merge status peers + pending queue into one node list. */
function nodes() {
  const d = state.data;
  const pendingByID = new Map((d.pending || []).map(p => [p.peer_id, p]));
  const out = [];
  const seen = new Set();
  // names for revoked peers (their cert is gone) come from the event feed
  const nameByID = new Map();
  for (const e of d.events || []) if (e.name) nameByID.set(e.peer_id, e.name);
  for (const p of d.status.peers || []) {
    seen.add(p.id);
    const pend = pendingByID.get(p.id);
    out.push({
      ...p,
      name: p.name || (pend && pend.status === "pending" ? pend.name : undefined) || nameByID.get(p.id),
      kind: classify(p, pendingByID),
    });
  }
  for (const [id, p] of pendingByID) {
    if (!seen.has(id) && p.status === "pending") {
      out.push({ id, name: p.name, connected: false, kind: "pending" });
    }
  }
  out.sort((a, b) => (a.name || a.id).localeCompare(b.name || b.id));
  return out;
}

function classify(p, pendingByID) {
  if (p.revoked) return "revoked";
  if (p.member) return p.connected ? "member" : "offline";
  const pend = pendingByID.get(p.id);
  if (pend && pend.status === "pending") return "pending";
  return "stranger";
}

const KIND_LABEL = {
  self: "this node", member: "member", offline: "member (offline)",
  pending: "pending approval", stranger: "stranger", revoked: "revoked",
};

/* ---------- render ---------- */

function render() {
  const banner = document.getElementById("banner");
  if (state.failing) {
    banner.hidden = false;
    banner.textContent = "Daemon not reachable — is `fabric up` running? (" + state.failing + ")";
    if (!state.data) return;
  } else {
    banner.hidden = true;
  }
  const d = state.data;
  const ns = nodes();

  renderHeader(d);
  renderGraph(d, ns);
  renderLegend(ns);
  if (!state.form) {         // don't repaint under an open passphrase form
    renderDetails(d, ns);
    renderPending(d);
  }
  renderFeed(d);
}

function renderHeader(d) {
  const nsChip = document.getElementById("ns-chip");
  nsChip.textContent = d.status.namespace_did;
  nsChip.onclick = () => copy(d.status.namespace_did, nsChip);

  const selfChip = document.getElementById("self-chip");
  selfChip.innerHTML = "";
  let role = d.status.master ? "master" : "member";
  if (d.status.queue_host && !d.status.master) role += " · queue host";
  selfChip.append(dot("var(--good)"), `${d.status.name} — ${role}`);

  const reach = document.getElementById("reach-chip");
  reach.innerHTML = "";
  const reachColor = { Public: "var(--good)", Private: "var(--warn)" }[d.status.reachability] || "var(--ink-3)";
  reach.append(dot(reachColor), `NAT: ${(d.status.reachability || "unknown").toLowerCase()}`);
}

function renderGraph(d, ns) {
  const svg = document.getElementById("graph");
  svg.innerHTML = "";
  const W = 800, H = 520, cx = W / 2, cy = H / 2 - 10;
  const r = Math.min(200, 130 + ns.length * 8);

  // positions: self at center, everyone else on the ring
  const pos = { [d.status.peer_id]: [cx, cy, 28] };
  ns.forEach((n, i) => {
    const [x, y] = ringPos(i, ns.length, cx, cy, r);
    pos[n.id] = [x, y, 24];
  });

  // Links: the aggregated whole-mesh view when available (every member
  // reports its own connections), else fall back to this node's links.
  let links = (d.links || []).filter(l => pos[l.a] && pos[l.b]);
  if (!links.length) {
    links = ns.filter(n => n.connected).map(n => ({
      a: d.status.peer_id, b: n.id, rtt_ms: n.rtt_ms, transport: n.transport, relayed: n.relayed,
    }));
  }

  const summary = document.getElementById("graph-summary");
  summary.textContent = `${ns.filter(n => n.kind.startsWith("member") || n.kind === "offline").length + 1} members · ${links.length} link${links.length === 1 ? "" : "s"} up`;

  // edges first, under the nodes; trimmed to node boundaries so lines and
  // labels never run under a node's own caption
  for (const l of links) {
    const [ax, ay, ar] = pos[l.a], [bx, by, br] = pos[l.b];
    const len = Math.hypot(bx - ax, by - ay) || 1;
    const ux = (bx - ax) / len, uy = (by - ay) / len;
    const x1 = ax + ux * (ar + 8), y1 = ay + uy * (ar + 8);
    const x2 = bx - ux * (br + 6), y2 = by - uy * (br + 6);
    svg.append(el("line", { x1, y1, x2, y2, class: "edge" + (l.relayed ? " relayed" : "") }));
    const parts = [];
    if (l.rtt_ms) parts.push(l.rtt_ms < 1 ? l.rtt_ms.toFixed(2) + " ms" : l.rtt_ms.toFixed(1) + " ms");
    if (l.transport) parts.push(l.transport + (l.relayed ? " · relay" : ""));
    if (parts.length) {
      // near-vertical edges get the label fully beside the line; otherwise
      // it sits above the midpoint, pushed out along the perpendicular
      const vertical = Math.abs(uy) > 0.7;
      const mx = (x1 + x2) / 2 - (vertical ? 8 : uy * 24);
      const my = (y1 + y2) / 2 + (vertical ? 4 : ux * 24 + 4);
      svg.append(el("text", { x: mx, y: my, "text-anchor": vertical ? "end" : "middle", class: "edge-label" }, parts.join(" · ")));
    }
  }

  drawNode(svg, cx, cy, { id: "self", name: d.status.name, kind: "self", ip: d.status.overlay_ip }, 28);
  ns.forEach((n, i) => {
    const [x, y] = ringPos(i, ns.length, cx, cy, r);
    drawNode(svg, x, y, n, 24);
  });
}

function ringPos(i, n, cx, cy, r) {
  const a = (i / Math.max(n, 1)) * 2 * Math.PI - Math.PI / 2;
  return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
}

function drawNode(svg, x, y, n, radius) {
  const g = el("g", { class: `node ${n.kind}` + (state.selected === n.id ? " selected" : "") });
  g.append(el("circle", { class: "halo", cx: x, cy: y, r: radius + 6 }));
  const body = el("circle", { class: "body", cx: x, cy: y, r: radius });
  if (n.kind === "offline") body.setAttribute("stroke-dasharray", "4 4");
  g.append(body);
  if (n.kind === "self") g.append(el("circle", { class: "core", cx: x, cy: y, r: 6 }));
  if (n.kind === "revoked") {
    const o = radius * 0.45;
    g.append(el("line", { class: "cross", x1: x - o, y1: y - o, x2: x + o, y2: y + o }));
    g.append(el("line", { class: "cross", x1: x - o, y1: y + o, x2: x + o, y2: y - o }));
  }
  g.append(el("text", { x, y: y + radius + 16, "text-anchor": "middle" }, n.name || short(n.id)));
  const sub = n.ip ? `${n.ip.split("/")[0]} · ${KIND_LABEL[n.kind]}` : KIND_LABEL[n.kind];
  g.append(el("text", { x, y: y + radius + 30, "text-anchor": "middle", class: "sub" }, sub));
  g.onclick = () => { state.selected = n.id; state.form = null; renderDetails(state.data, nodes()); renderGraph(state.data, nodes()); };
  svg.append(g);
}

function renderLegend(ns) {
  const kinds = ["member", "pending", "offline", "revoked", "stranger"];
  const present = new Set(ns.map(n => n.kind));
  const lg = document.getElementById("legend");
  lg.innerHTML = "";
  for (const k of kinds) {
    if (!present.has(k) && k !== "member") continue;
    const s = document.createElement("span");
    const sw = document.createElement("span");
    sw.className = "swatch";
    sw.style.borderColor = kindColor(k);
    if (k === "offline") sw.style.borderStyle = "dashed";
    s.append(sw, KIND_LABEL[k]);
    lg.append(s);
  }
  const direct = document.createElement("span");
  direct.innerHTML = `<span class="edge-swatch"></span>direct link`;
  lg.append(direct);
  if (ns.some(n => n.relayed)) {
    const rel = document.createElement("span");
    rel.innerHTML = `<span class="edge-swatch relayed"></span>relayed link`;
    lg.append(rel);
  }
}

function kindColor(k) {
  return { member: "var(--good)", pending: "var(--warn)", stranger: "var(--serious)", revoked: "var(--critical)" }[k] || "var(--ink-3)";
}

/* ---------- details panel ---------- */

function renderDetails(d, ns) {
  const box = document.getElementById("details");
  box.innerHTML = "";
  if (state.selected === "self") return renderSelf(d, box);
  const n = ns.find(x => x.id === state.selected);
  if (!n) { box.innerHTML = `<p class="muted">Select a node in the graph.</p>`; return; }

  box.append(badge(n.kind));
  const kv = document.createElement("dl");
  kv.className = "kv";
  add(kv, "name", n.name || "—");
  if (n.ip) add(kv, "overlay IP", mono(n.ip.split("/")[0]));
  add(kv, "peer ID", mono(n.id));
  if (n.connected) {
    add(kv, "link", `${n.relayed ? "RELAYED" : "direct"} · ${n.transport || "?"} · ${n.direction === "inbound" ? "they dialed us" : "we dialed them"}`);
    add(kv, "address", mono(n.addr || "—"));
    if (n.rtt_ms) add(kv, "RTT", n.rtt_ms.toFixed(2) + " ms");
  }
  if (n.cert_expiry) {
    const days = Math.floor((new Date(n.cert_expiry) - Date.now()) / 86400000);
    const ddEl = add(kv, "cert expires", `${new Date(n.cert_expiry).toLocaleDateString()} (${days}d)`);
    if (days < 30) {
      const b = badge("pending"); b.className = "badge warn-soft"; b.textContent = "renew soon";
      ddEl.append(" ", b);
    }
  }
  box.append(kv);

  const pend = (d.pending || []).find(p => p.peer_id === n.id && p.status === "pending");
  if (pend) {
    const fp = document.createElement("div");
    fp.className = "fingerprint";
    fp.textContent = groupFp(pend.fingerprint);
    box.append(note("Compare this fingerprint with the joining device's screen before approving."), fp);
  }

  if (!d.master) {
    if (n.kind === "pending") box.append(note("Approvals happen on the master node."));
    return;
  }
  const actions = document.createElement("div");
  actions.className = "actions";
  if (pend) {
    actions.append(
      actionButton("Approve", "approve", () => openForm(box, "approve", pend.fingerprint, `admit “${pend.name}” to the namespace`)),
      actionButton("Deny", "quiet", () => doPost("/api/deny", { fingerprint: pend.fingerprint })),
    );
  } else if (n.kind === "member" || n.kind === "offline") {
    const m = (d.members || []).find(m => m.id === n.id);
    if (m) actions.append(actionButton("Revoke membership", "danger",
      () => openForm(box, "revoke", m.fingerprint, `cut “${m.name}” off the mesh immediately`)));
  }
  if (actions.childElementCount) box.append(actions);
}

function renderSelf(d, box) {
  box.append(badge("self"));
  const kv = document.createElement("dl");
  kv.className = "kv";
  add(kv, "name", d.status.name);
  add(kv, "role", d.status.master ? "master (holds the root key)" : "member");
  if (d.status.overlay_ip) {
    add(kv, "overlay IP", mono(d.status.overlay_ip.split("/")[0]));
    add(kv, "TUN bridge", d.status.tun_active ? "up (fabric0)" : "down — other transports still work");
    if (d.status.tun_active) add(kv, ".fabric DNS", d.status.dns_active ? "serving" : "not running");
  }
  add(kv, "peer ID", mono(d.status.peer_id));
  add(kv, "NAT", (d.status.reachability || "unknown").toLowerCase());
  for (const a of d.status.addrs || []) add(kv, "listen", mono(a));
  box.append(kv);
}

/* ---------- pending card ---------- */

function renderPending(d) {
  const card = document.getElementById("pending-card");
  const list = document.getElementById("pending");
  const pending = (d.pending || []).filter(p => p.status === "pending");
  card.hidden = !(d.status.master && pending.length);
  if (card.hidden) return;
  list.innerHTML = "";
  for (const p of pending) {
    const item = document.createElement("div");
    item.className = "pending-item";
    const head = document.createElement("div");
    head.append(badge("pending"), " ", strong(p.name));
    const fp = document.createElement("div");
    fp.className = "fingerprint";
    fp.textContent = groupFp(p.fingerprint);
    item.append(head, fp, note("requested " + new Date(p.received_at).toLocaleString()));
    if (d.master) {
      const actions = document.createElement("div");
      actions.className = "actions";
      actions.append(
        actionButton("Approve", "approve", () => openForm(item, "approve", p.fingerprint, `admit “${p.name}” to the namespace`)),
        actionButton("Deny", "quiet", () => doPost("/api/deny", { fingerprint: p.fingerprint })),
      );
      item.append(actions);
    }
    list.append(item);
  }
}

/* ---------- passphrase form ---------- */

function openForm(host, kind, fingerprint, what) {
  state.form = { kind, fingerprint };
  host.querySelectorAll("form.passform").forEach(f => f.remove());
  const form = document.createElement("form");
  form.className = "passform";
  form.innerHTML = `
    <div class="form-note">Root-key passphrase to ${what}. Signing happens in this UI process, never in the daemon.</div>
    <input type="password" name="pass" placeholder="namespace root key passphrase" autocomplete="off" required>
    <div class="form-error" hidden></div>
    <div class="actions">
      <button class="action ${kind === "revoke" ? "danger" : "approve"}" type="submit">${kind === "revoke" ? "Sign revocation" : "Sign certificate"}</button>
      <button class="action quiet" type="button" data-cancel>Cancel</button>
    </div>`;
  form.querySelector("[data-cancel]").onclick = () => { state.form = null; render(); };
  form.onsubmit = async (e) => {
    e.preventDefault();
    const errBox = form.querySelector(".form-error");
    errBox.hidden = true;
    try {
      await doPost(`/api/${kind}`, { fingerprint, passphrase: form.pass.value });
      state.form = null;
      render();
    } catch (err) {
      errBox.textContent = String(err.message || err);
      errBox.hidden = false;
    }
  };
  host.append(form);
  form.pass.focus();
}

async function doPost(url, body) {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error((await r.json()).error || r.statusText);
  await poll();
}

/* ---------- activity feed ---------- */

function renderFeed(d) {
  const feed = document.getElementById("feed");
  feed.innerHTML = "";
  const events = d.events || [];
  if (!events.length) {
    feed.innerHTML = `<li class="muted">No membership events yet.</li>`;
    return;
  }
  for (const e of events.slice(0, 30)) {
    const li = document.createElement("li");
    const added = e.kind === "member-added";
    li.append(
      dot(added ? "var(--good)" : "var(--critical)"),
      `${e.name || short(e.peer_id)} was ${added ? "admitted to" : "revoked from"} the namespace`,
    );
    const t = document.createElement("time");
    t.textContent = new Date(e.at).toLocaleString();
    li.append(t);
    feed.append(li);
  }
}

/* ---------- tiny helpers ---------- */

function el(tag, attrs, text) {
  const n = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  if (text !== undefined) n.textContent = text;
  return n;
}
function dot(color) {
  const s = document.createElement("span");
  s.className = "dot";
  s.style.background = color;
  return s;
}
function badge(kind) {
  const b = document.createElement("span");
  b.className = "badge " + (kind === "self" ? "member" : kind);
  b.append(dot(kindColor(kind === "self" ? "member" : kind)), KIND_LABEL[kind]);
  return b;
}
function add(kv, k, v) {
  const dt = document.createElement("dt");
  dt.textContent = k;
  const dd = document.createElement("dd");
  dd.append(v);
  kv.append(dt, dd);
  return dd;
}
function mono(s) {
  const c = document.createElement("code");
  c.className = "mono";
  c.textContent = s;
  c.title = "click to copy";
  c.style.cursor = "pointer";
  c.onclick = () => copy(s, c);
  return c;
}
function note(text) {
  const p = document.createElement("p");
  p.className = "muted";
  p.textContent = text;
  return p;
}
function strong(text) {
  const s = document.createElement("strong");
  s.textContent = text;
  return s;
}
function actionButton(label, cls, onclick) {
  const b = document.createElement("button");
  b.className = "action " + cls;
  b.textContent = label;
  b.onclick = onclick;
  return b;
}
function short(id) { return id ? id.slice(0, 8) + "…" + id.slice(-6) : "?"; }
function groupFp(fp) { return (fp.match(/.{1,4}/g) || [fp]).join(" "); }
async function copy(text, elem) {
  try {
    await navigator.clipboard.writeText(text);
    const old = elem.textContent;
    elem.textContent = "copied ✓";
    setTimeout(() => { elem.textContent = old; }, 900);
  } catch { /* clipboard unavailable over plain http on some setups */ }
}

/* ---------- go ---------- */

initTheme();
poll().then(() => {
  // deep-link: ?select=<name or peer id> opens that node's details
  const sel = new URLSearchParams(location.search).get("select");
  if (sel && state.data) {
    const n = nodes().find(n => n.name === sel || n.id === sel) ||
      (sel === state.data.status.name ? { id: "self" } : null);
    if (n) { state.selected = n.id; render(); }
  }
});
setInterval(() => { if (!state.form) poll(); }, POLL_MS);
