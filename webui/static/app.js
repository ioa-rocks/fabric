/* fabric topology UI. No build step, no dependencies: poll /api/overview,
   render an SVG star graph of this node's view of the mesh, and drive the
   admission/revocation lifecycle (signing happens server-side in the
   `fabric ui` process — the passphrase field here unlocks one operation). */

const POLL_MS = 3000;
const SVG = "http://www.w3.org/2000/svg";

const state = {
  data: null,       // last /api/overview payload
  circle: (() => { try { return localStorage.getItem("fabric-circle") || null; } catch { return null; } })(), // circle DID the tabs filter on; null = all
  selected: null,   // selected node id ('self' or peer id)
  form: null,       // {kind:'approve'|'deny'|'revoke', fp, error, busy}
  failing: false,
  bucketID: location.pathname.match(/^\/buckets\/([^/]+)\/?$/)?.[1] || null,
  bucketTitle: "Bucket",
  placementBusy: false,
  objectView: null, // retained page and in-flight request, independent of dashboard polls
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
  /* A bare worker kept on a listed gate by a verified grant chain: in no
     circle's roster, yet legitimately connected (memo §17 item 1). */
  if (p.grantee) return "grantee";
  const pend = pendingByID.get(p.id);
  if (pend && pend.status === "pending") return "pending";
  /* A lapsed member: cert ran out unrenewed. Not a member, but known by
     name — and once it re-joins, its pending request shows up here first. */
  if (p.expired) return "expired";
  return "stranger";
}

const KIND_LABEL = {
  self: "this node", member: "device", offline: "device (offline)",
  pending: "pending approval", stranger: "stranger", revoked: "revoked",
  expired: "expired — re-join needed", grantee: "grantee (no circle)",
};

/* ---------- roles ----------
   What a node is on the mesh, beyond "device": a gate in a circle (admitted
   to relay and host, never to sync or read), a lighthouse (takes join
   requests), a relay (carries traffic for devices that cannot reach each
   other), a bootstrap (this node dials it first). Roles per circle come
   from the admissions; lighthouse and relay from the protocols a connected
   peer serves. */

const ROLE_HELP = {
  master: "holds the root key: admits and revokes devices",
  gate: "a public hop: relays and hosts for the circle, syncs nothing and reads nothing",
  lighthouse: "takes join requests for the master to approve",
  relay: "carries traffic between devices that cannot reach each other directly",
  bootstrap: "this node dials it first and trusts it to judge its reachability",
};

/* Role of a node in one circle: "gate", "device", "owner"… or "". */
function roleIn(d, n, did) {
  if (n.kind === "self") return heldCircles(d).find(c => c.did === did)?.role || "";
  return (n.roles || {})[did] || "";
}

/* A gate everywhere it is admitted — no circle has it as a device. */
function isGate(d, n) {
  const roles = circlesOf(d, n).map(did => roleIn(d, n, did)).filter(Boolean);
  return roles.length > 0 && roles.every(role => role === "gate");
}

/* Short tags for the graph caption and the details panel. */
function roleTags(d, n) {
  const tags = [];
  if (n.kind === "self") {
    if (d.status.master) tags.push("master");
    if (isGate(d, n)) tags.push("gate");
    if (d.status.queue_host) tags.push("lighthouse");
    return tags;
  }
  if (isGate(d, n)) tags.push("gate");
  else if (Object.values(n.roles || {}).includes("gate")) tags.push("gate in " + Object.entries(n.roles).filter(([, role]) => role === "gate").map(([did]) => circleName(d, did)).join(", "));
  if (n.queue_host) tags.push("lighthouse");
  if (n.relay) tags.push("relay");
  if (n.bootstrap) tags.push("bootstrap");
  return tags;
}

function roleChips(tags) {
  const wrap = document.createElement("span");
  for (const tag of tags) {
    const chip = document.createElement("span");
    chip.className = "role-chip";
    chip.textContent = tag;
    chip.title = ROLE_HELP[tag.split(" ")[0]] || "";
    wrap.append(chip);
  }
  return wrap;
}

/* ---------- circles ----------
   A circle's colour derives from its DID, so every node of the fleet paints
   the same circle the same way; its name is this node's own label for it
   (status.circles), the short DID when this node holds no such circle. A
   peer carries exactly the circles it verifiably shares with this node —
   nothing else is known here, by construction. */

function circleColor(did) {
  let h = 0;
  for (let i = 0; i < did.length; i++) h = (h * 31 + did.charCodeAt(i)) >>> 0;
  return `hsl(${h % 360} 62% 46%)`;
}
function heldCircles(d) { return (d.status && d.status.circles) || []; }
function circleName(d, did) {
  const c = heldCircles(d).find(c => c.did === did);
  return c ? c.name : short(did);
}
/* Circles a peer shares with this node; self holds everything listed. */
function circlesOf(d, n) {
  if (n.kind === "self") return heldCircles(d).map(c => c.did);
  return n.circles || [];
}
function inSelected(d, n) {
  return !state.circle || circlesOf(d, n).includes(state.circle);
}
function sharedBetween(d, a, b) {
  const ca = circlesOf(d, a), cb = new Set(circlesOf(d, b));
  return ca.filter(c => cb.has(c));
}

function renderTabs(d) {
  const box = document.getElementById("circle-tabs");
  box.innerHTML = "";
  const circles = heldCircles(d);
  if (!circles.length) { box.hidden = true; return; }
  box.hidden = false;
  if (state.circle && !circles.some(c => c.did === state.circle)) state.circle = null;
  const mk = (label, did, role, color) => {
    const b = document.createElement("button");
    b.type = "button";
    b.setAttribute("role", "tab");
    b.setAttribute("aria-selected", String((did || null) === state.circle));
    if (color) b.append(dot(color));
    b.append(label);
    if (role) { const r = document.createElement("span"); r.className = "tab-role"; r.textContent = role; b.append(r); }
    b.onclick = () => {
      state.circle = did || null;
      try { did ? localStorage.setItem("fabric-circle", did) : localStorage.removeItem("fabric-circle"); } catch {}
      render();
    };
    return b;
  };
  box.append(mk("All", null));
  for (const c of circles) {
    const title = `${c.did}${c.prefix ? " · overlay " + c.prefix : ""} · ${c.devices || 0} other device${c.devices === 1 ? "" : "s"} known`;
    const b = mk(c.name, c.did, c.role, circleColor(c.did));
    b.title = title;
    box.append(b);
  }
}

/* ---------- sections ----------
   One page per plane: the mesh (topology, admission, activity), the vault
   and astral. The choice lives in the URL fragment, so it survives a reload
   and the bucket pages can link back to "/#vault". */

const SECTIONS = [["mesh", "Mesh"], ["vault", "Vault"], ["astral", "Astral"]];

function sectionOf(d) {
  const available = { mesh: true, vault: !!d.vault, astral: !!d.astral };
  const wanted = location.hash.slice(1);
  return available[wanted] ? wanted : "mesh";
}

function renderSections(d, ns) {
  const current = sectionOf(d);
  const pending = d.status.master ? (d.pending || []).filter(p => p.status === "pending").length : 0;
  const devices = ns.filter(n => n.kind === "member" || n.kind === "offline").length + 1;
  const counts = {
    mesh: `${devices} device${devices === 1 ? "" : "s"}`,
    vault: d.vault ? `${(d.vault.buckets || []).length} bucket${(d.vault.buckets || []).length === 1 ? "" : "s"}` : "",
    astral: d.astral ? `${((d.astral.status || {}).hosted || []).length} hosted` : "",
  };
  const box = document.getElementById("section-tabs");
  box.replaceChildren();
  for (const [key, label] of SECTIONS) {
    document.getElementById("section-" + key).hidden = key !== current;
    if (key !== "mesh" && !d[key]) continue;
    const tab = document.createElement("button");
    tab.type = "button";
    tab.setAttribute("role", "tab");
    tab.setAttribute("aria-selected", String(key === current));
    tab.append(label);
    const count = document.createElement("span");
    count.className = "section-count";
    count.textContent = counts[key];
    tab.append(count);
    if (key === "mesh" && pending) {
      const alert = document.createElement("span");
      alert.className = "section-alert";
      alert.textContent = `${pending} pending`;
      tab.append(alert);
    }
    tab.onclick = () => { location.hash = key; };
    box.append(tab);
  }
  box.hidden = box.childElementCount < 2;
}

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
  renderHeader(d);
  if (state.bucketID) {
    renderBucketPage(d);
    if (!state.form || state.form.host !== "expiry") renderExpiryBanner(d);
    return;
  }
  const ns = nodes();
  if (!state.form || state.form.host !== "expiry") renderExpiryBanner(d);
  renderTabs(d);
  renderSections(d, ns);
  // Revoked peers never connect again — they are tombstones, not topology.
  // The graph shows the live mesh; they get their own list until they GC.
  const live = ns.filter(n => n.kind !== "revoked");
  renderGraph(d, live);
  renderLegend(d, live);
  renderRevoked(ns.filter(n => n.kind === "revoked"));
  if (!state.form) {         // don't repaint under an open passphrase form
    renderDetails(d, ns);
    renderPending(d);
  }
  renderVault(d);
  renderAstral(d);
  renderFeed(d);
}

/* ---------- certificate-expiry banner ----------
   Spec §5 renewal tiers, made impossible to miss: anything expired or
   expiring within 30 days raises a red banner across the top of every
   node's UI (critical); 30–90 days a softer one. Expiry is silent
   otherwise — a lapsed device drops off the mesh and can't take its
   renewal any more — so this is the alarm, not the node card's badge. */

const EXPIRY_LOUD_DAYS = 30, EXPIRY_SOFT_DAYS = 90;

function renderExpiryBanner(d) {
  const el = document.getElementById("expiry-banner");
  el.innerHTML = "";
  el.className = "banner expiry";
  const items = [];
  for (const m of d.members || []) {
    if (!m.expiry) continue;
    const days = Math.floor((new Date(m.expiry) - Date.now()) / 86400000);
    if (m.expired || days < 0) items.push({ m, days, tier: "expired" });
    else if (days < EXPIRY_LOUD_DAYS) items.push({ m, days, tier: "loud" });
    else if (days < EXPIRY_SOFT_DAYS) items.push({ m, days, tier: "soft" });
  }
  const loud = items.some(i => i.tier !== "soft");
  el.hidden = !items.length;
  document.title = (loud ? "⚠ certs expiring — " : "") + "fabric — " + (state.bucketID ? state.bucketTitle : "topology");
  if (el.hidden) return;
  el.classList.add(loud ? "critical" : "soft");
  items.sort((a, b) => a.days - b.days);

  const h = document.createElement("h3");
  h.textContent = loud ? "⚠ Certificates need attention now" : "Certificates due for renewal";
  el.append(h);
  const ul = document.createElement("ul");
  for (const { m, days, tier } of items) {
    const li = document.createElement("li");
    const who = m.self ? `${m.name} (this node)` : m.name;
    if (tier === "expired") {
      li.append(strong(who), ` — expired ${-days} day${-days === 1 ? "" : "s"} ago. It is off the mesh and a renewal can't reach it: run \`fabric join\` on that device (it keeps its name and address).`);
    } else {
      li.append(strong(who), ` — expires in ${days} day${days === 1 ? "" : "s"} (${new Date(m.expiry).toLocaleDateString()}).`);
      if (d.master) li.append(actionButton("Renew now", "approve",
        () => openForm(el, "renew", m.fingerprint, `re-sign “${m.name}”’s cert with a fresh validity window`, "expiry")));
    }
    ul.append(li);
  }
  el.append(ul);
  el.append(note(d.master
    ? "Renewal re-signs the same cert (name, address, scope unchanged) and reaches the device over the mesh — no restart. CLI: fabric renew -expiring"
    : "Renewals are signed on the master node: run `fabric renew -expiring` there, or use its UI."));
}

/* ---------- astral coordination card ---------- */

function renderAstral(d) {
  const card = document.getElementById("astral-card");
  card.hidden = !d.astral;
  if (card.hidden) return;

  const a = d.astral.status || {};
  const inCircle = ref => !state.circle || !ref || !ref.circle || ref.circle === state.circle;
  const hosted = (a.hosted || []).filter(inCircle);
  const placedAll = (a.placements || []).filter(inCircle);
  const placed = state.circle
    ? placedAll.map(p => [p.name, hostLabel(d, p.host)]).sort((x, y) => x[0].localeCompare(y[0]))
    : Object.entries(a.placed || {}).sort((x, y) => x[0].localeCompare(y[0]));
  const claims = (a.claims || []).filter(inCircle);
  const monitors = a.monitors || [];
  const pending = hosted.reduce((n, h) => n + (h.pending || 0), 0);
  document.getElementById("astral-summary").textContent =
    `${hosted.length} hosted · ${placed.length} remote · ${pending} pending · ${claims.length} claimed`;
  document.getElementById("astral-security").textContent =
    `Authorization: ${d.astral.capability}. Subject ACLs and client keys are the next security slice.`;

  const box = document.getElementById("astral");
  box.innerHTML = "";
  const grid = document.createElement("div");
  grid.className = "astral-grid";
  grid.append(
    astralPanel("Hosted here", hostedTable(hosted)),
    astralPanel("Placed on peers", placedTable(placed)),
    astralPanel("Active claims", claimsTable(claims)),
    astralPanel("Monitors", monitorsTable(monitors)),
  );
  box.append(grid);
  if (a.outbox) box.append(planeAlert(`${a.outbox} cast${a.outbox === 1 ? " is" : "s are"} parked in the offline outbox.`));
}

function astralPanel(title, content) {
  const panel = document.createElement("section");
  panel.className = "astral-panel";
  const h = document.createElement("h3");
  h.textContent = title;
  panel.append(h, content);
  return panel;
}

function operatorTable(headers, rows, empty) {
  if (!rows.length) return note(empty);
  const table = document.createElement("table");
  table.className = "operator-table";
  const head = document.createElement("tr");
  for (const label of headers) { const th = document.createElement("th"); th.textContent = label; head.append(th); }
  table.append(head);
  for (const cells of rows) {
    const tr = document.createElement("tr");
    for (const value of cells) tr.append(td(value));
    table.append(tr);
  }
  return table;
}

function hostedTable(hosted) {
  const d = state.data;
  return operatorTable(["name", "circle", "delivery", "pending", "accepts"], hosted.map(h => {
    const c = document.createElement("span");
    if (h.circle) c.append(dot(circleColor(h.circle)), " ", circleName(d, h.circle));
    return [mono(h.name), c, h.delivery || "exclusive", String(h.pending || 0), (h.accepts || []).join(", ") || "any kind"];
  }), state.circle ? `No subjects of ${circleName(d, state.circle)} are hosted on this node.` : "No subjects are hosted on this node.");
}

/* A placement host is a peer ID; name it from the roster when known. */
function hostLabel(d, host) {
  const p = (d.status.peers || []).find(p => p.id === host);
  return p && p.name ? p.name : short(host);
}

function placedTable(placed) {
  return operatorTable(["name", "host"], placed.map(([name, host]) => [mono(name), host]),
    "No remote placements discovered.");
}

function claimsTable(claims) {
  return operatorTable(["name", "consumer", "lease until"], claims.map(c => [
    mono(c.name), c.consumer, nanosDate(c.until),
  ]), "No events are currently leased to consumers.");
}

function monitorsTable(monitors) {
  return operatorTable(["entity", "generation", "lease"], monitors.map(m => {
    const expired = Number(m.until) / 1e6 < Date.now();
    return [mono(m.entity), String(m.gen), expired ? "lapsed" : nanosDate(m.until)];
  }), "No heartbeat monitors are registered.");
}

function nanosDate(ns) {
  return new Date(Number(ns) / 1e6).toLocaleTimeString();
}

function planeAlert(text) {
  const p = document.createElement("p");
  p.className = "plane-alert";
  p.textContent = text;
  return p;
}

/* ---------- vault card ---------- */

/* Buckets against devices: one row per bucket, one column per device, each
   cell that device's placement. This device's column comes from its own
   store; the others are what each peer last answered on /vault/place/1 —
   unsigned, for the operator's eye only. Links open the bucket pages; this
   view never loads file listings. */

const PLACE_HELP = {
  full: "keeps every file of the bucket",
  folder: "a folder on disk that mirrors the bucket; keeps every file",
  cache: "keeps what was read here; with a budget, drops the least recently read",
  none: "the list of files only; content is fetched when asked for",
};

function placementKind(mode, folder) {
  return folder ? "folder" : (mode || "none");
}

function placementPill(mode, folder, keep) {
  const kind = placementKind(mode, folder);
  const pill = document.createElement("span");
  pill.className = "place " + kind;
  pill.textContent = kind + (kind === "cache" && keep ? " · " + bytes(keep) : "");
  pill.title = PLACE_HELP[kind] || "";
  return pill;
}

/* One device's cell: placement, how much of the bucket is there, and for
   this device what the last eviction pass found. */
function placementCell(place) {
  const cell = document.createElement("td");
  cell.className = "place-cell";
  cell.append(placementPill(place.mode, place.folder, place.keep));
  const held = document.createElement("div");
  held.className = "place-held";
  held.textContent = `${place.held}/${place.files} held`;
  if (placementKind(place.mode, place.folder) !== "cache" && placementKind(place.mode, place.folder) !== "none") {
    held.classList.add(place.held >= place.files ? "held-ok" : "held-lag");
    if (place.held < place.files) held.textContent += " · fetching";
  }
  cell.append(held);
  for (const [text, warn] of place.notes || []) {
    const line = document.createElement("div");
    line.className = "place-held" + (warn ? " held-lag" : "");
    line.textContent = text;
    cell.append(line);
  }
  if (place.stale) cell.classList.add("stale");
  return cell;
}

function ownPlacement(b) {
  const notes = [];
  if (b.sub === "cache" && b.keep) {
    if (b.cache_bytes) notes.push([`${bytes(b.cache_bytes)} of ${bytes(b.keep)} used`, b.cache_bytes > b.keep]);
    if (b.cache_unconfirmed) notes.push([`${b.cache_unconfirmed} over budget kept: no full copy confirmed`, true]);
  }
  return { mode: b.sub, folder: !!b.folder, keep: b.keep, held: b.held, files: b.files, notes };
}

function peerPlacement(p) {
  const notes = p.connected ? [] : [["offline · as of " + new Date(p.at / 1e6).toLocaleTimeString(), false]];
  return { mode: p.mode, folder: p.folder, keep: p.keep, held: p.held, files: p.files, notes, stale: !p.connected };
}

/* The other devices to show: every one that answered for a visible bucket,
   and vault peers sharing a circle that did not answer (an older release). */
function placementColumns(vs, buckets) {
  const columns = new Map();
  for (const b of buckets) for (const p of b.peers || []) {
    columns.set(p.peer_id, { id: p.peer_id, name: p.name || short(p.peer_id), answered: true });
  }
  for (const p of vs.peers || []) {
    if (p.vault && (p.shared || []).length && !columns.has(p.peer_id)) {
      columns.set(p.peer_id, { id: p.peer_id, name: p.name || short(p.peer_id), answered: false });
    }
  }
  return [...columns.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function renderVault(d) {
  const card = document.getElementById("vault-card");
  card.hidden = !d.vault;
  if (card.hidden) { closeObjects(); return; }
  const vs = d.vault.status || {};
  const buckets = d.vault.buckets || [];

  /* Declared mounts (ADR 0016): daemon-owned, listed with their live state. */
  const mounts = vs.mounts || [];
  const mbox = document.getElementById("vault-mounts");
  mbox.replaceChildren();
  for (const m of mounts) {
    const line = document.createElement("div");
    const live = m.error ? `error: ${m.error}` : (m.mounted ? "mounted" : "not mounted — daemon retries");
    line.append(mono(m.dir), ` ${m.write ? "rw" : "ro"} · ${m.name || short(m.bucket)} — ${live}`);
    mbox.append(line);
  }
  document.getElementById("vault-mounts-card").hidden = !mounts.length;

  const box = document.getElementById("vault-buckets");
  const legend = document.getElementById("vault-legend");
  box.innerHTML = "";
  legend.replaceChildren();
  legend.hidden = true;
  const summary = document.getElementById("vault-summary");
  summary.textContent = `${buckets.length} bucket${buckets.length === 1 ? "" : "s"}`;
  if (!buckets.length) {
    box.append(note("No buckets yet — create one with: vault bucket create <name>"));
    return;
  }
  const visible = state.circle ? buckets.filter(b => b.owner === state.circle) : buckets;
  if (!visible.length) {
    box.append(note(`No buckets owned by ${circleName(d, state.circle)}.`));
    return;
  }
  const columns = placementColumns(vs, visible);
  const silent = columns.filter(c => !c.answered);
  summary.textContent += columns.length
    ? ` · ${columns.length} other device${columns.length === 1 ? "" : "s"}`
    : " · no other vault device connected";

  const table = document.createElement("table");
  table.className = "buckets placements";
  const head = document.createElement("tr");
  const th = (text, cls, title) => {
    const cell = document.createElement("th");
    cell.textContent = text;
    if (cls) cell.className = cls;
    if (title) cell.title = title;
    head.append(cell);
  };
  th("bucket"); th("circle"); th("files");
  th("full copies", "", "devices known to keep every file of the bucket");
  th(`${d.status.name || "this device"} (here)`, "device own");
  for (const column of columns) th(column.name, "device", column.id);
  table.append(head);

  for (const b of visible) {
    const tr = document.createElement("tr");
    tr.className = "bucket-row";
    const link = document.createElement("a");
    link.href = "/buckets/" + encodeURIComponent(b.id);
    link.className = "bucket-link";
    link.textContent = b.name;
    const circleCell = document.createElement("td");
    if (b.owner) circleCell.append(dot(circleColor(b.owner)), " ");
    circleCell.append((vs.circles || []).find(c => c.did === b.owner)?.name || circleName(d, b.owner || "") || "Unknown");

    const byPeer = new Map((b.peers || []).map(p => [p.peer_id, p]));
    const full = (b.sub === "full" || b.folder ? 1 : 0) + (b.peers || []).filter(p => p.mode === "full" || p.folder).length;
    const copies = document.createElement("td");
    copies.textContent = full + (silent.length ? " + ?" : "");
    copies.className = full ? "held-ok" : "held-lag";
    copies.title = full
      ? "devices that said they keep every file" + (silent.length ? "; some devices did not say" : "")
      : (silent.length ? "no device said it keeps every file; some did not say" : "no device keeps every file: a cache cannot drop anything, and nothing guarantees a copy");

    const fileCount = td(String(b.files));
    fileCount.title = b.objects === b.files ? "" : `${b.objects} entries in all: ${b.objects - b.files} are directories or links, which have no content to hold`;
    tr.append(td(link), circleCell, fileCount, copies);
    const own = placementCell(ownPlacement(b));
    own.classList.add("own");
    tr.append(own);
    for (const column of columns) {
      const answer = byPeer.get(column.id);
      if (answer) { tr.append(placementCell(peerPlacement(answer))); continue; }
      const cell = document.createElement("td");
      cell.className = "place-cell unknown";
      cell.textContent = column.answered ? "—" : "?";
      cell.title = column.answered
        ? "this device does not have the bucket"
        : "this device did not say: it runs a release that cannot be asked";
      tr.append(cell);
    }
    table.append(tr);
  }
  const scroll = document.createElement("div");
  scroll.className = "table-scroll";
  scroll.append(table);
  box.append(scroll);

  /* What the last read-back of held content found (scrub). */
  const scrub = vs.scrub || {};
  if (scrub.quarantined) box.append(planeAlert(
    `${scrub.quarantined} damaged file${scrub.quarantined === 1 ? " is" : "s are"} set aside on this device and not yet replaced by a clean copy from another device.`));
  if (scrub.folder_files) box.append(planeAlert(
    `${scrub.folder_files} file${scrub.folder_files === 1 ? "" : "s"} in a synced folder changed without size or time changing — run: fabric bucket scrub`));

  legend.hidden = false;
  for (const kind of ["full", "folder", "cache", "none"]) {
    const item = document.createElement("span");
    item.append(placementPill(kind === "folder" ? "full" : (kind === "none" ? "" : kind), kind === "folder"), " " + PLACE_HELP[kind]);
    legend.append(item);
  }
  if (silent.length) {
    const item = document.createElement("span");
    item.textContent = `? ${silent.map(c => c.name).join(", ")} did not say — an older release`;
    legend.append(item);
  }
}

function bytes(n) {
  return n ? formatBytes(n) : "0 B";
}

function td(child) {
  const c = document.createElement("td");
  c.append(child);
  return c;
}

// A dedicated detail view uses the existing overview data for metadata and
// only fetches files on entry or explicit navigation. Ordinary links provide
// bookmarking, reload, browser history and opening a bucket in another tab.
function renderBucketPage(d) {
  const b = (d.vault?.buckets || []).find(b => b.id === state.bucketID);
  const message = document.getElementById("bucket-message");
  document.getElementById("bucket-content").hidden = !b;
  message.hidden = !!b;
  state.bucketTitle = b?.name || "Bucket unavailable";
  document.getElementById("bucket-title").textContent = state.bucketTitle;
  document.getElementById("bucket-crumb").textContent = b?.name || "Bucket";
  if (!b) {
    message.textContent = d.vault ? "This bucket is not available on this device." : "Vault is not available on this device.";
    closeObjects();
    return;
  }
  document.getElementById("bucket-subtitle").textContent = "Details from " + (d.status.name || "this device");
  const vs = d.vault.status || {};
  const owner = (vs.circles || []).find(c => c.did === b.owner);
  const overview = document.createElement("dl");
  overview.className = "kv";
  const field = (dl, label, value) => {
    const dt = document.createElement("dt"), dd = document.createElement("dd");
    dt.textContent = label;
    dd.append(value);
    dl.append(dt, dd);
  };
  field(overview, "Circle", owner?.name || b.owner || "Unknown");
  field(overview, "Files", String(b.files));
  if (b.objects !== b.files) field(overview, "Directories and links", String(b.objects - b.files));
  field(overview, "Files held on this device", `${b.held} / ${b.files}`);
  field(overview, "Conflicts", String(b.conflicts || 0));
  field(overview, "Held deletions", String(b.held_deletions || 0));
  field(overview, "Bucket ID", mono(b.id));
  document.getElementById("bucket-overview").replaceChildren(overview);

  const local = document.createElement("dl");
  local.className = "kv";
  if (b.folder) {
    field(local, "Placement", "Folder replica");
    field(local, "Folder", mono(b.folder));
  } else {
    const select = document.createElement("select");
    select.setAttribute("aria-label", "Placement on this device");
    for (const mode of ["none", "cache", "full"]) {
      const option = document.createElement("option");
      option.value = mode; option.textContent = mode;
      option.selected = (b.sub || "none") === mode;
      select.append(option);
    }
    select.onchange = async () => {
      select.disabled = true;
      state.placementBusy = true;
      try { await doPost("/api/vault/sub", { bucket: b.id, mode: select.value }); }
      catch (err) { alert("Placement: " + (err.message || err)); }
      finally { state.placementBusy = false; select.disabled = false; select.blur(); renderBucketPage(state.data); }
    };
    field(local, "Placement", select);
    if (b.sub === "cache") {
      field(local, "Budget", b.keep ? bytes(b.keep) : "None — nothing is dropped");
      if (b.keep && b.cache_bytes) field(local, "Used", `${bytes(b.cache_bytes)} of ${bytes(b.keep)}`);
      if (b.cache_unconfirmed) field(local, "Over budget", `${b.cache_unconfirmed} files kept: no device holding the bucket in full confirmed them`);
      if (!b.keep) local.append(note(`Set one with: fabric bucket place ${b.name} cache -keep 20G`));
    }
    field(local, "Storage", b.root ? mono(b.root) : "Default store");
  }
  const folder = (vs.folders || []).find(f => f.bucket === b.id);
  if (folder) {
    field(local, "Folder status", folder.error || (folder.available ? "Available" : "Unavailable"));
    field(local, "Pending upload", String(folder.pending_up));
    field(local, "Pending download", String(folder.pending_down));
    field(local, "Last scan", folder.last_scan ? new Date(folder.last_scan / 1e6).toLocaleString() : "Not scanned yet");
    field(local, "Excluded repositories", String(folder.excluded_repos || 0));
    field(local, "Ignored entries", String(folder.ignored || 0));
  }
  for (const m of (vs.mounts || []).filter(m => m.bucket === b.id)) {
    field(local, "Mount", mono(m.dir));
    field(local, "Mount status", m.error || `${m.mounted ? "Mounted" : "Waiting to mount"} · ${m.write ? "read/write" : "read-only"}`);
  }
  const others = document.getElementById("bucket-peers");
  others.replaceChildren();
  if (!(b.peers || []).length) {
    others.append(note("No other device has said how it holds this bucket. A device answers once it is connected and runs a current release."));
  } else {
    const table = document.createElement("table");
    table.className = "buckets placements";
    table.innerHTML = "<tr><th>device</th><th>placement</th></tr>";
    for (const p of b.peers) {
      const tr = document.createElement("tr");
      tr.append(td(p.name || short(p.peer_id)), placementCell(peerPlacement(p)));
      table.append(tr);
    }
    others.append(table);
  }
  const localBox = document.getElementById("bucket-local");
  if (!state.placementBusy && !localBox.contains(document.activeElement)) localBox.replaceChildren(local);
  if (state.objectView?.bucket !== b.id) openObjects(b);
}

function closeObjects() {
  state.objectView?.controller?.abort();
  state.objectView?.row.remove();
  state.objectView = null;
}

function openObjects(b) {
  closeObjects();
  const row = document.createElement("div");
  row.className = "object-browser";
  const list = document.createElement("ul");
  list.className = "objects-list";
  const controls = document.createElement("div");
  controls.className = "objects-controls";
  const label = document.createElement("span");
  label.setAttribute("role", "status");
  const button = (text, click) => {
    const el = document.createElement("button");
    el.type = "button";
    el.textContent = text;
    el.onclick = click;
    return el;
  };
  const view = { bucket: b.id, row, list, label, after: "", history: [], next: "" };
  view.previous = button("Previous", () => loadObjects(view, view.history.at(-1), view.history.slice(0, -1)));
  view.forward = button("Next", () => loadObjects(view, view.next, [...view.history, view.after]));
  view.refresh = button("Refresh", () => loadObjects(view, "", []));
  controls.append(view.previous, view.forward, view.refresh, label);
  row.append(controls, list);
  document.getElementById("bucket-files").append(row);
  state.objectView = view;
  loadObjects(view, "", []);
}

const MEDIA_EXT = {
  image: ["jpg", "jpeg", "png", "gif", "webp", "avif", "bmp"],
  video: ["mp4", "m4v", "webm", "mov", "mkv"],
  audio: ["mp3", "m4a", "ogg", "opus", "flac", "wav"],
};

function mediaKind(name) {
  const ext = name.includes(".") ? name.split(".").pop().toLowerCase() : "";
  return Object.keys(MEDIA_EXT).find(kind => MEDIA_EXT[kind].includes(ext)) || "";
}

function formatBytes(n) {
  if (!n) return "";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i && n < 10 ? n.toFixed(1) : Math.round(n)) + " " + units[i];
}

// One preview per row; clicking the name again closes it. Removing the
// element ends the download of a video that is still buffering.
function togglePreview(li, media, src, name) {
  const open = li.querySelector(".object-preview");
  if (open) { open.remove(); return; }
  const el = document.createElement(media === "image" ? "img" : media);
  el.className = "object-preview";
  el.src = src;
  if (media === "image") {
    el.alt = name;
    el.loading = "lazy";
  } else {
    el.controls = true;
    el.preload = "metadata";
  }
  li.append(el);
}

async function loadObjects(view, after, history) {
  view.controller?.abort();
  const controller = new AbortController();
  view.controller = controller;
  view.previous.disabled = view.forward.disabled = view.refresh.disabled = true;
  view.label.textContent = "Loading…";
  try {
    const query = new URLSearchParams({ bucket: view.bucket, after });
    const r = await fetch("/api/vault/objects?" + query, { signal: controller.signal });
    if (!r.ok) throw new Error((await r.json()).error || r.statusText);
    const page = await r.json();
    if (state.objectView !== view || view.controller !== controller) return;
    view.after = after;
    view.history = history;
    view.next = page.next || "";
    view.list.replaceChildren();
    for (const o of page.objects) {
      const li = document.createElement("li");
      li.append(mono(o.id.slice(0, 12)), " ");
      const kind = o.kind || "file";
      if (kind !== "file" || !o.blob) {
        li.append(o.name + (kind === "dir" ? "/" : ""));
      } else {
        const src = "/api/vault/content?" + new URLSearchParams({ bucket: view.bucket, ref: o.id });
        const link = document.createElement("a");
        link.href = src;
        link.textContent = o.name;
        const media = mediaKind(o.name);
        // Media opens in place (the server sends ranges, so video seeks);
        // anything else the server hands over as a download.
        if (media) link.onclick = event => { event.preventDefault(); togglePreview(li, media, src, o.name); };
        const size = document.createElement("span");
        size.className = "tags";
        size.textContent = "  " + formatBytes(o.size);
        li.append(link, size);
      }
      if (o.tags && o.tags.length) {
        const t = document.createElement("span");
        t.className = "tags";
        t.textContent = "  [" + o.tags.join(" ") + "]";
        li.append(t);
      }
      view.list.append(li);
    }
    view.label.textContent = page.objects.length
      ? `Page ${history.length + 1} · ${page.objects.length} objects · refresh to see changes`
      : (view.next ? "No live objects in this page — continue with Next" : "No more objects");
  } catch (err) {
    if (err.name !== "AbortError" && state.objectView === view && view.controller === controller) {
      view.label.textContent = "Could not load files: " + (err.message || err);
    }
  } finally {
    if (state.objectView === view && view.controller === controller) {
      view.previous.disabled = !view.history.length;
      view.forward.disabled = !view.next;
      view.refresh.disabled = false;
    }
  }
}

function renderHeader(d) {
  const nsChip = document.getElementById("ns-chip");
  const held = heldCircles(d);
  nsChip.textContent = held.length ? held.map(c => c.name).join(" · ") : d.status.namespace_did;
  nsChip.title = held.length ? "circles this node holds (click to copy the first circle's DID)" : "namespace DID (click to copy)";
  nsChip.onclick = () => copy(held.length ? held[0].did : d.status.namespace_did, nsChip);

  const selfChip = document.getElementById("self-chip");
  selfChip.innerHTML = "";
  const role = roleTags(d, { kind: "self" }).join(" · ") || "device";
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

  // Everyone on one ring, self included — with self at the center, a
  // chord between opposite nodes would run straight through it.
  const all = [
    { id: d.status.peer_id, name: d.status.name, kind: "self", ip: d.status.overlay_ip, rad: 28 },
    ...ns.map(n => ({ ...n, rad: 24 })),
  ];
  const ringR = all.length === 1 ? 0 : r;
  const pos = {};
  all.forEach((n, i) => {
    const [x, y] = ringPos(i, all.length, cx, cy, ringR);
    pos[n.id] = [x, y, n.rad];
  });

  // Links: the aggregated whole-mesh view when available (every member
  // reports its own connections), else fall back to this node's links.
  let links = (d.links || []).filter(l => pos[l.a] && pos[l.b]);
  if (!links.length) {
    links = ns.filter(n => n.connected).map(n => ({
      a: d.status.peer_id, b: n.id, rtt_ms: n.rtt_ms, transport: n.transport, relayed: n.relayed,
    }));
  }

  // The circle tab filters: nodes outside the chosen circle are dimmed,
  // edges with an end outside it are not drawn (an edge is one connection;
  // the circles belong to its endpoints).
  const byID = Object.fromEntries(all.map(n => [n.id, n]));
  const shown = n => inSelected(d, n);
  if (state.circle) links = links.filter(l => shown(byID[l.a]) && shown(byID[l.b]));

  const summary = document.getElementById("graph-summary");
  const devices = ns.filter(n => (n.kind === "member" || n.kind === "offline") && shown(n)).length + 1;
  summary.textContent = (state.circle ? `${circleName(d, state.circle)}: ` : "") +
    `${devices} device${devices === 1 ? "" : "s"} · ${links.length} link${links.length === 1 ? "" : "s"} up`;

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
    // Shared circles on the label, not the line: two peers often share
    // several, and only what this node knows of each end is shown.
    const shared = byID[l.a] && byID[l.b] ? sharedBetween(d, byID[l.a], byID[l.b]) : [];
    if (shared.length) parts.push(shared.map(c => circleName(d, c)).join("+"));
    if (parts.length) {
      // near-vertical edges get the label fully beside the line; otherwise
      // it sits above the midpoint, pushed out along the perpendicular
      const vertical = Math.abs(uy) > 0.7;
      const mx = (x1 + x2) / 2 - (vertical ? 8 : uy * 24);
      const my = (y1 + y2) / 2 + (vertical ? 4 : ux * 24 + 4);
      svg.append(el("text", { x: mx, y: my, "text-anchor": vertical ? "end" : "middle", class: "edge-label" }, parts.join(" · ")));
    }
  }

  for (const n of all) {
    const [x, y, rad] = pos[n.id];
    drawNode(svg, x, y, n.kind === "self" ? { ...n, id: "self" } : n, rad, d, shown(n));
  }
}

function ringPos(i, n, cx, cy, r) {
  const a = (i / Math.max(n, 1)) * 2 * Math.PI - Math.PI / 2;
  return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
}

function drawNode(svg, x, y, n, radius, d, shown = true) {
  const g = el("g", { class: `node ${n.kind}` + (state.selected === n.id ? " selected" : "") + (shown ? "" : " dim") });
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
  // Circle badges: one dot per circle this node shares with the peer (all
  // held circles on self), along the upper arc, coloured by DID.
  const circles = d ? circlesOf(d, n).slice().sort() : [];
  circles.forEach((did, i) => {
    const a = -Math.PI / 2 + (i - (circles.length - 1) / 2) * 0.55;
    const dotEl = el("circle", {
      class: "circle-dot", cx: x + Math.cos(a) * (radius + 1), cy: y + Math.sin(a) * (radius + 1), r: 4.5,
      fill: circleColor(did),
    });
    const title = el("title", {}, `${circleName(d, did)} — ${did}`);
    dotEl.append(title);
    g.append(dotEl);
  });
  g.append(el("text", { x, y: y + radius + 16, "text-anchor": "middle" }, n.name || short(n.id)));
  const gate = d && isGate(d, n) && (n.kind === "member" || n.kind === "offline");
  const kindLabel = gate ? (n.kind === "offline" ? "gate (offline)" : "gate") : KIND_LABEL[n.kind];
  let sub = n.ip ? `${n.ip.split("/")[0]} · ${kindLabel}` : kindLabel;
  if (n.addr_conflict) sub += " · ADDRESS CONFLICT";
  g.append(el("text", { x, y: y + radius + 30, "text-anchor": "middle", class: "sub" }, sub));
  const tags = d ? roleTags(d, n).filter(tag => tag !== "gate") : [];
  if (tags.length) g.append(el("text", { x, y: y + radius + 43, "text-anchor": "middle", class: "sub roles" }, tags.join(" · ")));
  if (gate) g.classList.add("gate");
  g.onclick = () => {
    state.selected = n.id;
    state.form = null;
    const ns = nodes();
    renderDetails(state.data, ns);
    renderGraph(state.data, ns.filter(x => x.kind !== "revoked"));
  };
  svg.append(g);
}

function renderLegend(d, ns) {
  const kinds = ["member", "pending", "offline", "expired", "revoked", "stranger", "grantee"];
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
    if (k === "grantee") sw.style.borderStyle = "dotted";
    s.append(sw, KIND_LABEL[k]);
    lg.append(s);
  }
  if (ns.some(n => isGate(d, n))) {
    const s = document.createElement("span");
    const sw = document.createElement("span");
    sw.className = "swatch gate";
    sw.style.borderColor = kindColor("member");
    s.append(sw, "gate");
    s.title = ROLE_HELP.gate;
    lg.append(s);
  }
  for (const c of heldCircles(d)) {
    const s = document.createElement("span");
    s.append(dot(circleColor(c.did)), ` ${c.name}`);
    s.title = "dots on a node: the circles it shares with this node";
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
  return { member: "var(--good)", pending: "var(--warn)", expired: "var(--warn)", stranger: "var(--serious)", revoked: "var(--critical)", grantee: "var(--ink-3)" }[k] || "var(--ink-3)";
}

/* A row of circle chips (name, colour) for the details panels. */
function circleChips(d, dids, n) {
  const wrap = document.createElement("span");
  for (const did of dids.slice().sort()) {
    const chip = document.createElement("span");
    chip.className = "circle-chip";
    chip.title = did;
    chip.append(dot(circleColor(did)), circleName(d, did));
    const role = n ? roleIn(d, n, did) : "";
    if (role) { const r = document.createElement("span"); r.className = "tab-role"; r.textContent = role; chip.append(r); }
    wrap.append(chip);
  }
  return wrap;
}

/* ---------- details panel ---------- */

function renderDetails(d, ns) {
  const box = document.getElementById("details");
  box.innerHTML = "";
  if (state.selected === "self") return renderSelf(d, box);
  const n = ns.find(x => x.id === state.selected);
  if (!n) { box.innerHTML = `<p class="muted">Select a node in the graph.</p>`; return; }

  const kindBadge = badge(n.kind);
  if (isGate(d, n) && (n.kind === "member" || n.kind === "offline")) {
    kindBadge.lastChild.textContent = n.kind === "offline" ? "gate (offline)" : "gate";
  }
  box.append(kindBadge);
  const kv = document.createElement("dl");
  kv.className = "kv";
  add(kv, "name", n.name || "—");
  const tags = roleTags(d, n);
  if (n.member) add(kv, "role", tags.length ? roleChips(tags) : "device");
  if ((n.circles || []).length) add(kv, n.kind === "grantee" ? "granted in" : "shares", circleChips(d, n.circles, n));
  if (n.ip) add(kv, "overlay IP", mono(n.ip.split("/")[0]));
  if (n.addr_conflict) add(kv, "address conflict", `${n.addr_conflict} is held by another device's later admission — no route, no inbound until one of them is renumbered`);
  if (n.scope) add(kv, "scope", `mesh + ${n.scope.filter(f => f !== "mesh").join(" + ") || "nothing else"}`);
  add(kv, "peer ID", mono(n.id));
  if (n.agent) add(kv, "software", n.agent);
  if (n.connected) {
    add(kv, "link", `${n.relayed ? "RELAYED" : "direct"} · ${n.transport || "?"} · ${n.direction === "inbound" ? "they dialed us" : "we dialed them"}`);
    add(kv, "address", mono(n.addr || "—"));
    if (n.rtt_ms) add(kv, "RTT", n.rtt_ms.toFixed(2) + " ms");
  }
  addrList(kv, n);
  if (n.cert_expiry) expiryRow(kv, n.cert_expiry);
  box.append(kv);

  const pend = (d.pending || []).find(p => p.peer_id === n.id && p.status === "pending");
  if (pend) {
    const fp = document.createElement("div");
    fp.className = "fingerprint";
    fp.textContent = groupFp(pend.fingerprint);
    box.append(note("Compare this fingerprint with the joining device's screen before approving."), fp);
  } else if (n.kind === "expired") {
    box.append(note("This device's certificate ran out before it was renewed, so the mesh refuses it — and a renewal can't reach it. " +
      "On the device, run `fabric join` again: it keeps its name, device key and overlay address. Revoke it to forget it."));
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
    if (m) actions.append(
      actionButton("Renew cert", "approve",
        () => openForm(box, "renew", m.fingerprint, `re-sign “${m.name}”’s cert with a fresh validity window (same name, IP, and role)`)),
      actionButton("Revoke membership", "danger",
        () => openForm(box, "revoke", m.fingerprint, `cut “${m.name}” off the mesh immediately`)));
  } else if (n.kind === "expired") {
    const m = (d.members || []).find(m => m.id === n.id);
    if (m) actions.append(
      actionButton("Forget device", "danger",
        () => openForm(box, "revoke", m.fingerprint, `forget “${m.name}” — release its overlay address and stop listing it`)));
  }
  if (actions.childElementCount) box.append(actions);
}

/* Every address the daemon's peerstore holds for the peer — gossiped
   records, identify observations, relay circuits. The live connection's
   address (shown above) is the winner among these; for an offline member
   the list is where the next dial would go. */
function addrList(kv, n) {
  const addrs = (n.known_addrs || []).filter(a => a !== n.addr);
  if (!addrs.length) return;
  const dd = add(kv, n.connected ? "also known" : "known addrs", "");
  for (const a of addrs) {
    const row = document.createElement("div");
    row.append(mono(a));
    /* A /p2p-circuit entry is the relay fallback: "reach me via this
       lighthouse" — advertised by NAT'd nodes, upgraded to direct by
       hole-punching when possible. */
    if (a.includes("/p2p-circuit")) row.append(" ← relay fallback");
    dd.append(row);
  }
}

/* Cert-expiry line with the renewal-tier badge (spec §5: warn <90d, alarm <30d). */
function expiryRow(kv, iso) {
  const days = Math.floor((new Date(iso) - Date.now()) / 86400000);
  if (days < 0) {
    const ddEl = add(kv, "cert expired", `${new Date(iso).toLocaleDateString()} (${-days}d ago)`);
    const b = badge("pending"); b.className = "badge warn"; b.textContent = "re-join needed";
    ddEl.append(" ", b);
    return;
  }
  const ddEl = add(kv, "cert expires", `${new Date(iso).toLocaleDateString()} (${days}d)`);
  if (days < 30) {
    const b = badge("pending"); b.className = "badge warn"; b.textContent = "renew NOW";
    ddEl.append(" ", b);
  } else if (days < 90) {
    const b = badge("pending"); b.className = "badge warn-soft"; b.textContent = "renew soon";
    ddEl.append(" ", b);
  }
}

function renderSelf(d, box) {
  box.append(badge("self"));
  const kv = document.createElement("dl");
  kv.className = "kv";
  const overlayIP = (d.status.overlay_ip || "").split("/")[0];
  add(kv, "name", d.status.name);
  const selfTags = roleTags(d, { kind: "self" });
  add(kv, "role", selfTags.length ? roleChips(selfTags) : "device");
  if (d.status.posture) add(kv, "inbound", d.status.posture === "listed"
    ? "listed — accepts connections from devices it does not know yet"
    : "dark — refuses connections from devices it does not know" + (d.status.refused_inbound ? ` (${d.status.refused_inbound} refused)` : ""));
  for (const c of heldCircles(d)) {
    const dd = add(kv, c === heldCircles(d)[0] ? "circles" : "", circleChips(d, [c.did]));
    dd.append(` ${c.role || "device"}${c.prefix ? " · overlay " + c.prefix : ""}${c.attested === false ? " · NOT admitted" : ""}`);
  }
  if (d.status.overlay_ip) {
    add(kv, "overlay IP", mono(overlayIP));
    add(kv, "TUN bridge", d.status.tun_active ? "up (fabric0)" : "down — other transports still work");
    if (d.status.tun_active) add(kv, ".fabric DNS", d.status.dns_active ? "serving" : "not running");
  }
  add(kv, "peer ID", mono(d.status.peer_id));
  if (d.status.agent) add(kv, "software", d.status.agent);
  add(kv, "NAT", (d.status.reachability || "unknown").toLowerCase());
  /* Per-address verdicts (autonat v2) — on dual-stack NAT'd lines the
     single word above hides the real story (e.g. v4 reachable through a
     friendly CGNAT while the global v6 is firewalled). */
  for (const a of d.status.reachable_addrs || []) add(kv, "· reachable", mono(a));
  for (const a of d.status.unreachable_addrs || []) add(kv, "· unreachable", mono(a));
  for (const a of d.status.unverified_addrs || []) add(kv, "· unverified", mono(a));
  if (d.status.cert_expiry) expiryRow(kv, d.status.cert_expiry);
  for (const a of d.status.addrs || []) {
    const parts = a.split("/");
    if (parts[1] === (overlayIP.includes(":") ? "ip6" : "ip4") && parts[2] === overlayIP) continue;
    add(kv, "listen", mono(a));
  }
  box.append(kv);
  if (d.master) {
    const me = (d.members || []).find(m => m.self);
    if (me) {
      const actions = document.createElement("div");
      actions.className = "actions";
      actions.append(actionButton("Renew cert", "approve",
        () => openForm(box, "renew", me.fingerprint, "re-sign this node's own cert with a fresh validity window")));
      box.append(actions);
    }
  }
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

/* Revoked tombstones: listed apart from the mesh — they will never show a
   connection. Each row says when its revocation record garbage-collects
   (the revoked cert's own expiry) and the row disappears with it. */
function renderRevoked(revoked) {
  const card = document.getElementById("revoked-card");
  const list = document.getElementById("revoked");
  card.hidden = !revoked.length;
  if (card.hidden) return;
  list.innerHTML = "";
  for (const n of revoked) {
    const item = document.createElement("div");
    item.className = "revoked-item";
    const head = document.createElement("div");
    head.append(badge("revoked"), " ", strong(n.name || "unknown device"));
    const id = mono(n.id);      // clicking copies the full peer ID…
    id.textContent = short(n.id); // …but the row shows the short form
    const idRow = document.createElement("div");
    idRow.append(id);
    item.append(head, idRow);
    if (n.revoked_until) {
      item.append(note(`record kept until ${new Date(n.revoked_until).toLocaleDateString()} (the cert's own expiry), then gone`));
    }
    list.append(item);
  }
}

/* ---------- passphrase form ---------- */

function openForm(host, kind, fingerprint, what, hostName) {
  state.form = { kind, fingerprint, host: hostName };
  host.querySelectorAll("form.passform").forEach(f => f.remove());
  /* The form's submit is the action itself — hide the buttons that opened
     it so there is exactly one thing to press (Cancel brings them back). */
  host.querySelectorAll(":scope > .actions").forEach(a => { a.hidden = true; });
  const form = document.createElement("form");
  form.className = "passform";
  form.innerHTML = `
    <div class="form-note">Enter the root-key passphrase to ${what}. Signing happens in this UI process, never in the daemon.</div>
    <input type="password" name="pass" placeholder="namespace root key passphrase" autocomplete="off" required>
    ${kind === "approve" ? `<div class="form-note">Protocol scope signed into the cert — uncheck what this device must never do (hardware you don't fully trust). The mesh control plane is always on; every node enforces the rest.</div>
    <label class="form-note"><input type="checkbox" name="scope_tun" checked> overlay address + TUN leg</label>
    <label class="form-note"><input type="checkbox" name="scope_vault" checked> vault</label>
    <label class="form-note"><input type="checkbox" name="scope_astral" checked> astral</label>` : ""}
    <div class="form-error" hidden></div>
    <div class="actions">
      <button class="action ${kind === "revoke" ? "danger" : "approve"}" type="submit">${{ approve: "Approve — sign certificate", revoke: "Revoke — sign revocation", renew: "Renew — sign certificate" }[kind] || "Sign"}</button>
      <button class="action quiet" type="button" data-cancel>Cancel</button>
    </div>`;
  form.querySelector("[data-cancel]").onclick = () => { state.form = null; render(); };
  form.onsubmit = async (e) => {
    e.preventDefault();
    const errBox = form.querySelector(".form-error");
    errBox.hidden = true;
    try {
      const body = { fingerprint, passphrase: form.pass.value };
      if (kind === "approve") {
        const picked = ["tun", "vault", "astral"].filter(f => form[`scope_${f}`].checked);
        if (picked.length < 3) body.scope = picked.length ? picked : ["mesh"];
      }
      await doPost(`/api/${kind}`, body);
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

document.getElementById("dashboard").hidden = !!state.bucketID;
document.getElementById("bucket-page").hidden = !state.bucketID;
initTheme();
window.addEventListener("hashchange", () => { if (state.data) render(); });
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
