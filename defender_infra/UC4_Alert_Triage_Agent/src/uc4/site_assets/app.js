// UC4 triage website: shared helpers. Every value goes in through textContent (h() below) - never innerHTML with data.
"use strict";

// Microsoft Defender's own classification words (same table as src/uc4/labels.py), with a plain-English hint
const VERDICT = {
  likely_true_positive: { label: "True positive", color: "var(--tp)", short: "True positive", hint: "a real attack" },
  needs_investigation: { label: "Needs review", color: "var(--human)", short: "Needs review", hint: "an analyst decides" },
  benign_positive: { label: "Informational, expected activity", color: "var(--bp)", short: "Expected activity",
                     hint: "real activity, but allowed (e.g. a test or an approved admin)" },
  likely_false_positive: { label: "False positive", color: "var(--fp)", short: "False positive", hint: "the alarm was wrong, nothing happened" },
};
const SEV = { high: "var(--sev-high)", medium: "var(--sev-medium)", low: "var(--sev-low)", informational: "var(--sev-info)" };
const SLA_HOURS = { high: 1, medium: 4, low: 24, informational: 72 };
const SOURCE_NAMES = { microsoftDefenderForEndpoint: "Defender for Endpoint", microsoftSentinel: "Sentinel",
  microsoftDefenderForIdentity: "Defender for Identity", microsoftDefenderForOffice365: "Defender for Office 365",
  microsoftDefenderForCloudApps: "Defender for Cloud Apps", microsoft365Defender: "Defender XDR",
  microsoftDefenderForCloud: "Defender for Cloud", sentinel: "Sentinel", defender: "Defender",
  scheduledAlerts: "Sentinel rule", nrtAlerts: "Sentinel near-real-time rule" };
function sourceNames(s) { return String(s || "").split(",").filter(Boolean).map(x => SOURCE_NAMES[x] || x).join(", "); }

// h("div", {class: "x", onclick: fn}, child1, "text", ...) -> element. Strings become text nodes (safe).
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function verdictPill(v) {
  const meta = VERDICT[v] || { label: v || "-", color: "var(--muted)" };
  return h("span", { class: "pill", title: meta.hint || "" }, h("span", { class: "dot", style: { background: meta.color } }), meta.label);
}
function sevTag(s) {
  const sev = (s || "").toLowerCase() || "informational";
  return h("span", { class: "sev", style: { background: SEV[sev] || "var(--sev-info)" } }, sev === "informational" ? "info" : sev);
}
function fmtTime(t) {
  if (!t) return "-";
  const d = new Date(String(t).replace(" ", "T") + (String(t).endsWith("Z") ? "" : "Z"));
  return isNaN(d) ? String(t) : d.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}
function ago(t) {
  if (!t) return "";
  const d = new Date(String(t).replace(" ", "T") + (String(t).endsWith("Z") ? "" : "Z"));
  const m = Math.round((Date.now() - d.getTime()) / 60000);
  if (isNaN(m)) return "";
  if (m < 1) return "just now";
  if (m < 60) return m + " min ago";
  if (m < 48 * 60) return Math.round(m / 60) + " h ago";
  return Math.round(m / 1440) + " days ago";
}
function toast(text) {
  const t = h("div", { class: "toast", role: "status" }, text);
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}
async function post(url, header, body) {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json", "X-UC4": header },
                               body: JSON.stringify(body || {}) });
  let data = {};
  try { data = await r.json(); } catch (e) { /* empty */ }
  if (!r.ok) throw new Error(data.error || data.message || ("HTTP " + r.status));
  return data;
}

// top bar with navigation and the "Run now" control
function topBar(active, status) {
  const pulse = h("span", { class: "pulse" + (status && status.running ? " busy" : "") });
  const last = status && status.last_run;
  const info = h("span", {}, status && status.running ? "Run in progress…" :
    last ? `Last run ${ago(last.finished_at)} · ${last.status}` : "No run yet");
  const btn = h("button", { class: "btn primary", disabled: status && status.running ? true : null,
    onclick: async () => {
      btn.disabled = true;
      try { await post("/api/run", "run"); toast("Run started - the page refreshes when it finishes."); watchRun(); }
      catch (e) { toast(e.message); btn.disabled = false; }
    } }, "Run now");
  const nav = h("nav", { class: "nav" },
    [["/", "Triage queue", "queue"], ["/metrics", "Metrics", "metrics"], ["/backtest", "Accuracy", "backtest"]]
      .map(([href, label, key]) => h("a", { href, class: key === active ? "on" : null }, label)));
  const theme = h("button", { class: "btn", title: "Light / dark", onclick: () => {
    const cur = document.documentElement.getAttribute("data-theme");
    const next = cur === "dark" ? "light" : cur === "light" ? "dark" :
      (matchMedia("(prefers-color-scheme: dark)").matches ? "light" : "dark");
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("uc4-theme", next); } catch (e) { /* private mode */ }
  } }, "◐");
  return h("header", { class: "top" }, h("div", { class: "wrap" },
    h("div", { class: "brand" }, "SECURITY ASSISTANT", h("span", { class: "tag" }, "Alert response")),
    nav, h("div", { class: "spacer" }), h("div", { class: "runbox" }, pulse, info, btn, theme)));
}
function watchRun() {
  const timer = setInterval(async () => {
    try {
      const s = await (await fetch("/api/status")).json();
      if (!s.running) { clearInterval(timer); location.reload(); }
    } catch (e) { /* server restarting */ }
  }, 3000);
}
(function initTheme() {
  try { const t = localStorage.getItem("uc4-theme"); if (t) document.documentElement.setAttribute("data-theme", t); }
  catch (e) { /* private mode */ }
})();
