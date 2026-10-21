"use strict";
/* Vulnerability Command Centre — renders the data packed into D by build.py. No network access needed. */

// ---------- constants and helpers ----------
const SEVS = ["Critical", "High", "Medium", "Low", "Unrated"];   // Unrated = brand-new CVE, not rated by Microsoft yet
const SEVVAR = {Critical: "--sev-crit", High: "--sev-high", Medium: "--sev-med", Low: "--sev-low", Unrated: "--muted"};
const EXPLOITED = new Set(["ExploitIsVerified", "ExploitIsInKit"]);
const EXPL = {NoExploit: "No known exploit", ExploitIsPublic: "Public exploit", ExploitIsVerified: "Verified exploit",
              ExploitIsInKit: "In attack kits"};
const EXPL_RANK = {ExploitIsInKit: 3, ExploitIsVerified: 2, ExploitIsPublic: 1, NoExploit: 0};
const PRIO_RANK = {P1: 1, P2: 2, P3: 3, P4: 4};
const BUCKETS = ["0-30", "31-60", "61-90", "90+"];
const PAGES = {overview: "Vulnerability overview", opco: "By OpCo", risks: "Top risks", age: "Age & SLA",
               trends: "Trends", devices: "Device drill-down", fixes: "AI fix guide", health: "Data health"};
const PRETTY = {acrobat_reader_dc: "Acrobat Reader", visual_studio_code: "VS Code", meetings: "Zoom",
                vlc_media_player: "VLC", "notepad++": "Notepad++", "7-zip": "7-Zip", edge_chromium: "Edge", jre: "Java"};

const $ = id => document.getElementById(id);
const css = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const fmt = n => (n ?? 0).toLocaleString("en-GB");
const pct = x => x == null ? "–" : (x * 100).toFixed(1) + "%";
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
const pretty = s => PRETTY[s] || (s ? s.charAt(0).toUpperCase() + s.slice(1).replace(/_/g, " ") : "");
const sevTag = s => `<span class="sev"><i style="background:var(${SEVVAR[s] || "--muted"})"></i>${esc(s)}</span>`;
const sum = (a, f) => a.reduce((t, r) => t + f(r), 0);
const groupBy = (a, key) => a.reduce((m, r) => { const k = key(r); (m[k] = m[k] || []).push(r); return m; }, {});
const daysBetween = (a, b) => Math.round((new Date(b) - new Date(a)) / 86400000);
const addDays = (d, n) => { const x = new Date(d); x.setDate(x.getDate() + n); return x.toISOString().slice(0, 10); };

// ---------- data ----------
const DEV = D.devices;
const F = D.f.rows.map(r => Object.fromEntries(D.f.cols.map((c, i) => [c, r[i]])));
// "Update" = bring one app to its latest version; that clears every finding of the installed version.
// (Defender's RecommendedSecurityUpdate is a per-CVE advisory ID such as "mfsa2026-97", kept for the tables and CSV.)
F.forEach(f => { f.dv = DEV[f.d]; f.o = f.dv.opco; f.u = `Update ${pretty(f.sw)} (installed ${f.ver})`; });
const KEV = new Map(D.kev.map(k => [k.cve, k]));
const OPCOS = [...new Set(DEV.map(d => d.opco))].sort();
const SNAP = String(D.meta.snapshot);

const state = {opco: "All", sev: new Set(SEVS), page: "overview", device: null, search: ""};
const keepOpco = o => state.opco === "All" || o === state.opco;
const keep = f => keepOpco(f.o) && state.sev.has(f.sev);
const current = () => F.filter(keep);

// ---------- charts ----------
const charts = {};
const mk = id => {
  const el = $(id);
  if (charts[id] && charts[id].getDom() !== el) { charts[id].dispose(); delete charts[id]; }
  return charts[id] || (charts[id] = echarts.init(el, null, {renderer: "svg"}));
};
const base = () => ({
  textStyle: {fontFamily: 'system-ui,-apple-system,"Segoe UI",sans-serif', color: css("--ink-2")},
  animationDuration: 700, animationEasing: "cubicOut",
  tooltip: {backgroundColor: css("--card"), borderColor: css("--border"), textStyle: {color: css("--ink"), fontSize: 12},
            extraCssText: "box-shadow:0 8px 24px rgba(0,0,0,.25);border-radius:10px"}});
const axis = () => ({axisLine: {lineStyle: {color: css("--axis")}}, axisTick: {show: false},
                     axisLabel: {color: css("--muted"), fontSize: 11}, splitLine: {lineStyle: {color: css("--grid")}}});
const legend = () => ({top: 0, right: 0, icon: "roundRect", itemWidth: 10, itemHeight: 10,
                       textStyle: {color: css("--ink-2"), fontSize: 11.5}});
const shadowTip = () => ({...base().tooltip, trigger: "axis", axisPointer: {type: "shadow", shadowStyle: {color: "rgba(128,128,128,.08)"}}});
const activeSevs = () => [...SEVS].reverse().filter(s => state.sev.has(s));
function stackedSeries(categories, valueOf, horizontal, labelTotals) {
  const sevs = activeSevs();
  return sevs.map((s, i) => ({
    name: s, type: "bar", stack: "t", barMaxWidth: horizontal ? 16 : 46, data: categories.map(c => valueOf(c, s)),
    itemStyle: {color: css(SEVVAR[s]), borderColor: css("--card"), borderWidth: 1,
                borderRadius: i === sevs.length - 1 ? (horizontal ? [0, 4, 4, 0] : [4, 4, 0, 0]) : 0},
    label: labelTotals && i === sevs.length - 1 ? {show: true, position: horizontal ? "right" : "top", color: css("--ink"),
      fontSize: 11.5, fontWeight: 600, formatter: p => fmt(labelTotals[p.dataIndex])} : undefined}));
}
function empty(id, text) {
  mk(id).setOption({...base(), title: {text, left: "center", top: "middle", textStyle: {color: css("--muted"), fontSize: 13, fontWeight: 400}},
                    xAxis: {show: false}, yAxis: {show: false}, series: []}, true);
}

// ---------- header, filters, theme, navigation ----------
function header() {
  const r = D.run, dq = D.dq;
  const worst = dq.some(c => c.status === "FAIL") ? "FAIL" : dq.some(c => c.status === "WARN") ? "WARN" : "PASS";
  $("statusPill").innerHTML = `<span class="dot ${worst === "FAIL" ? "f" : worst === "WARN" ? "w" : ""}"></span>${esc(D.meta.source)} · checks ${worst}`;
  $("snapPill").textContent = `Snapshot ${SNAP}` + (r && r.started_at ? ` · run ${r.started_at.slice(11, 16)} UTC` : "");
  $("navFoot").textContent = `${fmt(F.length)} findings · ${DEV.length} devices · built ${D.meta.built_at.replace("T", " ").slice(0, 16)} UTC`;
  const st = D.status, alert = $("alert");
  const ageDays = daysBetween(SNAP, new Date().toISOString().slice(0, 10));
  if (st && (st.status === "FAIL" || st.status === "ERROR")) {
    alert.className = "alert"; alert.style.display = "";
    alert.innerHTML = `<b>⚠ The latest run (${esc(String(st.run_at).replace("T", " ").slice(0, 16))} UTC) did not publish new data:</b> ${esc(st.message)}. ` +
      `The dashboard still shows the last good snapshot (${esc(SNAP)}). See Data health.`;
  } else if (ageDays > 1) {
    alert.className = "alert w"; alert.style.display = "";
    alert.innerHTML = `<b>This data is ${ageDays} days old</b> (snapshot ${esc(SNAP)}). Run <span class="mono">python -m uc3 run</span> or check the daily task.`;
  }
  $("ribbon").textContent = `Microsoft Defender export generated ${r ? r.export_generated_time : "?"} · CISA KEV ${D.meta.kev.version || "not available"} · Apache ECharts`;
}
function filters() {
  const seg = $("opcoSeg");
  seg.innerHTML = ["All", ...OPCOS].map(o => `<button data-v="${esc(o)}" class="${o === state.opco ? "on" : ""}">${esc(o)}</button>`).join("");
  seg.querySelectorAll("button").forEach(b => b.onclick = () => { state.opco = b.dataset.v; filters(); render(); });
  const chips = $("sevChips");
  chips.innerHTML = "";
  SEVS.forEach(s => {
    const b = document.createElement("button");
    b.className = "chip" + (state.sev.has(s) ? "" : " off");
    b.innerHTML = `<i style="background:var(${SEVVAR[s]})"></i>${s}`;
    b.onclick = () => { if (state.sev.has(s)) { if (state.sev.size > 1) state.sev.delete(s); } else state.sev.add(s); filters(); render(); };
    chips.appendChild(b);
  });
}
$("themeBtn").onclick = () => {
  const r = document.documentElement;
  r.dataset.theme = r.dataset.theme === "dark" ? "light" : "dark";
  $("themeBtn").textContent = r.dataset.theme === "dark" ? "Switch to light" : "Switch to dark";
  try { localStorage.setItem("uc3-theme", r.dataset.theme); } catch (e) { /* storage may be blocked */ }
  render();
};
function go(page) {
  state.page = PAGES[page] ? page : "overview";
  document.querySelectorAll("nav a").forEach(a => a.classList.toggle("on", a.dataset.page === state.page));
  document.querySelectorAll("section.page").forEach(s => s.classList.toggle("on", s.id === "page-" + state.page));
  $("pageTitle").textContent = PAGES[state.page];
  $("filters").style.display = state.page === "health" ? "none" : "";
  $("sevChips").style.display = $("sevLabel").style.display = state.page === "fixes" ? "none" : "";
  if (location.hash !== "#" + state.page) history.replaceState(null, "", "#" + state.page);
  render();
}
document.querySelectorAll("nav a").forEach(a => a.onclick = () => go(a.dataset.page));

// ---------- page: overview ----------
function countUp(el, to) {
  const t0 = performance.now(), d = 700;
  const step = t => { const p = Math.min(1, (t - t0) / d); el.textContent = fmt(Math.round(to * (1 - Math.pow(1 - p, 3)))); if (p < 1) requestAnimationFrame(step); };
  requestAnimationFrame(step);
}
function hero() {
  const r = D.run, k = D.kql;
  const cov = r && r.coverage != null ? r.coverage : null;
  const kqlLine = k
    ? `Old way: one KQL query stops at <b>${fmt(k.rows_returned)}</b> rows. Tested on this tenant: ${fmt(k.rows_returned)} of ${fmt(k.rows_exist)} rows = <b>${pct(k.coverage)}</b>`
    : `Old way: one KQL query can never return more than <b>100,000</b> rows`;
  $("hero").innerHTML = `
    <div><div class="lab">Findings captured in one run</div>
      <div class="big">${fmt(r ? r.vulnerability_rows : F.length)} <span>of ${r && r.defender_count != null ? fmt(r.defender_count) : "?"} in Defender</span></div></div>
    <div class="bar">
      <div class="lab">New way: Defender export API, <b>${cov == null ? "coverage not measured" : pct(cov) + " of Defender's own count"}</b>, 0 KQL queries${r ? `, ${r.duration_seconds} s` : ""}</div>
      <div class="meter"><i style="width:${cov == null ? 0 : Math.min(100, cov * 100)}%"></i></div>
      <div class="lab">${kqlLine}</div>
      <div class="meter old"><i style="width:${k ? k.coverage * 100 : 0}%"></i></div>
    </div>`;
}
function kpis(rows) {
  const crit = rows.filter(f => f.sev === "Critical").length;
  const p1 = rows.filter(f => f.pr === "P1").length;
  const kevCves = new Set(rows.filter(f => f.kev).map(f => f.cve)).size;
  const devs = new Set(rows.map(f => f.d)).size;
  const onboarded = DEV.filter(d => keepOpco(d.opco)).length;
  const upd = new Set(rows.map(f => f.u)).size;
  const tiles = [
    ["Open findings", rows.length, "device × app × CVE", "--s1"],
    ["Critical", crit, `${rows.length ? Math.round(crit / rows.length * 100) : 0}% of findings`, "--sev-crit"],
    ["P1 · fix first", p1, "Critical, or High with a proven exploit", "--sev-high"],
    ["Exploited in the wild", kevCves, "CVEs on the CISA KEV list", "--bad"],
    ["Devices affected", devs, `of ${onboarded} onboarded`, "--s2"],
    ["Apps to update", upd, "app versions with findings", "--s1"]];
  const el = $("kpis");
  el.innerHTML = "";
  tiles.forEach(([l, v, h, a]) => {
    const d = document.createElement("div");
    d.className = "kpi"; d.style.setProperty("--acc", `var(${a})`);
    d.innerHTML = `<div class="l">${l}</div><div class="v">0</div><div class="h">${h}</div>`;
    el.appendChild(d); countUp(d.querySelector(".v"), v);
  });
}
function chUpd(rows) {
  if (!rows.length) return empty("chUpd", "No findings for this filter");
  const by = groupBy(rows, f => f.u);
  const top = Object.entries(by).map(([u, fs]) => ({u, fs, t: fs.length})).sort((a, b) => b.t - a.t).slice(0, 8).reverse();
  mk("chUpd").setOption({...base(), legend: legend(), grid: {left: 8, right: 48, top: 28, bottom: 4, containLabel: true},
    tooltip: shadowTip(), xAxis: {type: "value", ...axis(), axisLine: {show: false}},
    yAxis: {type: "category", data: top.map(r => r.u.length > 46 ? r.u.slice(0, 44) + "…" : r.u), ...axis(), splitLine: {show: false},
            axisLabel: {color: css("--ink-2"), fontSize: 11.5}},
    series: stackedSeries(top, (r, s) => r.fs.filter(f => f.sev === s).length, true, top.map(r => r.t))}, true);
}
function chTree(rows) {
  if (!rows.length) return empty("chTree", "No findings for this filter");
  const dark = document.documentElement.dataset.theme === "dark";
  const ramp = [0, 1, 2, 3, 4].map(i => css("--seq-" + i));
  const data = Object.entries(groupBy(rows, f => f.sw)).map(([sw, fs]) => {
    const share = fs.filter(f => f.sev === "Critical" || f.sev === "High").length / fs.length, idx = Math.min(4, Math.floor(share * 5));
    return {name: pretty(sw), value: fs.length, share, itemStyle: {color: ramp[idx]},
            label: {color: (dark ? idx >= 3 : idx <= 1) ? "#0b1120" : "#ffffff"}};
  });
  mk("chTree").setOption({...base(), tooltip: {...base().tooltip, formatter: p => `<b>${esc(p.name)}</b><br>${fmt(p.value)} findings<br>${Math.round(p.data.share * 100)}% Critical/High`},
    series: [{type: "treemap", data, roam: false, nodeClick: false, breadcrumb: {show: false}, left: 0, right: 0, top: 0, bottom: 0,
      itemStyle: {borderColor: css("--card"), borderWidth: 2, gapWidth: 2, borderRadius: 6},
      label: {show: true, formatter: p => `{n|${p.name}}\n${fmt(p.value)}`, fontSize: 11.5, rich: {n: {fontWeight: 600, fontSize: 12.5}}},
      upperLabel: {show: false}}]}, true);
}
function kevTable(rows) {
  const k = D.meta.kev;
  $("kevDesc").textContent = `Your CVEs on the free CISA "Known Exploited Vulnerabilities" list (${fmt(k.entries)} entries, version ${k.version || "n/a"})`;
  const by = groupBy(rows.filter(f => f.kev), f => f.cve);
  const list = Object.entries(by).map(([cve, fs]) => ({cve, fs, info: KEV.get(cve) || {}}))
    .sort((a, b) => (b.info.rw ? 1 : 0) - (a.info.rw ? 1 : 0) || b.fs.length - a.fs.length);
  $("kevTbl").innerHTML = `<tr><th>CVE</th><th>What it is</th><th>App</th><th>Severity</th><th class="num">CVSS</th><th>OpCos</th><th class="num">Devices</th><th>On list since</th></tr>` +
    (list.length ? list.map(({cve, fs, info}) => `<tr><td class="mono">${esc(cve)}</td>
      <td>${esc((info.name || "").replace(/ Vulnerability$/, ""))}${info.rw ? ' <span class="tag rw">ransomware</span>' : ""}</td>
      <td>${[...new Set(fs.map(f => pretty(f.sw)))].map(esc).join(", ")}</td><td>${sevTag(fs[0].sev)}</td>
      <td class="num">${(fs[0].cvss ?? 0).toFixed(1)}</td><td>${[...new Set(fs.map(f => f.o))].map(o => `<span class="tag">${esc(o)}</span>`).join(" ")}</td>
      <td class="num">${new Set(fs.map(f => f.d)).size}</td><td class="num">${esc(info.added || "")}</td></tr>`).join("")
    : `<tr><td colspan="8" class="empty">None for the current filter.</td></tr>`);
}
function chSev(rows) {
  const opcos = OPCOS.filter(keepOpco);
  mk("chSev").setOption({...base(), legend: legend(), grid: {left: 4, right: 16, top: 30, bottom: 4, containLabel: true},
    tooltip: shadowTip(), xAxis: {type: "category", data: opcos, ...axis(), splitLine: {show: false}, axisLabel: {color: css("--ink-2"), fontSize: 12}},
    yAxis: {type: "value", ...axis(), axisLine: {show: false}},
    series: stackedSeries(opcos, (o, s) => rows.filter(f => f.o === o && f.sev === s).length, false)}, true);
}
function chCvss(rows) {
  const bins = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
  const count = b => rows.filter(f => Math.min(9, Math.floor(f.cvss ?? 0)) === b).length;
  mk("chCvss").setOption({...base(), grid: {left: 4, right: 8, top: 12, bottom: 4, containLabel: true},
    tooltip: {...shadowTip(), formatter: p => `CVSS ${p[0].name}–${+p[0].name + 0.9}<br><b>${fmt(p[0].value)}</b> findings`},
    xAxis: {type: "category", data: bins.map(String), ...axis(), splitLine: {show: false}},
    yAxis: {type: "value", ...axis(), axisLine: {show: false}},
    series: [{type: "bar", barWidth: "62%", data: bins.map(count), itemStyle: {color: css("--s1"), borderRadius: [4, 4, 0, 0]}}]}, true);
}
function changes() {
  // The latest run's numbers from Defender's own change list (D.download); older data: the events of the last day
  const dl = D.download, c = (dl && dl.counts) || {};
  const known = dl && c.new !== undefined, stale = known && c.defender_refreshed === false;
  const rows = D.changes.filter(c => keepOpco(c[1]) && (c[3] === "None" || state.sev.has(c[3])));
  const last = rows.length ? rows.map(c => c[0]).sort().at(-1) : null;
  const n = st => known ? (stale ? 0 : c[st.toLowerCase()] || 0) : sum(rows.filter(c => c[0] === last && c[2] === st), c => c[4]);
  $("chgDesc").textContent = known ? `From Defender's own change list, downloaded ${(dl.started_at || dl.run_date).slice(0, 16).replace("T", " ")} UTC · already applied`
    : last ? `Changes Defender recorded on ${last}` : "No change events yet";
  $("chg").innerHTML = `<div><b>${fmt(n("New"))}</b><span>New</span></div><div><b style="color:var(--good-ink)">${fmt(n("Fixed"))}</b><span>Fixed</span></div><div><b>${fmt(n("Updated"))}</b><span>Updated</span></div>`;
  const none = known && !n("New") && !n("Fixed") && !n("Updated");
  $("chgNote").textContent = (stale ? "No changes: Defender has not refreshed its data since the last run. "
    : none ? "No changes in Defender since the last run. " : "")
    + (c.vulnerability_rows != null ? `Every run downloads the full list again: ${fmt(c.vulnerability_rows)} this time`
       + (typeof c.previous_rows === "number" ? `, ${fmt(c.previous_rows)} the run before. ` : ". ") : "")
    + "See the Trends page for every day.";
}
const ICON = {PASS: ["ok", "✓"], WARN: ["w", "!"], FAIL: ["f", "✕"], INFO: ["i", "i"]};
const LABEL = {completeness: "Complete", coverage_vs_defender: "Coverage vs Defender", not_empty: "Data received", freshness: "Fresh",
               no_duplicates: "No duplicates", mandatory_fields: "Key fields filled", volume_change: "Normal volume",
               devices_known: "Devices known", opco_mapping: "OpCo mapping", stale_devices: "Stale devices",
               unrated_cves: "Not yet rated"};
function trust() {
  const pick = ["completeness", "coverage_vs_defender", "freshness", "no_duplicates", "opco_mapping"];
  $("trust").innerHTML = D.dq.filter(c => pick.includes(c.name)).map(c => {
    const [cls, sym] = ICON[c.status] || ICON.INFO;
    return `<li><span class="ic ${cls}">${sym}</span><div><b>${LABEL[c.name] || esc(c.name)}</b> <span>(${esc(c.value)})</span></div></li>`;
  }).join("") || `<li><span class="ic i">i</span><div>No quality results yet</div></li>`;
}
function renderOverview() {
  const rows = current();
  hero(); kpis(rows); chUpd(rows); chTree(rows); kevTable(rows); chSev(rows); chCvss(rows); changes(); trust();
}

// ---------- page: by OpCo ----------
function renderOpco() {
  const rows = current(), opcos = OPCOS.filter(keepOpco), sevs = SEVS.filter(s => state.sev.has(s));
  const cells = [];
  opcos.forEach((o, y) => sevs.forEach((s, x) => cells.push([x, y, rows.filter(f => f.o === o && f.sev === s).length])));
  const max = Math.max(1, ...cells.map(c => c[2]));
  mk("chHeat").setOption({...base(), grid: {left: 8, right: 8, top: 8, bottom: 60, containLabel: true},
    tooltip: {...base().tooltip, formatter: p => `${esc(opcos[p.value[1]])} · ${sevs[p.value[0]]}<br><b>${fmt(p.value[2])}</b> findings`},
    xAxis: {type: "category", data: sevs, ...axis(), splitLine: {show: false}}, yAxis: {type: "category", data: opcos, ...axis(), splitLine: {show: false}},
    visualMap: {min: 0, max, calculable: false, orient: "horizontal", left: "center", bottom: 0, itemHeight: 160,
                inRange: {color: [0, 1, 2, 3, 4].map(i => css("--seq-" + i))}, textStyle: {color: css("--muted")}},
    series: [{type: "heatmap", data: cells.map(c => ({value: c, label: {color: (c[2] > max / 2) === (document.documentElement.dataset.theme === "dark") ? "#0b1120" : "#ffffff"}})),
              label: {show: true, fontWeight: 600, formatter: p => fmt(p.value[2])},
              itemStyle: {borderColor: css("--card"), borderWidth: 3, borderRadius: 6}}]}, true);
  const devCount = o => DEV.filter(d => d.opco === o).length || 1;
  mk("chPerDev").setOption({...base(), legend: legend(), grid: {left: 4, right: 16, top: 30, bottom: 4, containLabel: true},
    tooltip: shadowTip(), xAxis: {type: "category", data: opcos, ...axis(), splitLine: {show: false}},
    yAxis: {type: "value", ...axis(), axisLine: {show: false}},
    series: stackedSeries(opcos, (o, s) => Math.round(rows.filter(f => f.o === o && f.sev === s).length / devCount(o)), false)}, true);
  $("opcoTbl").innerHTML = `<tr><th>OpCo</th><th class="num">Devices</th><th class="num">Findings</th><th class="num">Per device</th><th class="num">Critical</th>
    <th class="num">P1</th><th class="num">SLA breached</th><th class="num">Exploited CVEs (KEV)</th></tr>` +
    opcos.map(o => { const fs = rows.filter(f => f.o === o);
      return `<tr class="click" data-o="${esc(o)}"><td><b>${esc(o)}</b></td><td class="num">${devCount(o)}</td><td class="num">${fmt(fs.length)}</td>
        <td class="num">${fmt(Math.round(fs.length / devCount(o)))}</td><td class="num">${fmt(fs.filter(f => f.sev === "Critical").length)}</td>
        <td class="num">${fmt(fs.filter(f => f.pr === "P1").length)}</td><td class="num">${fmt(fs.filter(f => f.br).length)}</td>
        <td class="num">${fmt(new Set(fs.filter(f => f.kev).map(f => f.cve)).size)}</td></tr>`; }).join("");
  $("opcoTbl").querySelectorAll("tr.click").forEach(tr => tr.onclick = () => { state.opco = tr.dataset.o; filters(); go("overview"); });
}

// ---------- page: top risks ----------
function cveList(rows) {
  return Object.entries(groupBy(rows, f => f.cve)).map(([cve, fs]) => {
    const best = fs.reduce((a, f) => (EXPL_RANK[f.ex] || 0) > (EXPL_RANK[a.ex] || 0) ? f : a, fs[0]);
    return {cve, fs, sev: fs[0].sev, cvss: Math.max(...fs.map(f => f.cvss ?? 0)), ex: best.ex,
            pr: fs.map(f => f.pr).sort()[0], devs: new Set(fs.map(f => f.d)).size, kev: fs.some(f => f.kev)};
  }).sort((a, b) => (PRIO_RANK[a.pr] - PRIO_RANK[b.pr]) || (b.kev - a.kev) || (b.devs - a.devs) || (b.cvss - a.cvss));
}
function renderRisks() {
  const rows = current(), list = cveList(rows).slice(0, 50);
  $("cveTbl").innerHTML = `<tr><th>#</th><th>CVE</th><th>Priority</th><th>Severity</th><th class="num">CVSS</th><th>Exploit</th><th>App</th>
    <th class="num">Devices</th><th>OpCos</th><th>Vendor advisory</th></tr>` + (list.length ? list.map((c, i) => `<tr><td class="num">${i + 1}</td>
      <td class="mono">${esc(c.cve)}${c.kev ? ' <span class="tag kev" title="On the CISA KEV list">⚠ KEV</span>' : ""}</td><td>${esc(c.pr)}</td>
      <td>${sevTag(c.sev)}</td><td class="num">${c.cvss.toFixed(1)}</td><td>${esc(EXPL[c.ex] || c.ex)}</td>
      <td>${[...new Set(c.fs.map(f => pretty(f.sw) + " " + f.ver))].map(esc).join(", ")}</td><td class="num">${c.devs}</td>
      <td>${[...new Set(c.fs.map(f => f.o))].map(o => `<span class="tag">${esc(o)}</span>`).join(" ")}</td>
      <td class="mono">${esc(c.fs[0].upd || "–")}</td></tr>`).join("") : `<tr><td colspan="10" class="empty">No findings for this filter.</td></tr>`);
  const bySw = Object.entries(groupBy(rows, f => `${pretty(f.sw)} ${f.ver}`)).map(([k, fs]) => ({k, fs, t: fs.length}))
    .sort((a, b) => b.t - a.t).slice(0, 12).reverse();
  if (!bySw.length) return empty("chSw", "No findings for this filter");
  mk("chSw").setOption({...base(), legend: legend(), grid: {left: 8, right: 48, top: 28, bottom: 4, containLabel: true},
    tooltip: shadowTip(), xAxis: {type: "value", ...axis(), axisLine: {show: false}},
    yAxis: {type: "category", data: bySw.map(r => r.k), ...axis(), splitLine: {show: false}, axisLabel: {color: css("--ink-2"), fontSize: 11.5}},
    series: stackedSeries(bySw, (r, s) => r.fs.filter(f => f.sev === s).length, true, bySw.map(r => r.t))}, true);
}
$("csvBtn").onclick = () => {
  const cols = ["device", "opco", "software", "version", "cve", "severity", "cvss", "exploitability", "priority",
                "age_days", "sla_breached", "cisa_kev", "recommended_update", "first_seen"];
  const q = v => { const s = String(v ?? ""); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
  const lines = [cols.join(",")].concat(current().map(f => [f.dv.name, f.o, f.sw, f.ver, f.cve, f.sev, f.cvss, f.ex, f.pr,
    f.age, f.br ? "yes" : "no", f.kev ? "yes" : "no", f.upd, f.fs].map(q).join(",")));
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob(["﻿" + lines.join("\r\n")], {type: "text/csv;charset=utf-8"}));
  a.download = `UC3_findings_${SNAP}${state.opco === "All" ? "" : "_" + state.opco.replace(/\W+/g, "_")}.csv`;
  a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
};

// ---------- page: age & SLA ----------
function renderAge() {
  const rows = current(), sla = D.meta.sla;
  mk("chAge").setOption({...base(), legend: legend(), grid: {left: 4, right: 16, top: 30, bottom: 4, containLabel: true},
    tooltip: shadowTip(), xAxis: {type: "category", data: BUCKETS.map(b => b + " days"), ...axis(), splitLine: {show: false}},
    yAxis: {type: "value", ...axis(), axisLine: {show: false}},
    series: stackedSeries(BUCKETS, (b, s) => rows.filter(f => f.bk === b && f.sev === s).length, false)}, true);
  const breached = rows.filter(f => f.br).length;
  $("slaDesc").textContent = `${fmt(breached)} of ${fmt(rows.length)} findings are past their fix-by date`;
  mk("chSla").setOption({...base(), tooltip: {...base().tooltip, trigger: "item", formatter: p => `${p.name}<br><b>${fmt(p.value)}</b> (${p.percent}%)`},
    legend: {...legend(), top: "bottom", right: "center"},
    series: [{type: "pie", radius: ["55%", "80%"], center: ["50%", "45%"], label: {show: true, position: "center", fontSize: 22, fontWeight: 700,
              color: css("--ink"), formatter: () => rows.length ? Math.round(breached / rows.length * 100) + "%\nbreached" : "–"},
              itemStyle: {borderColor: css("--card"), borderWidth: 2},
              data: [{name: "Within SLA", value: rows.length - breached, itemStyle: {color: css("--s1")}},
                     {name: "Breached", value: breached, itemStyle: {color: css("--sev-high")}}]}]}, true);
  $("slaTbl").innerHTML = `<tr><th>Severity</th><th class="num">Fix within</th><th class="num">Open</th><th class="num">Breached</th><th>Next due</th></tr>` +
    SEVS.filter(s => state.sev.has(s)).map(s => {
      const fs = rows.filter(f => f.sev === s), open = fs.filter(f => !f.br);
      const next = open.length ? open.map(f => addDays(f.fs, sla[s])).sort()[0] : null;
      return `<tr><td>${sevTag(s)}</td><td class="num">${sla[s] ?? "–"} days</td><td class="num">${fmt(fs.length)}</td>
        <td class="num">${fmt(fs.length - open.length)}</td><td>${next ? `${next} (${daysBetween(SNAP, next)} days)` : "–"}</td></tr>`;
    }).join("");
  const old = rows.filter(f => f.sev === "Critical" || f.sev === "High").sort((a, b) => b.age - a.age).slice(0, 20);
  $("oldTbl").innerHTML = `<tr><th>Device</th><th>App</th><th>CVE</th><th>Severity</th><th class="num">Age</th><th>SLA</th></tr>` +
    (old.length ? old.map(f => `<tr><td>${esc(f.dv.name)}</td><td>${esc(pretty(f.sw) + " " + f.ver)}</td><td class="mono">${esc(f.cve)}</td>
      <td>${sevTag(f.sev)}</td><td class="num">${f.age} d</td><td>${f.br ? '<span class="tag rw">breached</span>' : "within"}</td></tr>`).join("")
    : `<tr><td colspan="6" class="empty">No Critical or High findings for this filter.</td></tr>`);
}

// ---------- page: trends ----------
function renderTrends() {
  const daily = D.daily.filter(r => keepOpco(r[1]) && state.sev.has(r[2]));
  const dates = [...new Set(D.daily.map(r => String(r[0])))].sort();
  $("trendDesc").textContent = dates.length > 1
    ? `${dates.length} daily snapshots from ${dates[0]} to ${dates.at(-1)}`
    : "History builds up with each daily run; the line appears from the second day.";
  mk("chTrend").setOption({...base(), legend: legend(), grid: {left: 4, right: 16, top: 30, bottom: 4, containLabel: true},
    tooltip: {...base().tooltip, trigger: "axis"}, xAxis: {type: "category", boundaryGap: false, data: dates, ...axis(), splitLine: {show: false}},
    yAxis: {type: "value", ...axis(), axisLine: {show: false}},
    series: activeSevs().map(s => ({name: s, type: "line", stack: "t", smooth: true, symbol: "circle", symbolSize: 6, areaStyle: {opacity: .85},
      lineStyle: {width: 1.5, color: css(SEVVAR[s])}, itemStyle: {color: css(SEVVAR[s])},
      data: dates.map(d => sum(daily.filter(r => String(r[0]) === d && r[2] === s), r => r[4]))}))}, true);
  const ch = D.changes.filter(c => keepOpco(c[1]) && (c[3] === "None" || state.sev.has(c[3])));
  const days = [...new Set(ch.map(c => String(c[0])))].sort();
  const series = [["New", "--sev-high"], ["Fixed", "--good"], ["Updated", "--s1"]].map(([st, col]) => ({name: st, type: "bar", barMaxWidth: 26,
    itemStyle: {color: css(col), borderRadius: [4, 4, 0, 0]}, data: days.map(d => sum(ch.filter(c => String(c[0]) === d && c[2] === st), c => c[4]))}));
  if (!days.length) empty("chNewFixed", "No change events yet");
  else mk("chNewFixed").setOption({...base(), legend: legend(), grid: {left: 4, right: 16, top: 30, bottom: 4, containLabel: true},
    tooltip: shadowTip(), xAxis: {type: "category", data: days, ...axis(), splitLine: {show: false}},
    yAxis: {type: "value", ...axis(), axisLine: {show: false}}, series}, true);
  const rem = D.remed.filter(r => keepOpco(r[1]) && state.sev.has(r[2]));
  $("mttrTbl").innerHTML = `<tr><th>Severity</th><th class="num">Fixed</th><th class="num">Avg days to fix</th></tr>` +
    SEVS.filter(s => state.sev.has(s)).map(s => { const r = rem.filter(x => x[2] === s);
      return `<tr><td>${sevTag(s)}</td><td class="num">${fmt(r.length)}</td><td class="num">${r.length ? (sum(r, x => x[3]) / r.length).toFixed(1) : "–"}</td></tr>`; }).join("");
  $("mttrNote").textContent = rem.length < 20 ? "Few fixes so far. This fills in as vulnerabilities get patched (e.g. update Firefox on a test VM)." : "";
}

// ---------- page: devices ----------
function renderDevices() {
  const q = state.search.toLowerCase();
  const devs = DEV.map((d, i) => ({d, i})).filter(({d}) => keepOpco(d.opco) && (!q || (d.name || "").toLowerCase().includes(q)));
  const rows = current();
  $("devTbl").innerHTML = `<tr><th>Device</th><th>OpCo</th><th>OS</th><th class="num">Findings</th><th class="num">Critical</th><th class="num">P1</th>
    <th class="num">KEV CVEs</th><th>Last seen</th><th>Health</th><th>Tags</th></tr>` +
    (devs.length ? devs.map(({d, i}) => { const fs = rows.filter(f => f.d === i);
      return `<tr class="click ${state.device === i ? "sel" : ""}" data-i="${i}"><td><b>${esc(d.name)}</b>${d.stale ? ' <span class="tag">stale</span>' : ""}</td>
        <td>${esc(d.opco)}</td><td>${esc([d.os, d.osv].filter(Boolean).join(" "))}</td><td class="num">${fmt(fs.length)}</td>
        <td class="num">${fmt(fs.filter(f => f.sev === "Critical").length)}</td><td class="num">${fmt(fs.filter(f => f.pr === "P1").length)}</td>
        <td class="num">${new Set(fs.filter(f => f.kev).map(f => f.cve)).size}</td><td>${esc(d.last_seen || "–")}</td><td>${esc(d.health || "–")}</td>
        <td>${(d.tags || []).map(t => `<span class="tag">${esc(t)}</span>`).join(" ") || '<span class="tag">no tag</span>'}</td></tr>`; }).join("")
    : `<tr><td colspan="10" class="empty">No devices match.</td></tr>`);
  $("devTbl").querySelectorAll("tr.click").forEach(tr => tr.onclick = () => { state.device = +tr.dataset.i; renderDevices(); });
  if (state.device == null && devs.length) state.device = devs[0].i;
  const dev = DEV[state.device];
  const fs = dev ? rows.filter(f => f.d === state.device) : [];
  $("devTitle").textContent = dev ? `Findings by app on ${dev.name}` : "Findings by app";
  $("devDesc").textContent = dev ? `${fmt(fs.length)} findings · ${dev.opco} · exposure ${dev.exposure || "–"}` : "Select a device above";
  const bySw = Object.entries(groupBy(fs, f => pretty(f.sw))).map(([k, x]) => ({k, fs: x, t: x.length})).sort((a, b) => a.t - b.t);
  if (!bySw.length) empty("chDev", "No findings for this device and filter");
  else mk("chDev").setOption({...base(), legend: legend(), grid: {left: 8, right: 48, top: 28, bottom: 4, containLabel: true},
    tooltip: shadowTip(), xAxis: {type: "value", ...axis(), axisLine: {show: false}},
    yAxis: {type: "category", data: bySw.map(r => r.k), ...axis(), splitLine: {show: false}, axisLabel: {color: css("--ink-2"), fontSize: 11.5}},
    series: stackedSeries(bySw, (r, s) => r.fs.filter(f => f.sev === s).length, true, bySw.map(r => r.t))}, true);
  const upd = Object.entries(groupBy(fs, f => f.u)).map(([u, x]) => ({u, t: x.length, c: x.filter(f => f.sev === "Critical").length,
    k: new Set(x.filter(f => f.kev).map(f => f.cve)).size})).sort((a, b) => b.t - a.t);
  $("devUpdTbl").innerHTML = `<tr><th>#</th><th>Update</th><th class="num">Clears</th><th class="num">Critical</th><th class="num">KEV</th></tr>` +
    (upd.length ? upd.map((r, i) => `<tr><td class="num">${i + 1}</td><td>${esc(r.u)}</td><td class="num">${fmt(r.t)}</td><td class="num">${fmt(r.c)}</td>
      <td class="num">${r.k || ""}</td></tr>`).join("") : `<tr><td colspan="5" class="empty">Nothing to install.</td></tr>`);
}
$("devSearch").oninput = e => { state.search = e.target.value; state.device = null; renderDevices(); };

// ---------- page: AI fix guide ----------
const URG_VAR = {1: "--bad", 2: "--warn", 3: "--muted"};
const fixState = {kind: "app", type: "All", q: ""};
const fixCards = () => D.fixes ? (fixState.kind === "app" ? D.fixes.apps : (D.fixes.settings || [])) : [];
function renderFixes() {
  const X = D.fixes;
  if (!X) {
    $("fixHero").innerHTML = `<div><div class="big">No fix guide yet</div><div class="lab">Run <span class="mono">python -m uc3 ai-fixes</span> to build it.</div></div>`;
    $("fixBar").innerHTML = $("fixGrid").innerHTML = ""; return;
  }
  const inOpco = c => state.opco === "All" || c.opcos.includes(state.opco);
  const apps = X.apps.filter(inOpco), sets = (X.settings || []).filter(inOpco);
  const c = X.counts, now = [...apps, ...sets].filter(a => a.urgency.level === 1).length;
  const when = X.built_at ? X.built_at.replace("T", " ").slice(0, 16) + " UTC" : "–";
  const total = c.apps + (c.settings || 0);
  const aiLine = c.ai
    ? `AI explained <b>${c.ai} of ${total}</b> cards${X.model ? ` with <span class="mono">${esc(X.model)}</span>` : ""} · fact check removed <b>${fmt(c.corrections)}</b> AI sentence(s) not backed by the data`
    : `AI text not available${X.ai_message ? ": " + esc(X.ai_message) : ""}. Cards show the data-based fix only.`;
  const types = Object.entries(c.by_fix_type || {}).sort((a, b) => b[1] - a[1])
    .map(([t, n]) => `<span class="tag">${esc(t)} · ${n}</span>`).join(" ");
  $("fixHero").innerHTML = `
    <div><div class="big">${fmt(apps.length)} <span>apps to update</span> · ${fmt(sets.length)} <span>settings to fix</span></div>
      <div class="lab">${fmt(now)} marked “Fix now” · ${fmt(sum(apps, a => a.cves))} CVEs cleared if all apps are done</div>
      <div class="lab" style="margin-top:6px">${types}</div></div>
    <div class="bar"><div class="lab">${aiLine}</div>
      <div class="lab" style="margin-top:6px">Facts, urgency and commands come from Defender data, Microsoft's own fix text and <span class="mono">config/*_catalog.csv</span>; the AI only explains them.
      Built ${esc(when)}${X.stale ? ` · <b style="color:var(--warn)">built for snapshot ${esc(X.snapshot)}, run <span class="mono">python -m uc3 ai-fixes</span></b>` : ""}</div></div>`;
  const cards = fixCards().filter(inOpco);
  const typeCounts = cards.reduce((m, a) => (m[a.fix_type] = (m[a.fix_type] || 0) + 1, m), {});
  if (fixState.type !== "All" && !typeCounts[fixState.type]) fixState.type = "All";
  $("fixBar").innerHTML = `<div class="seg">${[["app", `Apps to update (${apps.length})`], ["setting", `Settings to fix (${sets.length})`]]
      .map(([k, l]) => `<button data-k="${k}" class="${fixState.kind === k ? "on" : ""}">${l}</button>`).join("")}</div>
    <span class="flabel" style="margin-left:10px">Fix type</span>
    ${["All", ...Object.keys(typeCounts).sort()].map(t => `<button class="chip${fixState.type === t ? " on" : ""}" data-t="${esc(t)}">${esc(t)}${t === "All" ? "" : " · " + typeCounts[t]}</button>`).join("")}
    <input class="search" id="fixSearch" placeholder="Search name, PC, CVE…" value="${esc(fixState.q)}">`;
  $("fixBar").querySelectorAll("button[data-k]").forEach(b => b.onclick = () => { fixState.kind = b.dataset.k; fixState.type = "All"; renderFixes(); });
  $("fixBar").querySelectorAll("button[data-t]").forEach(b => b.onclick = () => { fixState.type = b.dataset.t; renderFixes(); });
  $("fixSearch").oninput = e => { fixState.q = e.target.value; fixGrid(); };
  fixGrid();
}
function fixGrid() {
  const q = fixState.q.trim().toLowerCase();
  const cards = fixCards().filter(a => (state.opco === "All" || a.opcos.includes(state.opco))
    && (fixState.type === "All" || a.fix_type === fixState.type)
    && (!q || JSON.stringify([a.app, a.devices, a.kev_cves || [], a.category || "", a.versions || []]).toLowerCase().includes(q)));
  $("fixGrid").innerHTML = cards.length ? cards.map((a, i) => a.kind === "setting" ? settingCard(a, i + 1) : fixCard(a, i + 1)).join("")
    : `<div class="empty">Nothing matches this filter.</div>`;
  $("fixGrid").querySelectorAll("button[data-cmd]").forEach(b => b.onclick = () => {
    const text = b.dataset.cmd;
    const done = () => { b.textContent = "Copied"; setTimeout(() => b.textContent = "Copy", 1500); };
    if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, () => prompt("Copy the command:", text));
    else prompt("Copy the command:", text);
  });
}
function cardFoot(a, url, linkText) {
  const ai = (a.source || "").startsWith("ai");
  return `<div class="foot">${ai ? `<span class="aib">AI-generated · check before acting</span>${a.model ? `<span>${esc(a.model)}</span>` : ""}${a.guard_notes && a.guard_notes.length ? `<span title="${esc(a.guard_notes.join("\n"))}">${a.guard_notes.length} sentence(s) removed by fact check</span>` : ""}${a.source !== "ai" ? "<span>text from an earlier run</span>" : ""}`
      : '<span class="aib r">Data-based text (no AI)</span>'}
      ${url ? `<span class="spacer"></span><a href="${esc(url)}" target="_blank" rel="noopener noreferrer" style="color:var(--s1)">${linkText} ↗</a>` : ""}</div>`;
}
function cmdBox(cmd) {
  return cmd ? `<div class="cmd"><code>${esc(cmd)}</code><button data-cmd="${esc(cmd)}">Copy</button></div>` : "";
}
function aiText(t, ai) {
  return `<p>${esc(t.what_is_wrong)}</p>
    ${t.worst_case ? `<p><b>Worst case:</b> ${esc(t.worst_case)}</p>` : ""}
    ${t.why_now ? `<p><b>Why now:</b> ${esc(t.why_now)}</p>` : ""}`;
}
function stepsBlock(t, ai) {
  return `<div class="lbl">Step by step ${ai ? '<span class="aib">AI</span>' : ""}</div>
    <ol>${(t.steps || []).map(s => `<li>${esc(s)}</li>`).join("")}</ol>
    <details><summary>How to check it worked · what users will notice</summary><p>${esc(t.verify)}</p><p>${esc(t.side_effects)}</p></details>`;
}
function fixCard(a, rank) {
  const t = a.ai || {}, f = a.fix, ai = (a.source || "").startsWith("ai");
  const eosTxt = v => v.eos ? (v.eos.status === "EOS Version" ? ` <span class="tag rw" title="End of support ${esc(v.eos.date)}">no fixes since ${esc(v.eos.date)}</span>`
                                                            : ` <span class="tag kev" title="End of support ${esc(v.eos.date)}">support ends ${esc(v.eos.date)}</span>`) : "";
  const vers = a.versions.map(v => esc(v.version) + eosTxt(v)).join(", ");
  const outOfSupport = a.versions.filter(v => v.eos && v.eos.status === "EOS Version").length;
  const nums = [[a.cves, "CVEs"], [a.p1, "P1"], [a.kev_cves.length, "used by attackers"], [a.devices.length, "devices"]]
    .map(([n, l]) => `<span><b>${fmt(n)}</b>${l}</span>`).join("") +
    (outOfSupport ? `<span><b style="color:var(--bad)">${outOfSupport}</b>version${outOfSupport === 1 ? "" : "s"} out of support</span>` : "") +
    (a.fix_by ? `<span>fix by <b>${esc(a.fix_by)}</b>${a.overdue ? ` · <b style="color:var(--bad)">${fmt(a.overdue)}</b> overdue` : ""}</span>` : "");
  const where = a.versions.map(v => `<div style="margin-top:6px"><b>${esc(v.version)}</b> · ${fmt(v.cves)} CVEs · ${v.devices.map(esc).join(", ")}
    ${v.folders.length ? `<ul class="folders">${v.folders.map(x => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}</div>`).join("");
  return `<div class="fix" style="--acc:var(${URG_VAR[a.urgency.level]})">
    <div class="hd"><span class="rk">#${rank}</span><div><h3>${esc(a.app)}</h3><div class="v">Installed: ${vers} · ${a.opcos.map(o => `<span class="tag">${esc(o)}</span>`).join(" ")}</div></div>
      <span class="urg l${a.urgency.level}">${esc(a.urgency.label)}</span></div>
    <div class="nums">${nums}</div>
    ${aiText(t, ai)}
    <div class="lbl">The fix · <span class="tag">${esc(a.fix_type || "Update the app")}</span></div>
    <p><b>${esc(f.action)}</b></p>
    ${cmdBox(f.command)}
    ${f.note ? `<p class="note" style="margin-top:6px">${esc(f.note)}</p>` : ""}
    ${stepsBlock(t, ai)}
    <details><summary>Where it is installed (${a.devices.length} device${a.devices.length === 1 ? "" : "s"})</summary>${where}</details>
    ${a.kev_cves.length ? `<details><summary>On the CISA “used by attackers” list (${a.kev_cves.length})</summary><ul class="folders">${a.kev_cves.map(k => `<li>${esc(k.cve)}${k.name ? " · " + esc(k.name) : ""}</li>`).join("")}</ul></details>` : ""}
    ${cardFoot(a, f.url, "Official download")}
  </div>`;
}
function settingCard(s, rank) {
  const t = s.ai || {}, f = s.fix, ms = s.microsoft || {}, ai = (s.source || "").startsWith("ai");
  const nums = `<span><b>${fmt(s.devices.length)}</b>PC${s.devices.length === 1 ? "" : "s"} failing</span>
    <span><b>${esc(String(s.impact))}</b>/10 Microsoft impact</span>
    ${s.user_impact ? '<span class="tag kev" title="Microsoft expects users may notice this change">may affect users: test first</span>' : ""}
    ${s.benchmarks ? `<span class="tag" title="Security standards that require this setting">${esc(s.benchmarks)}</span>` : ""}`;
  const pcs = s.devices.map(d => `<div style="margin-top:6px"><b>${esc(d.name)}</b> <span class="tag">${esc(d.opco)}</span>
    ${d.context ? `<div class="folders" style="white-space:pre-wrap;padding-left:0;margin-top:4px">${esc(d.context)}</div>` : ""}</div>`).join("");
  const links = (ms.links || []).map(u => `<li><a href="${esc(u)}" target="_blank" rel="noopener noreferrer" style="color:var(--s1)">${esc(u.replace(/^https:\/\//, "").slice(0, 80))}</a></li>`).join("");
  return `<div class="fix" style="--acc:var(${URG_VAR[s.urgency.level]})">
    <div class="hd"><span class="rk">#${rank}</span><div><h3>${esc(s.app)}</h3><div class="v">${esc([s.category, s.subcategory].filter(Boolean).join(" · "))} · ${s.opcos.map(o => `<span class="tag">${esc(o)}</span>`).join(" ")}</div></div>
      <span class="urg l${s.urgency.level}">${esc(s.urgency.label)}</span></div>
    <div class="nums">${nums}</div>
    ${aiText(t, ai)}
    <div class="lbl">The fix · <span class="tag">${esc(s.fix_type)}</span></div>
    ${f.command ? `<p class="note" style="margin-top:2px">One PC: PowerShell as Administrator. Many PCs: Group Policy or Intune (see Microsoft's instructions).</p>${cmdBox(f.command)}` : `<p class="note">No single command: follow Microsoft's instructions below.</p>`}
    ${f.note ? `<p class="note" style="margin-top:6px">${esc(f.note)}</p>` : ""}
    ${stepsBlock(t, ai)}
    <details><summary>Microsoft's instructions</summary><div style="white-space:pre-wrap;margin-top:6px">${esc(ms.remediation || "Not provided.")}</div>${links ? `<ul class="folders">${links}</ul>` : ""}</details>
    <details><summary>Which PCs (${s.devices.length}) and Defender's details</summary>${pcs}</details>
    ${cardFoot(s, f.url, "Microsoft docs")}
  </div>`;
}

// ---------- page: data health ----------
function renderHealth() {
  const r = D.run;
  $("runDesc").textContent = r ? `Run of ${r.run_date}, started ${String(r.started_at).replace("T", " ").slice(0, 16)} UTC` : "No run recorded yet";
  const exportAge = r && r.export_generated_time ? ((new Date(r.started_at) - new Date(r.export_generated_time)) / 3600000).toFixed(1) + " h" : "–";
  $("runFacts").innerHTML = r ? [
    [fmt(r.vulnerability_rows), "rows exported"], [r.defender_count == null ? "–" : fmt(r.defender_count), "rows in Defender (own count)"],
    [pct(r.coverage), "coverage"], [fmt(r.machines), "devices"], [`${r.duration_seconds} s`, "run time"], [fmt(r.retries), "retries needed"],
    [exportAge, "export age at run"], [fmt(r.change_rows), "change events"], [esc(r.quality || "–"), "quality result"]]
    .map(([v, l]) => `<div><b>${v}</b><span>${l}</span></div>`).join("") : "";
  const P = D.posture;
  $("postureDesc").textContent = P ? `Download of ${P.run_date}: Defender's security-configuration checks and end-of-support software` : "Not downloaded yet (runs before 5 Oct)";
  $("postureFacts").innerHTML = P ? [
    [P.config ? fmt(P.config.rows) : "–", "setting readings downloaded"], [P.config ? esc(P.config.method) : "failed", "settings method"],
    [P.compliance == null ? "–" : pct(P.compliance), "settings OK (latest)"], [fmt(P.failing), "settings failing (PC × setting)"],
    [P.eos ? fmt(P.eos.rows) : "–", "end-of-support installs"], [P.eos ? esc(P.eos.method) : "failed", "end-of-support method"]]
    .map(([v, l]) => `<div><b>${v}</b><span>${l}</span></div>`).join("") +
    ((P.errors || []).length ? `<div style="grid-column:1/-1"><b style="color:var(--warn)">Problems</b><span>${P.errors.map(esc).join(" · ")}</span></div>` : "") : "";
  const counts = s => D.dq.filter(c => c.status === s).length;
  $("dqDesc").textContent = `${counts("PASS")} passed · ${counts("WARN")} warnings · ${counts("FAIL")} failed`;
  $("dqList").innerHTML = D.dq.map(c => { const [cls, sym] = ICON[c.status] || ICON.INFO;
    return `<li><span class="ic ${cls}">${sym}</span><div><b>${LABEL[c.name] || esc(c.name)}</b> <span>${esc(c.value)} (expected ${esc(c.expected)})</span>
      ${c.status === "WARN" || c.status === "FAIL" ? `<div style="color:var(--ink-2);margin-top:2px">${esc(c.message)}</div>` : ""}</div></li>`; }).join("");
  $("histTbl").innerHTML = `<tr><th>Date</th><th class="num">Rows</th><th class="num">Defender count</th><th class="num">Coverage</th><th class="num">Devices</th>
    <th class="num">Run time</th><th>Quality</th></tr>` + [...D.runs].reverse().map(h => `<tr><td>${esc(h.run_date)}</td><td class="num">${fmt(h.vulnerability_rows)}</td>
      <td class="num">${h.defender_count == null ? "–" : fmt(h.defender_count)}</td><td class="num">${pct(h.coverage)}</td><td class="num">${fmt(h.machines)}</td>
      <td class="num">${h.duration_seconds} s</td><td>${esc(h.quality || "–")}</td></tr>`).join("");
  $("mapTbl").innerHTML = `<tr><th>Device</th><th>OpCo</th><th>Device group</th><th>Tags</th><th>Advice</th></tr>` +
    DEV.map(d => `<tr><td>${esc(d.name)}</td><td>${esc(d.opco)}</td><td>${esc(d.rbac_group_name || "Unassigned")}</td>
      <td>${(d.tags || []).map(t => `<span class="tag">${esc(t)}</span>`).join(" ") || "–"}</td>
      <td>${d.opco === "UNMAPPED" ? "Add an OpCo tag in Defender or a rule in config/opco_mapping.csv"
           : (d.tags || []).length ? "OK" : "Mapped by name; adding an OpCo tag in Defender makes it explicit"}</td></tr>`).join("");
}

// ---------- live mode (only when opened through `python -m uc3 serve`) ----------
function liveMode() {
  if (!window.UC3_LIVE) return;
  const pill = document.createElement("span"), btn = document.createElement("button");
  pill.className = "pill"; btn.className = "btn"; btn.textContent = "⟳ Refresh from Defender now";
  $("themeBtn").before(pill, btn);
  let fast = false, timer = null;
  const when = t => t ? new Date(t).toLocaleString("en-GB", {day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit"}) : "–";
  async function poll() {
    try {
      const s = await (await fetch("/api/status", {cache: "no-store"})).json();
      if (s.dashboard_mtime > window.UC3_LIVE.mtime) { location.reload(); return; }
      btn.disabled = s.running;
      if (s.running) {
        pill.innerHTML = `<span class="dot w"></span>Fetching from Defender… ${esc(s.step)}`;
      } else {
        const last = s.last_run;
        const bad = s.last_outcome === "error" || s.last_outcome === "quality_failed";
        pill.innerHTML = `<span class="dot ${bad ? "f" : ""}"></span>Live · last fetch ${esc(when(last && last.run_at))}` +
          (s.last_outcome && s.last_outcome !== "published" ? ` · ${esc(s.last_message)}` : "");
        if (fast && !s.running) { fast = false; schedule(); }
      }
    } catch (e) {
      pill.innerHTML = `<span class="dot f"></span>Live server not reachable (was it stopped?)`;
    }
  }
  function schedule() { clearInterval(timer); timer = setInterval(poll, fast ? 2000 : 15000); }
  btn.onclick = async () => {
    btn.disabled = true;
    const r = await fetch("/api/refresh", {method: "POST", headers: {"X-UC3": "refresh"}});
    fast = true; schedule(); poll();
    if (r.status === 409) pill.innerHTML = `<span class="dot w"></span>A fetch is already running…`;
  };
  schedule(); poll();
}

// ---------- start ----------
const RENDER = {overview: renderOverview, opco: renderOpco, risks: renderRisks, age: renderAge, trends: renderTrends,
                devices: renderDevices, fixes: renderFixes, health: renderHealth};
function render() { RENDER[state.page](); requestAnimationFrame(() => Object.values(charts).forEach(c => c.resize())); }
window.addEventListener("resize", () => Object.values(charts).forEach(c => c.resize()));
window.addEventListener("hashchange", () => { const p = location.hash.slice(1); if (p !== state.page) go(p); });
try { const t = localStorage.getItem("uc3-theme"); if (t) { document.documentElement.dataset.theme = t; $("themeBtn").textContent = t === "dark" ? "Switch to light" : "Switch to dark"; } } catch (e) { /* ignore */ }
header(); filters(); liveMode(); go(location.hash.slice(1) || "overview");
