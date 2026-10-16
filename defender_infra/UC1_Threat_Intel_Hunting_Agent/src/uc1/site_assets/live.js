// UC1 website: live control shown on every page. Polls /api/status, starts runs, reloads when new data arrives.
(() => {
  const here = location.pathname;
  const box = document.createElement("div");
  box.className = "uc1-live";
  box.setAttribute("role", "status");
  box.innerHTML = `<span class="ldot"></span><span class="ltext">Live</span>
    ${here === "/" ? "" : '<a href="/">Command Centre</a>'}
    ${here === "/reports" ? "" : '<a href="/reports">Reports</a>'}
    ${here === "/fix" ? "" : '<a href="/fix">Fix Centre</a>'}
    <button type="button">▶ Run now</button>`;
  document.body.appendChild(box);
  const text = box.querySelector(".ltext"), btn = box.querySelector("button");
  const baseline = (window.UC1_LIVE && window.UC1_LIVE.mtime) || 0;
  let newData = false;

  function show(s) {
    box.classList.toggle("busy", s.running || s.scheduled_running);
    box.classList.toggle("err", !s.running && s.last_outcome && s.last_outcome !== "ok");
    btn.disabled = s.running || s.scheduled_running;
    if (s.running) text.textContent = "Running… " + (s.step || "");
    else if (s.scheduled_running) text.textContent = "A scheduled run is in progress; this page updates when it's done";
    else if (s.last_message) text.textContent = s.last_message;
    else if (s.last_run) text.textContent = `Live · last run ${String(s.last_run.finished_at || s.last_run.started_at || "").replace("T", " ").slice(5, 16)} UTC · ${s.last_run.status}`;
    else text.textContent = "Live";
    if (s.dashboard_mtime > baseline + 0.5 && !newData) {
      newData = true;
      if (here === "/") { location.reload(); return; }
      text.innerHTML = 'New data available · <a href="">reload</a>';
    }
  }
  async function poll() {
    try { show(await (await fetch("/api/status", {cache: "no-store"})).json()); }
    catch (e) { box.classList.add("err"); text.textContent = "Website stopped (start it again with: python -m uc1 serve)"; }
  }
  btn.addEventListener("click", async () => {
    btn.disabled = true; text.textContent = "Starting…";
    try {
      const r = await fetch("/api/run", {method: "POST", headers: {"X-UC1": "run"}});
      const s = await r.json(); show(s); if (!s.started) text.textContent = s.message;
    } catch (e) { text.textContent = "Could not start the run"; }
  });
  poll(); setInterval(poll, 4000);
})();
