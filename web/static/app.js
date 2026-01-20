const $ = (id) => document.getElementById(id);

function badgeClass(status) {
  const s = (status || "").toUpperCase();
  if (s === "FAIL") return "fail";
  if (s === "WARN") return "warn";
  if (s === "PASS") return "pass";
  return "skip";
}

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderSummary(findings) {
  const counts = { FAIL: 0, WARN: 0, PASS: 0, SKIP: 0 };
  for (const f of findings) {
    const st = String(f.status || "").toUpperCase();
    if (counts[st] !== undefined) counts[st] += 1;
  }
  const pills = [];
  for (const key of ["FAIL", "WARN", "PASS", "SKIP"]) {
    pills.push(`<span class="pill">${key}: <b>${counts[key]}</b></span>`);
  }
  $("summaryPills").innerHTML = pills.join("");
}

function renderResults(resp) {
  const findings = resp.findings || [];
  renderSummary(findings);

  if (!findings.length) {
    $("results").classList.add("empty");
    $("results").innerHTML = `<p class="muted">No findings returned. Try removing filters or scan a workflow that violates a control.</p>`;
    return;
  }

  $("results").classList.remove("empty");

  const items = findings.map((f) => {
    const status = String(f.status || "").toUpperCase();
    const badge = badgeClass(status);
    const control = escapeHtml(f.control_id);
    const rule = escapeHtml(f.rule_id || "");
    const msg = escapeHtml(f.message || "");
    const sev = escapeHtml(f.severity || "");
    const file = escapeHtml(f.file_path || "");
    const line = (f.start_line == null) ? "n/a" : String(f.start_line);

    const explain = f.explain || {};
    const why = escapeHtml(explain.why || "");
    const detect = escapeHtml(explain.detect || "");
    const fix = escapeHtml(explain.fix || "");
    const verify = escapeHtml(explain.verify || "");
    const difficulty = escapeHtml(explain.difficulty || "");

    return `
      <div class="finding">
        <div class="findingTop">
          <div>
            <p class="findingTitle">${control} <span class="muted">(${rule})</span></p>
            <div class="findingMeta">
              <div><b>${status}</b> · Severity: <b>${sev}</b></div>
              <div>File: <code>${file}</code> · Line: <code>${line}</code></div>
              <div>${msg}</div>
            </div>
          </div>
          <span class="badge ${badge}">${status}</span>
        </div>

        <details class="details">
          <summary class="muted">Explain</summary>
          <div class="kv"><div class="k">Why</div><div class="v">${why}</div></div>
          <div class="kv"><div class="k">Detect</div><div class="v">${detect}</div></div>
          <div class="kv"><div class="k">Fix</div><div class="v">${fix}</div></div>
          <div class="kv"><div class="k">Verify</div><div class="v">${verify}</div></div>
          <div class="kv"><div class="k">Difficulty</div><div class="v">${difficulty}</div></div>
        </details>
      </div>
    `;
  });

  $("results").innerHTML = items.join("");
}

function setStatus(msg) {
  const el = $("statusBar");
  el.classList.remove("hidden");
  el.textContent = msg;
}

function clearStatus() {
  const el = $("statusBar");
  el.classList.add("hidden");
  el.textContent = "";
}

async function scanFile(file, level, onlyStatus) {
  const fd = new FormData();
  fd.append("file", file);
  fd.append("level", level);
  if (onlyStatus) fd.append("only_status", onlyStatus);

  const res = await fetch("/api/scan/file", { method: "POST", body: fd });
  const ct = res.headers.get("content-type") || "";
  const isJson = ct.includes("application/json");
  const body = isJson ? await res.json() : { error: "bad_response", message: await res.text() };

  if (!res.ok) {
    throw new Error(body?.message || "Request failed");
  }
  return body;
}

document.addEventListener("DOMContentLoaded", () => {
  const form = $("scanForm");
  const scanBtn = $("scanBtn");
  const clearBtn = $("clearBtn");

  clearBtn.addEventListener("click", () => {
    $("file").value = "";
    $("results").innerHTML = `<p class="muted">No scan results yet. Upload a workflow and click <b>Scan</b>.</p>`;
    $("results").classList.add("empty");
    $("summaryPills").innerHTML = "";
    clearStatus();
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearStatus();

    const fileInput = $("file");
    const file = fileInput.files && fileInput.files[0];
    const level = $("level").value || "L1";
    const onlyStatus = $("onlyStatus").value || "";

    if (!file) {
      setStatus("Please choose a YAML file first.");
      return;
    }

    scanBtn.disabled = true;
    setStatus("Scanning...");

    try {
      const resp = await scanFile(file, level, onlyStatus);
      setStatus(`Scan complete. Returned ${resp.findings?.length ?? 0} findings.`);
      renderResults(resp);
    } catch (err) {
      setStatus(`Scan failed: ${err?.message || err}`);
    } finally {
      scanBtn.disabled = false;
    }
  });
});
