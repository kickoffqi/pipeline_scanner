const $ = (id) => document.getElementById(id);

let currentWorkflowText = "";
let currentFilePath = "workflow.yml";
let currentMode = "upload";

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
  return counts;
}

function groupByControl(findings) {
  const map = new Map();
  for (const f of findings) {
    const key = f.control_id || "UNKNOWN";
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(f);
  }
  return Array.from(map.entries()).sort((a, b) => String(a[0]).localeCompare(String(b[0])));
}

function makeSnippet(text, lineNumber, context = 4) {
  const lines = (text || "").split("\n");
  const idx = Math.max(0, (lineNumber || 1) - 1);
  const start = Math.max(0, idx - context);
  const end = Math.min(lines.length - 1, idx + context);

  const out = [];
  for (let i = start; i <= end; i++) {
    const ln = i + 1;
    const content = lines[i] ?? "";
    const prefix = String(ln).padStart(4, " ") + " | ";
    if (ln === lineNumber) out.push(prefix + `<span class="hl">${escapeHtml(content)}</span>`);
    else out.push(prefix + escapeHtml(content));
  }
  return out.join("\n");
}

function renderFindingCard(f) {
  const status = String(f.status || "").toUpperCase();
  const badge = badgeClass(status);
  const control = escapeHtml(f.control_id);
  const rule = escapeHtml(f.rule_id || "");
  const msg = escapeHtml(f.message || "");
  const sev = escapeHtml(f.severity || "");
  const file = escapeHtml(f.file_path || currentFilePath || "");
  const line = (f.start_line == null) ? null : Number(f.start_line);

  const explain = f.explain || {};
  const why = escapeHtml(explain.why || "");
  const detect = escapeHtml(explain.detect || "");
  const fix = escapeHtml(explain.fix || "");
  const verify = escapeHtml(explain.verify || "");
  const difficulty = escapeHtml(explain.difficulty || "");

  const lineHtml = line == null
    ? `<code>n/a</code>`
    : `<button class="lineLink" type="button" data-line="${line}"><code>${line}</code></button>`;

  return `
    <div class="finding">
      <div class="findingTop">
        <div>
          <p class="findingTitle">${control} <span class="muted">(${rule})</span></p>
          <div class="findingMeta">
            <div><b>${status}</b> · Severity: <b>${sev}</b></div>
            <div>File: <code>${file}</code> · Line: ${lineHtml}</div>
            <div>${msg}</div>
          </div>
        </div>
        <span class="badge ${badge}">${status}</span>
      </div>

      <div class="snippet hidden"></div>

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
}

function wireSnippetHandlers() {
  document.querySelectorAll(".lineLink").forEach((btn) => {
    btn.addEventListener("click", () => {
      const line = Number(btn.dataset.line || "0");
      if (!line || !currentWorkflowText) return;

      const findingEl = btn.closest(".finding");
      if (!findingEl) return;
      const snip = findingEl.querySelector(".snippet");
      if (!snip) return;

      if (!snip.classList.contains("hidden")) {
        snip.classList.add("hidden");
        snip.innerHTML = "";
        return;
      }

      const snippet = makeSnippet(currentWorkflowText, line, 4);
      snip.innerHTML = `
        <div class="snippetHeader">
          <span>Source snippet (line ${line})</span>
          <button type="button" class="button secondary" style="padding:6px 10px; border-radius:999px;">Hide</button>
        </div>
        <pre class="snippetPre">${snippet}</pre>
      `;
      snip.classList.remove("hidden");

      const hideBtn = snip.querySelector("button");
      hideBtn.addEventListener("click", () => {
        snip.classList.add("hidden");
        snip.innerHTML = "";
      });
    });
  });
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

  const groups = groupByControl(findings);
  const groupHtml = groups.map(([controlId, items]) => {
    const c = { FAIL: 0, WARN: 0, PASS: 0, SKIP: 0 };
    for (const f of items) {
      const st = String(f.status || "").toUpperCase();
      if (c[st] !== undefined) c[st] += 1;
    }
    const open = (c.FAIL + c.WARN) > 0;
    const pills = `
      <span class="smallPills">
        <span class="smallPill">FAIL: <b>${c.FAIL}</b></span>
        <span class="smallPill">WARN: <b>${c.WARN}</b></span>
        <span class="smallPill">PASS: <b>${c.PASS}</b></span>
        <span class="smallPill">SKIP: <b>${c.SKIP}</b></span>
      </span>
    `;
    const cards = items.map(renderFindingCard).join("");
    return `
      <details class="controlGroup" ${open ? "open" : ""}>
        <summary class="controlSummary">
          <span class="controlTitle">${escapeHtml(controlId)}</span>
          ${pills}
        </summary>
        <div>${cards}</div>
      </details>
    `;
  }).join("");

  $("results").innerHTML = groupHtml;
  wireSnippetHandlers();
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

async function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ""));
    reader.onerror = () => reject(new Error("Failed to read file."));
    reader.readAsText(file);
  });
}

async function scanText(level, filePath, workflowText, onlyStatus) {
  const payload = { level, file_path: filePath, workflow: workflowText };
  if (onlyStatus) payload.only_status = onlyStatus;

  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  const ct = res.headers.get("content-type") || "";
  const body = ct.includes("application/json")
    ? await res.json()
    : { error: "bad_response", message: await res.text() };

  if (!res.ok) throw new Error(body?.message || "Request failed");
  return body;
}

function setMode(mode) {
  currentMode = mode;
  const up = $("uploadPanel");
  const pa = $("pastePanel");
  const tabUp = $("tabUpload");
  const tabPa = $("tabPaste");

  if (mode === "upload") {
    up.classList.remove("hidden");
    pa.classList.add("hidden");
    tabUp.classList.add("active");
    tabPa.classList.remove("active");
    tabUp.setAttribute("aria-selected", "true");
    tabPa.setAttribute("aria-selected", "false");
  } else {
    up.classList.add("hidden");
    pa.classList.remove("hidden");
    tabUp.classList.remove("active");
    tabPa.classList.add("active");
    tabUp.setAttribute("aria-selected", "false");
    tabPa.setAttribute("aria-selected", "true");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const form = $("scanForm");
  const scanBtn = $("scanBtn");
  const clearBtn = $("clearBtn");

  $("tabUpload").addEventListener("click", () => setMode("upload"));
  $("tabPaste").addEventListener("click", () => setMode("paste"));
  setMode("upload");

  clearBtn.addEventListener("click", () => {
    $("file").value = "";
    $("yamlText").value = "";
    currentWorkflowText = "";
    currentFilePath = "workflow.yml";
    $("results").innerHTML = `<p class="muted">No scan results yet. Upload a workflow or paste YAML and click <b>Scan</b>.</p>`;
    $("results").classList.add("empty");
    $("summaryPills").innerHTML = "";
    clearStatus();
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearStatus();

    const level = $("level").value || "L1";
    const onlyStatus = $("onlyStatus").value || "";

    scanBtn.disabled = true;
    setStatus("Scanning...");

    try {
      if (currentMode === "upload") {
        const file = $("file").files && $("file").files[0];
        if (!file) throw new Error("Please choose a YAML file first.");
        const text = await readFileAsText(file);
        if (!text.trim()) throw new Error("Uploaded file is empty.");
        currentWorkflowText = text;
        currentFilePath = file.name || "workflow.yml";
        const resp = await scanText(level, currentFilePath, currentWorkflowText, onlyStatus);
        setStatus(`Scan complete. Returned ${resp.findings?.length ?? 0} findings.`);
        renderResults(resp);
      } else {
        const text = $("yamlText").value || "";
        if (!text.trim()) throw new Error("Please paste YAML first.");
        currentWorkflowText = text;
        currentFilePath = "pasted.yml";
        const resp = await scanText(level, currentFilePath, currentWorkflowText, onlyStatus);
        setStatus(`Scan complete. Returned ${resp.findings?.length ?? 0} findings.`);
        renderResults(resp);
      }
    } catch (err) {
      setStatus(`Scan failed: ${err?.message || err}`);
    } finally {
      scanBtn.disabled = false;
    }
  });
});
