(() => {
  const data = window.MCP_GUARD_DEMO;
  const byId = (id) => document.getElementById(id);
  const esc = (value) => String(value).replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
  const asCode = (value) => esc(typeof value === "string" ? value : JSON.stringify(value, null, 2));
  const locationText = (loc) => loc.file ? `${loc.file}:${loc.line}:${loc.column}` : loc.pointer;

  function renderFinding(finding, index) {
    const locations = finding.locations.map(locationText).join(" · ");
    const evidenceLabel = finding.evidenceType === "static-pattern" ? "SOURCE EVIDENCE" : "DESCRIPTOR EVIDENCE";
    return `<details class="finding-card" ${index === 0 ? "open" : ""}>
      <summary><span class="rule-pill">${esc(finding.ruleId)}</span><span class="severity severity-${esc(finding.severity)}">${esc(finding.severity)}</span><span class="finding-title">${esc(finding.title)}</span><span class="finding-location">${esc(locations)}</span><span class="chevron" aria-hidden="true">⌄</span></summary>
      <div class="finding-body">
        <p class="observed">${esc(finding.observed)}</p>
        <div class="evidence-box"><div class="evidence-label"><span>${evidenceLabel}</span><button class="copy-evidence" type="button" data-copy="${esc(finding.evidence)}" aria-label="Copy evidence: ${esc(finding.evidence)}">Copy</button></div><code>${esc(finding.evidence)}</code></div>
        <div class="finding-explain"><div><b>WHY IT MATTERS</b><p>${esc(finding.why)}</p></div><div><b>REVIEW STEP</b><p>${esc(finding.remediation)}</p></div></div>
        <details class="fine-print"><summary>Assumptions, limitations & record details</summary><div class="fine-print-content"><b>Assumptions</b>${finding.assumptions.length ? `<ul>${finding.assumptions.map(x=>`<li>${esc(x)}</li>`).join("")}</ul>` : "<p>None recorded.</p>"}<b>Limitations</b><ul>${finding.limitations.map(x=>`<li>${esc(x)}</li>`).join("")}</ul><div class="record-meta"><span>Confidence: ${esc(finding.confidence)}</span><span>Evidence type: ${esc(finding.evidenceType)}</span><span>Rule version: ${esc(finding.ruleVersion)}</span><span>Fingerprint: <code>${esc(finding.fingerprint)}</code></span></div></div></details>
      </div>
    </details>`;
  }

  byId("source-findings").innerHTML = data.source.findings.map(renderFinding).join("");
  byId("inventory-findings").innerHTML = data.inventory.findings.map(renderFinding).join("");
  byId("corrected-coverage").innerHTML = `<dl><dt>Target</dt><dd>${esc(data.corrected.target)}</dd><dt>Inspected</dt><dd>${esc(data.corrected.coverage.inspected.join(", "))}</dd><dt>Rules applied</dt><dd>${esc(data.corrected.coverage.rulesApplied.join(", "))}</dd><dt>Recognized tools</dt><dd>${data.corrected.coverage.recognizedTools}</dd><dt>Coverage</dt><dd>${data.corrected.coverage.complete ? "Complete within declared scope" : "Incomplete"}</dd><dt>Diagnostics</dt><dd>${data.corrected.coverage.diagnostics.length ? esc(data.corrected.coverage.diagnostics.join("; ")) : "None recorded"}</dd></dl>`;

  const before = data.drift.before, after = data.drift.after;
  byId("snapshot-rail").innerHTML = `<article class="snapshot-card"><span class="snapshot-label">BEFORE · FIXTURE SNAPSHOT</span><h4>${before.toolNames.map(esc).join(" · ")}</h4><p>lookup description: “${esc(before.lookupDescription)}”</p><p>Required input: <code>${before.required.map(esc).join(", ") || "none"}</code></p><code class="hash">SHA-256 ${esc(before.hash)}</code></article><div class="snapshot-arrow" aria-hidden="true">→</div><article class="snapshot-card snapshot-after"><span class="snapshot-label">AFTER · FIXTURE SNAPSHOT</span><h4>${after.toolNames.map(esc).join(" · ")}</h4><p>lookup description: “${esc(after.lookupDescription)}”</p><p>Required input: <code>${after.required.map(esc).join(", ") || "none"}</code></p><code class="hash">SHA-256 ${esc(after.hash)}</code></article>`;
  byId("drift-changes").innerHTML = data.drift.changes.map((change, index) => `<details class="drift-item" ${index === 0 ? "open" : ""}><summary><span class="drift-count">0${index+1}</span><span class="drift-kind">${esc(change.kind.replaceAll("-", " "))}</span><span class="drift-tool">${esc(change.tool || "inventory")}</span><span class="drift-path">${esc(change.pointer)}</span><span class="chevron" aria-hidden="true">⌄</span></summary><div class="drift-body"><div><b>BEFORE</b><pre>${change.before === undefined ? "—" : asCode(change.before)}</pre></div><div><b>AFTER</b><pre>${change.after === undefined ? "—" : asCode(change.after)}</pre></div></div></details>`).join("");

  const tabs = [...document.querySelectorAll('[role="tab"]')];
  const panels = [...document.querySelectorAll('[role="tabpanel"]')];
  function activate(tab, focus = false) {
    tabs.forEach(button => { const active = button === tab; button.setAttribute("aria-selected", String(active)); button.tabIndex = active ? 0 : -1; });
    panels.forEach(panel => { panel.hidden = panel.id !== tab.getAttribute("aria-controls"); });
    byId("tab-status").textContent = `${tab.querySelector("b").textContent} selected`;
    if (focus) tab.focus();
  }
  tabs.forEach((tab, i) => {
    tab.addEventListener("click", () => activate(tab));
    tab.addEventListener("keydown", event => {
      let next = i;
      if (event.key === "ArrowDown" || event.key === "ArrowRight") next = (i + 1) % tabs.length;
      else if (event.key === "ArrowUp" || event.key === "ArrowLeft") next = (i - 1 + tabs.length) % tabs.length;
      else if (event.key === "Home") next = 0;
      else if (event.key === "End") next = tabs.length - 1;
      else return;
      event.preventDefault(); activate(tabs[next], true);
    });
  });

  async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    const field = document.createElement("textarea"); field.value = text; field.style.position = "fixed"; field.style.opacity = "0"; document.body.append(field); field.select();
    const ok = document.execCommand("copy"); field.remove(); if (!ok) throw new Error("Clipboard unavailable");
  }
  document.addEventListener("click", async event => {
    const button = event.target.closest("[data-copy], #copy-install, #copy-demo"); if (!button) return;
    const text = button.id === "copy-install" ? byId("install-command").textContent : button.id === "copy-demo" ? ["git clone https://github.com/zayyanla-hash/mcp-guard.git", "cd mcp-guard", "npm ci --ignore-scripts", "npm run demo"].join("\n") : button.dataset.copy;
    const status = button.id === "copy-install" ? byId("copy-status") : null;
    try {
      await copyText(text);
      if (button.id === "copy-install") { byId("copy-label").textContent = "Copied"; status.textContent = "Release install and version check commands copied."; setTimeout(() => byId("copy-label").textContent = "Copy install steps", 1800); }
      else if (button.id === "copy-demo") { button.textContent = "Copied"; byId("copy-demo-status").textContent = "Source demo reproduction commands copied."; setTimeout(() => button.textContent = "Copy demo commands", 1800); }
      else { button.textContent = "Copied"; button.setAttribute("aria-label", "Evidence copied"); setTimeout(() => { button.textContent = "Copy"; button.removeAttribute("aria-label"); }, 1600); }
    } catch { if (status) status.textContent = "Copy failed. Select the command text and copy it manually."; if (button.id === "copy-demo") byId("copy-demo-status").textContent = "Copy failed. Select the demo commands and copy them manually."; }
  });
})();
