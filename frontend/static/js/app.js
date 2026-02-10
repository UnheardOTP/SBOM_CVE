/**
 * SBOM CVE Scanner — Frontend JS
 * Handles SBOM upload, manual entry, results display, history
 */

'use strict';

// ─── State ────────────────────────────────────────────────────────────────────
const state = {
  manualComponents: [],
  currentCves: [],
  activeFilter: 'ALL',
};

// ─── DOM References ───────────────────────────────────────────────────────────
const views = {
  scan:    document.getElementById('view-scan'),
  results: document.getElementById('view-results'),
  history: document.getElementById('view-history'),
};

const els = {
  companyName:   document.getElementById('company-name'),
  dropZone:      document.getElementById('drop-zone'),
  fileInput:     document.getElementById('file-input'),
  fileSelected:  document.getElementById('file-selected'),
  mName:         document.getElementById('m-name'),
  mVersion:      document.getElementById('m-version'),
  mEcosystem:    document.getElementById('m-ecosystem'),
  btnAdd:        document.getElementById('btn-add-component'),
  componentList: document.getElementById('component-list'),
  btnScan:       document.getElementById('btn-scan'),
  btnScanText:   document.getElementById('btn-scan-text'),
  scanProgress:  document.getElementById('scan-progress'),
  progressBar:   document.getElementById('progress-bar'),
  progressLabel: document.getElementById('progress-label'),
  btnBack:       document.getElementById('btn-back'),
  resultsCompany:document.getElementById('results-company'),
  resultsMeta:   document.getElementById('results-meta'),
  resultsSummary:document.getElementById('results-summary'),
  cveTbody:      document.getElementById('cve-tbody'),
  cveSearch:     document.getElementById('cve-search'),
  noResults:     document.getElementById('no-results'),
  historyGrid:   document.getElementById('history-grid'),
};

// ─── View Switching ───────────────────────────────────────────────────────────
function showView(name) {
  Object.entries(views).forEach(([k, el]) => {
    el.classList.toggle('active', k === name);
  });
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.view === name);
  });
  if (name === 'history') loadHistory();
}

document.querySelectorAll('.nav-btn').forEach(btn => {
  btn.addEventListener('click', () => showView(btn.dataset.view));
});

els.btnBack.addEventListener('click', () => showView('scan'));

// ─── File Upload ──────────────────────────────────────────────────────────────
els.dropZone.addEventListener('click', () => els.fileInput.click());

els.dropZone.addEventListener('dragover', e => {
  e.preventDefault();
  els.dropZone.classList.add('drag-over');
});
els.dropZone.addEventListener('dragleave', () => els.dropZone.classList.remove('drag-over'));
els.dropZone.addEventListener('drop', e => {
  e.preventDefault();
  els.dropZone.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) setSelectedFile(file);
});

els.fileInput.addEventListener('change', () => {
  if (els.fileInput.files[0]) setSelectedFile(els.fileInput.files[0]);
});

function setSelectedFile(file) {
  els.fileInput._selectedFile = file;
  els.fileSelected.textContent = `✓ ${file.name}  (${formatBytes(file.size)})`;
  els.fileSelected.classList.remove('hidden');
}

function formatBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / (1024 * 1024)).toFixed(1) + ' MB';
}

// ─── Manual Component Entry ───────────────────────────────────────────────────
els.btnAdd.addEventListener('click', addManualComponent);

[els.mName, els.mVersion, els.mEcosystem].forEach(input => {
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') addManualComponent();
  });
});

function addManualComponent() {
  const name = els.mName.value.trim();
  if (!name) { els.mName.focus(); return; }

  const comp = {
    name,
    version:   els.mVersion.value.trim() || null,
    ecosystem: els.mEcosystem.value.trim() || null,
  };

  state.manualComponents.push(comp);
  renderComponentList();

  els.mName.value = '';
  els.mVersion.value = '';
  els.mEcosystem.value = '';
  els.mName.focus();
}

function removeManualComponent(idx) {
  state.manualComponents.splice(idx, 1);
  renderComponentList();
}

function renderComponentList() {
  els.componentList.innerHTML = '';
  state.manualComponents.forEach((c, i) => {
    const item = document.createElement('div');
    item.className = 'component-item';
    item.innerHTML = `
      <div class="component-item-info">
        <span class="comp-name">${escHtml(c.name)}</span>
        ${c.version   ? `<span class="comp-ver">${escHtml(c.version)}</span>` : ''}
        ${c.ecosystem ? `<span class="comp-eco">${escHtml(c.ecosystem)}</span>` : ''}
      </div>
      <button class="comp-remove" title="Remove" data-idx="${i}">✕</button>
    `;
    item.querySelector('.comp-remove').addEventListener('click', () => removeManualComponent(i));
    els.componentList.appendChild(item);
  });
}

// ─── Scan ─────────────────────────────────────────────────────────────────────
els.btnScan.addEventListener('click', initiateScan);

async function initiateScan() {
  const company = els.companyName.value.trim() || 'Unknown';
  const hasFile = els.fileInput._selectedFile;
  const hasManual = state.manualComponents.length > 0;

  if (!hasFile && !hasManual) {
    alert('Please upload a SBOM file or add at least one component manually.');
    return;
  }

  // Disable UI
  els.btnScan.disabled = true;
  els.btnScanText.textContent = 'SCANNING...';
  els.scanProgress.classList.remove('hidden');
  setProgress(10, 'Connecting to NVD...');

  try {
    let result;

    if (hasFile) {
      result = await scanFile(els.fileInput._selectedFile, company);
    } else {
      result = await scanManual(state.manualComponents, company);
    }

    console.log('[DEBUG] Scan result:', result);
    setProgress(100, 'Scan complete.');
    await sleep(400);
    console.log('[DEBUG] Calling displayResults...');
    displayResults(result, company);
    console.log('[DEBUG] Showing results view...');
    showView('results');

  } catch (err) {
    console.error('[DEBUG] Scan error:', err);
    alert(`Scan failed: ${err.message}`);
  } finally {
    els.btnScan.disabled = false;
    els.btnScanText.textContent = 'INITIATE SCAN';
    els.scanProgress.classList.add('hidden');
    setProgress(0, '');
  }
}

async function scanFile(file, company) {
  setProgress(30, `Parsing ${file.name}...`);
  const formData = new FormData();
  formData.append('file', file);
  formData.append('company_name', company);

  setProgress(50, 'Querying NVD for CVEs...');
  const resp = await fetch('/api/scan/upload', { method: 'POST', body: formData });
  if (!resp.ok) {
    const err = await resp.json();
    throw new Error(err.detail || 'Upload scan failed.');
  }
  setProgress(90, 'Processing results...');
  return resp.json();
}

async function scanManual(components, company) {
  setProgress(30, 'Preparing component list...');
  setProgress(50, 'Querying NVD for CVEs...');

  const resp = await fetch('/api/scan/manual', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ components, company_name: company }),
  });
  if (!resp.ok) {
    const err = await resp.json();
    throw new Error(err.detail || 'Manual scan failed.');
  }
  setProgress(90, 'Processing results...');
  return resp.json();
}

function setProgress(pct, label) {
  els.progressBar.style.width = `${pct}%`;
  els.progressLabel.textContent = label;
}

// ─── Results Display ──────────────────────────────────────────────────────────
function displayResults(data, company) {
  console.log('[DEBUG] displayResults called with:', data);
  state.currentCves = data.cves || [];
  state.activeFilter = 'ALL';

  // Header
  els.resultsCompany.textContent = company.toUpperCase();
  els.resultsMeta.textContent =
    `SCAN #${data.scan_id} · ${data.component_count} components · ${data.cve_count} CVEs found · ${new Date().toLocaleString()}`;

  // Summary badges
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  state.currentCves.forEach(c => {
    if (counts[c.severity] !== undefined) counts[c.severity]++;
  });
  console.log('[DEBUG] Severity counts:', counts);

  els.resultsSummary.innerHTML = Object.entries(counts).map(([sev, n]) => `
    <div class="sev-badge badge-${sev.toLowerCase()}">
      <span class="sev-badge-count">${n}</span>
      <span class="sev-badge-label">${sev}</span>
    </div>
  `).join('');

  // Reset filters
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.sev === 'ALL');
  });
  els.cveSearch.value = '';

  renderCveTable();
}

function renderCveTable() {
  const searchTerm = els.cveSearch.value.toLowerCase();
  const filtered = state.currentCves.filter(cve => {
    const sevMatch = state.activeFilter === 'ALL' || cve.severity === state.activeFilter;
    const searchMatch = !searchTerm ||
      cve.cve_id.toLowerCase().includes(searchTerm) ||
      cve.component.toLowerCase().includes(searchTerm) ||
      (cve.description || '').toLowerCase().includes(searchTerm);
    return sevMatch && searchMatch;
  });

  els.cveTbody.innerHTML = '';

  if (filtered.length === 0) {
    els.noResults.classList.remove('hidden');
    return;
  }

  els.noResults.classList.add('hidden');

  filtered.forEach(cve => {
    const tr = document.createElement('tr');
    const score = cve.cvss_score != null ? parseFloat(cve.cvss_score).toFixed(1) : '—';
    const scoreClass = cve.cvss_score >= 9 ? 'critical' : cve.cvss_score >= 7 ? 'high' : cve.cvss_score >= 4 ? 'medium' : cve.cvss_score > 0 ? 'low' : 'none';
    const affectedVers = (cve.affected_versions || []).slice(0, 2).join(', ') || '—';
    const sev = (cve.severity || 'UNKNOWN').toUpperCase();

    tr.innerHTML = `
      <td class="td-cve">
        <a href="${escHtml(cve.nvd_url)}" target="_blank" rel="noopener">${escHtml(cve.cve_id)}</a>
      </td>
      <td class="td-component">${escHtml(cve.component)}</td>
      <td class="td-version">${escHtml(cve.component_version || '—')}</td>
      <td><span class="sev-pill sev-${sev}">${sev}</span></td>
      <td><span class="score-val score-${scoreClass}">${score}</span></td>
      <td class="td-affected">${escHtml(affectedVers)}</td>
      <td class="td-published">${escHtml(cve.published || '—')}</td>
      <td class="td-link"><a href="${escHtml(cve.nvd_url)}" target="_blank" rel="noopener">NVD ↗</a></td>
    `;
    els.cveTbody.appendChild(tr);
  });
}

// Filter buttons
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    state.activeFilter = btn.dataset.sev;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    renderCveTable();
  });
});

// Search
els.cveSearch.addEventListener('input', renderCveTable);

// ─── Scan History ─────────────────────────────────────────────────────────────
async function loadHistory() {
  els.historyGrid.innerHTML = '<div class="loading-msg">Loading scan history...</div>';
  try {
    const resp = await fetch('/api/scans');
    const data = await resp.json();
    renderHistory(data.scans || []);
  } catch (e) {
    els.historyGrid.innerHTML = '<div class="loading-msg">Failed to load history.</div>';
  }
}

function renderHistory(scans) {
  if (!scans.length) {
    els.historyGrid.innerHTML = '<div class="loading-msg">No scans yet. Run your first scan!</div>';
    return;
  }

  els.historyGrid.innerHTML = scans.map(s => `
    <div class="history-card" data-scan-id="${s.id}">
      <div class="hcard-company">${escHtml(s.company_name)}</div>
      <div class="hcard-meta">Scan #${s.id} · ${new Date(s.scan_date).toLocaleString()}</div>
      <div class="hcard-stats">
        <div class="hcard-stat">
          <span class="hcard-stat-num">${s.component_count}</span>
          <span class="hcard-stat-label">COMPONENTS</span>
        </div>
        <div class="hcard-stat">
          <span class="hcard-stat-num ${s.cve_count > 0 ? 'has-cves' : ''}">${s.cve_count}</span>
          <span class="hcard-stat-label">CVEs FOUND</span>
        </div>
      </div>
    </div>
  `).join('');

  els.historyGrid.querySelectorAll('.history-card').forEach(card => {
    card.addEventListener('click', () => loadHistoryScan(parseInt(card.dataset.scanId)));
  });
}

async function loadHistoryScan(scanId) {
  try {
    const resp = await fetch(`/api/scans/${scanId}`);
    const data = await resp.json();
    const company = data.scan.company_name;

    state.currentCves = data.cves.map(c => ({
      ...c,
      affected_versions: typeof c.affected_versions === 'string'
        ? JSON.parse(c.affected_versions)
        : (c.affected_versions || []),
    }));

    displayResults({
      scan_id: scanId,
      component_count: data.components.length,
      cve_count: data.cves.length,
      cves: state.currentCves,
    }, company);

    showView('results');
  } catch (e) {
    alert('Failed to load scan details.');
  }
}

// ─── Utils ────────────────────────────────────────────────────────────────────
function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
