/**
 * Password Breach Monitoring (PBM) Intelligence Platform - Frontend Application
 * Interacts with Flask REST API and MySQL / MariaDB / SQLite backends.
 * Features enterprise threat telemetry, forensic case studies, multi-page executive dossier,
 * regulatory evidence registry, and sandboxed read-only SQL terminal.
 */

const titles = {
  dashboard: ['Threat Operations Center', 'Global cybersecurity incident and credential exposure workspace'],
  database: ['Incident Master Repository', 'Query, filter, and inspect verified historical data breaches and exposures'],
  'case-study': ['Forensic Autopsies', 'In-depth root cause and technical forensics post-mortems'],
  reports: ['Executive Intelligence Dossier', 'Comprehensive multi-page briefing and threat analysis across all documented incidents'],
  analytics: ['Exposure Metrics & Analytics', 'Empirical aggregate metrics calculated from historical breaches'],
  sql: ['SQL Terminal & Console', 'Interactive toggle query builder with safe read-only execution'],
  sources: ['Regulatory Evidence Registry', '100% authentic citations from regulatory enforcement dockets and advisories'],
  about: ['System Architecture & Governance', 'Enterprise cybersecurity threat modeling and intelligence platform']
};

let currentPage = 1;
const perPage = 10;
let currentSort = { by: 'breach_date', order: 'desc' };
let currentActiveReport = null;
let currentRawSourcesText = '';

// Toggleable SQL Builder State
let sqlState = {
  columns: ['id', 'organization', 'breach_date', 'affected_records', 'severity'],
  severity: '',
  industry: '',
  vector: '',
  sort: 'affected_records',
  order: 'DESC',
  limit: '10',
  customQuery: null
};

// Formatting Utilities
const fmt = n => new Intl.NumberFormat('en-US').format(n || 0);

function getBadgeClass(severity) {
  const s = (severity || '').toLowerCase();
  if (s === 'critical') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'medium') return 'medium';
  return 'low';
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => toast.remove(), 200);
  }, 2800);
}

function renderRow(b) {
  const badgeCls = getBadgeClass(b.severity);
  return `<tr data-id="${b.id}">
    <td class="mono subtle">${b.id}</td>
    <td class="org">${b.organization}</td>
    <td class="mono">${b.breach_date}</td>
    <td class="mono">${fmt(b.affected_records)}</td>
    <td><span class="badge ${badgeCls}">${(b.severity || '').toUpperCase()}</span></td>
    <td>${b.attack_vector}</td>
    <td><span class="badge status-badge">${(b.status || 'RESOLVED').toUpperCase()}</span></td>
  </tr>`;
}

function bindRowClicks(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.querySelectorAll('tr[data-id]').forEach(tr => {
    tr.onclick = () => fetchAndOpenModal(tr.dataset.id);
  });
}

// Navigation Engine
function navigate(id) {
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === id));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.view === id));
  
  if (titles[id]) {
    document.getElementById('pageTitle').textContent = titles[id][0];
    document.getElementById('pageSubtitle').textContent = titles[id][1];
  }

  const sidebar = document.getElementById('sidebar');
  if (sidebar) sidebar.classList.remove('open');
  const main = document.querySelector('main');
  if (main) main.scrollTop = 0;

  // Load view-specific data
  if (id === 'dashboard') loadDashboard();
  else if (id === 'database') loadDatabase();
  else if (id === 'case-study') {
    const sel = document.getElementById('caseStudySelect');
    loadCaseStudy(sel ? sel.value : 'PBM-EQFX');
  }
  else if (id === 'reports') loadReportView();
  else if (id === 'analytics') loadAnalytics();
  else if (id === 'sources') loadSourcesCatalog();
  else if (id === 'sql') {
    loadSqlExamples();
    updateSqlPreviewAndRun();
  }
}

// Modal Detail View
async function fetchAndOpenModal(breachId) {
  try {
    const res = await fetch(`/api/breaches/${breachId}`);
    const json = await res.json();
    if (json.status === 'success') {
      openModal(json.data);
    }
  } catch (err) {
    console.error('Error fetching breach detail:', err);
  }
}

function openModal(b) {
  if (!b) return;
  document.getElementById('modalId').textContent = b.id;
  document.getElementById('modalTitle').textContent = `${b.organization} — Incident Analysis`;
  document.getElementById('modalDetails').innerHTML = [
    ['Incident Date', b.breach_date],
    ['Discovery Date', b.discovery_date || b.breach_date],
    ['Records Compromised', fmt(b.affected_records)],
    ['Threat Severity', b.severity],
    ['Target Industry', b.industry],
    ['Incident Type', b.breach_type],
    ['Attack Vector', b.attack_vector],
    ['Containment Status', b.status]
  ].map(([lbl, val]) => `<div class="detail"><small>${lbl}</small><b>${val}</b></div>`).join('');
  
  document.getElementById('modalCopy').innerHTML = `
    <strong>Root Cause:</strong> ${b.root_cause}<br><br>
    <strong>Exposed Data Elements:</strong> ${b.data_exposed}
  `;

  const repBtn = document.getElementById('modalViewReportBtn');
  if (repBtn) {
    repBtn.style.display = 'inline-flex';
    repBtn.onclick = () => {
      closeModal();
      navigate('reports');
    };
  }

  const srcSection = document.getElementById('modalSourcesSection');
  const srcList = document.getElementById('modalSourcesList');
  if (b.sources && b.sources.length > 0) {
    srcSection.style.display = 'block';
    srcList.innerHTML = b.sources.map(s => `
      <div style="font-size:11.5px; margin-bottom:6px;">
        <strong>${s.authority_or_publisher} (${s.publication_year}):</strong> 
        <a href="${s.url}" target="_blank" rel="noopener noreferrer">${s.title}</a>
        ${s.citation_note ? `<br><small class="subtle">${s.citation_note}</small>` : ''}
      </div>
    `).join('');
  } else {
    srcSection.style.display = 'none';
  }

  document.getElementById('modal').classList.add('open');
}

function closeModal() {
  document.getElementById('modal').classList.remove('open');
}

// Dashboard Data Loading
async function loadDashboard() {
  try {
    const res = await fetch('/api/dashboard');
    const data = await res.json();
    if (data.status !== 'success') return;

    document.getElementById('dashTotalBreaches').textContent = fmt(data.total_breaches);
    document.getElementById('dashTotalRecords').textContent = data.total_records_formatted;
    document.getElementById('dashCriticalCount').textContent = fmt(data.critical_breaches);
    document.getElementById('dashCriticalPct').textContent = `${data.critical_percentage} of all incidents`;
    document.getElementById('dashLatestDate').textContent = data.latest_incident.breach_date || 'N/A';
    document.getElementById('dashLatestOrg').textContent = data.latest_incident.organization || 'N/A';

    // Render Recent Table
    document.getElementById('recentRows').innerHTML = data.recent_activity.map(renderRow).join('');
    bindRowClicks('recentRows');

    // Render Line Chart
    renderDashboardLineChart(data.by_year);

    // Render Donut
    renderDashboardDonut(data.total_breaches, data.severity_distribution, data.severity_percentages);
  } catch (err) {
    console.error('Failed to load dashboard data:', err);
  }
}

function renderDashboardLineChart(byYearData) {
  if (!byYearData || !byYearData.length) return;

  const chartG = document.getElementById('dashChartContent');
  const years = byYearData.map(d => d.year);
  const counts = byYearData.map(d => d.count);
  const maxCount = Math.max(...counts, 8);
  
  const xStart = 40, xEnd = 625, yTop = 20, yBottom = 135;
  const widthSpan = xEnd - xStart;
  const heightSpan = yBottom - yTop;

  const points = byYearData.map((d, i) => {
    const x = xStart + (i / Math.max(1, years.length - 1)) * widthSpan;
    const y = yBottom - (d.count / maxCount) * heightSpan;
    return { x, y, year: d.year, count: d.count };
  });

  const pathD = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ');
  const areaD = `${pathD} L${points[points.length - 1].x.toFixed(1)} ${yBottom} L${points[0].x.toFixed(1)} ${yBottom}Z`;

  let gridLines = '';
  for (let step = 0; step <= 3; step++) {
    const y = yBottom - (step / 3) * heightSpan;
    const val = Math.round((step / 3) * maxCount);
    gridLines += `<line class="grid-line" x1="35" y1="${y}" x2="630" y2="${y}"/><text class="chart-label" x="8" y="${y + 4}">${val}</text>`;
  }

  let labels = '<g class="chart-label">';
  points.forEach((p, idx) => {
    if (points.length > 8 && idx % 2 !== 0 && idx !== points.length - 1) return;
    labels += `<text x="${(p.x - 12).toFixed(1)}" y="154">${p.year}</text>`;
  });
  labels += '</g>';

  let dots = points.map(p => `<circle class="dot" cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="4"><title>${p.year}: ${p.count} major breaches</title></circle>`).join('');

  chartG.innerHTML = `
    ${gridLines}
    <path class="area" d="${areaD}"/>
    <path class="line" d="${pathD}"/>
    ${labels}
    ${dots}
  `;
}

function renderDashboardDonut(total, dist, pcts) {
  const donut = document.getElementById('dashDonut');
  if (donut) {
    donut.setAttribute('data-center', `${total}\nincidents`);
    const cPct = pcts.Critical || 0;
    const hPct = cPct + (pcts.High || 0);
    const mPct = hPct + (pcts.Medium || 0);
    donut.style.background = `conic-gradient(var(--red) 0% ${cPct}%, var(--amber) ${cPct}% ${hPct}%, var(--blue) ${hPct}% ${mPct}%, var(--green) ${mPct}% 100%)`;
  }

  const legend = document.getElementById('dashDonutLegend');
  if (legend) {
    legend.innerHTML = `
      <div class="legend-row"><i class="swatch" style="background:var(--red)"></i><span>Critical</span><b>${pcts.Critical || 0}%</b></div>
      <div class="legend-row"><i class="swatch" style="background:var(--amber)"></i><span>High</span><b>${pcts.High || 0}%</b></div>
      <div class="legend-row"><i class="swatch" style="background:var(--blue)"></i><span>Medium</span><b>${pcts.Medium || 0}%</b></div>
      <div class="legend-row"><i class="swatch" style="background:var(--green)"></i><span>Low</span><b>${pcts.Low || 0}%</b></div>
    `;
  }
}

// Breach Database View & Filtering
async function loadDatabase() {
  const q = document.getElementById('dbSearch').value;
  const severity = document.getElementById('severityFilter').value;
  const year = document.getElementById('yearFilter').value;
  const industry = document.getElementById('industryFilter').value;

  const params = new URLSearchParams({
    q: q,
    severity: severity,
    year: year,
    industry: industry,
    page: currentPage,
    per_page: perPage,
    sort_by: currentSort.by,
    sort_order: currentSort.order
  });

  try {
    const res = await fetch(`/api/breaches?${params}`);
    const data = await res.json();
    if (data.status !== 'success') return;

    const rows = data.data;
    const tbody = document.getElementById('databaseRows');

    if (rows.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty">No matching incident records found in repository</td></tr>';
    } else {
      tbody.innerHTML = rows.map(renderRow).join('');
      bindRowClicks('databaseRows');
    }

    document.getElementById('recordCount').textContent = `${data.total} RECORD${data.total === 1 ? '' : 'S'}`;
    
    const start = data.total === 0 ? 0 : (data.page - 1) * perPage + 1;
    const end = Math.min(data.page * perPage, data.total);
    document.getElementById('pageInfo').textContent = data.total ? `Showing ${start}–${end} of ${data.total}` : 'Showing 0 records';

    renderPaginationControls(data.page, data.total_pages);
  } catch (err) {
    console.error('Error loading incident database:', err);
  }
}

function renderPaginationControls(page, totalPages) {
  const controls = document.getElementById('pageNumbers');
  if (!controls) return;

  let btns = '';
  for (let i = 1; i <= totalPages; i++) {
    const activeStyle = i === page ? 'style="border-color:var(--primary); background:var(--primary-light); color:var(--primary); font-weight:700;"' : '';
    btns += `<button class="icon-btn" ${activeStyle} onclick="changePage(${i})">${i}</button>`;
  }
  controls.innerHTML = btns;

  const prevBtn = document.getElementById('prevPageBtn');
  const nextBtn = document.getElementById('nextPageBtn');
  if (prevBtn) prevBtn.onclick = () => { if (currentPage > 1) changePage(currentPage - 1); };
  if (nextBtn) nextBtn.onclick = () => { if (currentPage < totalPages) changePage(currentPage + 1); };
}

function changePage(p) {
  currentPage = p;
  loadDatabase();
}

// Case Study View
async function loadCaseStudy(breachId = 'PBM-EQFX') {
  try {
    const res = await fetch(`/api/case-studies/${breachId}`);
    const json = await res.json();
    if (json.status !== 'success') return;

    const cs = json.data;
    document.getElementById('caseEyebrow').textContent = `Investigation ${cs.breach_id} · Post-Mortem`;
    document.getElementById('caseTitle').textContent = cs.title;
    document.getElementById('caseSubtitle').textContent = cs.subtitle;
    
    const badge = document.getElementById('caseSeverityBadge');
    badge.className = `badge ${getBadgeClass(cs.severity)}`;
    badge.textContent = cs.severity.toUpperCase();

    document.getElementById('caseExecSummary').textContent = cs.executive_summary;
    document.getElementById('caseResponse').textContent = cs.response;
    document.getElementById('caseRootCause').textContent = cs.root_cause;
    document.getElementById('caseLessons').textContent = cs.lessons_learned;

    // Timeline
    const timelineEl = document.getElementById('caseTimeline');
    timelineEl.innerHTML = (cs.timeline || []).map(ev => `
      <div class="event">
        <time>${ev.time}</time>
        <strong>${ev.title}</strong>
        <p>${ev.description}</p>
      </div>
    `).join('');

    // Tags
    document.getElementById('caseVectorTags').innerHTML = (cs.attack_vector_tags || [])
      .map(t => `<span class="tag">${t}</span>`).join('');

    document.getElementById('caseDataTags').innerHTML = (cs.data_exposed_tags || [])
      .map(t => `<span class="tag">${t}</span>`).join('');

    // Impact Metrics
    const metrics = cs.impact_metrics || {};
    document.getElementById('caseImpactMetrics').innerHTML = `
      <div class="metric"><b>${metrics.records || 'N/A'}</b><small>Records Compromised</small></div>
      <div class="metric"><b>${metrics.exposure_window || 'N/A'}</b><small>Exposure Window</small></div>
      <div class="metric"><b>${metrics.regulatory_fines || metrics.financial_impact || 'Settled'}</b><small>Regulatory Penalty</small></div>
      <div class="metric"><b>${metrics.plaintext_passwords || '0'}</b><small>Plaintext Passwords</small></div>
    `;

    // Sources list
    const srcListEl = document.getElementById('caseSourcesList');
    if (cs.sources && cs.sources.length > 0) {
      srcListEl.innerHTML = cs.sources.map(s => `
        <div style="margin-bottom:6px;">
          <strong>${s.authority_or_publisher} (${s.publication_year}):</strong><br>
          <a href="${s.url}" target="_blank" rel="noopener noreferrer">${s.title}</a>
          ${s.citation_note ? `<br><small class="subtle">${s.citation_note}</small>` : ''}
        </div>
      `).join('');
    } else {
      srcListEl.innerHTML = '<span class="subtle">Verified against public regulatory dockets and filings.</span>';
    }

    const select = document.getElementById('caseStudySelect');
    if (select && select.value !== breachId) {
      select.value = breachId;
    }
  } catch (err) {
    console.error('Error loading case study:', err);
  }
}

// CONSOLIDATED 8-PAGE EXECUTIVE INTELLIGENCE DOSSIER
async function loadReportView() {
  const contentEl = document.getElementById('reportDynamicContent');
  contentEl.innerHTML = '<div style="padding:40px; text-align:center;" class="mono subtle">Synthesizing 8-page executive threat intelligence dossier...</div>';

  try {
    const res = await fetch('/api/reports/summary');
    const json = await res.json();
    if (json.status !== 'success') return;
    currentActiveReport = json.data;
    renderAllDataSummaryReport(json.data);
  } catch (err) {
    contentEl.innerHTML = `<div class="error-banner">Failed to generate intelligence dossier: ${err.message}</div>`;
  }
}

function renderAllDataSummaryReport(sum) {
  const contentEl = document.getElementById('reportDynamicContent');

  contentEl.innerHTML = `
    <!-- PAGE 1: TITLE, CLASSIFICATION, EXECUTIVE BRIEFING & MACRO SCORECARD -->
    <div class="report-header">
      <div class="report-header-top">
        <span class="report-badge-confidential">${sum.classification}</span>
        <span class="subtle mono" style="font-size:11px;">DOSSIER ID: ${sum.report_id} · GENERATED: ${sum.generated_at}</span>
      </div>
      <h1 class="report-title">${sum.title}</h1>
      <p class="report-subtitle">${sum.subtitle}</p>
    </div>

    <!-- Macro Exposure Scorecard -->
    <div class="report-meta-grid">
      <div class="report-meta-item">
        <small>Total Audited Incidents</small>
        <b>${fmt(sum.total_authentic_incidents)} Incidents</b>
      </div>
      <div class="report-meta-item">
        <small>Total Records Compromised</small>
        <b>${sum.total_records_exposed}</b>
      </div>
      <div class="report-meta-item">
        <small>Critical Severity Share</small>
        <b>${sum.critical_incidents_count} (${sum.critical_percentage})</b>
      </div>
      <div class="report-meta-item">
        <small>Data Source Validation</small>
        <b>100% Statutory Filings</b>
      </div>
    </div>

    <!-- 1. Executive Briefing -->
    <section class="report-section">
      <h3 class="report-section-title">1. Executive Summary & Threat Telemetry Briefing</h3>
      <p class="report-body-text">${sum.executive_summary}</p>
    </section>

    <!-- PAGE 2: SECTOR RISK RANKING & ATTACK VECTOR TAXONOMY -->
    <div class="report-page-divider report-page-break">
      <span class="report-page-number">PAGE 2 OF 8 · SECTOR RISK & EXPLOITATION TAXONOMY</span>
      <span class="report-page-number">PBM INTELLIGENCE</span>
    </div>

    <!-- 2. Targeted Industry Risk Matrix -->
    <section class="report-section">
      <h3 class="report-section-title">2. Sector Exposure & Industry Risk Ranking</h3>
      <div class="report-table-wrapper">
        <table class="report-table">
          <thead>
            <tr>
              <th style="width:26%;">Industry Sector</th>
              <th style="width:16%;">Incident Count</th>
              <th style="width:26%;">Total Records Exposed</th>
              <th style="width:32%;">Relative Exposure Volume</th>
            </tr>
          </thead>
          <tbody>
            ${(sum.industry_risk_ranking || []).map(ind => {
              const maxR = sum.total_records_raw || 1;
              const pct = Math.min(100, Math.max(5, Math.round((ind.records / maxR) * 100)));
              return `
                <tr>
                  <td><strong>${ind.industry}</strong></td>
                  <td class="mono">${ind.count}</td>
                  <td class="mono"><strong>${ind.records_formatted}</strong></td>
                  <td>
                    <div class="track" style="height:6px; background:#f1f5f9; border-radius:3px; overflow:hidden;">
                      <div class="fill" style="width:${pct}%; height:100%; background:linear-gradient(to right, #2563eb, #38bdf8); border-radius:3px;"></div>
                    </div>
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    </section>

    <!-- 3. Attack Vector Taxonomy -->
    <section class="report-section">
      <h3 class="report-section-title">3. Attack Vector Taxonomy & Systemic Root Causes</h3>
      <div class="report-table-wrapper">
        <table class="report-table">
          <thead>
            <tr>
              <th style="width:24%;">Exploitation Vector</th>
              <th style="width:14%;">Incidents</th>
              <th style="width:22%;">Total Records Impacted</th>
              <th style="width:40%;">Primary Vulnerability Driver</th>
            </tr>
          </thead>
          <tbody>
            ${(sum.attack_vector_taxonomy || []).map(vec => `
              <tr>
                <td><strong>${vec.attack_vector}</strong></td>
                <td class="mono">${vec.count}</td>
                <td class="mono"><strong>${vec.records_formatted}</strong></td>
                <td style="font-size:11px; color:#475569;">${getVectorSummaryNote(vec.attack_vector)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </section>

    <!-- PAGE 3: HISTORICAL THREAT ERAS & EVOLUTION -->
    <div class="report-page-divider report-page-break">
      <span class="report-page-number">PAGE 3 OF 8 · HISTORICAL THREAT EVOLUTION</span>
      <span class="report-page-number">PBM INTELLIGENCE</span>
    </div>

    <!-- 4. Chronological Incident Evolution -->
    <section class="report-section">
      <h3 class="report-section-title">4. Historical Threat Evolution & Decade-by-Decade Attack Eras</h3>
      <p class="report-body-text" style="margin-bottom:12px;">
        Empirical timeline telemetry tracking the shift from early unencrypted database dumps (2009–2014) to advanced supply chain backdoors (2020) and automated cloud tenant infostealer scraping campaigns (2023–2026).
      </p>
      <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(110px, 1fr)); gap:8px; margin-top:10px;">
        ${(sum.chronological_eras || []).map(era => `
          <div class="report-card" style="text-align:center; padding:10px 8px;">
            <small style="font-size:9.5px; font-weight:700; color:#64748b;">${era.year}</small>
            <div class="val" style="font-size:13px; margin-top:2px; color:#1e293b;">${era.incidents} breaches</div>
            <div class="subtle mono" style="font-size:9.5px; margin-top:2px;">${era.records} records</div>
          </div>
        `).join('')}
      </div>
    </section>

    <!-- PAGE 4: LANDMARK CASE STUDIES FORENSIC AUTOPSIES -->
    <div class="report-page-divider report-page-break">
      <span class="report-page-number">PAGE 4 OF 8 · LANDMARK FORENSIC AUTOPSIES</span>
      <span class="report-page-number">PBM INTELLIGENCE</span>
    </div>

    <!-- 5. Landmark Case Studies Synopsis -->
    <section class="report-section">
      <h3 class="report-section-title">5. Landmark Case Studies Forensic Autopsies (12 Investigations)</h3>
      <div class="report-table-wrapper">
        <table class="report-table">
          <thead>
            <tr>
              <th style="width:12%;">Case ID</th>
              <th style="width:22%;">Organization & Incident</th>
              <th style="width:18%;">Impact & Fines</th>
              <th style="width:24%;">Technical Root Cause</th>
              <th style="width:24%;">Actionable Lesson</th>
            </tr>
          </thead>
          <tbody>
            ${(sum.case_studies_summaries || []).map(cs => `
              <tr>
                <td class="mono" style="font-size:11px;"><strong>${cs.breach_id}</strong></td>
                <td>
                  <strong>${cs.title}</strong><br>
                  <small class="subtle mono">${cs.date}</small>
                  <span class="badge ${getBadgeClass(cs.severity)}" style="margin-left:4px; font-size:8px;">${cs.severity.toUpperCase()}</span>
                </td>
                <td>
                  <div class="mono" style="font-size:11px;"><strong>${cs.records}</strong> records</div>
                  <small class="subtle">Window: ${cs.exposure_window}</small><br>
                  <small style="color:#d97706; font-weight:600;">${cs.fines}</small>
                </td>
                <td style="font-size:11px; line-height:1.45; color:#334155;">${cs.root_cause}</td>
                <td style="font-size:11px; line-height:1.45; color:#1e3a8a; background:#f8fafc;">${cs.lessons_learned}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </section>

    <!-- PAGE 5: MITRE ATT&CK FRAMEWORK MATRIX -->
    <div class="report-page-divider report-page-break">
      <span class="report-page-number">PAGE 5 OF 8 · MITRE ATT&CK FRAMEWORK MAPPING</span>
      <span class="report-page-number">PBM INTELLIGENCE</span>
    </div>

    <!-- 6. MITRE ATT&CK Mapping -->
    <section class="report-section">
      <h3 class="report-section-title">6. MITRE ATT&CK Enterprise Matrix & Adversary TTP Telemetry</h3>
      <div class="report-table-wrapper">
        <table class="report-table">
          <thead>
            <tr>
              <th style="width:20%;">ATT&CK Tactic</th>
              <th style="width:28%;">Techniques & Identifiers</th>
              <th style="width:52%;">Observed Incident Telemetry & Exploitation Pattern</th>
            </tr>
          </thead>
          <tbody>
            ${(sum.mitre_attack_matrix || []).map(m => `
              <tr>
                <td><strong>${m.tactic}</strong><br><small class="subtle mono">${m.id}</small></td>
                <td style="font-size:11px; font-family:ui-monospace, monospace; color:#1e3a8a;">${m.technique}</td>
                <td style="font-size:11.5px; line-height:1.45;">${m.telemetry}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </section>

    <!-- PAGE 6: STATUTORY ENFORCEMENT & REGULATORY PENALTIES -->
    <div class="report-page-divider report-page-break">
      <span class="report-page-number">PAGE 6 OF 8 · STATUTORY ENFORCEMENT & LEGAL PENALTIES</span>
      <span class="report-page-number">PBM INTELLIGENCE</span>
    </div>

    <!-- 7. Regulatory Penalties & Statutory Analysis -->
    <section class="report-section">
      <h3 class="report-section-title">7. Regulatory Impact, Statutory Fines & Legal Enforcement Analysis</h3>
      <div class="report-table-wrapper">
        <table class="report-table">
          <thead>
            <tr>
              <th style="width:22%;">Regulatory Authority</th>
              <th style="width:24%;">Statutory Basis</th>
              <th style="width:20%;">Notable Penalties</th>
              <th style="width:34%;">Mandated Corrective Action Order</th>
            </tr>
          </thead>
          <tbody>
            ${(sum.regulatory_statutory_impact || []).map(r => `
              <tr>
                <td><strong>${r.authority}</strong></td>
                <td style="font-size:11px; color:#475569;">${r.statute}</td>
                <td style="font-size:11px; font-weight:700; color:#dc2626;">${r.penalties}</td>
                <td style="font-size:11px; line-height:1.45;">${r.mandate}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </section>

    <!-- PAGE 7: NIST CSF 2.0 MATRIX & MULTI-PHASE CISO ROADMAP -->
    <div class="report-page-divider report-page-break">
      <span class="report-page-number">PAGE 7 OF 8 · NIST CSF 2.0 & MULTI-PHASE CISO ROADMAP</span>
      <span class="report-page-number">PBM INTELLIGENCE</span>
    </div>

    <!-- 8. NIST CSF 2.0 Mapping Matrix -->
    <section class="report-section">
      <h3 class="report-section-title">8. NIST Cybersecurity Framework (CSF 2.0) Strategic Control Matrix</h3>
      <div class="report-table-wrapper">
        <table class="report-table">
          <thead>
            <tr>
              <th style="width:18%;">NIST Function</th>
              <th style="width:26%;">Control Category</th>
              <th style="width:56%;">Systemic Vulnerability & Mitigation Requirement</th>
            </tr>
          </thead>
          <tbody>
            ${(sum.nist_csf_mapping || []).map(m => `
              <tr>
                <td><span class="badge ${m.function.includes('GOVERN') || m.function.includes('PROTECT') || m.function.includes('IDENTIFY') ? 'critical' : 'medium'}">${m.function}</span></td>
                <td><strong>${m.control}</strong></td>
                <td style="line-height:1.45; font-size:11px;">${m.finding}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </section>

    <!-- 9. Prioritized Multi-Phase CISO Remediation Roadmap -->
    <section class="report-section">
      <h3 class="report-section-title">9. Prioritized Multi-Phase CISO Remediation Roadmap</h3>
      <div style="display:grid; gap:10px; margin-top:8px;">
        ${(sum.ciso_remediation_phases || []).map(p => `
          <div class="report-phase-card">
            <div class="report-phase-title">${p.phase} — <em>${p.focus}</em></div>
            <ul class="report-phase-list">
              ${p.actions.map(act => `<li>${act}</li>`).join('')}
            </ul>
          </div>
        `).join('')}
      </div>
    </section>

    <!-- PAGE 8: EVIDENTIARY REGULATORY REGISTRY & SOURCES -->
    <div class="report-page-divider report-page-break">
      <span class="report-page-number">PAGE 8 OF 8 · STATUTORY EVIDENCE REGISTRY</span>
      <span class="report-page-number">PBM INTELLIGENCE</span>
    </div>

    <!-- 10. Verified Regulatory Sources & Citations -->
    <section class="report-section">
      <h3 class="report-section-title">10. Statutory Evidence Registry, Legal Dockets & Regulatory Citations</h3>
      <p class="report-body-text" style="margin-bottom:10px;">
        All empirical findings and metrics in this dossier are verified against legal settlements, SEC 8-K filings, DOJ indictments, and official threat research advisories.
      </p>
      <div class="report-sources-list">
        ${(sum.sources_and_citations || []).map(s => `
          <div style="font-size:11px; margin-bottom:8px; line-height:1.45;">
            <strong>${s.authority_or_publisher} (${s.publication_year}):</strong> 
            <a href="${s.url}" target="_blank" rel="noopener noreferrer">${s.title}</a>
            ${s.citation_note ? `<br><span class="subtle" style="font-size:10.5px;">${s.citation_note}</span>` : ''}
          </div>
        `).join('')}
      </div>
    </section>
  `;
}

function getVectorSummaryNote(vector) {
  const map = {
    'Credential stuffing': 'Automated credential reuse against accounts lacking mandatory multi-factor authentication (MFA).',
    'Phishing': 'Social engineering and spear phishing targeting privileged administrative and help desk credentials.',
    'Cloud misconfiguration': 'Over-privileged IAM roles, SSRF vulnerabilities, and publicly exposed storage repositories.',
    'Supply chain': 'Compromised third-party software dependencies, vendor contractors, and tainted build pipelines.',
    'Stolen session': 'Session cookie theft, infostealer malware infection on engineer workstations, and forged tokens.',
    'Unpatched vulnerability': 'Known CVE vulnerabilities left unpatched on internet-facing web portals beyond SLA windows.',
    'Zero-day exploit': 'Novel application vulnerabilities exploited before vendor patches become available.',
    'SQL Injection': 'Lack of parameterized queries allowing unauthorized database table exfiltration.',
    'API Key leak': 'Hardcoded static secrets in source code repositories or exposed public endpoints.'
  };
  return map[vector] || 'Exploitation of perimeter controls and unauthorized access.';
}

// Generate Downloadable Report Plain Text
function getReportPlainText() {
  if (!currentActiveReport) return '';
  const s = currentActiveReport;
  let text = `================================================================================\n`;
  text += `${s.title.toUpperCase()}\n`;
  text += `${s.subtitle}\n`;
  text += `Classification: ${s.classification} | Dossier ID: ${s.report_id}\n`;
  text += `Generated At: ${s.generated_at} | Scope: ${s.dataset_scope}\n`;
  text += `================================================================================\n\n`;
  text += `[PAGE 1] 1. EXECUTIVE SUMMARY:\n${s.executive_summary}\n\n`;
  text += `2. MACRO EXPOSURE SCORECARD:\n`;
  text += `- Total Audited Incidents: ${s.total_authentic_incidents}\n`;
  text += `- Total Records Compromised: ${s.total_records_exposed}\n`;
  text += `- Critical Severity Share: ${s.critical_incidents_count} (${s.critical_percentage})\n\n`;
  text += `[PAGE 2] 3. SECTOR RISK RANKING:\n`;
  s.industry_risk_ranking.forEach(ind => {
    text += `- ${ind.industry}: ${ind.count} breaches (${ind.records_formatted} records)\n`;
  });
  text += `\n4. ATTACK VECTOR TAXONOMY:\n`;
  s.attack_vector_taxonomy.forEach(vec => {
    text += `- ${vec.attack_vector}: ${vec.count} breaches (${vec.records_formatted} records)\n`;
  });
  text += `\n[PAGE 5] 5. MITRE ATT&CK FRAMEWORK MAPPING:\n`;
  (s.mitre_attack_matrix || []).forEach(m => {
    text += `- ${m.tactic} (${m.id}): ${m.technique} -> ${m.telemetry}\n`;
  });
  text += `\n[PAGE 6] 6. STATUTORY REGULATORY PENALTIES:\n`;
  (s.regulatory_statutory_impact || []).forEach(r => {
    text += `- ${r.authority} [${r.statute}]: ${r.penalties} -> ${r.mandate}\n`;
  });
  text += `\n[PAGE 7] 7. PRIORITIZED CISO REMEDIATION PHASES:\n`;
  (s.ciso_remediation_phases || []).forEach(p => {
    text += `\n${p.phase} (${p.focus}):\n`;
    p.actions.forEach(a => text += `  * ${a}\n`);
  });
  text += `\n[PAGE 8] 8. STATUTORY EVIDENCE REGISTRY & SOURCES:\n`;
  (s.sources_and_citations || []).forEach(src => {
    text += `- ${src.authority_or_publisher} (${src.publication_year}): ${src.title} [${src.url}]\n`;
  });
  return text;
}

// Generate Downloadable Report Markdown
function getReportMarkdown() {
  if (!currentActiveReport) return '';
  const s = currentActiveReport;
  let md = `# ${s.title}\n\n`;
  md += `> **Subtitle**: ${s.subtitle}  \n`;
  md += `> **Classification**: ${s.classification} | **Dossier ID**: \`${s.report_id}\`  \n`;
  md += `> **Generated**: ${s.generated_at} | **Scope**: ${s.dataset_scope}\n\n`;
  md += `## 1. Executive Summary\n\n${s.executive_summary}\n\n`;
  md += `## 2. Quantitative Macro Exposure Scorecard\n\n`;
  md += `| Metric | Value |\n| :--- | :--- |\n`;
  md += `| **Total Audited Incidents** | ${fmt(s.total_authentic_incidents)} |\n`;
  md += `| **Total Records Compromised** | ${s.total_records_exposed} |\n`;
  md += `| **Critical Severity Incidents** | ${s.critical_incidents_count} (${s.critical_percentage}) |\n\n`;
  md += `## 3. Targeted Industry Risk Ranking\n\n`;
  md += `| Industry Sector | Incident Count | Records Compromised |\n| :--- | :--- | :--- |\n`;
  s.industry_risk_ranking.forEach(ind => {
    md += `| **${ind.industry}** | ${ind.count} | ${ind.records_formatted} |\n`;
  });
  md += `\n## 4. Attack Vector Taxonomy\n\n`;
  md += `| Attack Vector | Incident Count | Records Compromised |\n| :--- | :--- | :--- |\n`;
  s.attack_vector_taxonomy.forEach(vec => {
    md += `| **${vec.attack_vector}** | ${vec.count} | ${vec.records_formatted} |\n`;
  });
  md += `\n## 5. MITRE ATT&CK Enterprise Matrix\n\n`;
  (s.mitre_attack_matrix || []).forEach(m => {
    md += `- **${m.tactic}** (\`${m.id}\`): *${m.technique}* — ${m.telemetry}\n`;
  });
  md += `\n## 6. Statutory Regulatory Penalties\n\n`;
  (s.regulatory_statutory_impact || []).forEach(r => {
    md += `- **${r.authority}** (\`${r.statute}\`): **${r.penalties}** — *${r.mandate}*\n`;
  });
  md += `\n## 7. Prioritized CISO Remediation Phases\n\n`;
  (s.ciso_remediation_phases || []).forEach(p => {
    md += `### ${p.phase} — *${p.focus}*\n\n`;
    p.actions.forEach(act => md += `- ${act}\n`);
    md += `\n`;
  });
  md += `\n## 8. Statutory Evidence Registry & Citations\n\n`;
  (s.sources_and_citations || []).forEach(src => {
    md += `1. **${src.authority_or_publisher}** (${src.publication_year}): [${src.title}](${src.url}) — *${src.citation_note || ''}*\n`;
  });
  return md;
}

function downloadFile(content, fileName, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Data Sources Catalog View
async function loadSourcesCatalog() {
  try {
    const res = await fetch('/api/sources');
    const json = await res.json();
    if (json.status !== 'success') return;

    currentRawSourcesText = json.raw_documentation || '';
    const rawBox = document.getElementById('rawSourcesText');
    if (rawBox) rawBox.textContent = currentRawSourcesText;

    const grid = document.getElementById('sourcesCardsGrid');
    if (grid) {
      grid.innerHTML = json.sources.map(s => `
        <div class="source-card">
          <div class="source-card-top">
            <span class="badge medium">${s.source_type}</span>
            <span class="subtle mono" style="font-size:10px;">PUB: ${s.publication_year}</span>
          </div>
          <h4>${s.title}</h4>
          <p><strong>Authority:</strong> ${s.authority_or_publisher}<br>${s.citation_note ? `<span class="subtle">${s.citation_note}</span>` : ''}</p>
          <a class="link-btn" href="${s.url}" target="_blank" rel="noopener noreferrer">View Statutory Filing</a>
        </div>
      `).join('');
    }
  } catch (err) {
    console.error('Failed to load sources catalog:', err);
  }
}

// Threat Analytics Data Loading
async function loadAnalytics() {
  try {
    const res = await fetch('/api/analytics');
    const data = await res.json();
    if (data.status !== 'success') return;

    // Breaches by Year Bars
    const maxBreaches = Math.max(...data.breaches_by_year.map(d => d.count), 1);
    document.getElementById('analyticsYearBars').innerHTML = data.breaches_by_year.map(d => {
      const pct = Math.max(8, Math.round((d.count / maxBreaches) * 100));
      return `<div class="bar-col"><div class="bar" style="height:${pct}%" title="${d.count} breaches"></div><small>${d.year}</small></div>`;
    }).join('');

    // Records Exposed by Year Bars
    const maxRecords = Math.max(...data.records_by_year.map(d => d.total_records), 1);
    document.getElementById('analyticsRecordsBars').innerHTML = data.records_by_year.map(d => {
      const pct = Math.max(8, Math.round((d.total_records / maxRecords) * 100));
      return `<div class="bar-col"><div class="bar" style="height:${pct}%" title="${d.formatted}"></div><small>${d.year.slice(2)}</small></div>`;
    }).join('');

    // Top Industries Horizontal Progress Bars
    const maxInd = Math.max(...data.industry_breakdown.map(d => d.count), 1);
    document.getElementById('analyticsIndustryBars').innerHTML = data.industry_breakdown.map(d => {
      const pct = Math.round((d.count / maxInd) * 100);
      return `<div class="hrow"><span>${d.industry}</span><div class="track"><div class="fill" style="width:${pct}%"></div></div><b>${d.count}</b></div>`;
    }).join('');

    // Top Attack Vectors Horizontal Progress Bars
    const maxVec = Math.max(...data.vector_breakdown.map(d => d.count), 1);
    document.getElementById('analyticsVectorBars').innerHTML = data.vector_breakdown.map(d => {
      const pct = Math.round((d.count / maxVec) * 100);
      return `<div class="hrow"><span>${d.attack_vector}</span><div class="track"><div class="fill" style="width:${pct}%"></div></div><b>${d.count}</b></div>`;
    }).join('');

    // Severity Share Donut Chart
    const sev = data.severity_counts || {};
    const total = (sev.Critical || 0) + (sev.High || 0) + (sev.Medium || 0) + (sev.Low || 0);
    const cPct = total ? Math.round((sev.Critical || 0) / total * 100) : 0;
    const hPct = cPct + (total ? Math.round((sev.High || 0) / total * 100) : 0);
    const mPct = hPct + (total ? Math.round((sev.Medium || 0) / total * 100) : 0);

    const donut = document.getElementById('analyticsDonut');
    if (donut) {
      donut.setAttribute('data-center', `${total}\ntotal`);
      donut.style.background = `conic-gradient(var(--red) 0% ${cPct}%, var(--amber) ${cPct}% ${hPct}%, var(--blue) ${hPct}% ${mPct}%, var(--green) ${mPct}% 100%)`;
    }

    document.getElementById('analyticsDonutLegend').innerHTML = `
      <div class="legend-row"><i class="swatch" style="background:var(--red)"></i><span>Critical</span><b>${sev.Critical || 0}</b></div>
      <div class="legend-row"><i class="swatch" style="background:var(--amber)"></i><span>High</span><b>${sev.High || 0}</b></div>
      <div class="legend-row"><i class="swatch" style="background:var(--blue)"></i><span>Medium</span><b>${sev.Medium || 0}</b></div>
      <div class="legend-row"><i class="swatch" style="background:var(--green)"></i><span>Low</span><b>${sev.Low || 0}</b></div>
    `;

  } catch (err) {
    console.error('Failed to load analytics data:', err);
  }
}

// TOGGLEABLE SQL BUILDER & LIVE PREVIEW ENGINE
function generateSqlFromState() {
  if (sqlState.customQuery) {
    return sqlState.customQuery;
  }

  const cols = sqlState.columns.length > 0 ? sqlState.columns.join(', ') : '*';
  let sql = `SELECT ${cols}\nFROM breaches`;

  const wheres = [];
  if (sqlState.severity) {
    wheres.push(`severity = '${sqlState.severity}'`);
  }
  if (sqlState.industry) {
    wheres.push(`industry = '${sqlState.industry}'`);
  }
  if (sqlState.vector) {
    wheres.push(`attack_vector = '${sqlState.vector}'`);
  }

  if (wheres.length > 0) {
    sql += `\nWHERE ${wheres.join('\n  AND ')}`;
  }

  if (sqlState.sort) {
    sql += `\nORDER BY ${sqlState.sort} ${sqlState.order}`;
  }

  if (sqlState.limit) {
    sql += `\nLIMIT ${sqlState.limit};`;
  } else {
    sql += `;`;
  }

  return sql;
}

function updateSqlPreviewAndRun() {
  const generatedSql = generateSqlFromState();
  const previewEl = document.getElementById('sqlPreviewCode');
  if (previewEl) {
    previewEl.textContent = generatedSql;
  }
  runSqlQuery(generatedSql);
}

async function runSqlQuery(sqlQueryOverride) {
  const sql = sqlQueryOverride || generateSqlFromState();
  const metaSpan = document.getElementById('queryMeta');
  const errorBox = document.getElementById('sqlErrorBox');
  const headersTr = document.getElementById('queryHeaders');
  const rowsTbody = document.getElementById('queryRows');
  const historyList = document.getElementById('history');

  errorBox.style.display = 'none';
  metaSpan.textContent = 'Executing query...';

  try {
    const res = await fetch('/api/sql/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: sql })
    });

    const data = await res.json();
    const now = new Date().toLocaleTimeString('en-GB', { hour12: false });

    if (data.status === 'success') {
      metaSpan.textContent = `${data.row_count} row${data.row_count === 1 ? '' : 's'} · ${data.execution_time_ms} ms`;
      
      headersTr.innerHTML = '<tr>' + (data.columns || []).map(c => `<th>${c}</th>`).join('') + '</tr>';

      if (data.rows.length === 0) {
        rowsTbody.innerHTML = `<tr><td colspan="${data.columns.length || 1}" class="empty">0 rows returned from database query</td></tr>`;
      } else {
        rowsTbody.innerHTML = data.rows.map(r => `<tr>${r.map(val => `<td>${val !== null ? val : 'NULL'}</td>`).join('')}</tr>`).join('');
      }

      const firstLine = sql.trim().split('\n')[0].substring(0, 36);
      historyList.insertAdjacentHTML('afterbegin', `<div class="list-item" onclick="applyPresetSql(\`${sql.replace(/`/g, '\\`')}\`)">${firstLine}...<span class="history-time">${now} · ${data.execution_time_ms} ms</span></div>`);

    } else {
      metaSpan.textContent = 'Query Error';
      errorBox.style.display = 'block';
      errorBox.textContent = data.error || 'Execution failed.';
      headersTr.innerHTML = '';
      rowsTbody.innerHTML = '';

      historyList.insertAdjacentHTML('afterbegin', `<div class="list-item" style="color:var(--red)">Blocked Administrative/Mutation Query<span class="history-time">${now} · Blocked</span></div>`);
    }
  } catch (err) {
    metaSpan.textContent = 'Query Error';
    errorBox.style.display = 'block';
    errorBox.textContent = `Server Error: ${err.message}`;
  }
}

function applyPresetSql(query) {
  sqlState.customQuery = query;
  const previewEl = document.getElementById('sqlPreviewCode');
  if (previewEl) {
    previewEl.textContent = query;
  }
  runSqlQuery(query);
}

async function loadSqlExamples() {
  try {
    const res = await fetch('/api/sql/examples');
    const json = await res.json();
    if (json.status !== 'success') return;

    const list = document.getElementById('sqlExamplesList');
    list.innerHTML = json.data.map(ex => `
      <button class="list-item" onclick="applyPresetSql(\`${ex.sql.replace(/`/g, '\\`')}\`)">${ex.name}</button>
    `).join('');
  } catch (err) {
    console.error('Failed to load SQL examples:', err);
  }
}

function initSqlToggleControls() {
  // Columns Toggles
  document.querySelectorAll('#colToggles .toggle-pill').forEach(btn => {
    btn.onclick = () => {
      btn.classList.toggle('active');
      const activeCols = [];
      document.querySelectorAll('#colToggles .toggle-pill.active').forEach(b => {
        activeCols.push(b.dataset.col);
      });
      sqlState.columns = activeCols;
      sqlState.customQuery = null;
      updateSqlPreviewAndRun();
    };
  });

  // Severity Toggles
  document.querySelectorAll('#severityToggles .toggle-pill').forEach(btn => {
    btn.onclick = () => {
      document.querySelectorAll('#severityToggles .toggle-pill').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      sqlState.severity = btn.dataset.sev;
      sqlState.customQuery = null;
      updateSqlPreviewAndRun();
    };
  });

  // Industry Dropdown
  const indSelect = document.getElementById('sqlIndustrySelect');
  if (indSelect) {
    indSelect.onchange = () => {
      sqlState.industry = indSelect.value;
      sqlState.customQuery = null;
      updateSqlPreviewAndRun();
    };
  }

  // Vector Dropdown
  const vecSelect = document.getElementById('sqlVectorSelect');
  if (vecSelect) {
    vecSelect.onchange = () => {
      sqlState.vector = vecSelect.value;
      sqlState.customQuery = null;
      updateSqlPreviewAndRun();
    };
  }

  // Sort Field Toggles
  document.querySelectorAll('#sortToggles .toggle-pill').forEach(btn => {
    btn.onclick = () => {
      document.querySelectorAll('#sortToggles .toggle-pill').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      sqlState.sort = btn.dataset.sort;
      sqlState.customQuery = null;
      updateSqlPreviewAndRun();
    };
  });

  // Sort Order Toggles
  document.querySelectorAll('#orderToggles .toggle-pill').forEach(btn => {
    btn.onclick = () => {
      document.querySelectorAll('#orderToggles .toggle-pill').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      sqlState.order = btn.dataset.order;
      sqlState.customQuery = null;
      updateSqlPreviewAndRun();
    };
  });

  // Limit Toggles
  document.querySelectorAll('#limitToggles .toggle-pill').forEach(btn => {
    btn.onclick = () => {
      document.querySelectorAll('#limitToggles .toggle-pill').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      sqlState.limit = btn.dataset.limit;
      sqlState.customQuery = null;
      updateSqlPreviewAndRun();
    };
  });

  // Reset Toggles Button
  const resetBtn = document.getElementById('resetSqlToggles');
  if (resetBtn) {
    resetBtn.onclick = () => {
      sqlState = {
        columns: ['id', 'organization', 'breach_date', 'affected_records', 'severity'],
        severity: '',
        industry: '',
        vector: '',
        sort: 'affected_records',
        order: 'DESC',
        limit: '10',
        customQuery: null
      };

      document.querySelectorAll('#colToggles .toggle-pill').forEach(b => {
        b.classList.toggle('active', ['id', 'organization', 'breach_date', 'affected_records', 'severity'].includes(b.dataset.col));
      });
      document.querySelectorAll('#severityToggles .toggle-pill').forEach(b => {
        b.classList.toggle('active', b.dataset.sev === '');
      });
      if (indSelect) indSelect.value = '';
      if (vecSelect) vecSelect.value = '';
      document.querySelectorAll('#sortToggles .toggle-pill').forEach(b => {
        b.classList.toggle('active', b.dataset.sort === 'affected_records');
      });
      document.querySelectorAll('#orderToggles .toggle-pill').forEach(b => {
        b.classList.toggle('active', b.dataset.order === 'DESC');
      });
      document.querySelectorAll('#limitToggles .toggle-pill').forEach(b => {
        b.classList.toggle('active', b.dataset.limit === '10');
      });

      updateSqlPreviewAndRun();
    };
  }

  // Run Query Button
  document.getElementById('runSql').onclick = () => updateSqlPreviewAndRun();
}

// Global Event Listeners Setup
document.addEventListener('DOMContentLoaded', () => {
  // Navigation buttons
  document.querySelectorAll('.nav-btn').forEach(b => {
    b.onclick = () => navigate(b.dataset.view);
  });
  document.querySelectorAll('[data-jump]').forEach(b => {
    b.onclick = () => navigate(b.dataset.jump);
  });

  // Database Filter Handlers
  ['dbSearch', 'severityFilter', 'yearFilter', 'industryFilter'].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('input', () => {
        currentPage = 1;
        loadDatabase();
      });
    }
  });

  // Filter Chips in Database View
  document.querySelectorAll('.filter-chips .chip').forEach(chip => {
    chip.onclick = () => {
      document.querySelectorAll('.filter-chips .chip').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');

      if (chip.dataset.chipSev !== undefined) {
        document.getElementById('severityFilter').value = chip.dataset.chipSev;
      }
      if (chip.dataset.chipInd !== undefined) {
        document.getElementById('industryFilter').value = chip.dataset.chipInd;
      }
      if (chip.dataset.chipVec !== undefined) {
        document.getElementById('dbSearch').value = chip.dataset.chipVec;
      }
      if (chip.dataset.chipMega) {
        document.getElementById('dbSearch').value = '';
        currentSort = { by: 'affected_records', order: 'desc' };
      }
      if (chip.dataset.chipSev === '' && !chip.dataset.chipInd && !chip.dataset.chipVec && !chip.dataset.chipMega) {
        document.getElementById('dbSearch').value = '';
        document.getElementById('severityFilter').value = '';
        document.getElementById('yearFilter').value = '';
        document.getElementById('industryFilter').value = '';
      }
      currentPage = 1;
      loadDatabase();
    };
  });

  // Export CSV Button
  const exportCsvBtn = document.getElementById('exportCsvBtn');
  if (exportCsvBtn) {
    exportCsvBtn.onclick = () => {
      const q = document.getElementById('dbSearch').value;
      const severity = document.getElementById('severityFilter').value;
      const industry = document.getElementById('industryFilter').value;
      const url = `/api/breaches/export?q=${encodeURIComponent(q)}&severity=${encodeURIComponent(severity)}&industry=${encodeURIComponent(industry)}`;
      window.location.href = url;
      showToast('Downloading CSV breach database export...', 'success');
    };
  }

  // Table Sorting Handlers
  const sortMap = {
    'th-id': 'id',
    'th-org': 'organization',
    'th-date': 'breach_date',
    'th-records': 'affected_records'
  };
  Object.keys(sortMap).forEach(thId => {
    const el = document.getElementById(thId);
    if (el) {
      el.onclick = () => {
        const col = sortMap[thId];
        if (currentSort.by === col) {
          currentSort.order = currentSort.order === 'asc' ? 'desc' : 'asc';
        } else {
          currentSort.by = col;
          currentSort.order = 'desc';
        }
        loadDatabase();
      };
    }
  });

  // Global Search
  const globalSearch = document.getElementById('globalSearch');
  if (globalSearch) {
    globalSearch.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        const query = e.target.value;
        navigate('database');
        document.getElementById('dbSearch').value = query;
        currentPage = 1;
        loadDatabase();
      }
    });
  }

  // Case Study Selector
  const caseSelect = document.getElementById('caseStudySelect');
  if (caseSelect) {
    caseSelect.onchange = () => loadCaseStudy(caseSelect.value);
  }

  // Open Report from Case Study View
  const openReportFromCaseBtn = document.getElementById('openReportFromCaseBtn');
  if (openReportFromCaseBtn) {
    openReportFromCaseBtn.onclick = () => {
      navigate('reports');
    };
  }

  // Refresh Report Button
  const refreshReportBtn = document.getElementById('refreshReportBtn');
  if (refreshReportBtn) {
    refreshReportBtn.onclick = () => {
      loadReportView();
      showToast('Executive intelligence dossier refreshed.');
    };
  }

  // Print / Save as PDF
  const printReportBtn = document.getElementById('printReportBtn');
  if (printReportBtn) {
    printReportBtn.onclick = () => {
      window.print();
    };
  }

  // Copy Report Text
  const copyReportBtn = document.getElementById('copyReportBtn');
  if (copyReportBtn) {
    copyReportBtn.onclick = () => {
      const text = getReportPlainText();
      navigator.clipboard.writeText(text).then(() => {
        showToast('Executive dossier plain text copied to clipboard.');
      }).catch(err => {
        showToast('Failed to copy: ' + err);
      });
    };
  }

  // Download Markdown
  const downloadMdBtn = document.getElementById('downloadMdBtn');
  if (downloadMdBtn) {
    downloadMdBtn.onclick = () => {
      const md = getReportMarkdown();
      const filename = `global_cyber_threat_dossier.md`;
      downloadFile(md, filename, 'text/markdown');
      showToast(`Downloaded ${filename}`);
    };
  }

  // Download Plain Text
  const downloadTxtBtn = document.getElementById('downloadTxtBtn');
  if (downloadTxtBtn) {
    downloadTxtBtn.onclick = () => {
      const txt = getReportPlainText();
      const filename = `global_cyber_threat_dossier.txt`;
      downloadFile(txt, filename, 'text/plain');
      showToast(`Downloaded ${filename}`);
    };
  }

  // Download JSON
  const downloadJsonBtn = document.getElementById('downloadJsonBtn');
  if (downloadJsonBtn) {
    downloadJsonBtn.onclick = () => {
      if (!currentActiveReport) return;
      const jsonStr = JSON.stringify(currentActiveReport, null, 2);
      const filename = `global_cyber_threat_dossier.json`;
      downloadFile(jsonStr, filename, 'application/json');
      showToast(`Exported ${filename}`);
    };
  }

  // Data Sources Download / Copy
  const downloadSourcesTxtBtn = document.getElementById('downloadSourcesTxtBtn');
  if (downloadSourcesTxtBtn) {
    downloadSourcesTxtBtn.onclick = () => {
      downloadFile(currentRawSourcesText, 'DATA_SOURCES.txt', 'text/plain');
      showToast('Downloaded DATA_SOURCES.txt');
    };
  }

  const copySourcesTxtBtn = document.getElementById('copySourcesTxtBtn');
  if (copySourcesTxtBtn) {
    copySourcesTxtBtn.onclick = () => {
      navigator.clipboard.writeText(currentRawSourcesText).then(() => {
        showToast('All statutory citations copied to clipboard.');
      });
    };
  }

  // Mobile Menu & Modal Controls
  document.getElementById('menuBtn').onclick = () => document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('closeModal').onclick = closeModal;
  document.getElementById('closeModalFoot').onclick = closeModal;
  document.getElementById('modal').onclick = e => { if (e.target.id === 'modal') closeModal(); };
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

  // Init Toggleable SQL Builder
  initSqlToggleControls();

  // Initial Data Load
  loadDashboard();
});
