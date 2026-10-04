/**
 * Password Breach Monitoring (PBM) - Frontend Application
 * Interacts with Flask REST API endpoints and SQLite database.
 */

const titles = {
  dashboard: ['Security Overview', 'Password breach intelligence workspace'],
  database: ['Breach Database', 'Search and inspect SQLite breach records'],
  'case-study': ['Case Study', 'Structured incident analysis'],
  sql: ['SQL Explorer', 'Execute safe read-only SELECT queries on SQLite'],
  analytics: ['Threat Analytics', 'Aggregated breach intelligence'],
  about: ['About PBM', 'Educational cybersecurity case-study platform']
};

let currentPage = 1;
const perPage = 10;
let currentSort = { by: 'breach_date', order: 'desc' };

// Utility Functions
const fmt = n => new Intl.NumberFormat('en-US').format(n);

function getBadgeClass(severity) {
  const s = (severity || '').toLowerCase();
  if (s === 'critical') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'medium') return 'medium';
  return 'low';
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
    <td><span class="badge status-badge">${(b.status || 'CONTAINED').toUpperCase()}</span></td>
  </tr>`;
}

function bindRowClicks(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.querySelectorAll('tr[data-id]').forEach(tr => {
    tr.onclick = () => fetchAndOpenModal(tr.dataset.id);
  });
}

// Navigation
function navigate(id) {
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === id));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.view === id));
  
  if (titles[id]) {
    document.getElementById('pageTitle').textContent = titles[id][0];
    document.getElementById('pageSubtitle').textContent = titles[id][1];
  }

  document.getElementById('sidebar').classList.remove('open');
  document.querySelector('main').scrollTop = 0;

  // Load view-specific data
  if (id === 'dashboard') loadDashboard();
  else if (id === 'database') loadDatabase();
  else if (id === 'case-study') loadCaseStudy();
  else if (id === 'analytics') loadAnalytics();
  else if (id === 'sql') loadSqlExamples();
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
  document.getElementById('modalTitle').textContent = b.organization;
  document.getElementById('modalDetails').innerHTML = [
    ['Date', b.breach_date],
    ['Discovery', b.discovery_date || b.breach_date],
    ['Records', fmt(b.affected_records)],
    ['Severity', b.severity],
    ['Industry', b.industry],
    ['Type', b.breach_type],
    ['Vector', b.attack_vector],
    ['Status', b.status]
  ].map(([lbl, val]) => `<div class="detail"><small>${lbl}</small><b>${val}</b></div>`).join('');
  
  document.getElementById('modalCopy').textContent = `${b.breach_name} - ${b.root_cause} (Exposed: ${b.data_exposed})`;
  document.getElementById('modal').classList.add('open');
}

function closeModal() {
  document.getElementById('modal').classList.remove('open');
}

// Dashboard Data Loading & Dynamic SVG Line Chart
async function loadDashboard() {
  try {
    const res = await fetch('/api/dashboard');
    const data = await res.json();
    if (data.status !== 'success') return;

    document.getElementById('dashTotalBreaches').textContent = fmt(data.total_breaches);
    document.getElementById('dashTotalRecords').textContent = data.total_records_formatted;
    document.getElementById('dashCriticalCount').textContent = fmt(data.critical_breaches);
    document.getElementById('dashCriticalPct').textContent = `${data.critical_percentage} of incidents`;
    document.getElementById('dashLatestDate').textContent = data.latest_incident.breach_date || 'N/A';
    document.getElementById('dashLatestOrg').textContent = data.latest_incident.organization || 'N/A';

    // Render Recent Table
    document.getElementById('recentRows').innerHTML = data.recent_activity.map(renderRow).join('');
    bindRowClicks('recentRows');

    // Render Breaches by Year SVG Line Chart
    renderDashboardLineChart(data.by_year);

    // Render Donut Chart & Legend
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
  const maxCount = Math.max(...counts, 10);
  
  // SVG coordinate dimensions: viewBox="0 0 650 160"
  const xStart = 40, xEnd = 625, yTop = 20, yBottom = 140;
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
    gridLines += `<line class="grid-line" x1="35" y1="${y}" x2="630" y2="${y}"/><text class="chart-label" x="5" y="${y + 4}">${val}</text>`;
  }

  let labels = '<g class="chart-label">';
  points.forEach(p => {
    labels += `<text x="${(p.x - 12).toFixed(1)}" y="156">${p.year}</text>`;
  });
  labels += '</g>';

  let dots = points.map(p => `<circle class="dot" cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="3"><title>${p.year}: ${p.count} breaches</title></circle>`).join('');

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
      tbody.innerHTML = '<tr><td colspan="7" class="empty">No matching SQLite breach records found</td></tr>';
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
    console.error('Error loading breach database:', err);
  }
}

function renderPaginationControls(page, totalPages) {
  const controls = document.getElementById('pageNumbers');
  if (!controls) return;

  let btns = '';
  for (let i = 1; i <= totalPages; i++) {
    const activeStyle = i === page ? 'style="border-color:var(--cyan-2);color:var(--cyan)"' : '';
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
async function loadCaseStudy(breachId = 'PBM-0261') {
  try {
    const res = await fetch(`/api/case-studies/${breachId}`);
    const json = await res.json();
    if (json.status !== 'success') return;

    const cs = json.data;
    document.getElementById('caseEyebrow').textContent = `Case ${cs.breach_id}`;
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
      <div class="metric"><b>${metrics.records || 'N/A'}</b><small>Records</small></div>
      <div class="metric"><b>${metrics.exposure_window || 'N/A'}</b><small>Exposure window</small></div>
      <div class="metric"><b>${metrics.sessions_reset || 'N/A'}</b><small>Sessions reset</small></div>
      <div class="metric"><b>${metrics.plaintext_passwords || '0'}</b><small>Plaintext passwords</small></div>
    `;
  } catch (err) {
    console.error('Error loading case study:', err);
  }
}

// SQL Explorer Execution
async function runSqlQuery() {
  const sql = document.getElementById('sqlEditor').value;
  const metaSpan = document.getElementById('queryMeta');
  const errorBox = document.getElementById('sqlErrorBox');
  const headersTr = document.getElementById('queryHeaders');
  const rowsTbody = document.getElementById('queryRows');
  const historyList = document.getElementById('history');

  errorBox.style.display = 'none';
  metaSpan.textContent = 'Executing...';

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
        rowsTbody.innerHTML = `<tr><td colspan="${data.columns.length || 1}" class="empty">0 rows returned</td></tr>`;
      } else {
        rowsTbody.innerHTML = data.rows.map(r => `<tr>${r.map(val => `<td>${val !== null ? val : 'NULL'}</td>`).join('')}</tr>`).join('');
      }

      // Add to Query History
      const firstLine = sql.trim().split('\n')[0].substring(0, 32);
      historyList.insertAdjacentHTML('afterbegin', `<div class="list-item" onclick="setSqlEditor(\`${sql.replace(/`/g, '\\`')}\`)">${firstLine}...<span class="history-time">${now} · ${data.execution_time_ms} ms</span></div>`);

    } else {
      metaSpan.textContent = 'Error';
      errorBox.style.display = 'block';
      errorBox.textContent = data.error || 'Execution failed.';
      headersTr.innerHTML = '';
      rowsTbody.innerHTML = '';

      historyList.insertAdjacentHTML('afterbegin', `<div class="list-item" style="color:var(--red)">Blocked Query<span class="history-time">${now} · Error</span></div>`);
    }
  } catch (err) {
    metaSpan.textContent = 'Error';
    errorBox.style.display = 'block';
    errorBox.textContent = `Server Error: ${err.message}`;
  }
}

function setSqlEditor(sql) {
  document.getElementById('sqlEditor').value = sql;
}

async function loadSqlExamples() {
  try {
    const res = await fetch('/api/sql/examples');
    const json = await res.json();
    if (json.status !== 'success') return;

    const list = document.getElementById('sqlExamplesList');
    list.innerHTML = json.data.map(ex => `
      <button class="list-item example" onclick="setSqlEditor(\`${ex.sql.replace(/`/g, '\\`')}\`)">${ex.name}</button>
    `).join('');
  } catch (err) {
    console.error('Failed to load SQL examples:', err);
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
      const pct = Math.max(5, Math.round((d.count / maxBreaches) * 100));
      return `<div class="bar-col"><div class="bar" style="height:${pct}%" title="${d.count} breaches"></div><small>${d.year}</small></div>`;
    }).join('');

    // Records Exposed by Year Bars
    const maxRecords = Math.max(...data.records_by_year.map(d => d.total_records), 1);
    document.getElementById('analyticsRecordsBars').innerHTML = data.records_by_year.map(d => {
      const pct = Math.max(5, Math.round((d.total_records / maxRecords) * 100));
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

  // Mobile Menu & Modal Controls
  document.getElementById('menuBtn').onclick = () => document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('closeModal').onclick = closeModal;
  document.getElementById('closeModalFoot').onclick = closeModal;
  document.getElementById('modal').onclick = e => { if (e.target.id === 'modal') closeModal(); };
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

  // SQL Explorer Buttons
  document.getElementById('runSql').onclick = runSqlQuery;
  document.getElementById('clearSql').onclick = () => {
    document.getElementById('sqlEditor').value = '';
    document.getElementById('sqlErrorBox').style.display = 'none';
  };

  // Initial Data Load
  loadDashboard();
});
