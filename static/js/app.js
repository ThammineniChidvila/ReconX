(() => {
'use strict';
const $ = (s, r = document) => r.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const NA = '<span class="na">Not available</span>';
const empty = v => v === null || v === undefined || v === '' || (Array.isArray(v) && !v.length);
const val = v => empty(v) ? NA : esc(Array.isArray(v) ? v.join(', ') : v);
const badge = (text, cls) => `<span class="badge ${esc(cls ?? text)}">${esc(text)}</span>`;
const fmt = d => d ? String(d).replace('T', ' ').replace(/(\+00:00|Z)$/, '') : '';
const TYPES = {intelligence: 'Intelligence', port_assessment: 'Port assessment'};
const MODS = ['dns', 'rdap', 'ssl', 'subdomains', 'technology'];
const SECTION_PAGES = ['dns', 'rdap', 'ssl', 'subdomains', 'technology'];
const sleep = ms => new Promise(r => setTimeout(r, ms));
const page = document.body.dataset.page;

async function api(path, opts = {}) {
  const o = {method: opts.method || 'GET', headers: {'X-Requested-With': 'ReconX'}};
  if (opts.body !== undefined) { o.headers['Content-Type'] = 'application/json'; o.body = JSON.stringify(opts.body); }
  const r = await fetch(path, o);
  let data = null;
  try { data = await r.json(); } catch (e) { /* non-JSON */ }
  if (!r.ok) throw new Error((data && data.error) || `Request failed (${r.status})`);
  return data;
}
function toast(msg, bad) {
  const t = document.createElement('div');
  t.className = 'toast' + (bad ? ' bad' : '');
  t.textContent = msg;
  $('#toasts').appendChild(t);
  setTimeout(() => t.remove(), 4500);
}
const kv = rows => `<dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join('')}</dl>`;
const card = (title, inner) => `<section class="card">${title ? `<h2>${esc(title)}</h2>` : ''}${inner}</section>`;
const chips = list => `<div class="chips">${list.map(x => `<span class="chip">${esc(x)}</span>`).join('')}</div>`;
const viewLink = s => s.scan_type === 'port_assessment' ? `/ports?scan=${s.id}` : `/intelligence?scan=${s.id}`;

/* ---------- target bar and live scan pipeline ---------- */
function setChip(mod, state) {
  const li = $(`#pipeline li[data-mod="${mod}"]`);
  if (li) li.className = state;
}
async function runScan(domain) {
  const msg = $('#target-msg'), btn = $('#target-btn'), pipe = $('#pipeline');
  msg.textContent = ''; btn.disabled = true;
  try {
    const {scan_id} = await api('/api/scans', {method: 'POST', body: {domain}});
    pipe.hidden = false; MODS.forEach(m => setChip(m, 'running'));
    for (;;) {
      await sleep(1200);
      const scan = await api(`/api/scans/${scan_id}`);
      MODS.forEach(m => setChip(m, scan.results[m] ? scan.results[m].status : 'running'));
      if (scan.status !== 'running') {
        toast(`Scan ${scan.status} for ${scan.domain}`);
        await sleep(700);
        location.href = SECTION_PAGES.includes(page) ? `${location.pathname}?scan=${scan_id}` : `/intelligence?scan=${scan_id}`;
        return;
      }
    }
  } catch (e) { msg.textContent = e.message; btn.disabled = false; }
}
$('#target-form').addEventListener('submit', e => { e.preventDefault(); runScan($('#target-input').value); });

/* ---------- section renderers ---------- */
function unavailable(d, label) {
  if (!d) return card(label, '<p class="empty">Still running...</p>');
  return card(label, `<p>${badge(d.status)} ${esc(d.message || '')}</p>` + (d.notes ? `<p class="muted">${esc(d.notes.join(' '))}</p>` : ''));
}
const R = {};
R.dns = s => {
  const d = s.results.dns;
  if (!d || d.status !== 'ok') return unavailable(d, 'DNS records');
  const rows = d.records.map(r => `<tr><td><strong>${esc(r.type)}</strong></td><td class="mono">${esc(r.value)}</td><td>${badge(r.status, r.status === 'found' ? 'found' : (r.status.startsWith('lookup') ? 'error' : 'info'))}</td></tr>`).join('');
  return card('Resolved IP addresses', d.ips.length ? chips(d.ips) : '<p class="muted">No A or AAAA records.</p>') +
    card('DNS records', `<div class="table-wrap"><table class="table"><thead><tr><th>Type</th><th>Value</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table></div>`);
};
R.rdap = s => {
  const d = s.results.rdap;
  if (!d || d.status !== 'ok') return unavailable(d, 'WHOIS / RDAP');
  return card('Registration data', kv([['Registrar', val(d.registrar)], ['Registration date', val(fmt(d.registered))], ['Expiry date', val(fmt(d.expires))],
    ['Last updated', val(fmt(d.updated))], ['Domain status', d.domain_status.length ? chips(d.domain_status) : NA], ['Name servers', d.nameservers.length ? chips(d.nameservers) : NA], ['Source', val(d.source)]]));
};
const yn = v => v === true ? badge('Verified', 'ok') : v === false ? badge('Mismatch', 'bad') : '<span class="na">Not determined</span>';
R.ssl = s => {
  const d = s.results.ssl;
  if (!d || d.status !== 'ok') return unavailable(d, 'SSL / TLS certificate');
  if (!d.trusted) return card('SSL / TLS certificate', kv([['Validity', badge('untrusted')], ['Hostname verification', yn(d.hostname_verified)], ['Reason', val(d.verification_error)], ['Note', val(d.message)]]));
  const days = d.days_remaining;
  return card('SSL / TLS certificate', kv([['Issuer', val(d.issuer)], ['Subject', val(d.subject)], ['Valid from', val(fmt(d.valid_from))], ['Valid until', val(fmt(d.valid_until))],
    ['Days remaining', badge(`${days} days`, days < 0 ? 'bad' : days < 30 ? 'warn' : 'ok')], ['Certificate status', badge(d.validity_status, d.validity_status === 'valid' ? 'ok' : 'bad')],
    ['Hostname verification', yn(d.hostname_verified)], ['TLS version', val(d.protocol)], ['Cipher', val(d.cipher)], ['Alternative names', d.sans.length ? chips(d.sans) : NA]]));
};
R.subdomains = s => {
  const d = s.results.subdomains;
  if (!d || d.status !== 'ok') return unavailable(d, 'Passive subdomain discovery');
  const list = d.subdomains.slice(0, 600);
  return card('Passive subdomain discovery', kv([['Source', val(d.source)], ['Discovery status', badge(d.status)], ['Unique subdomains', `<strong>${d.count}</strong>`], ['Note', val(d.message)]])) +
    (d.count ? card('Discovered subdomains', `<div class="toolbar"><label class="sr" for="sub-filter">Filter subdomains</label><input id="sub-filter" type="search" placeholder="Filter subdomains" spellcheck="false"></div>
      <div id="sub-list">${chips(list)}</div>${d.count > 600 ? `<p class="muted">Showing first 600 of ${d.count}. The PDF report lists up to 150.</p>` : ''}`) : '');
};
R.technology = s => {
  const d = s.results.technology;
  if (!d || d.status !== 'ok') return unavailable(d, 'Technology detection');
  const hdr = d.security_headers.map(h => `<tr><td>${esc(h.header)}</td><td>${badge(h.present ? 'Present' : 'Missing', h.present ? 'ok' : 'warn')}</td><td class="mono">${val(h.value)}</td></tr>`).join('');
  const tech = d.technologies.map(t => `<tr><td><strong>${esc(t.name)}</strong></td><td>${esc(t.category)}</td><td>${esc(t.evidence)}</td></tr>`).join('');
  return card('HTTP overview', kv([['HTTP status', val(d.http_status)], ['HTTPS available', d.https_available ? badge('Yes', 'ok') : badge('No', 'bad')], ['Final URL', val(d.final_url)], ['Web server', val(d.server)],
    ['X-Powered-By', val(d.x_powered_by)], ['Page title', val(d.title)]]) + (d.notes.length ? `<p class="muted">${esc(d.notes.join(' '))}</p>` : '')) +
    card('Security headers', `<div class="table-wrap"><table class="table"><thead><tr><th>Header</th><th>Status</th><th>Value</th></tr></thead><tbody>${hdr}</tbody></table></div>`) +
    card('Technologies with evidence', tech ? `<div class="table-wrap"><table class="table"><thead><tr><th>Technology</th><th>Category</th><th>Evidence</th></tr></thead><tbody>${tech}</tbody></table></div>` : '<p class="muted">No technologies could be identified from the response. ReconX only reports what it can support with evidence.</p>');
};
R.intelligence = s => {
  const r = s.results, info = r.domain_info || {}, ips = (r.dns && r.dns.ips) || [];
  const mods = MODS.map(m => `<span class="mod"><span>${esc({dns:'DNS',rdap:'RDAP',ssl:'TLS',subdomains:'Subdomains',technology:'Technology'}[m])}</span>${badge(r[m] ? r[m].status : 'running')}</span>`).join('');
  const obs = (r.observations || []).map(o => `<li>${badge(o.severity)}<span>${esc(o.text)}</span></li>`).join('');
  return card('Target', kv([['Domain status', badge(info.valid ? 'Valid' : 'Invalid', info.valid ? 'ok' : 'bad')], ['Normalised domain', `<strong>${esc(s.domain)}</strong>`], ['Scan timestamp (UTC)', val(fmt(info.scanned_at))],
    ['Scan status', badge(s.status)], ['Resolved IPs', ips.length ? chips(ips) : NA]])) +
    card('Modules', `<div class="module-row">${mods}</div>`) +
    card('Security observations', s.status === 'running' ? '<p class="empty">Observations appear when the scan finishes.</p>' : obs ? `<ul class="obs">${obs}</ul>` : '<p class="muted">No observations could be derived from the collected data.</p>') +
    `<p><a class="btn primary" href="/api/scans/${s.id}/report">Download PDF report</a></p>`;
};

/* ---------- intelligence and section pages ---------- */
async function initViewPage() {
  const scans = await api('/api/scans?type=intelligence&limit=60');
  const sel = $('#scan-select'), view = $('#view');
  if (!scans.length) { sel.closest('.scan-picker').hidden = true; view.innerHTML = '<p class="empty">No scans yet. Enter a domain in the bar above and run an intelligence scan.</p>'; return; }
  let wanted = Number(new URLSearchParams(location.search).get('scan')) || scans[0].id;
  if (!scans.some(s => s.id === wanted)) wanted = scans[0].id;
  sel.innerHTML = scans.map(s => `<option value="${s.id}" ${s.id === wanted ? 'selected' : ''}>${esc(s.domain)} - ${esc(fmt(s.started_at))} (${esc(s.status)})</option>`).join('');
  sel.onchange = () => { location.search = '?scan=' + sel.value; };
  const key = page === 'intelligence' ? 'intelligence' : page;
  for (;;) {
    const scan = await api(`/api/scans/${wanted}`);
    view.innerHTML = R[key](scan);
    const f = $('#sub-filter');
    if (f) f.addEventListener('input', () => {
      const q = f.value.trim().toLowerCase();
      $('#sub-list').innerHTML = chips(scan.results.subdomains.subdomains.filter(x => x.includes(q)).slice(0, 600));
    });
    if (scan.status !== 'running') break;
    await sleep(1500);
  }
}

/* ---------- dashboard ---------- */
function barChart(data) {
  const W = 520, H = 210, pad = 28, max = Math.max(1, ...data.map(d => d.count)), bw = (W - pad * 2) / data.length;
  const bars = data.map((d, i) => {
    const h = Math.round((H - 70) * d.count / max), x = pad + i * bw + bw * .2, y = H - 36 - h;
    return `<rect x="${x}" y="${y}" width="${bw * .6}" height="${Math.max(h, 2)}" rx="4" fill="${d.count ? 'var(--blue)' : 'var(--line)'}"/><text x="${x + bw * .3}" y="${y - 6}" text-anchor="middle" fill="var(--text)" font-size="12">${d.count}</text><text x="${x + bw * .3}" y="${H - 14}" text-anchor="middle" fill="var(--muted)" font-size="11">${esc(d.day.slice(5))}</text>`;
  }).join('');
  return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Scans per day for the last 7 days"><line x1="${pad}" x2="${W - pad}" y1="${H - 36}" y2="${H - 36}" stroke="var(--line)"/>${bars}</svg>`;
}
function donut(by) {
  const colors = {completed: 'var(--ok)', partial: 'var(--warn)', failed: 'var(--bad)', running: 'var(--cyan)'};
  const total = Object.values(by).reduce((a, b) => a + b, 0);
  if (!total) return '<p class="empty">Status breakdown appears after your first scan.</p>';
  let off = 0;
  const segs = Object.entries(by).map(([k, n]) => {
    const pct = n / total * 100, s = `<circle cx="21" cy="21" r="15.9155" fill="none" stroke="${colors[k] || 'var(--muted)'}" stroke-width="5" stroke-dasharray="${pct} ${100 - pct}" stroke-dashoffset="${25 - off}"/>`;
    off += pct; return s;
  }).join('');
  const legend = Object.entries(by).map(([k, n]) => `<li><i style="background:${colors[k] || 'var(--muted)'}"></i>${esc(k)}: <strong>${n}</strong></li>`).join('');
  return `<svg viewBox="0 0 42 42" width="150" height="150" role="img" aria-label="Scan status breakdown">${segs}<text x="21" y="23" text-anchor="middle" fill="var(--text)" font-size="8">${total}</text></svg><ul class="legend">${legend}</ul>`;
}
function scanRows(scans, extra) {
  return scans.map(s => `<tr><td><strong>${esc(s.domain)}</strong></td><td>${esc(TYPES[s.scan_type] || s.scan_type)}</td><td>${esc(fmt(s.started_at))}</td><td>${badge(s.status)}</td>${extra ? extra(s) : ''}<td>${extra === null ? '' : `<a class="link" href="${viewLink(s)}">Open</a>`}</td></tr>`).join('');
}
async function initDashboard() {
  const [st, recent] = await Promise.all([api('/api/stats'), api('/api/scans?limit=8')]);
  $('#s-domains').textContent = st.total_domains; $('#s-scans').textContent = st.total_scans;
  $('#s-subs').textContent = st.total_subdomains; $('#s-verified').textContent = st.verified_targets;
  $('#chart-activity').innerHTML = barChart(st.activity);
  $('#chart-status').innerHTML = donut(st.by_status);
  $('#recent-empty').hidden = recent.length > 0;
  $('#recent-table tbody').innerHTML = scanRows(recent);
  if (recent.some(s => s.status === 'running')) setTimeout(initDashboard, 3000);
}

/* ---------- history and reports ---------- */
async function initHistory() {
  const all = await api('/api/scans?limit=500');
  const draw = () => {
    const q = $('#h-filter').value.trim().toLowerCase(), t = $('#h-type').value;
    const rows = all.filter(s => s.domain.includes(q) && (!t || s.scan_type === t));
    $('#history-empty').hidden = rows.length > 0;
    $('#history-table tbody').innerHTML = rows.map(s => `<tr><td><strong>${esc(s.domain)}</strong></td><td>${esc(TYPES[s.scan_type] || s.scan_type)}</td><td>${esc(fmt(s.started_at))}</td><td>${badge(s.status)}</td><td>${badge(s.verification_status === 'verified' ? 'Ownership verified' : 'Not required (passive)', s.verification_status === 'verified' ? 'ok' : 'info')}</td><td><a class="link" href="${viewLink(s)}">Open</a>${s.status !== 'running' ? ` &nbsp; <a class="link" href="/api/scans/${s.id}/report">PDF</a>` : ''}</td></tr>`).join('');
  };
  $('#h-filter').addEventListener('input', draw); $('#h-type').addEventListener('change', draw); draw();
}
async function initReports() {
  const done = (await api('/api/scans?limit=500')).filter(s => s.status !== 'running');
  $('#reports-empty').hidden = done.length > 0;
  $('#reports-table tbody').innerHTML = done.map(s => `<tr><td><strong>${esc(s.domain)}</strong></td><td>${esc(TYPES[s.scan_type] || s.scan_type)}</td><td>${esc(fmt(s.started_at))}</td><td>${badge(s.status)}</td><td><a class="btn small" href="/api/scans/${s.id}/report">Download PDF</a></td></tr>`).join('');
}

/* ---------- authorised port assessment ---------- */
function renderPorts(res) {
  $('#pa-results').hidden = false;
  if (res.status !== 'ok') { $('#pa-results-body').innerHTML = `<p>${badge(res.status || 'failed')} ${esc(res.message || '')}</p>`; return; }
  const rows = res.ports.map(p => `<tr><td class="num">${p.port}</td><td>${esc(p.service)}</td><td>${badge(p.state)}</td></tr>`).join('');
  $('#pa-results-body').innerHTML = kv([['Target IP', `<code>${esc(res.target_ip)}</code>`], ['Open ports', `<strong>${res.open_count}</strong>`], ['Scan duration', `${res.duration_seconds} s`], ['Started (UTC)', esc(fmt(res.started_at))]]) +
    `<div class="table-wrap"><table class="table"><thead><tr><th>Port</th><th>Service</th><th>State</th></tr></thead><tbody>${rows}</tbody></table></div><p class="muted">${esc(res.note || '')}</p>`;
}
async function initPorts() {
  const msg = $('#pa-msg'), domainInput = $('#pa-domain');
  const say = (t, good) => { msg.textContent = t || ''; msg.classList.toggle('good', !!good); };
  const setVerified = v => {
    const b = $('#pa-state'); b.textContent = v ? 'Ownership verified' : 'Not verified'; b.className = 'badge ' + (v ? 'ok' : 'warn');
    $('#pa-scan-card').hidden = !v;
  };
  const showRecord = d => {
    if (!d.record) return;
    $('#pa-record').hidden = false; $('#r-name').textContent = d.record.name; $('#r-value').textContent = d.record.value; setVerified(d.verified);
  };
  try { const s = await api('/api/settings'); $('#pa-ports').textContent = Object.entries(s.safe_ports).map(([p, n]) => `${p} (${n})`).join(', '); } catch (e) { /* optional */ }
  $('#verify-form').addEventListener('submit', async e => {
    e.preventDefault(); say('');
    try { showRecord(await api('/api/verification', {method: 'POST', body: {domain: domainInput.value}})); } catch (err) { say(err.message); }
  });
  $('#pa-check').addEventListener('click', async () => {
    say('Checking DNS...', true);
    try {
      const d = await api('/api/verification/check', {method: 'POST', body: {domain: domainInput.value}});
      setVerified(d.verified); say(d.verified ? 'Verified. You can now run the port assessment.' : (d.error || 'The TXT record value did not match.'), d.verified);
    } catch (err) { say(err.message); }
  });
  $('#pa-start').addEventListener('click', async () => {
    const b = $('#pa-start'); b.disabled = true; say('Assessing ports...', true);
    try { const d = await api('/api/ports/scan', {method: 'POST', body: {domain: domainInput.value}}); renderPorts(d.result); say('Assessment complete and saved to history.', true); }
    catch (err) { say(err.message); } finally { b.disabled = false; }
  });
  document.addEventListener('click', e => {
    const id = e.target.dataset && e.target.dataset.copy;
    if (id) navigator.clipboard.writeText($('#' + id).textContent).then(() => toast('Copied to clipboard'));
  });
  const scanId = Number(new URLSearchParams(location.search).get('scan'));
  if (scanId) {
    try {
      const s = await api(`/api/scans/${scanId}`);
      if (s.scan_type === 'port_assessment') { domainInput.value = s.domain; renderPorts(s.results); const v = await api(`/api/verification?domain=${encodeURIComponent(s.domain)}`); showRecord(v); }
    } catch (err) { say(err.message); }
  }
}

/* ---------- settings ---------- */
async function initSettings() {
  const s = await api('/api/settings');
  $('#set-runtime').outerHTML = kv([['ReconX version', esc(s.version)], ['Python', esc(s.python)], ['Listening on', `<code>${esc(s.host)}:${s.port}</code>`], ['Stored intelligence scans', s.totals.scans], ['Stored port assessments', s.totals.port_assessments], ['Verified domains', s.totals.verified]]);
  $('#set-limits').outerHTML = kv([...Object.entries(s.timeouts).map(([k, v]) => [`${k} timeout`, `${v} s`]), ['Port scan workers', s.port_workers]]);
  $('#set-ports').innerHTML = Object.entries(s.safe_ports).map(([p, n]) => `<span class="chip">${p} ${esc(n)}</span>`).join('');
  const wire = (id, what, text) => $(id).addEventListener('click', async () => {
    if (!confirm(text)) return;
    try { await api('/api/data', {method: 'DELETE', body: {what}}); toast('Cleared'); setTimeout(() => location.reload(), 600); } catch (e) { toast(e.message, true); }
  });
  wire('#clear-scans', 'scans', 'Delete all stored scans? This cannot be undone.');
  wire('#clear-verifs', 'verifications', 'Reset all domain verifications? You will need to verify again before port assessments.');
}

const INIT = {overview: initDashboard, intelligence: initViewPage, ports: initPorts, history: initHistory, reports: initReports, settings: initSettings};
SECTION_PAGES.forEach(p => { INIT[p] = initViewPage; });
(INIT[page] || (() => {}))().catch(e => toast(e.message, true));
})();
