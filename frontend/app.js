'use strict';

const POLL_INTERVAL_MS = 2500;
const $ = (selector) => document.querySelector(selector);

// All scan data (page titles etc.) comes from untrusted sites: build DOM nodes, never innerHTML.
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

async function api(path, options = {}) {
  const res = await fetch(path, { credentials: 'same-origin', ...options });
  if (res.status === 401 || res.status === 403) {
    window.location.href = `/.auth/login/aad?post_login_redirect_uri=${encodeURIComponent(location.pathname + location.hash)}`;
    throw new Error('Sign-in required');
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `Request failed (HTTP ${res.status})`);
  return body;
}

async function showUser() {
  try {
    const res = await fetch('/.auth/me');
    const { clientPrincipal } = await res.json();
    if (clientPrincipal) {
      $('#user').replaceChildren(el('span', { text: clientPrincipal.userDetails }), el('a', { href: '/.auth/logout', text: 'Sign out' }));
    }
  } catch {
    /* running locally without SWA auth */
  }
}

let pollTimer = null;

function setBusy(busy) {
  $('#scan-button').disabled = busy;
  $('#scan-button').textContent = busy ? 'Scanning…' : 'Scan URL';
}

function showError(message) {
  const box = $('#form-error');
  box.textContent = message;
  box.hidden = !message;
}

async function startScan(event) {
  event.preventDefault();
  showError('');
  const url = $('#url').value.trim();
  if (!url) return;
  setBusy(true);
  $('#result').hidden = true;
  try {
    const { id } = await api('/api/scan', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    history.replaceState(null, '', `#${id}`);
    renderProgress({ url, progress: null });
    poll(id);
  } catch (err) {
    showError(err.message);
    setBusy(false);
  }
}

async function poll(id) {
  clearTimeout(pollTimer);
  try {
    const scan = await api(`/api/scan/${encodeURIComponent(id)}`);
    if (scan.report) {
      $('#progress').hidden = true;
      setBusy(false);
      renderReport(scan.report);
      return;
    }
    if (scan.error) throw new Error(scan.error);
    renderProgress(scan);
    pollTimer = setTimeout(() => poll(id), POLL_INTERVAL_MS);
  } catch (err) {
    $('#progress').hidden = true;
    setBusy(false);
    showError(err.message);
  }
}

const STATUS_TEXT = { running: 'Running…', waiting: 'Waiting', ok: 'Done', skipped: 'Not configured', error: 'Failed' };

function renderProgress(scan) {
  $('#progress').hidden = false;
  $('#progress-url').textContent = scan.url || '';
  $('#progress-stage').textContent = scan.progress?.stage || 'Starting scan…';
  const checks = scan.progress?.checks || [];
  $('#progress-checks').replaceChildren(
    ...checks.map((c) => {
      const text = c.status === 'ok' && c.verdict && c.verdict !== 'unknown' ? c.verdict : STATUS_TEXT[c.status] || c.status;
      const cls = c.status === 'ok' ? c.verdict : c.status;
      return el('li', {}, el('span', { text: c.label }), el('span', { class: `pill ${cls}`, text }));
    }),
  );
}

function capabilityCard(title, result, flaggedText) {
  const detected = result.detected;
  const signals = result.signals.slice(0, 6);
  return el(
    'div',
    { class: 'card' },
    el('div', { class: 'cap-head' }, el('h3', { text: title }), el('span', { class: `pill ${detected ? 'detected' : 'clear'}`, text: detected ? flaggedText : 'Not detected' })),
    detected ? el('p', { class: 'muted small', text: `Confidence: ${result.confidence}` }) : null,
    signals.length
      ? el(
          'ul',
          { class: 'signals' },
          signals.map((s) => el('li', {}, el('span', { class: `strength ${s.strength}`, text: s.strength }), s.description)),
        )
      : el('p', { class: 'muted small', text: 'No indicators found.' }),
    result.signals.length > signals.length ? el('p', { class: 'muted small', text: `+${result.signals.length - signals.length} more in the PDF report` }) : null,
  );
}

function maliciousCard(m) {
  const state = m.detected ? 'Malicious' : m.coverageSufficient ? 'Not detected' : 'Unverified';
  return el(
    'div',
    { class: 'card' },
    el('div', { class: 'cap-head' }, el('h3', { text: 'Malicious' }), el('span', { class: `pill ${m.detected || !m.coverageSufficient ? 'detected' : 'clear'}`, text: state })),
    el('p', { class: 'muted small', text: `${m.flaggedBy.length} of ${m.sourcesChecked.length} reputation sources flagged this URL` }),
    m.flaggedBy.length ? el('ul', { class: 'signals' }, m.flaggedBy.map((f) => el('li', {}, el('strong', { text: `${f.source}: ` }), f.summary))) : null,
    m.sourcesUnavailable.length ? el('p', { class: 'muted small', text: `Unavailable: ${m.sourcesUnavailable.join(', ')}` }) : null,
  );
}

function kvList(pairs) {
  return el('dl', { class: 'kv' }, pairs.filter(([, v]) => v).flatMap(([k, v]) => [el('dt', { text: k }), el('dd', { text: v })]));
}

function renderReport(report) {
  const safe = report.determination === 'SAFE';
  const m = report.malicious;
  const d = report.domain;

  const sourcesTable = el(
    'div',
    { class: 'table-wrap' },
    el(
      'table',
      {},
      el('thead', {}, el('tr', {}, ['Source', 'Status', 'Verdict', 'Findings'].map((h) => el('th', { text: h })))),
      el(
        'tbody',
        {},
        report.sources.map((s) =>
          el(
            'tr',
            {},
            el('td', {}, s.reference ? el('a', { href: s.reference, target: '_blank', rel: 'noopener noreferrer', text: s.source }) : s.source),
            el('td', {}, el('span', { class: `pill ${s.status}`, text: STATUS_TEXT[s.status] || s.status })),
            el('td', {}, s.status === 'ok' && s.verdict !== 'unknown' ? el('span', { class: `pill ${s.verdict}`, text: s.verdict }) : '–'),
            el('td', { text: s.summary || '' }),
          ),
        ),
      ),
    ),
  );

  $('#result').replaceChildren(
    el(
      'div',
      { class: `verdict ${safe ? 'safe' : 'unsafe'}` },
      el('div', { class: 'label', text: report.determination }),
      el('div', { class: 'url', text: report.url }),
      safe ? el('div', { text: report.summary }) : el('ul', {}, report.reasons.map((r) => el('li', { text: r }))),
    ),
    el(
      'div',
      { class: 'actions' },
      el('a', { class: 'button', href: `/api/scan/${encodeURIComponent(report.id)}/report`, text: 'Download PDF report' }),
      el('button', { class: 'button secondary', type: 'button', text: 'Scan another URL', onclick: resetForm }),
    ),
    el('div', { class: 'grid3' }, maliciousCard(m), capabilityCard('File sharing', report.fileSharing, 'Detected'), capabilityCard('AI usage', report.ai, 'Detected')),
    m.warnings.length
      ? el('section', { class: 'card' }, el('h3', { text: 'Warnings' }), el('ul', { class: 'warnings' }, m.warnings.map((w) => el('li', { text: `${w.message} (${w.source})` }))))
      : null,
    el('section', { class: 'card' }, el('h3', { text: 'Sources' }), sourcesTable),
    el(
      'section',
      { class: 'card' },
      el('h3', { text: 'Site details' }),
      kvList([
        ['Final URL', report.site.finalUrl],
        ['Title', report.site.title],
        ['Description', report.site.description],
        ['Domain', d ? `${d.name}${d.registered ? ` · registered ${d.registered.slice(0, 10)} (${d.ageDays} days ago)` : ''}` : null],
        ['Registrar', d?.registrar],
        ['IP / country', [report.site.ip, report.site.country].filter(Boolean).join(' · ')],
        ['Network', report.site.asn],
        ['TLS issuer', report.site.tlsIssuer],
        ['Technologies', report.site.technologies.join(', ')],
        ['Scanned', new Date(report.completedAt).toLocaleString()],
      ]),
    ),
  );
  $('#result').hidden = false;
}

function resetForm() {
  history.replaceState(null, '', location.pathname);
  $('#result').hidden = true;
  $('#url').value = '';
  $('#url').focus();
}

$('#scan-form').addEventListener('submit', startScan);
showUser();

// Resume a scan after a page refresh (scan id is kept in the URL fragment).
const resumeId = location.hash.slice(1);
if (/^[A-Za-z0-9-]{8,64}$/.test(resumeId)) {
  setBusy(true);
  renderProgress({ url: '', progress: null });
  poll(resumeId);
}
