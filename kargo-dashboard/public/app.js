'use strict';

const rowsEl = document.getElementById('rows');
const legendEl = document.getElementById('legend');
const bannerEl = document.getElementById('banner');
const updatedEl = document.getElementById('updated');
const NEUTRAL = '#9e9e9e';

// Pick black or white text for readability on a #rrggbb background (WCAG relative luminance).
function textColor(hex) {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex || '');
  if (!m) return '#000';
  const [r, g, b] = [0, 2, 4].map((i) => {
    const c = parseInt(m[1].slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b > 0.4 ? '#000' : '#fff';
}

function el(tag, className, text) {
  const e = document.createElement(tag);
  if (className) e.className = className;
  if (text !== undefined) e.textContent = text;
  return e;
}

// Set from each payload (config.promotion); the defaults only matter before the first response.
let promoStyle = { color: '#1e6fd9', waitingColor: '#7b1fa2', animate: true };

function renderLegend(thresholds) {
  legendEl.replaceChildren();
  let prev = 0;
  for (const t of thresholds) {
    const range = t.max === null ? `${prev}+` : t.max === prev ? `${prev}` : `${prev}–${t.max}`;
    const item = el('span');
    const swatch = el('i');
    swatch.style.background = t.color;
    item.append(swatch, document.createTextNode(`${t.label} (${range} behind)`));
    legendEl.append(item);
    if (t.max !== null) prev = t.max + 1;
  }
  // The round swatch stands in for the card's ● marker; the waiting card keeps its ⏸ marker.
  for (const [color, text, round] of [[promoStyle.color, 'Promoting', true], [promoStyle.waitingColor, '⏸ Waiting for input', false]]) {
    const item = el('span', 'promo-key');
    const swatch = el('i');
    if (round) swatch.style.borderRadius = '50%';
    swatch.style.background = color;
    item.append(swatch, document.createTextNode(text));
    legendEl.append(item);
  }
}

function promotionLabel(p) {
  if (!p.steps || !p.uses) return '● Promoting…';
  const where = `${p.step} of ${p.steps}: ${p.uses}`;
  return p.waiting ? `⏸ Waiting for input · ${where}` : `● ${where}`;
}

function tooltip(cell) {
  const lines = [];
  const p = cell.promotion;
  if (p) {
    lines.push(p.waiting ? 'Promotion is waiting for someone to act' : 'Promotion in progress');
    lines.push(`Promotion: ${p.name}`);
    if (p.alias) lines.push(`Step: ${p.alias}`);
    if (p.message) lines.push(`Message: ${p.message}`);
    if (p.startedAt) lines.push(`Started: ${new Date(p.startedAt).toLocaleString()}`);
    lines.push('');
  }
  if (cell.alias) lines.push(`Alias: ${cell.alias}`);
  if (cell.freightName) lines.push(`Freight: ${cell.freightName}`);
  if (cell.decay.behind !== null && cell.decay.behind !== undefined) {
    lines.push(`${cell.decay.label}: ${cell.decay.behind} version${cell.decay.behind === 1 ? '' : 's'} behind latest`);
  }
  if (cell.since) lines.push(`Deployed since: ${new Date(cell.since).toLocaleString()}`);
  if (cell.createdAt) lines.push(`Created: ${new Date(cell.createdAt).toLocaleString()}`);
  return lines.join('\n');
}

// A link when a URL is known, otherwise plain text. Opens Kargo in a new tab.
function linkOrText(tag, className, text, href) {
  const e = el(tag, className);
  if (!href) {
    e.textContent = text;
    return e;
  }
  const a = el('a', '', text);
  a.href = href;
  a.target = '_blank';
  a.rel = 'noopener noreferrer';
  e.append(a);
  return e;
}

// While a promotion runs the card takes the promotion color (blue, or purple when the current step
// waits for a person), pulses, and shows "current → target" with the step summary.
function renderPromotingCell(s) {
  const p = s.promotion;
  const color = p.waiting ? promoStyle.waitingColor : promoStyle.color;
  const c = el('div', `cell promoting${p.waiting ? ' waiting' : ''}`);
  c.style.background = color;
  c.style.color = textColor(color);
  c.style.setProperty('--glow', `${color}99`);
  const version = el('span', 'version');
  version.append(linkOrText('span', '', s.version ?? '—', s.freightUrl));
  if (p.targetVersion && p.targetVersion !== s.version) {
    version.append(el('span', 'arrow', ' → '), linkOrText('span', '', p.targetVersion, p.targetFreightUrl));
  }
  c.append(linkOrText('span', 'stage', s.name, s.stageUrl), version, linkOrText('span', 'status', promotionLabel(p), p.promotionUrl));
  c.title = tooltip(s);
  return c;
}

function renderCell(s) {
  if (s.promotion) return renderPromotingCell(s);
  const color = s.decay.color || NEUTRAL;
  const c = el('div', 'cell');
  c.style.background = color;
  c.style.color = textColor(color);
  c.append(linkOrText('span', 'stage', s.name, s.stageUrl), linkOrText('span', 'version', s.version ?? '—', s.freightUrl),
    el('span', 'status', s.decay.label));
  c.title = tooltip(s);
  return c;
}

// One warehouse's pipeline: [caption?][latest][stage cells...], left-packed in pipeline order.
function renderLane(lane, showCaption) {
  const l = el('div', 'lane');
  if (showCaption) {
    l.classList.add('captioned');
    l.append(el('div', 'lane-caption', lane.warehouse));
  }
  if (lane.error) {
    l.classList.add('error');
    l.append(el('div', 'message', lane.error));
    return l;
  }
  const latest = el('div', 'cell latest');
  latest.append(el('span', 'stage', 'latest'),
    linkOrText('span', 'version', lane.latest ? lane.latest.version : '—', lane.latest?.freightUrl));
  if (lane.latest) latest.title = tooltip({ ...lane.latest, decay: {} });
  l.append(latest, ...lane.stages.map(renderCell));
  return l;
}

// A project is one row: its label once on the left, then one lane per warehouse.
function renderRow(row) {
  const r = el('section', 'row');
  const label = el('div', 'label');
  label.append(linkOrText('span', '', row.displayName, row.projectUrl));
  if (row.displayName !== row.project) label.append(el('small', '', row.project));
  r.append(label);

  if (row.error) {
    r.classList.add('error');
    r.append(el('div', 'message', row.error));
    return r;
  }
  const lanes = el('div', 'lanes');
  lanes.append(...row.lanes.map((lane) => renderLane(lane, row.showLaneCaptions)));
  r.append(lanes);
  return r;
}

function render(data) {
  promoStyle = data.promotionStyle || promoStyle;
  document.body.classList.toggle('no-motion', promoStyle.animate === false);
  renderLegend(data.thresholds);
  rowsEl.replaceChildren(...data.rows.map(renderRow));
  bannerEl.hidden = !data.refreshError;
  bannerEl.textContent = data.refreshError ? `Showing the last known data. ${data.refreshError}` : '';
  updatedEl.textContent = `Updated ${new Date(data.generatedAt).toLocaleTimeString()}`;
}

// ---- Dashboards: the title is the picker; the URL is the state (/ is the default, /d/<id> the rest) ----
const titleEl = document.getElementById('title');
let dashboards = [];
let currentId = null;
let source = null;     // the EventSource for the current dashboard
let lostTimer = null;  // shows the 'cannot reach' banner if the stream stays broken

const defaultDashboard = () => dashboards.find((d) => d.default) || dashboards[0];
const pathFor = (d) => (d.default ? '/' : `/d/${encodeURIComponent(d.id)}`);

function idFromLocation() {
  const m = /^\/d\/([^/]+)\/?$/.exec(location.pathname);
  return m ? decodeURIComponent(m[1]) : defaultDashboard().id;
}

// Built once, so keyboard focus survives switching; afterwards only its value and the page title change.
function buildTitle() {
  const current = dashboards.find((d) => d.id === currentId) || defaultDashboard();
  if (dashboards.length < 2) {
    titleEl.textContent = current.name; // a single dashboard looks like a plain heading
    return;
  }
  const picker = el('span', 'picker');
  const select = el('select');
  select.id = 'dashboard-select';
  select.setAttribute('aria-label', 'Dashboard');
  for (const d of dashboards) {
    const o = el('option', '', d.default ? `${d.name} (default)` : d.name);
    o.value = d.id;
    select.append(o);
  }
  // Browsers size a select from its options at normal weight, which clips the bold heading text.
  const longest = Math.max(...dashboards.map((d) => (d.default ? `${d.name} (default)` : d.name).length));
  select.style.minWidth = `calc(${longest * 1.15}ch + 40px)`;
  select.addEventListener('change', () => {
    const next = dashboards.find((d) => d.id === select.value);
    history.pushState({}, '', pathFor(next));
    showDashboard(next.id);
  });
  picker.append(select);
  titleEl.replaceChildren(picker);
}

function syncTitle() {
  const current = dashboards.find((d) => d.id === currentId) || defaultDashboard();
  document.title = `${current.name} · Kargo Dashboard`;
  const select = document.getElementById('dashboard-select');
  if (select) select.value = current.id;
}

function showDashboard(id) {
  currentId = id;
  syncTitle();
  rowsEl.replaceChildren(el('p', 'muted', 'Loading…'));
  bannerEl.hidden = true;
  updatedEl.textContent = '';
  connect();
}

// One server-sent event stream per open dashboard: the server pushes a full summary whenever Kargo
// changes. EventSource reconnects by itself; the banner only appears if that keeps failing.
function connect() {
  source?.close();
  clearTimeout(lostTimer);
  lostTimer = null;
  const es = new EventSource(`/api/stream?dashboard=${encodeURIComponent(currentId)}`);
  source = es; // a late event from a closed stream is ignored by the identity checks below
  es.addEventListener('summary', (ev) => {
    if (source !== es) return;
    clearTimeout(lostTimer);
    lostTimer = null;
    render(JSON.parse(ev.data)); // also clears the banner unless the payload carries a refreshError
  });
  es.onerror = () => {
    if (source !== es || lostTimer) return;
    lostTimer = setTimeout(() => {
      bannerEl.hidden = false;
      bannerEl.textContent = 'Cannot reach the dashboard server: connection lost, retrying';
    }, 10000);
  };
}

async function start() {
  try {
    dashboards = await (await fetch('/api/dashboards')).json();
  } catch (err) {
    bannerEl.hidden = false;
    bannerEl.textContent = `Cannot reach the dashboard server: ${err.message}`;
    setTimeout(start, 10000);
    return;
  }
  currentId = idFromLocation();
  buildTitle();
  window.addEventListener('popstate', () => showDashboard(idFromLocation()));
  showDashboard(currentId);
}

start();
