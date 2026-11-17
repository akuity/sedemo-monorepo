// Browser tests: `npm run test:e2e`. Needs Chrome (set CHROME_PATH if it is not at the macOS default).
// Starts a fake Kargo API, starts the real dashboard server against it, and drives the page with Puppeteer.
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import puppeteer from 'puppeteer-core';
import { startFakeKargo, FAKE_TOKEN } from './fake-kargo.mjs';

const CHROME = process.env.CHROME_PATH || ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/google-chrome', '/usr/bin/chromium']
  .find((p) => existsSync(p));
if (!CHROME) { console.error('Chrome not found; set CHROME_PATH'); process.exit(2); }

const FAKE_PORT = 18091, APP_PORT = 18090, NOANIM_PORT = 18092;
const IMG = 'ghcr.io/akuity/sedemo-monorepo-rollouts-app';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const results = [];
const check = (name, ok, detail = '') => results.push({ ok, line: `${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ` — ${detail}` : ''}` });

const dir = mkdtempSync(join(tmpdir(), 'kd-e2e-'));
const baseConfig = (extra = {}) => ({
  kargo: { url: `http://127.0.0.1:${FAKE_PORT}`, tokenEnv: 'FAKE_TOKEN' },
  promotion: { ...(extra.promotion || {}) },
  defaultDashboard: 'demos',
  dashboards: {
    demos: { name: 'SE Demos', projects: { 'demo-rollouts': { displayName: 'Rollouts Demo', warehouse: 'demo-rollouts' } } },
    teams: { name: 'Team Apps', projects: { 'team-ada': { warehouses: ['akkoma-main', 'akkoma-release'] }, 'sedemo-app-demo': {} } },
  },
});
function startApp(port, config) {
  const file = join(dir, `config-${port}.json`);
  writeFileSync(file, JSON.stringify(config));
  const child = spawn('node', ['src/server.js'], { env: { ...process.env, FAKE_TOKEN, CONFIG_PATH: file, PORT: String(port) }, stdio: 'ignore' });
  return child;
}
async function waitHealthy(base) {
  for (let i = 0; i < 80; i += 1) {
    try { if ((await fetch(`${base}/healthz`)).ok) return; } catch { /* not up yet */ }
    await sleep(250);
  }
  throw new Error(`${base} never became healthy`);
}

const fake = await startFakeKargo(FAKE_PORT);
const app = startApp(APP_PORT, baseConfig());
const noanim = startApp(NOANIM_PORT, baseConfig({ promotion: { animate: false } }));
const browser = await puppeteer.launch({ executablePath: CHROME, headless: 'new', args: ['--no-sandbox'] });

try {
  const BASE = `http://127.0.0.1:${APP_PORT}`;
  await Promise.all([waitHealthy(BASE), waitHealthy(`http://127.0.0.1:${NOANIM_PORT}`)]);
  const page = await browser.newPage();
  let summaryRequests = 0; // the page must never poll
  page.on('request', (r) => { if (r.url().includes('/api/summary')) summaryRequests += 1; });
  await page.setViewport({ width: 1100, height: 800 });
  const waitRows = () => page.waitForFunction(() => document.querySelectorAll('.cell').length > 1 && !document.querySelector('#rows .muted'), { timeout: 15000 });
  const labels = () => page.$$eval('.row .label', (els) => els.map((e) => e.firstChild.textContent.trim()));
  const summary = async (base = BASE) => (await fetch(`${base}/api/summary`)).json();
  const cell = (stage) => page.evaluate((stage) => {
    const c = [...document.querySelectorAll('.cell')].find((x) => x.querySelector('.stage')?.textContent === stage);
    if (!c) return null;
    const cs = getComputedStyle(c);
    return { cls: c.className, bg: cs.backgroundColor, fg: cs.color, anim: cs.animationName, dur: cs.animationDuration,
      version: c.querySelector('.version').textContent.trim(), status: c.querySelector('.status').textContent.trim(), title: c.title,
      links: [...c.querySelectorAll('a')].map((a) => a.getAttribute('href')) };
  }, stage);

  // ---- dashboards (PLAN 15) ----
  await page.goto(`${BASE}/`); await waitRows();
  check('/ shows the default dashboard (title and rows)', (await page.title()) === 'SE Demos · Kargo Dashboard' && (await labels()).join() === 'Rollouts Demo', await page.title());
  check('the title is a native select listing both dashboards, default marked', (await page.$$eval('#dashboard-select option', (o) => o.map((x) => x.textContent))).join('|') === 'SE Demos (default)|Team Apps');
  await page.select('#dashboard-select', 'teams'); await page.waitForFunction(() => location.pathname === '/d/teams'); await waitRows();
  check('switching updates the URL, title and rows without a reload', (await page.title()) === 'Team Apps · Kargo Dashboard' && (await labels()).join() === 'team-ada,sedemo-app-demo');
  await page.goBack(); await page.waitForFunction(() => location.pathname === '/'); await waitRows();
  check('Back returns to the default dashboard', (await page.title()) === 'SE Demos · Kargo Dashboard' && (await labels()).join() === 'Rollouts Demo');
  await page.goForward(); await page.waitForFunction(() => location.pathname === '/d/teams'); await waitRows();
  check('Forward returns to Team Apps', (await page.title()) === 'Team Apps · Kargo Dashboard');
  await page.goto(`${BASE}/d/teams`); await waitRows();
  check('a deep link opens that dashboard with the picker on it', (await page.$eval('#dashboard-select', (s) => s.value)) === 'teams');
  await page.goto(`${BASE}/`); await waitRows();
  await page.keyboard.press('Tab');
  check('keyboard: Tab focuses the picker', (await page.evaluate(() => document.activeElement?.id)) === 'dashboard-select');
  await page.keyboard.press('T'); await page.waitForFunction(() => location.pathname === '/d/teams', { timeout: 5000 }).catch(() => {});
  check('keyboard: type-ahead switches dashboard and focus stays on the picker', new URL(page.url()).pathname === '/d/teams' && (await page.evaluate(() => document.activeElement?.id)) === 'dashboard-select');
  const missing = await page.goto(`${BASE}/d/nope`);
  check('/d/<unknown> is a 404 page linking to the default', missing.status() === 404 && (await page.$eval('a', (a) => `${a.getAttribute('href')} ${a.textContent}`)) === '/ Go to SE Demos');

  // ---- promotions (PLAN 14) ----
  await page.goto(`${BASE}/`); await waitRows();
  let d = await cell('dev');
  check('idle: nothing is promoting', !(await page.$('.cell.promoting')) && d.anim === 'none');
  const legend = await page.$eval('#legend', (e) => e.textContent);
  check('legend has Promoting and Waiting for input', legend.includes('Promoting') && legend.includes('⏸ Waiting for input'));

  const t0 = Date.now();
  await fake.set('demo-rollouts', 'dev', { name: 'dev.p1', origin: 'demo-rollouts', repoURL: IMG, tag: '51-blue', currentStep: 4 });
  await fake.set('demo-rollouts', 'staging', { name: 'staging.p2', origin: 'demo-rollouts', repoURL: IMG, tag: '51-blue', currentStep: 6 });
  await page.waitForFunction(() => document.querySelectorAll('.cell.promoting').length >= 2, { timeout: 5000 });
  const latency = Date.now() - t0;
  check('live update: both promoting cards appear within 2s, with no page reload', latency < 2000, `${latency}ms`);
  d = await cell('dev');
  check('running: promotion blue with the 1.6s heartbeat', d.cls.includes('promoting') && !d.cls.includes('waiting') && d.bg === 'rgb(30, 111, 217)' && d.anim === 'heartbeat' && d.dur === '1.6s', JSON.stringify([d.bg, d.anim, d.dur]));
  check('running: "5 of 7: helm-template" and "50-blue → 51-blue"', d.status === '● 5 of 7: helm-template' && d.version === '50-blue → 51-blue', `${d.status} | ${d.version}`);
  check('running: stage, current, target and promotion links', d.links.length === 4 && d.links[0].endsWith('/project/demo-rollouts/stage/dev') && d.links[2].endsWith('/freight/incoming-freight') && d.links[3].endsWith('/project/demo-rollouts/promotion/dev.p1'), d.links.join(' '));
  check('running: white text on blue; tooltip keeps the decay info', d.fg === 'rgb(255, 255, 255)' && d.title.includes('Promotion: dev.p1') && d.title.includes('Good: 0 versions behind'));
  const w = await cell('staging');
  check('waiting: purple, slow 3s breathing, ⏸ label with the step', w.cls.includes('waiting') && w.bg === 'rgb(123, 31, 162)' && w.anim === 'breathe' && w.dur === '3s' && w.status === '⏸ Waiting for input · 7 of 7: wait-for-approval', JSON.stringify([w.bg, w.anim, w.status]));
  check('waiting: tooltip says someone must act; the step summary links to the promotion page', w.title.startsWith('Promotion is waiting for someone to act') && w.links.at(-1).endsWith('/project/demo-rollouts/promotion/staging.p2'));
  check('other cards are unaffected', !(await cell('prod')).cls.includes('promoting'));

  await page.setViewport({ width: 390, height: 900 }); await page.goto(`${BASE}/`); await waitRows();
  check('390px: no page-level horizontal scroll', (await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)) <= 0);
  if (process.env.SHOT_DIR) await page.screenshot({ path: join(process.env.SHOT_DIR, 'e2e-phone.png'), fullPage: true });
  await page.setViewport({ width: 1100, height: 800 }); await page.goto(`${BASE}/`); await waitRows();
  if (process.env.SHOT_DIR) await page.screenshot({ path: join(process.env.SHOT_DIR, 'e2e-desktop.png') });

  await page.emulateMediaFeatures([{ name: 'prefers-reduced-motion', value: 'reduce' }]);
  d = await cell('dev'); const wr = await cell('staging');
  check('prefers-reduced-motion: no animation; color and text still carry the state', d.anim === 'none' && wr.anim === 'none' && d.bg === 'rgb(30, 111, 217)' && wr.status.startsWith('⏸'));
  await page.emulateMediaFeatures([{ name: 'prefers-reduced-motion', value: 'no-preference' }]);

  const nPage = await browser.newPage();
  await nPage.goto(`http://127.0.0.1:${NOANIM_PORT}/`); await nPage.waitForSelector('.cell.promoting', { timeout: 15000 });
  check('promotion.animate=false: no animation, color and text remain', await nPage.evaluate(() => {
    const c = document.querySelector('.cell.promoting'); return getComputedStyle(c).animationName === 'none' && c.querySelector('.status').textContent.startsWith('●');
  }));

  await fake.set('demo-rollouts', 'dev', null); await fake.set('demo-rollouts', 'staging', null);
  await page.bringToFront(); // the animate=false check above opened another tab; rAF-based waits stall in a background tab
  await page.waitForFunction(() => !document.querySelector('.cell.promoting'), { timeout: 5000 });
  check('after the promotions end no card is promoting, again with no reload', true);

  // a new Freight arrives: the "latest" cell moves and the stages fall behind, live
  const latestVersion = () => page.$eval('.row .cell.latest .version', (e) => e.textContent.trim());
  const before = await latestVersion();
  const sample = structuredClone(Object.values(JSON.parse(readFileSync(new URL('../test/fixtures/demo-rollouts/freight.json', import.meta.url))).groups)[0].items[0]);
  sample.metadata = { name: 'live-freight', creationTimestamp: '2030-01-01T00:00:00Z' };
  sample.images = [{ repoURL: IMG, tag: '99-live' }];
  const t1 = Date.now();
  await fake.addFreight('demo-rollouts', sample);
  await page.waitForFunction(() => document.querySelector('.row .cell.latest .version')?.textContent.trim() === '99-live', { timeout: 5000 });
  check('a new Freight updates "latest" within 2s with no reload', before !== '99-live' && Date.now() - t1 < 2000, `${before} -> 99-live in ${Date.now() - t1}ms`);
  check('and the stages are now one version behind', (await cell('dev')).title.includes('1 version behind'), (await cell('dev')).title);

  await fake.set('sedemo-app-demo', 'dev', { name: 'dev.p3', origin: 'sedemo-app-demo-chart', repoURL: 'x', tag: 'y', currentStep: 0 });
  let teams;
  for (let i = 0; i < 50; i += 1) {
    teams = await (await fetch(`${BASE}/api/summary?dashboard=teams`)).json();
    if (teams.rows.find((r) => r.project === 'sedemo-app-demo').lanes.some((l) => l.stages.some((c) => c.promotion))) break;
    await sleep(100);
  }
  const sedemo = teams.rows.find((r) => r.project === 'sedemo-app-demo').lanes;
  check('multi-warehouse: a promotion shows only in the lane whose warehouse supplied the Freight',
    sedemo.find((l) => l.warehouse === 'sedemo-app-demo').stages.find((c) => c.name === 'dev').promotion === null &&
    sedemo.find((l) => l.warehouse === 'sedemo-app-demo-chart').stages.find((c) => c.name === 'dev').promotion?.step === 1);
  // ---- nothing polls ----
  const stats = await fake.stats();
  check('the browser never requested /api/summary: it only listens to the stream', summaryRequests === 0, `${summaryRequests} requests`);
  const lists = Object.entries(stats.lists);
  check('Kargo was listed once per stream per app instance, not on a timer', lists.length > 0 && lists.every(([, n]) => n <= 2), JSON.stringify(stats.lists));
  check('and watched once per stream per app instance: no reconnect storm', Object.values(stats.watches).every((n) => n <= 2), JSON.stringify(stats.watches));
} catch (err) {
  check('e2e run completed without an exception', false, err.stack || String(err));
} finally {
  await browser.close();
  app.kill(); noanim.kill();
  await fake.close();
}
console.log(results.map((r) => r.line).join('\n'));
const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} browser checks passed`);
process.exit(failed ? 1 : 0);
