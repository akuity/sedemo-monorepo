import express from 'express';
import { fileURLToPath } from 'node:url';
import { loadConfig } from './config.js';
import { createKargoClient } from './kargo-client.js';
import { createCollector } from './collector.js';
import { buildDashboard } from './summarize.js';

const PUBLIC_DIR = fileURLToPath(new URL('../public', import.meta.url));
const INDEX = `${PUBLIC_DIR}/index.html`;

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// Builds the express app around a refresh function so it can be started or tested separately.
// `refreshAll()` -> { bodies: { [dashboardId]: { dashboard, rows, generatedAt } }, active: boolean }
// where `active` means some stage has a promotion running (the server then polls faster).
export function createApp({ config, refreshAll }) {
  let latest = null; // last good bodies, per dashboard
  let active = false;
  let refreshError = null;
  let lastSeen = Date.now(); // last time a browser asked for a summary

  // Idle = nobody has asked for a summary for idlePauseSeconds; the loop then stops calling Kargo.
  const idleMs = (config.idlePauseSeconds ?? 120) * 1000;
  const isIdle = () => idleMs > 0 && Date.now() - lastSeen > idleMs;

  const currentInterval = () => (active ? config.promotion.activeRefreshIntervalSeconds : config.refreshIntervalSeconds);

  const payload = (id) => ({
    ...latest[id],
    refreshIntervalSeconds: currentInterval(),
    thresholds: config.decay.thresholds,
    promotionStyle: {
      color: config.promotion.color,
      waitingColor: config.promotion.waitingColor,
      animate: config.promotion.animate,
    },
    refreshError,
  });

  async function refresh() {
    const started = Date.now();
    try {
      const result = await refreshAll();
      latest = result.bodies;
      active = result.active;
      refreshError = null;
      const rows = Object.values(latest).flatMap((b) => b.rows);
      console.log(`refresh ok: ${Object.keys(latest).length} dashboards, ${rows.length} rows, ${rows.filter((r) => r.error).length} with errors${active ? ', promotion active' : ''}, ${Date.now() - started}ms`);
    } catch (err) {
      refreshError = err.message;
      console.error(`refresh failed after ${Date.now() - started}ms: ${err.message}`);
    }
  }

  const app = express();

  app.get('/api/dashboards', (_req, res) => {
    res.json(Object.values(config.dashboards).map((d) => ({
      id: d.id, name: d.name, default: d.id === config.defaultDashboard,
    })));
  });

  app.get('/api/summary', (req, res) => {
    const id = req.query.dashboard || config.defaultDashboard;
    if (!config.dashboards[id]) return res.status(404).json({ error: `no dashboard named ${id}` });
    const wasIdle = isIdle();
    lastSeen = Date.now();
    // Data may be arbitrarily old after a pause: make the page retry shortly while the loop wakes up.
    if (wasIdle) return res.status(503).json({ error: 'resuming after idle' });
    if (!latest || !latest[id]) return res.status(503).json({ error: 'first refresh has not completed' });
    res.json(payload(id));
  });

  app.get('/healthz', (_req, res) => res.status(latest ? 200 : 503).send(latest ? 'ok' : 'starting'));

  // The page is one HTML file; the script reads the dashboard id from the URL.
  app.get('/', (_req, res) => res.sendFile(INDEX));
  app.get('/d/:id', (req, res) => {
    if (config.dashboards[req.params.id]) return res.sendFile(INDEX);
    const def = config.dashboards[config.defaultDashboard];
    res.status(404).type('html').send(
      `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">` +
      `<title>Not found · Kargo Dashboard</title>` +
      `<body style="font:16px system-ui;margin:16px"><h1>No dashboard named “${escapeHtml(req.params.id)}”</h1>` +
      `<p><a href="/">Go to ${escapeHtml(def.name)}</a></p></body>`,
    );
  });
  app.use(express.static(PUBLIC_DIR, { index: false }));

  return { app, refresh, currentInterval, isIdle };
}

// Chained timeouts rather than setInterval so slow refreshes never overlap, and so the delay can
// follow the current (adaptive) interval.
const IDLE_CHECK_SECONDS = 2;
function startLoop(refresh, intervalSeconds, isIdle = () => false) {
  const tick = async () => {
    // While idle, skip Kargo entirely and re-check cheaply so the first visitor wakes it quickly.
    if (isIdle()) return void setTimeout(tick, IDLE_CHECK_SECONDS * 1000).unref?.();
    await refresh();
    setTimeout(tick, intervalSeconds() * 1000).unref?.();
  };
  return tick();
}

async function main() {
  const config = loadConfig();
  config.warnings.forEach((w) => console.warn(`warn: ${w}`));
  const client = createKargoClient({ url: config.kargo.url });
  const warn = (m) => console.warn(`warn: ${m}`);
  const collector = createCollector({ client, warn });

  const refreshAll = async () => {
    const { snapshots, active } = await collector.collect(config);
    const ctx = { thresholds: config.decay.thresholds, kargoUrl: config.kargo.url, promotion: config.promotion, warn };
    const generatedAt = new Date().toISOString();
    const bodies = {};
    for (const d of Object.values(config.dashboards)) {
      bodies[d.id] = { ...buildDashboard(d, snapshots, ctx), generatedAt };
    }
    return { bodies, active: Boolean(active) };
  };

  const { app, refresh, currentInterval, isIdle } = createApp({ config, refreshAll });
  const port = Number(process.env.PORT) || 8080;
  app.listen(port, () => console.log(`kargo-dashboard listening on :${port} (${config.kargo.url})`));
  await startLoop(refresh, currentInterval, isIdle);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
