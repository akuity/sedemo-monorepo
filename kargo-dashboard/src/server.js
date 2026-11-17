import express from 'express';
import { fileURLToPath } from 'node:url';
import { loadConfig } from './config.js';
import { createKargoClient } from './kargo-client.js';
import { createStore } from './store.js';
import { buildDashboard } from './summarize.js';

const PUBLIC_DIR = fileURLToPath(new URL('../public', import.meta.url));
const INDEX = `${PUBLIC_DIR}/index.html`;

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const clock = (ms) => new Date(ms).toISOString().slice(11, 19);

// Builds the express app around a store of Kargo state (see store.js): `store.on('change', fn)`,
// `store.status()` -> { ready, down: [{ project, since }] }, and `build()` -> { [dashboardId]: { dashboard, rows } }.
// Store changes are debounced, every dashboard is rebuilt, and only dashboards whose payload actually
// changed are pushed to their browsers over /api/stream (SSE). Nothing polls.
export function createApp({
  config, store, build,
  debounceMs = 250,        // W9: batch bursts of events
  staleMs = 120_000,       // W8: a stream down this long is reported in the banner
  pingMs = 25_000,         // keeps proxies from closing idle browser streams
  recheckMs = 30_000,      // re-evaluates staleness when no events arrive
  now = Date.now,
  log = console.log,
}) {
  const latest = {};       // dashboardId -> payload (with generatedAt)
  const lastJson = {};     // dashboardId -> serialized payload without generatedAt, to detect real changes
  const clients = new Map(Object.keys(config.dashboards).map((id) => [id, new Set()]));
  let ready = false;

  const staticPart = {
    thresholds: config.decay.thresholds,
    promotionStyle: { color: config.promotion.color, waitingColor: config.promotion.waitingColor, animate: config.promotion.animate },
  };

  // W8: keep showing the last good data; name the projects that have been unreachable for a while.
  function refreshError() {
    const t = now();
    const stale = store.status().down.filter((d) => t - d.since > staleMs);
    if (!stale.length) return null;
    const since = Math.min(...stale.map((d) => d.since));
    return `Lost connection to Kargo for ${stale.map((d) => d.project).join(', ')} since ${clock(since)} UTC`;
  }

  const frame = (payload) => `event: summary\ndata: ${JSON.stringify(payload)}\n\n`;

  function rebuild() {
    if (!store.status().ready) return;
    ready = true;
    const bodies = build();
    const error = refreshError();
    const changedIds = [];
    for (const [id, body] of Object.entries(bodies)) {
      const stable = JSON.stringify({ ...body, ...staticPart, refreshError: error });
      if (stable === lastJson[id]) continue;
      lastJson[id] = stable;
      latest[id] = { ...body, ...staticPart, refreshError: error, generatedAt: new Date(now()).toISOString() };
      changedIds.push(id);
      for (const res of clients.get(id) || []) res.write(frame(latest[id]));
    }
    if (changedIds.length) {
      const n = changedIds.reduce((sum, id) => sum + (clients.get(id)?.size || 0), 0);
      log(`update: ${changedIds.join(', ')} changed, pushed to ${n} browser(s)${error ? `, ${error}` : ''}`);
    }
  }

  let timer = null;
  const schedule = () => {
    if (timer) return;
    timer = setTimeout(() => { timer = null; rebuild(); }, debounceMs);
  };
  store.on('change', schedule);
  const recheck = setInterval(schedule, recheckMs);
  const ping = setInterval(() => { for (const set of clients.values()) for (const res of set) res.write(': ping\n\n'); }, pingMs);
  recheck.unref?.(); ping.unref?.();
  schedule(); // the store may already be ready

  const app = express();

  app.get('/api/dashboards', (_req, res) => {
    res.json(Object.values(config.dashboards).map((d) => ({
      id: d.id, name: d.name, default: d.id === config.defaultDashboard,
    })));
  });

  app.get('/api/summary', (req, res) => {
    const id = req.query.dashboard || config.defaultDashboard;
    if (!config.dashboards[id]) return res.status(404).json({ error: `no dashboard named ${id}` });
    if (!ready || !latest[id]) return res.status(503).json({ error: 'first load from Kargo has not completed' });
    res.json(latest[id]);
  });

  // Server-Sent Events: the current payload on connect, then one `summary` event per real change.
  // Never put compression in front of this route: it would hold events back.
  app.get('/api/stream', (req, res) => {
    const id = req.query.dashboard || config.defaultDashboard;
    if (!config.dashboards[id]) return res.status(404).json({ error: `no dashboard named ${id}` });
    res.status(200).set({
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    res.flushHeaders();
    res.write(': connected\n\n');
    if (latest[id]) res.write(frame(latest[id]));
    const set = clients.get(id);
    set.add(res);
    res.on('close', () => set.delete(res));
  });

  app.get('/healthz', (_req, res) => res.status(ready ? 200 : 503).send(ready ? 'ok' : 'starting'));

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

  // Stops the timers and ends every browser stream (call before closing the HTTP server).
  function close() {
    clearTimeout(timer); clearInterval(recheck); clearInterval(ping);
    store.off('change', schedule);
    for (const set of clients.values()) for (const res of set) res.end();
    for (const set of clients.values()) set.clear();
  }

  return { app, rebuild, close, clientCount: (id) => clients.get(id)?.size ?? 0 };
}

// W11: logs how much Kargo sent us, so the drop can be matched against CloudWatch.
export function startTrafficLog({ client, store, intervalMs = 10 * 60_000, log = console.log }) {
  let lastBytes = client.bytesReceived();
  let lastReconnects = store.status().reconnects;
  const t = setInterval(() => {
    const bytes = client.bytesReceived();
    const { streams, reconnects } = store.status();
    log(`kargo rx: ${bytes - lastBytes} bytes in last ${Math.round(intervalMs / 60_000)}m (${streams} streams, ${reconnects - lastReconnects} reconnects)`);
    lastBytes = bytes; lastReconnects = reconnects;
  }, intervalMs);
  t.unref?.();
  return () => clearInterval(t);
}

async function main() {
  const config = loadConfig();
  config.warnings.forEach((w) => console.warn(`warn: ${w}`));
  const warn = (m) => console.warn(`warn: ${m}`);
  const client = createKargoClient({ url: config.kargo.url });
  const store = createStore({ config, client, warn });
  const ctx = { thresholds: config.decay.thresholds, kargoUrl: config.kargo.url, promotion: config.promotion, warn };
  const build = () => {
    const snapshots = store.snapshots();
    return Object.fromEntries(Object.values(config.dashboards).map((d) => [d.id, buildDashboard(d, snapshots, ctx)]));
  };

  const { app, close } = createApp({ config, store, build });
  const port = Number(process.env.PORT) || 8080;
  const server = app.listen(port, () => console.log(`kargo-dashboard listening on :${port} (${config.kargo.url})`));
  const stopLog = startTrafficLog({ client, store });
  store.start();

  let stopping = false;
  const shutdown = async () => {
    if (stopping) return;
    stopping = true;
    stopLog();
    close();
    await store.stop();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 3000).unref();
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
