import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createApp, startTrafficLog } from '../src/server.js';
import { parseSSE } from '../src/sse.js';
import { DEFAULT_THRESHOLDS, DEFAULT_PROMOTION } from '../src/config.js';

const config = {
  decay: { thresholds: DEFAULT_THRESHOLDS },
  promotion: { ...DEFAULT_PROMOTION },
  defaultDashboard: 'demos',
  dashboards: {
    demos: { id: 'demos', name: 'SE Demos', projects: {} },
    teams: { id: 'teams', name: 'Team <Apps>', projects: {} },
  },
};

// A stand-in for store.js: tests flip `ready`/`down`, edit `data`, and call poke() like a watch event.
function fakeStore() {
  const s = new EventEmitter();
  s.state = { ready: false, down: [], reconnects: 0, streams: 3 };
  s.data = { demos: [{ project: 'p1' }], teams: [{ project: 'p2' }] };
  s.status = () => s.state;
  s.poke = () => s.emit('change');
  return s;
}
const buildFrom = (store) => () => ({
  demos: { dashboard: { id: 'demos', name: 'SE Demos' }, rows: store.data.demos },
  teams: { dashboard: { id: 'teams', name: 'Team <Apps>' }, rows: store.data.teams },
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const waitFor = async (fn, ms = 1000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await fn()) return true; await sleep(5); }
  return false;
};
const json = async (res) => res.json();

async function withServer(fn, { store = fakeStore(), ...opts } = {}) {
  const log = [];
  const handle = createApp({ config, store, build: buildFrom(store), debounceMs: 5, log: (m) => log.push(m), ...opts });
  const server = handle.app.listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  try { await fn({ base, store, handle, log }); } finally { handle.close(); server.close(); server.closeAllConnections?.(); }
}
// Opens /api/stream and collects summary events as they arrive.
async function openStream(base, id) {
  const ac = new AbortController();
  const res = await fetch(`${base}/api/stream${id ? `?dashboard=${id}` : ''}`, { signal: ac.signal });
  const events = [];
  const done = (async () => {
    try { for await (const f of parseSSE(res.body)) if (f.event === 'summary') events.push(JSON.parse(f.data)); } catch { /* aborted */ }
  })();
  return { res, events, close: () => { ac.abort(); return done; } };
}
const makeReady = async (store) => { store.state.ready = true; store.poke(); await sleep(30); };

test('healthz and summary are 503 until the first load completes, then 200 with the payload', async () => {
  await withServer(async ({ base, store }) => {
    assert.equal((await fetch(`${base}/healthz`)).status, 503);
    assert.equal((await fetch(`${base}/api/summary`)).status, 503);
    await makeReady(store);
    assert.equal((await fetch(`${base}/healthz`)).status, 200);
    const body = await json(await fetch(`${base}/api/summary`));
    assert.deepEqual([body.rows[0].project, body.thresholds.length, body.refreshError], ['p1', 4, null]);
    assert.ok(Date.parse(body.generatedAt) > 0);
    assert.ok(!('refreshIntervalSeconds' in body), 'nothing polls any more');
    assert.deepEqual(body.promotionStyle, { color: '#1e6fd9', waitingColor: '#7b1fa2', animate: true });
  });
});

test('/api/dashboards lists names in config order, flags the default, and works before the first load', async () => {
  await withServer(async ({ base }) => {
    assert.deepEqual(await json(await fetch(`${base}/api/dashboards`)), [
      { id: 'demos', name: 'SE Demos', default: true },
      { id: 'teams', name: 'Team <Apps>', default: false },
    ]);
  });
});

test('/api/summary serves the default, ?dashboard= picks another, an unknown id is 404 JSON', async () => {
  await withServer(async ({ base, store }) => {
    await makeReady(store);
    assert.equal((await json(await fetch(`${base}/api/summary`))).dashboard.id, 'demos');
    const teams = await json(await fetch(`${base}/api/summary?dashboard=teams`));
    assert.deepEqual([teams.dashboard.id, teams.rows[0].project], ['teams', 'p2']);
    const nope = await fetch(`${base}/api/summary?dashboard=nope`);
    assert.equal(nope.status, 404);
    assert.match((await json(nope)).error, /no dashboard named nope/);
  });
});

test('page routes: / and /d/<id> serve the app; /d/<unknown> is a 404 page linking to the default', async () => {
  await withServer(async ({ base }) => {
    for (const path of ['/', '/d/demos', '/d/teams']) {
      const res = await fetch(`${base}${path}`);
      assert.equal(res.status, 200, path);
      assert.match(await res.text(), /<title>Kargo Dashboard<\/title>/);
    }
    const res = await fetch(`${base}/d/nope`);
    assert.equal(res.status, 404);
    const html = await res.text();
    assert.match(html, /No dashboard named “nope”/);
    assert.match(html, /<a href="\/">Go to SE Demos<\/a>/);
    const evil = await (await fetch(`${base}/d/${encodeURIComponent('<script>x</script>')}`)).text();
    assert.ok(!evil.includes('<script>x'), 'ids are HTML-escaped');
    assert.equal((await fetch(`${base}/app.js`)).status, 200);
    assert.equal((await fetch(`${base}/style.css`)).status, 200);
  });
});

// ---- /api/stream ----
test('/api/stream is event-stream, unbuffered, and sends the current payload on connect', async () => {
  await withServer(async ({ base, store, handle }) => {
    await makeReady(store);
    const s = await openStream(base, 'teams');
    assert.equal(s.res.status, 200);
    assert.match(s.res.headers.get('content-type'), /^text\/event-stream/);
    assert.equal(s.res.headers.get('x-accel-buffering'), 'no');
    assert.match(s.res.headers.get('cache-control'), /no-cache/);
    assert.ok(await waitFor(() => s.events.length === 1));
    assert.equal(s.events[0].dashboard.id, 'teams');
    assert.equal(handle.clientCount('teams'), 1);
    await s.close();
  });
});

test('a client that connects before the first load gets its first payload as soon as the load finishes', async () => {
  await withServer(async ({ base, store }) => {
    const s = await openStream(base);
    await sleep(30);
    assert.equal(s.events.length, 0);
    await makeReady(store);
    assert.ok(await waitFor(() => s.events.length === 1));
    assert.equal(s.events[0].dashboard.id, 'demos', 'no dashboard param means the default');
    await s.close();
  });
});

test('a change pushes only to the dashboards whose payload changed; an identical rebuild pushes nothing', async () => {
  await withServer(async ({ base, store, log }) => {
    await makeReady(store);
    const demos = await openStream(base, 'demos');
    const teams = await openStream(base, 'teams');
    assert.ok(await waitFor(() => demos.events.length === 1 && teams.events.length === 1));

    store.poke(); store.poke(); await sleep(40); // changes, but nothing differs
    assert.equal(demos.events.length + teams.events.length, 2, 'no push when the payload is identical');

    store.data.demos = [{ project: 'p1', changed: true }];
    store.poke();
    assert.ok(await waitFor(() => demos.events.length === 2));
    await sleep(30);
    assert.equal(teams.events.length, 1, 'teams was not pushed');
    assert.equal(demos.events[1].rows[0].changed, true);
    assert.ok(log.some((m) => /update: demos changed, pushed to 1 browser/.test(m)));
    await demos.close(); await teams.close();
  });
});

test('a burst of events is batched into one rebuild', async () => {
  await withServer(async ({ base, store }) => {
    await makeReady(store);
    const s = await openStream(base);
    assert.ok(await waitFor(() => s.events.length === 1));
    store.data.demos = [{ project: 'p1', n: 1 }];
    for (let i = 0; i < 20; i += 1) store.poke();
    await sleep(60);
    assert.equal(s.events.length, 2);
    await s.close();
  }, { debounceMs: 20 });
});

test('a disconnected client is removed; an unknown dashboard is a 404', async () => {
  await withServer(async ({ base, store, handle }) => {
    await makeReady(store);
    const s = await openStream(base, 'demos');
    assert.ok(await waitFor(() => handle.clientCount('demos') === 1));
    await s.close();
    assert.ok(await waitFor(() => handle.clientCount('demos') === 0));
    const nope = await fetch(`${base}/api/stream?dashboard=nope`);
    assert.equal(nope.status, 404);
  });
});

test('close() ends the browser streams', async () => {
  await withServer(async ({ base, store, handle }) => {
    await makeReady(store);
    const s = await openStream(base);
    assert.ok(await waitFor(() => s.events.length === 1));
    handle.close();
    await Promise.race([s.close(), sleep(1000).then(() => assert.fail('stream did not end'))]);
  });
});

test('keepalive pings are sent so proxies keep the stream open', async () => {
  await withServer(async ({ base, store }) => {
    await makeReady(store);
    const ac = new AbortController();
    const res = await fetch(`${base}/api/stream`, { signal: ac.signal });
    let sawPing = false;
    const reader = (async () => { try { for await (const f of parseSSE(res.body)) if (f.comment === 'ping') { sawPing = true; break; } } catch { /* aborted */ } })();
    assert.ok(await waitFor(() => sawPing, 1000));
    ac.abort(); await reader;
  }, { pingMs: 20 });
});

// ---- W8: staleness ----
test('refreshError names projects whose stream has been down longer than staleMs, and clears when they recover', async () => {
  let t = 10_000_000;
  await withServer(async ({ base, store }) => {
    await makeReady(store);
    const s = await openStream(base);
    assert.ok(await waitFor(() => s.events.length === 1));
    assert.equal(s.events[0].refreshError, null);

    store.state.down = [{ project: 'team-ada', since: t - 30_000 }];
    store.poke(); await sleep(40);
    assert.equal(s.events.length, 1, 'down for only 30s: not reported yet');

    t += 100_000; // now 130s
    store.poke();
    assert.ok(await waitFor(() => s.events.length === 2));
    assert.match(s.events[1].refreshError, /^Lost connection to Kargo for team-ada since \d\d:\d\d:\d\d UTC$/);
    assert.equal(s.events[1].rows.length, 1, 'rows are kept, never blanked');

    store.state.down = [];
    store.poke();
    assert.ok(await waitFor(() => s.events.length === 3));
    assert.equal(s.events[2].refreshError, null);
    await s.close();
  }, { now: () => t, staleMs: 120_000 });
});

test('staleness is noticed even when no events arrive (periodic recheck)', async () => {
  let t = 10_000_000;
  await withServer(async ({ base, store }) => {
    await makeReady(store);
    const s = await openStream(base);
    assert.ok(await waitFor(() => s.events.length === 1));
    store.state.down = [{ project: 'p', since: t }];
    t += 200_000; // no poke: only the timer can notice
    assert.ok(await waitFor(() => s.events.length === 2, 1000));
    assert.match(s.events[1].refreshError, /Lost connection/);
    await s.close();
  }, { now: () => t, staleMs: 120_000, recheckMs: 20 });
});

// ---- W11 ----
test('the traffic log reports bytes received and reconnects per interval', async () => {
  const lines = [];
  let bytes = 100; const store = fakeStore();
  const client = { bytesReceived: () => bytes };
  const stop = startTrafficLog({ client, store, intervalMs: 20, log: (m) => lines.push(m) });
  bytes += 4321; store.state.reconnects = 2;
  assert.ok(await waitFor(() => lines.length >= 1));
  stop();
  assert.match(lines[0], /^kargo rx: 4321 bytes in last 0m \(3 streams, 2 reconnects\)$/);
});
