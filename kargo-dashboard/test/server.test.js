import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/server.js';
import { DEFAULT_THRESHOLDS, DEFAULT_PROMOTION } from '../src/config.js';

const config = {
  refreshIntervalSeconds: 30,
  decay: { thresholds: DEFAULT_THRESHOLDS },
  promotion: { ...DEFAULT_PROMOTION },
  defaultDashboard: 'demos',
  dashboards: {
    demos: { id: 'demos', name: 'SE Demos', projects: {} },
    teams: { id: 'teams', name: 'Team <Apps>', projects: {} },
  },
};
const bodies = () => ({
  demos: { dashboard: { id: 'demos', name: 'SE Demos' }, rows: [{ project: 'p1' }], generatedAt: 'now' },
  teams: { dashboard: { id: 'teams', name: 'Team <Apps>' }, rows: [{ project: 'p2' }], generatedAt: 'now' },
});

async function withServer(refreshAll, fn, cfg = config) {
  const { app, refresh, currentInterval } = createApp({ config: cfg, refreshAll });
  const server = app.listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  try { await fn(base, refresh, currentInterval); } finally { server.close(); }
}
const json = async (res) => res.json();

test('healthz and summary are 503 until the first refresh, then 200', async () => {
  await withServer(async () => ({ bodies: bodies(), active: false }), async (base, refresh) => {
    assert.equal((await fetch(`${base}/healthz`)).status, 503);
    assert.equal((await fetch(`${base}/api/summary`)).status, 503);
    await refresh();
    assert.equal((await fetch(`${base}/healthz`)).status, 200);
    const body = await json(await fetch(`${base}/api/summary`));
    assert.deepEqual([body.rows[0].project, body.refreshIntervalSeconds, body.thresholds.length, body.refreshError], ['p1', 30, 4, null]);
    assert.deepEqual(body.promotionStyle, { color: '#1e6fd9', waitingColor: '#7b1fa2', animate: true });
  });
});

test('/api/dashboards lists names in config order, flags the default, and works before the first refresh', async () => {
  await withServer(async () => ({ bodies: bodies(), active: false }), async (base) => {
    assert.deepEqual(await json(await fetch(`${base}/api/dashboards`)), [
      { id: 'demos', name: 'SE Demos', default: true },
      { id: 'teams', name: 'Team <Apps>', default: false },
    ]);
  });
});

test('/api/summary serves the default, ?dashboard= picks another, an unknown id is 404 JSON', async () => {
  await withServer(async () => ({ bodies: bodies(), active: false }), async (base, refresh) => {
    await refresh();
    assert.equal((await json(await fetch(`${base}/api/summary`))).dashboard.id, 'demos');
    const teams = await json(await fetch(`${base}/api/summary?dashboard=teams`));
    assert.deepEqual([teams.dashboard.id, teams.rows[0].project], ['teams', 'p2']);
    const nope = await fetch(`${base}/api/summary?dashboard=nope`);
    assert.equal(nope.status, 404);
    assert.match((await json(nope)).error, /no dashboard named nope/);
  });
});

test('page routes: / and /d/<id> serve the app; /d/<unknown> is a 404 page linking to the default', async () => {
  await withServer(async () => ({ bodies: bodies(), active: false }), async (base) => {
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

test('a failed refresh keeps every dashboard\'s previous rows and reports the error', async () => {
  let n = 0;
  const refreshAll = async () => {
    if (++n === 2) throw new Error('kaboom');
    return { bodies: bodies(), active: false };
  };
  await withServer(refreshAll, async (base, refresh) => {
    await refresh();
    await refresh();
    for (const id of ['demos', 'teams']) {
      const body = await json(await fetch(`${base}/api/summary?dashboard=${id}`));
      assert.equal(body.rows.length, 1);
      assert.equal(body.refreshError, 'kaboom');
    }
    await refresh();
    assert.equal((await json(await fetch(`${base}/api/summary`))).refreshError, null);
  });
});

test('the refresh interval drops to the active value while a promotion runs, then returns', async () => {
  let active = true;
  await withServer(async () => ({ bodies: bodies(), active }), async (base, refresh, currentInterval) => {
    assert.equal(currentInterval(), 30);
    await refresh();
    assert.equal(currentInterval(), 5);
    assert.equal((await json(await fetch(`${base}/api/summary`))).refreshIntervalSeconds, 5);
    active = false;
    await refresh();
    assert.equal(currentInterval(), 30);
    assert.equal((await json(await fetch(`${base}/api/summary`))).refreshIntervalSeconds, 30);
  });
});

test('after idlePauseSeconds without a summary request, the next request gets 503 (resuming) and marks the app active again', async () => {
  const cfg = { ...config, idlePauseSeconds: 0.05 };
  const { app, refresh, isIdle } = createApp({ config: cfg, refreshAll: async () => ({ bodies: bodies(), active: false }) });
  const server = app.listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    await refresh();
    assert.equal((await fetch(`${base}/api/summary`)).status, 200);
    await new Promise((r) => setTimeout(r, 80));
    assert.equal(isIdle(), true);
    assert.equal((await fetch(`${base}/api/summary`)).status, 503);
    assert.equal(isIdle(), false);
    assert.equal((await fetch(`${base}/api/summary`)).status, 200);
  } finally { server.close(); }
});
