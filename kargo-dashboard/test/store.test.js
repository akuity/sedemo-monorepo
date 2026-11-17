import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createStore, planProjects } from '../src/store.js';
import { buildDashboard } from '../src/summarize.js';
import { KargoApiError } from '../src/kargo-client.js';
import { validateConfig, DEFAULT_THRESHOLDS as T } from '../src/config.js';

const load = (project, file) => JSON.parse(readFileSync(new URL(`./fixtures/${project}/${file}.json`, import.meta.url)));
const golden = JSON.parse(readFileSync(new URL('./fixtures/golden-dashboards.json', import.meta.url)));
const tick = () => new Promise((r) => setImmediate(r));
const flushAll = async () => { for (let i = 0; i < 5; i += 1) await tick(); };

// A fake Kargo that serves the fixtures and lets tests push watch events.
function fakeKargo({ stages, getPromotion, fail = {} } = {}) {
  const calls = [];
  const sessions = new Map(); // `${project}/${kind}` -> [{ push, end }]
  const stagesFor = (p) => (stages ? stages(p) : structuredClone(load(p, 'stages').items));
  const freightFor = (p, origins) => Object.values(load(p, 'freight').groups).flatMap((g) => g.items)
    .filter((f) => !origins.length || origins.includes(f.origin.name));
  const maybeFail = (kind, p) => { const f = fail[kind]; if (f) { const e = f(p); if (e) throw e; } };
  const client = {
    calls,
    async listWarehouses(p, t) { calls.push(['warehouses', p, t]); maybeFail('warehouses', p); return { items: load(p, 'warehouses').items, resourceVersion: '1' }; },
    async listStages(p, t) { calls.push(['stages', p, t]); maybeFail('stages', p); return { items: stagesFor(p), resourceVersion: '1' }; },
    async listFreight(p, { origins }, t) { calls.push(['freight', p, origins, t]); maybeFail('freight', p); return { items: freightFor(p, origins), resourceVersion: '1' }; },
    async getPromotion(p, name, t) {
      calls.push(['promotion', p, name, t]);
      if (getPromotion) return getPromotion(p, name);
      return { metadata: { name }, spec: { steps: golden.promotion.steps }, status: { phase: 'Running', currentStep: 1 } };
    },
    watch(p, kind, { signal }) {
      calls.push(['watch', p, kind]);
      const queue = []; let notify = null; let over = false;
      const key = `${p}/${kind}`;
      if (!sessions.has(key)) sessions.set(key, []);
      sessions.get(key).push({ push: (x) => { queue.push(x); notify?.(); }, end: () => { over = true; notify?.(); } });
      signal.addEventListener('abort', () => { over = true; notify?.(); });
      return (async function* () {
        for (;;) {
          if (queue.length) { yield queue.shift(); continue; }
          if (over) return;
          await new Promise((r) => { notify = r; });
        }
      })();
    },
    emit(p, kind, type, object) { sessions.get(`${p}/${kind}`).at(-1).push({ type, object }); },
    close(p, kind) { sessions.get(`${p}/${kind}`).at(-1).end(); },
  };
  return client;
}
const count = (calls, kind) => calls.filter((c) => c[0] === kind).length;
const pc = (extra = {}) => ({ displayName: 'x', warehouses: [], plural: false, includeStages: [], excludeStages: [], tokenEnv: 'T', ...extra });
const cfg = (dashboards) => ({
  dashboards: Object.fromEntries(Object.entries(dashboards).map(([id, projects]) => [id, { id, name: id, projects }])),
});
async function startStore(config, client, extra = {}) {
  const store = createStore({ config, client, env: { T: 'secret-t', T_ONE: 'one' }, ...extra }).start();
  await flushAll();
  return store;
}
const dashboards = (store, config) => {
  const ctx = { thresholds: T, kargoUrl: 'https://k.example', promotion: config.promotion, warn: () => {} };
  const snaps = store.snapshots();
  return Object.fromEntries(Object.values(config.dashboards).map((d) => [d.id, JSON.parse(JSON.stringify(buildDashboard(d, snaps, ctx)))]));
};

test('planProjects: unique projects, union of warehouses, and "all" if any dashboard wants every warehouse', () => {
  const plan = planProjects(cfg({
    a: { 'sedemo-app-demo': pc({ warehouses: ['sedemo-app-demo'] }), 'team-ada': pc({ warehouses: ['akkoma-main'] }) },
    b: { 'sedemo-app-demo': pc({ warehouses: ['sedemo-app-demo-chart'] }), 'team-ada': pc({ warehouses: [] }) },
  }));
  assert.deepEqual([...plan.keys()], ['sedemo-app-demo', 'team-ada']);
  assert.deepEqual([...plan.get('sedemo-app-demo').names].sort(), ['sedemo-app-demo', 'sedemo-app-demo-chart']);
  assert.equal(plan.get('sedemo-app-demo').all, false);
  assert.equal(plan.get('team-ada').all, true);
});

// ---- golden equivalence with the polling collector (captured before it was deleted) ----
test('golden: a store seeded from the fixtures builds exactly the dashboards the polling collector built', async () => {
  const config = validateConfig(golden.rawConfig, { T: 'x' });
  const client = fakeKargo();
  const store = await startStore(config, client);
  assert.equal(store.status().ready, true);
  assert.deepEqual(dashboards(store, config), golden.idle);
  await store.stop();
});

test('golden: the same with a running promotion', async () => {
  const config = validateConfig(golden.rawConfig, { T: 'x' });
  const client = fakeKargo({
    stages: (p) => {
      const items = structuredClone(load(p, 'stages').items);
      if (p === 'demo-rollouts') items.find((s) => s.metadata.name === 'dev').status.currentPromotion = golden.promotion.ref;
      return items;
    },
  });
  const store = await startStore(config, client);
  assert.deepEqual(dashboards(store, config), golden.promoting);
  assert.equal(store.status().active, true);
  await store.stop();
});

// ---- streams and calls ----
test('a project on two dashboards gets one set of streams: one list and one watch per kind, freight over the union of warehouses', async () => {
  const client = fakeKargo();
  const config = cfg({
    a: { 'sedemo-app-demo': pc({ warehouses: ['sedemo-app-demo'] }) },
    b: { 'sedemo-app-demo': pc({ warehouses: ['sedemo-app-demo', 'sedemo-app-demo-chart'], plural: true, displayName: 'Same project' }) },
  });
  const store = await startStore(config, client);
  assert.equal(count(client.calls, 'warehouses'), 1);
  assert.equal(count(client.calls, 'stages'), 1);
  assert.deepEqual(client.calls.filter((c) => c[0] === 'freight').map((c) => c[2].slice().sort()), [['sedemo-app-demo', 'sedemo-app-demo-chart']]);
  assert.deepEqual(client.calls.filter((c) => c[0] === 'watch').map((c) => c[2]).sort(), ['freight', 'stages', 'warehouses']);
  const d = dashboards(store, config);
  assert.equal(d.a.rows[0].lanes.length, 1);
  assert.equal(d.b.rows[0].lanes.length, 2);
  assert.deepEqual(d.a.rows[0].lanes[0], d.b.rows[0].lanes[0]);
  await store.stop();
});

test('the project token is used for every call to that project', async () => {
  const client = fakeKargo();
  const store = await startStore(cfg({ a: { 'demo-rollouts': pc({ tokenEnv: 'T_ONE' }) } }), client);
  const tokenCalls = client.calls.filter((c) => c[0] !== 'watch');
  assert.ok(tokenCalls.length >= 3);
  assert.ok(tokenCalls.every((c) => c[c.length - 1] === 'one'));
  await store.stop();
});

test('no key lists every warehouse; named warehouses restrict freight and unknown names are ignored', async () => {
  const all = fakeKargo();
  const s1 = await startStore(cfg({ a: { 'sedemo-app-demo': pc() } }), all);
  assert.deepEqual(all.calls.find((c) => c[0] === 'freight')[2], [], 'no origins filter');
  assert.deepEqual([...s1.snapshots().get('sedemo-app-demo').freightByWarehouse.keys()].sort(), ['sedemo-app-demo', 'sedemo-app-demo-chart']);
  await s1.stop();

  const some = fakeKargo();
  const s2 = await startStore(cfg({ a: { 'sedemo-app-demo': pc({ warehouses: ['nope', 'sedemo-app-demo'] }) } }), some);
  assert.deepEqual(some.calls.find((c) => c[0] === 'freight')[2], ['nope', 'sedemo-app-demo']);
  assert.deepEqual([...s2.snapshots().get('sedemo-app-demo').freightByWarehouse.keys()], ['sedemo-app-demo']);
  await s2.stop();
});

test('failures: project-level on warehouses/stages (403, 500), lane-level on freight; other projects are unaffected', async () => {
  const locked = fakeKargo({ fail: { warehouses: () => new KargoApiError('token lacks access to project demo-rollouts', 403) } });
  const s1 = await startStore(cfg({ a: { 'demo-rollouts': pc() } }), locked);
  assert.equal(s1.status().ready, true, 'a failed project counts as settled so the others can be shown');
  assert.match(s1.snapshots().get('demo-rollouts').error, /token lacks access/);
  assert.equal(s1.status().down[0].project, 'demo-rollouts');
  await s1.stop();

  const stagesDown = fakeKargo({ fail: { stages: () => new KargoApiError('Kargo API returned HTTP 500', 500) } });
  const s2 = await startStore(cfg({ a: { 'demo-rollouts': pc() } }), stagesDown);
  assert.match(s2.snapshots().get('demo-rollouts').error, /HTTP 500/);
  await s2.stop();

  const noFreight = fakeKargo({ fail: { freight: () => new Error('boom') } });
  const s3 = await startStore(cfg({ a: { 'sedemo-app-demo': pc() } }), noFreight);
  const snap = s3.snapshots().get('sedemo-app-demo');
  assert.equal(snap.error, null);
  assert.equal(snap.freightByWarehouse.get('sedemo-app-demo').error, 'boom');
  await s3.stop();
});

test('a project-level failure becomes an error row in every dashboard that lists the project', async () => {
  const client = fakeKargo({ fail: { warehouses: (p) => (p === 'team-ada' ? new KargoApiError('token lacks access to project team-ada', 403) : null) } });
  const config = cfg({ a: { 'team-ada': pc(), 'demo-rollouts': pc() }, b: { 'team-ada': pc({ displayName: 'Ada' }) } });
  const store = await startStore(config, client);
  const d = dashboards(store, config);
  assert.match(d.a.rows[0].error, /token lacks access/);
  assert.equal(d.a.rows[1].error, null, 'the other project still renders');
  assert.match(d.b.rows[0].error, /token lacks access/);
  assert.equal(d.b.rows[0].displayName, 'Ada');
  await store.stop();
});

// ---- events ----
const row = (d) => d.rows[0].lanes[0];
const devCell = (d) => row(d).stages.find((s) => s.name === 'dev');

test('a freight ADDED makes it the latest and increases how far behind the stages are; a DELETED undoes it', async () => {
  const config = cfg({ a: { 'demo-rollouts': pc({ warehouses: ['demo-rollouts'] }) } });
  const client = fakeKargo();
  const store = await startStore(config, client);
  const before = dashboards(store, config).a;
  assert.equal(row(before).latest.version, '50-blue');
  assert.equal(devCell(before).decay.behind, 0);

  const newest = structuredClone(Object.values(load('demo-rollouts', 'freight').groups).flatMap((g) => g.items)[0]);
  newest.metadata = { name: 'brand-new-freight', creationTimestamp: '2026-12-01T00:00:00Z' };
  newest.images = [{ repoURL: newest.images[0].repoURL, tag: '51-blue' }];
  let changes = 0; store.on('change', () => { changes += 1; });
  client.emit('demo-rollouts', 'freight', 'ADDED', newest);
  await flushAll();
  assert.ok(changes >= 1);
  const after = dashboards(store, config).a;
  assert.equal(row(after).latest.version, '51-blue');
  assert.equal(devCell(after).decay.behind, 1);

  client.emit('demo-rollouts', 'freight', 'DELETED', newest);
  await flushAll();
  assert.deepEqual(dashboards(store, config).a, before);
  await store.stop();
});

test('a stage MODIFIED with a new freightHistory changes that cell; a stage DELETED removes it', async () => {
  const config = cfg({ a: { 'demo-rollouts': pc({ warehouses: ['demo-rollouts'] }) } });
  const client = fakeKargo();
  const store = await startStore(config, client);
  const stages = load('demo-rollouts', 'stages').items;
  const prod = structuredClone(stages.find((s) => s.metadata.name === 'prod'));
  const dev = stages.find((s) => s.metadata.name === 'dev');
  prod.status.freightHistory = structuredClone(dev.status.freightHistory);
  client.emit('demo-rollouts', 'stages', 'MODIFIED', prod);
  await flushAll();
  const cell = (d, n) => row(d).stages.find((s) => s.name === n);
  const d1 = dashboards(store, config).a;
  assert.equal(cell(d1, 'prod').version, cell(d1, 'dev').version);
  client.emit('demo-rollouts', 'stages', 'DELETED', prod);
  await flushAll();
  assert.equal(cell(dashboards(store, config).a, 'prod'), undefined);
  await store.stop();
});

// ---- promotions (PLAN 14.5 step cache, now driven by stage events) ----
const stageWithPromotion = (ref) => {
  const s = structuredClone(load('demo-rollouts', 'stages').items.find((x) => x.metadata.name === 'dev'));
  s.status.currentPromotion = ref;
  return s;
};
const runningRef = (name = 'dev.p1', status = { phase: 'Running', currentStep: 1 }) =>
  ({ name, freight: { name: 'f', origin: { name: 'demo-rollouts' } }, ...(status ? { status } : {}) });
const pconfig = () => cfg({ a: { 'demo-rollouts': pc() } });
const promo = (store) => store.snapshots().get('demo-rollouts').promotions.get('dev');

test('a new currentPromotion fetches the Promotion exactly once; progress then comes from stage events', async () => {
  const client = fakeKargo();
  const store = await startStore(pconfig(), client);
  assert.equal(promo(store), undefined);
  client.emit('demo-rollouts', 'stages', 'MODIFIED', stageWithPromotion(runningRef('dev.p1', { phase: 'Running', currentStep: 1 })));
  await flushAll();
  assert.equal(count(client.calls, 'promotion'), 1);
  assert.deepEqual(promo(store).steps.map((s) => s.uses), ['git-clone', 'helm-template', 'wait-for-approval']);
  assert.equal(promo(store).status.currentStep, 1);
  assert.equal(store.status().active, true);
  client.emit('demo-rollouts', 'stages', 'MODIFIED', stageWithPromotion(runningRef('dev.p1', { phase: 'Running', currentStep: 2 })));
  await flushAll();
  assert.equal(count(client.calls, 'promotion'), 1, 'cached');
  assert.equal(promo(store).status.currentStep, 2, 'live progress re-read from the stage');
  assert.ok(client.calls.filter((c) => c[0] === 'promotion').every((c) => c[3] === 'secret-t'), 'uses the project token');
  await store.stop();
});

test('a terminal phase clears the promotion; cache entries are dropped so a returning name is fetched again', async () => {
  const client = fakeKargo();
  const store = await startStore(pconfig(), client);
  client.emit('demo-rollouts', 'stages', 'MODIFIED', stageWithPromotion(runningRef()));
  await flushAll();
  client.emit('demo-rollouts', 'stages', 'MODIFIED', stageWithPromotion(runningRef('dev.p1', { phase: 'Succeeded', currentStep: 2 })));
  await flushAll();
  assert.equal(promo(store), undefined);
  assert.equal(store.status().active, false);
  client.emit('demo-rollouts', 'stages', 'MODIFIED', stageWithPromotion(runningRef()));
  await flushAll();
  assert.equal(count(client.calls, 'promotion'), 2);
  await store.stop();
});

test('terminal references and stages without a promotion cause no extra calls', async () => {
  const client = fakeKargo({ stages: () => [stageWithPromotion(runningRef('dev.old', { phase: 'Succeeded', currentStep: 9 }))] });
  const store = await startStore(pconfig(), client);
  assert.equal(count(client.calls, 'promotion'), 0);
  assert.equal(store.status().active, false);
  await store.stop();
});

test('a reference with no status makes the store read the Promotion for its status, at most once per retry interval', async () => {
  let now = 1_000_000;
  const pending = [];
  const timers = { now: () => now, setTimeout: (fn, ms) => { pending.push({ fn, at: now + ms }); return pending.length; }, clearTimeout: () => {} };
  const client = fakeKargo({ getPromotion: (p, name) => ({ metadata: { name }, spec: { steps: golden.promotion.steps }, status: { phase: 'Running', currentStep: 2 } }) });
  const store = await startStore(pconfig(), client, { timers, promotionRetryMs: 5000 });
  client.emit('demo-rollouts', 'stages', 'MODIFIED', stageWithPromotion(runningRef('dev.p1', null)));
  await flushAll();
  assert.equal(count(client.calls, 'promotion'), 1);
  assert.equal(promo(store).status.currentStep, 2);
  client.emit('demo-rollouts', 'stages', 'MODIFIED', stageWithPromotion(runningRef('dev.p1', null)));
  await flushAll();
  assert.equal(count(client.calls, 'promotion'), 1, 'within the interval: no second read');
  now += 5001;
  client.emit('demo-rollouts', 'stages', 'MODIFIED', stageWithPromotion(runningRef('dev.p1', null)));
  await flushAll();
  assert.equal(count(client.calls, 'promotion'), 2);
  await store.stop();
});

test('a failed Promotion fetch is isolated to that card, warns without the token, and is retried', async () => {
  const warnings = [];
  let fail = true;
  const pending = [];
  const timers = { now: Date.now, setTimeout: (fn) => { pending.push(fn); return pending.length; }, clearTimeout: () => {} };
  const client = fakeKargo({ getPromotion: (p, name) => {
    if (fail) throw new KargoApiError('token lacks access to project demo-rollouts', 403);
    return { metadata: { name }, spec: { steps: golden.promotion.steps }, status: {} };
  } });
  const store = await startStore(pconfig(), client, { warn: (m) => warnings.push(m), timers });
  client.emit('demo-rollouts', 'stages', 'MODIFIED', stageWithPromotion(runningRef()));
  await flushAll();
  const snap = store.snapshots().get('demo-rollouts');
  assert.equal(snap.error, null, 'the project still renders');
  assert.equal(promo(store).steps, null);
  assert.ok(warnings.length === 1 && !warnings[0].includes('secret-t'));
  fail = false;
  pending.splice(0).forEach((fn) => fn()); // the scheduled retry fires
  await flushAll();
  assert.equal(promo(store).steps.length, 3);
  await store.stop();
});

test('status().down reports a project whose stream dropped, and since when; it clears once the stream is back', async () => {
  let now = 5_000_000;
  const pending = new Map(); let seq = 0;
  const timers = { now: () => now, setTimeout: (fn) => { seq += 1; pending.set(seq, fn); return seq; }, clearTimeout: (id) => { pending.delete(id); } };
  const client = fakeKargo();
  const store = await startStore(pconfig(), client, { timers });
  assert.deepEqual(store.status().down, []);
  now += 1000;
  client.close('demo-rollouts', 'stages');
  await flushAll();
  assert.deepEqual(store.status().down, [{ project: 'demo-rollouts', since: now }]);
  assert.equal(store.snapshots().get('demo-rollouts').error, null, 'data is kept while reconnecting');
  now += 3000;
  const [id, fn] = [...pending.entries()].at(-1); pending.delete(id); fn(); // the newest timer is the backoff sleep: it ends and the watcher reconnects
  await flushAll();
  client.emit('demo-rollouts', 'stages', 'MODIFIED', load('demo-rollouts', 'stages').items[0]);
  await flushAll();
  assert.deepEqual(store.status().down, []);
  await store.stop();
});
