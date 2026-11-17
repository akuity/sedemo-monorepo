import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildLane, buildRow, buildDashboard, selectWarehouses, kargoLink, projectLink } from '../src/summarize.js';
import { createStore } from '../src/store.js';
import { KargoApiError } from '../src/kargo-client.js';
import { DEFAULT_THRESHOLDS as T } from '../src/config.js';
import { sortFreight } from '../src/decay.js';

// Real responses captured from the live Kargo API (scrubbed), see test/fixtures.
const load = (project, file) => JSON.parse(readFileSync(new URL(`./fixtures/${project}/${file}.json`, import.meta.url)));
const fixture = (project, warehouse) => ({
  warehouses: load(project, 'warehouses').items,
  warehouse: load(project, 'warehouses').items.find((w) => w.metadata.name === warehouse),
  stages: load(project, 'stages').items,
  freight: Object.values(load(project, 'freight').groups).flatMap((g) => g.items),
});
// One lane (one warehouse's pipeline). Row-level assembly is tested through runProject below.
const row = (project, warehouse, overrides = {}, cfg = {}) => {
  const f = fixture(project, warehouse);
  return buildLane({ project, projectConfig: { displayName: project, ...cfg }, thresholds: T, ...f, ...overrides });
};
const summary = (r) => r.stages.map((s) => [s.name, s.version, s.decay.label, s.decay.behind]);

test('demo-rollouts: pipeline order, image tags, all current', () => {
  const r = row('demo-rollouts', 'demo-rollouts');
  assert.equal(r.warehouse, 'demo-rollouts');
  assert.deepEqual(r.stages.map((s) => s.name),
    ['dev', 'staging', 'prod', 'prod-amer-east', 'prod-amer-west', 'prod-emea']);
  assert.equal(r.latest.version, '50-blue');
  assert.equal(r.latest.alias, 'limping-jaguar');
  for (const s of r.stages) assert.deepEqual([s.version, s.decay.label, s.decay.behind], ['50-blue', 'Good', 0]);
  assert.equal(r.error, null);
});

test('sedemo-app-demo image warehouse: only that warehouse counts', () => {
  const r = row('sedemo-app-demo', 'sedemo-app-demo');
  assert.deepEqual(summary(r), [['dev', '15', 'Good', 0], ['staging', '15', 'Good', 0], ['prod', '15', 'Good', 0]]);
  assert.equal(r.latest.alias, 'sullen-sheep');
  assert.ok(r.stages[0].since, 'deployed-since comes from freight.status.currentlyIn');
});

test('sedemo-app-demo chart warehouse (git only): short SHAs, 5 behind, and nothing deployed', () => {
  const r = row('sedemo-app-demo', 'sedemo-app-demo-chart');
  assert.deepEqual(summary(r), [
    ['dev', '8e87771', 'Good', 0],
    ['staging', '4aca0f4', 'Worse', 5],
    ['prod', null, 'unknown', null],
  ]);
});

test('exactly 3 behind is Bad, 4 is Worse (owner decision), using real shapes', () => {
  const f = fixture('demo-rollouts', 'demo-rollouts');
  const sorted = sortFreight(f.freight.filter((x) => x.origin.name === 'demo-rollouts'));
  const pin = (stageName, idx) => {
    const stages = structuredClone(f.stages);
    const s = stages.find((x) => x.metadata.name === stageName);
    s.status.freightHistory[0].items['Warehouse/demo-rollouts'].name = sorted[idx].metadata.name;
    return stages;
  };
  const dev3 = row('demo-rollouts', 'demo-rollouts', { stages: pin('dev', 3) }).stages.find((s) => s.name === 'dev');
  assert.deepEqual([dev3.decay.behind, dev3.decay.label], [3, 'Bad']);
  const dev4 = row('demo-rollouts', 'demo-rollouts', { stages: pin('dev', 4) }).stages.find((s) => s.name === 'dev');
  assert.deepEqual([dev4.decay.behind, dev4.decay.label], [4, 'Worse']);
});

test('a deployed freight that no longer exists is Worse/unknown but keeps its version', () => {
  const f = fixture('demo-rollouts', 'demo-rollouts');
  const stages = structuredClone(f.stages);
  stages.find((x) => x.metadata.name === 'dev').status.freightHistory[0].items['Warehouse/demo-rollouts'].name = 'gone';
  const dev = row('demo-rollouts', 'demo-rollouts', { stages }).stages.find((s) => s.name === 'dev');
  assert.deepEqual([dev.decay.label, dev.decay.behind], ['unknown', null]);
});

test('include/exclude filters apply after ordering and keep order', () => {
  const r = row('demo-rollouts', 'demo-rollouts', {}, { includeStages: ['dev', 'regex:^prod'], excludeStages: ['prod-emea', 'prod'] });
  assert.deepEqual(r.stages.map((s) => s.name), ['dev', 'prod-amer-east', 'prod-amer-west']);
});

test('control-flow stages are not rendered but do not disturb downstream order', () => {
  const f = fixture('demo-rollouts', 'demo-rollouts');
  const stages = structuredClone(f.stages);
  delete stages.find((x) => x.metadata.name === 'staging').spec.promotionTemplate;
  const names = row('demo-rollouts', 'demo-rollouts', { stages }).stages.map((s) => s.name);
  assert.deepEqual(names, ['dev', 'prod', 'prod-amer-east', 'prod-amer-west', 'prod-emea']);
});

test('warehouse with no freight: no latest, neutral cells labeled "no freight"', () => {
  const r = row('demo-rollouts', 'demo-rollouts', { freight: [] });
  assert.equal(r.latest, null);
  assert.ok(r.stages.length > 0);
  for (const s of r.stages) assert.deepEqual([s.version, s.decay.label, s.decay.color], [null, 'no freight', '#9e9e9e']);
});

test('selectWarehouses: configured names keep config order; unknown names come back without a warehouse', () => {
  const two = fixture('sedemo-app-demo', 'sedemo-app-demo').warehouses;
  const sel = selectWarehouses(two, ['sedemo-app-demo-chart', 'nope', 'sedemo-app-demo']);
  assert.deepEqual(sel.map((x) => x.name), ['sedemo-app-demo-chart', 'nope', 'sedemo-app-demo']);
  assert.deepEqual(sel.map((x) => Boolean(x.warehouse)), [true, false, true]);
});

test('selectWarehouses: nothing configured means every warehouse, sorted by name', () => {
  const two = fixture('sedemo-app-demo', 'sedemo-app-demo').warehouses;
  assert.deepEqual(selectWarehouses([...two].reverse()).map((x) => x.name), ['sedemo-app-demo', 'sedemo-app-demo-chart']);
  const one = fixture('demo-rollouts', 'demo-rollouts').warehouses;
  assert.deepEqual(selectWarehouses(one, []).map((x) => x.name), ['demo-rollouts']);
  assert.throws(() => selectWarehouses([], []), /no warehouses/);
});

// A fake client that serves the fixtures per project and records the tokens it was given.
function fakeClient(tokensSeen = []) {
  return {
    async listWarehouses(project, token) {
      tokensSeen.push([project, token]);
      if (project === 'locked') throw new KargoApiError('token lacks access to project locked', 403);
      return load(project, 'warehouses').items;
    },
    async listStages(project) { return load(project, 'stages').items; },
    async listFreight(project, wh) {
      return Object.values(load(project, 'freight').groups).flatMap((g) => g.items).filter((f) => f.origin.name === wh);
    },
  };
}

// Runs the real store (seeded by lists, no watch events) against an old-style fake client and returns what the
// polling collector used to: { snapshots, active }. The fake watch just stays open until aborted.
async function collectViaStore(oldClient, config, env) {
  const warehouses = new Map(); // one old-client listWarehouses call per project, like the store makes
  const whFor = (p, t) => { if (!warehouses.has(p)) warehouses.set(p, oldClient.listWarehouses(p, t)); return warehouses.get(p); };
  const client = {
    async listWarehouses(p, t) { return { items: await whFor(p, t), resourceVersion: '1' }; },
    async listStages(p, t) { return { items: await oldClient.listStages(p, t), resourceVersion: '1' }; },
    async listFreight(p, { origins }, t) {
      const names = origins.length ? origins : (await whFor(p, t)).map((w) => w.metadata.name);
      return { items: (await Promise.all(names.map((n) => oldClient.listFreight(p, n, t)))).flat(), resourceVersion: '1' };
    },
    getPromotion: (...a) => oldClient.getPromotion(...a),
    async* watch(p, kind, { signal }) { await new Promise((r) => signal.addEventListener('abort', r)); },
  };
  const store = createStore({ config, client, env }).start();
  for (let i = 0; i < 100 && !store.status().ready; i += 1) await new Promise((r) => setImmediate(r));
  for (let i = 0; i < 10; i += 1) await new Promise((r) => setImmediate(r)); // let promotion fetches land
  const out = { snapshots: store.snapshots(), active: store.status().active };
  await store.stop();
  return out;
}
const createCollector = ({ client }) => ({
  collect: (config, env) => collectViaStore(client, config, env),
  async collectProject(name, wanted, token) {
    const config = { dashboards: { x: { id: 'x', name: 'x', projects: { [name]: { warehouses: wanted.all ? [] : [...wanted.names], tokenEnv: 'T' } } } } };
    return (await collectViaStore(client, config, { T: token })).snapshots.get(name);
  },
});

// Runs the real store against a fake client, then builds one project's row (pure).
const wantedOf = (pc) => ({ tokenEnv: 'T', all: !(pc.warehouses?.length), names: new Set(pc.warehouses || []) });
async function runProject(client, name, projectConfig, ctxExtra = {}) {
  const snapshot = await createCollector({ client }).collectProject(name, wantedOf(projectConfig), 't');
  return buildRow(name, { displayName: name, ...projectConfig }, snapshot,
    { thresholds: T, kargoUrl: 'https://kargo.example', ...ctxExtra });
}

test('collect + buildDashboard: one failing project does not fail the others; order and per-project tokens kept', async () => {
  const seen = [];
  const config = {
    kargo: { url: 'https://kargo.example' }, decay: { thresholds: T },
    dashboards: { d: { id: 'd', name: 'D', projects: {
      locked: { displayName: 'locked', warehouses: [], tokenEnv: 'T_LOCKED' },
      'demo-rollouts': { displayName: 'Rollouts', warehouses: ['demo-rollouts'], tokenEnv: 'T_MAIN' },
      'sedemo-app-demo': { displayName: 'App', warehouses: ['sedemo-app-demo'], tokenEnv: 'T_MAIN' },
    } } },
  };
  const { snapshots } = await createCollector({ client: fakeClient(seen) }).collect(config, { T_LOCKED: 'a', T_MAIN: 'b' });
  const out = buildDashboard(config.dashboards.d, snapshots, { thresholds: T, kargoUrl: config.kargo.url });
  assert.deepEqual(out.dashboard, { id: 'd', name: 'D' });
  assert.deepEqual(out.rows.map((r) => r.project), ['locked', 'demo-rollouts', 'sedemo-app-demo']);
  assert.match(out.rows[0].error, /token lacks access to project locked/);
  assert.equal(out.rows[1].error, null);
  assert.equal(out.rows[2].error, null);
  assert.deepEqual(seen.sort(), [['demo-rollouts', 'b'], ['locked', 'a'], ['sedemo-app-demo', 'b']]);
});

test('kargoLink follows the Kargo URL patterns and encodes segments', () => {
  assert.equal(kargoLink('https://k.example/', 'proj', 'stage', 'dev'), 'https://k.example/project/proj/stage/dev');
  assert.equal(kargoLink('https://k.example', 'p', 'freight', 'abc123'), 'https://k.example/project/p/freight/abc123');
  assert.equal(kargoLink('https://k.example', 'a b', 'stage', 'x/y'), 'https://k.example/project/a%20b/stage/x%2Fy');
  assert.equal(kargoLink(undefined, 'p', 'stage', 'dev'), undefined);
  assert.equal(kargoLink('https://k.example', 'p', 'freight', undefined), undefined);
});

test('projectLink follows the Kargo project URL pattern', () => {
  assert.equal(projectLink('https://k.example/', 'my proj'), 'https://k.example/project/my%20proj');
  assert.equal(projectLink(undefined, 'p'), undefined);
});

test('every row, including error rows, links its project name', async () => {
  const kargoUrl = 'https://kargo.example';
  const good = await runProject(fakeClient(), 'demo-rollouts', { displayName: 'R', warehouses: [] });
  assert.equal(good.projectUrl, `${kargoUrl}/project/demo-rollouts`);
  const bad = await runProject(fakeClient(), 'locked', { displayName: 'L', warehouses: [] });
  assert.ok(bad.error);
  assert.equal(bad.projectUrl, `${kargoUrl}/project/locked`);
});

test('rows link the latest version to its freight and each cell to its stage and deployed freight', () => {
  const kargoUrl = 'https://kargo.example';
  const r = row('sedemo-app-demo', 'sedemo-app-demo-chart', { kargoUrl });
  const f = fixture('sedemo-app-demo', 'sedemo-app-demo-chart');
  const sorted = sortFreight(f.freight.filter((x) => x.origin.name === 'sedemo-app-demo-chart'));
  assert.equal(r.latest.freightUrl, `${kargoUrl}/project/sedemo-app-demo/freight/${sorted[0].metadata.name}`);
  const [dev, staging, prod] = r.stages;
  assert.equal(dev.stageUrl, `${kargoUrl}/project/sedemo-app-demo/stage/dev`);
  assert.equal(dev.freightUrl, `${kargoUrl}/project/sedemo-app-demo/freight/${sorted[0].metadata.name}`);
  assert.equal(staging.freightUrl, `${kargoUrl}/project/sedemo-app-demo/freight/${sorted[5].metadata.name}`);
  assert.equal(prod.stageUrl, `${kargoUrl}/project/sedemo-app-demo/stage/prod`);
  assert.equal(prod.freightUrl, undefined, 'nothing deployed, so no freight to link');
});

test('buildDashboard passes the configured Kargo URL through to links', async () => {
  const config = { dashboards: { d: { id: 'd', name: 'D', projects: { 'demo-rollouts': { displayName: 'R', warehouses: ['demo-rollouts'], tokenEnv: 'T' } } } } };
  const { snapshots } = await createCollector({ client: fakeClient() }).collect(config, { T: 'x' });
  const out = buildDashboard(config.dashboards.d, snapshots, { thresholds: T, kargoUrl: 'https://kargo.example/' });
  assert.match(out.rows[0].lanes[0].stages[0].stageUrl, /^https:\/\/kargo\.example\/project\/demo-rollouts\/stage\/dev$/);
});

// ---- Section 13: lanes ----
const project = (name, projectConfig, client = fakeClient()) => runProject(client, name, projectConfig);
const laneSummary = (l) => [l.warehouse, l.latest?.version, l.stages.map((c) => c.name), l.error];

test('team-ada: two lanes under one project, each with its own (disjoint) pipeline', async () => {
  const r = await project('team-ada', { warehouses: ['akkoma-main', 'akkoma-release'], plural: true });
  assert.equal(r.error, null);
  assert.equal(r.showLaneCaptions, true);
  assert.equal(r.projectUrl, 'https://kargo.example/project/team-ada');
  assert.deepEqual(r.lanes.map((l) => [l.warehouse, l.stages.map((c) => c.name)]), [
    ['akkoma-main', ['dev', 'release']],
    ['akkoma-release', ['staging', 'prod']],
  ]);
  // both warehouses list a chart subscription first, so the version is the chart version, not the image tag
  assert.match(r.lanes[0].latest.version, /^0\.0\.0-main\./);
  assert.equal(r.lanes[1].latest.version, '0.8.7');
  assert.ok(r.lanes.every((l) => l.stages.every((c) => c.decay.label === 'Good' && c.decay.behind === 0)));
});

test('sedemo-app-demo as two lanes: same stage names, different versions and decay', async () => {
  const r = await project('sedemo-app-demo', { warehouses: ['sedemo-app-demo', 'sedemo-app-demo-chart'], plural: true });
  const [img, chart] = r.lanes;
  assert.deepEqual(img.stages.map((c) => c.name), chart.stages.map((c) => c.name));
  assert.deepEqual(img.stages.map((c) => [c.version, c.decay.label]), [['15', 'Good'], ['15', 'Good'], ['15', 'Good']]);
  assert.deepEqual(chart.stages.map((c) => [c.version, c.decay.label, c.decay.behind]),
    [['8e87771', 'Good', 0], ['4aca0f4', 'Worse', 5], [null, 'unknown', null]]);
});

test('no key: a multi-warehouse project shows every warehouse as a lane, sorted by name, with captions (D7)', async () => {
  const listed = await project('sedemo-app-demo', { warehouses: ['sedemo-app-demo', 'sedemo-app-demo-chart'], plural: true });
  const unset = await project('sedemo-app-demo', { warehouses: [], plural: false });
  assert.deepEqual(unset.lanes, listed.lanes);
  assert.equal(unset.showLaneCaptions, true);
  assert.equal(unset.error, null);
});

test('no key on a single-warehouse project: one lane, no caption; singular key likewise', async () => {
  for (const cfg of [{ warehouses: [], plural: false }, { warehouses: ['demo-rollouts'], plural: false }]) {
    const r = await project('demo-rollouts', cfg);
    assert.equal(r.lanes.length, 1);
    assert.equal(r.showLaneCaptions, false);
    assert.equal(r.lanes[0].stages.length, 6);
  }
});

test('explicit plural form with one entry still shows its caption', async () => {
  const r = await project('demo-rollouts', { warehouses: ['demo-rollouts'], plural: true });
  assert.deepEqual([r.lanes.length, r.showLaneCaptions], [1, true]);
});

test('an unknown warehouse name is a lane error; the other lanes still render', async () => {
  const r = await project('sedemo-app-demo', { warehouses: ['nope', 'sedemo-app-demo'], plural: true });
  assert.equal(r.error, null);
  assert.deepEqual(laneSummary(r.lanes[0]), ['nope', undefined, [], 'warehouse nope not found in project']);
  assert.equal(r.lanes[1].error, null);
  assert.equal(r.lanes[1].latest.version, '15');
});

// PLAN 17: freight is one list (and one watch) per project, so a freight failure shows in every lane of
// that project, while the project row and its stages still render. (Polling fetched each warehouse separately.)
test('a freight failure shows in the project\'s lanes without turning the project into an error row', async () => {
  const client = fakeClient();
  const real = client.listFreight;
  client.listFreight = async (p, wh, t) => {
    if (wh === 'sedemo-app-demo-chart') throw new KargoApiError('Kargo API returned HTTP 500 for project sedemo-app-demo', 500);
    return real(p, wh, t);
  };
  const r = await project('sedemo-app-demo', { warehouses: [], plural: false }, client);
  assert.equal(r.error, null);
  assert.equal(r.lanes.length, 2);
  for (const lane of r.lanes) {
    assert.match(lane.error, /HTTP 500/);
    assert.deepEqual(lane.stages, []);
  }
});

test('project-level failures stay a single error row with no lanes', async () => {
  const locked = await project('locked', { warehouses: [], plural: false });
  assert.match(locked.error, /token lacks access to project locked/);
  assert.deepEqual([locked.lanes, locked.showLaneCaptions, locked.projectUrl], [[], false, 'https://kargo.example/project/locked']);

  const empty = fakeClient();
  empty.listWarehouses = async () => [];
  assert.match((await project('demo-rollouts', { warehouses: [], plural: false }, empty)).error, /no warehouses/);
});

test('every lane carries its own links', async () => {
  const r = await project('team-ada', { warehouses: ['akkoma-main', 'akkoma-release'], plural: true });
  for (const l of r.lanes) {
    assert.match(l.latest.freightUrl, /^https:\/\/kargo\.example\/project\/team-ada\/freight\/[0-9a-f]+$/);
    for (const c of l.stages) assert.equal(c.stageUrl, `https://kargo.example/project/team-ada/stage/${c.name}`);
  }
});

// ---- Section 14: promotion state on cells ----
const PROMO_CFG = { color: '#1e6fd9', waitingColor: '#7b1fa2', waitingStepPattern: 'wait-for|^get-user-input$', animate: true, activeRefreshIntervalSeconds: 5 };
const promoInfo = (originName, currentStep = 1) => ({
  name: 'dev.p1',
  ref: { name: 'dev.p1', freight: { name: 'f1', origin: { kind: 'Warehouse', name: originName }, images: [{ repoURL: 'ghcr.io/akuity/sedemo-monorepo-rollouts-app', tag: '51-blue' }] }, status: { phase: 'Running' } },
  status: { phase: 'Running', currentStep },
  steps: [{ uses: 'git-clone', as: 'a' }, { uses: 'helm-template', as: 'b' }, { uses: 'wait-for-approval', as: 'c' }],
});

test('a running promotion appears on that stage\'s card with its step summary and target version', () => {
  const r = row('demo-rollouts', 'demo-rollouts', { promotions: new Map([['dev', promoInfo('demo-rollouts', 1)]]), promotion: PROMO_CFG, kargoUrl: 'https://kargo.example' });
  const dev = r.stages.find((c) => c.name === 'dev');
  assert.deepEqual([dev.promotion.step, dev.promotion.steps, dev.promotion.uses, dev.promotion.waiting], [2, 3, 'helm-template', false]);
  assert.equal(dev.promotion.targetVersion, '51-blue');
  assert.equal(dev.promotion.targetFreightUrl, 'https://kargo.example/project/demo-rollouts/freight/f1');
  assert.equal(dev.version, '50-blue', 'the deployed version is still the current one');
  assert.equal(r.stages.find((c) => c.name === 'staging').promotion, null, 'other stages are unaffected');
  const waiting = row('demo-rollouts', 'demo-rollouts', { promotions: new Map([['dev', promoInfo('demo-rollouts', 2)]]), promotion: PROMO_CFG });
  assert.equal(waiting.stages.find((c) => c.name === 'dev').promotion.waiting, true);
});

test('a promotion only shows in the lane of the warehouse whose Freight it promotes', () => {
  const promotions = new Map([['dev', promoInfo('sedemo-app-demo-chart', 0)]]);
  const img = row('sedemo-app-demo', 'sedemo-app-demo', { promotions, promotion: PROMO_CFG });
  const chart = row('sedemo-app-demo', 'sedemo-app-demo-chart', { promotions, promotion: PROMO_CFG });
  assert.equal(img.stages.find((c) => c.name === 'dev').promotion, null);
  assert.equal(chart.stages.find((c) => c.name === 'dev').promotion.step, 1);
});

test('without promotion settings or data every card has promotion: null', () => {
  assert.ok(row('demo-rollouts', 'demo-rollouts').stages.every((c) => c.promotion === null));
  assert.ok(row('demo-rollouts', 'demo-rollouts', { promotions: new Map(), promotion: PROMO_CFG }).stages.every((c) => c.promotion === null));
});

test('end to end: collector snapshot -> buildDashboard puts the promotion on the card', async () => {
  const stages = structuredClone(load('demo-rollouts', 'stages').items);
  stages.find((s) => s.metadata.name === 'staging').status.currentPromotion = {
    name: 'staging.p9', freight: { name: 'f9', origin: { name: 'demo-rollouts' }, images: [{ repoURL: 'ghcr.io/akuity/sedemo-monorepo-rollouts-app', tag: '51-blue' }] },
  };
  const client = { ...fakeClient(), async listStages() { return stages; },
    async getPromotion() { return { spec: { steps: [{ uses: 'git-clone' }, { uses: 'get-user-input' }] }, status: { phase: 'Running', currentStep: 1 } }; } };
  const config = { dashboards: { d: { id: 'd', name: 'D', projects: { 'demo-rollouts': { displayName: 'R', warehouses: ['demo-rollouts'], tokenEnv: 'T' } } } } };
  const { snapshots, active } = await createCollector({ client }).collect(config, { T: 'x' });
  const out = buildDashboard(config.dashboards.d, snapshots, { thresholds: T, kargoUrl: 'https://k', promotion: PROMO_CFG });
  const card = out.rows[0].lanes[0].stages.find((c) => c.name === 'staging');
  assert.equal(active, true);
  assert.deepEqual([card.promotion.step, card.promotion.steps, card.promotion.uses, card.promotion.waiting], [2, 2, 'get-user-input', true]);
});

test('a promotion that carries Freight from several warehouses shows in each of those lanes with its own target', () => {
  const info = promoInfo('sedemo-app-demo', 5);
  info.status.freightCollection = { items: {
    'Warehouse/sedemo-app-demo': { name: 'f-img', origin: { name: 'sedemo-app-demo' }, images: [{ repoURL: 'ghcr.io/akuity/sedemo-app-demo', tag: '13' }] },
    'Warehouse/sedemo-app-demo-chart': { name: 'f-chart', origin: { name: 'sedemo-app-demo-chart' }, commits: [{ repoURL: 'https://github.com/akuity/sedemo-platform', id: 'f450b5d719d6e40f8704dd3f57c774ae88a0d35a' }] },
  } };
  const promotions = new Map([['staging', info]]);
  const img = row('sedemo-app-demo', 'sedemo-app-demo', { promotions, promotion: PROMO_CFG, kargoUrl: 'https://k' }).stages.find((c) => c.name === 'staging').promotion;
  const chart = row('sedemo-app-demo', 'sedemo-app-demo-chart', { promotions, promotion: PROMO_CFG, kargoUrl: 'https://k' }).stages.find((c) => c.name === 'staging').promotion;
  assert.deepEqual([img.targetVersion, img.targetFreightName], ['13', 'f-img']);
  assert.deepEqual([chart.targetVersion, chart.targetFreightName], ['f450b5d', 'f-chart'], 'git-only warehouse: short sha of its own incoming commit');
  assert.equal(chart.targetFreightUrl, 'https://k/project/sedemo-app-demo/freight/f-chart');
});

test('a promotion whose collection does not include a lane\'s warehouse does not show in that lane', () => {
  const info = promoInfo('sedemo-app-demo', 5);
  info.status.freightCollection = { items: { 'Warehouse/sedemo-app-demo': { name: 'f-img', origin: { name: 'sedemo-app-demo' } } } };
  const promotions = new Map([['staging', info]]);
  assert.ok(row('sedemo-app-demo', 'sedemo-app-demo', { promotions, promotion: PROMO_CFG }).stages.find((c) => c.name === 'staging').promotion);
  assert.equal(row('sedemo-app-demo', 'sedemo-app-demo-chart', { promotions, promotion: PROMO_CFG }).stages.find((c) => c.name === 'staging').promotion, null);
});
