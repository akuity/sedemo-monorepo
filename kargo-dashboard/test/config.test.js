import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateConfig, DEFAULT_THRESHOLDS } from '../src/config.js';

const env = { KARGO_TOKEN: 't', OTHER_TOKEN: 'o' };
const base = () => ({ kargo: { url: 'https://k.example/' }, projects: { a: {}, b: { warehouse: 'w' } } });

test('applies defaults and preserves project order', () => {
  const c = validateConfig(base(), env);
  assert.deepEqual(Object.keys(c.dashboards.default.projects), ['a', 'b']);
  assert.equal(c.kargo.url, 'https://k.example');
  assert.equal(c.kargo.tokenEnv, 'KARGO_TOKEN');
  assert.equal('refreshIntervalSeconds' in c, false, 'polling settings are gone from the parsed config');
  assert.deepEqual(c.decay.thresholds, DEFAULT_THRESHOLDS);
  assert.equal(c.dashboards.default.projects.a.displayName, 'a');
  assert.deepEqual(c.dashboards.default.projects.a.includeStages, []);
});

test('KARGO_URL overrides config url', () => {
  const c = validateConfig(base(), { ...env, KARGO_URL: 'https://override' });
  assert.equal(c.kargo.url, 'https://override');
});

test('per-project tokenEnv is honored and must be set', () => {
  const raw = base();
  raw.projects.a.tokenEnv = 'OTHER_TOKEN';
  assert.equal(validateConfig(raw, env).dashboards.default.projects.a.tokenEnv, 'OTHER_TOKEN');
  raw.projects.a.tokenEnv = 'MISSING';
  assert.throws(() => validateConfig(raw, env), /MISSING/);
});

test('missing or empty global token fails and the message omits values', () => {
  assert.throws(() => validateConfig(base(), { KARGO_TOKEN: '' }), /KARGO_TOKEN/);
});

test('projects must be a non-empty object of objects', () => {
  assert.throws(() => validateConfig({ ...base(), projects: {} }, env), /non-empty/);
  assert.throws(() => validateConfig({ ...base(), projects: [] }, env), /non-empty/);
  assert.throws(() => validateConfig({ ...base(), projects: { a: 'x' } }, env), /projects.a must be an object/);
});

test('bad regex and non-string patterns fail at load', () => {
  const raw = base();
  raw.projects.a.includeStages = ['regex:('];
  assert.throws(() => validateConfig(raw, env), /Invalid regular expression/);
  raw.projects.a.includeStages = [1];
  assert.throws(() => validateConfig(raw, env), /must be a string/);
});

test('threshold validation', () => {
  const t = (thresholds) => validateConfig({ ...base(), decay: { thresholds } }, env);
  const c = (max) => ({ max, label: 'x', color: '#000' });
  assert.throws(() => t([c(0), c(0), c(null)]), /ascending/);
  assert.throws(() => t([c(1), c(0), c(null)]), /ascending/);
  assert.throws(() => t([c(0), c(1)]), /last entry must have max null/);
  assert.throws(() => t([c(null), c(1)]), /only the last/);
  assert.throws(() => t([c(-1), c(null)]), /non-negative integer/);
  assert.throws(() => t([c(1.5), c(null)]), /non-negative integer/);
  assert.doesNotThrow(() => t([c(0), c(null)]));
});

const withProject = (p) => validateConfig({ ...base(), projects: { a: p } }, env).dashboards.default.projects.a;

test('warehouse selection normalises to a list plus a plural flag', () => {
  assert.deepEqual([withProject({ warehouse: 'w' }).warehouses, withProject({ warehouse: 'w' }).plural], [['w'], false]);
  assert.deepEqual([withProject({ warehouses: ['x', 'y'] }).warehouses, withProject({ warehouses: ['x', 'y'] }).plural], [['x', 'y'], true]);
  assert.equal(withProject({ warehouses: ['only'] }).plural, true, 'explicit plural form is honored even with one entry');
  assert.deepEqual([withProject({}).warehouses, withProject({}).plural], [[], false], 'neither key means all warehouses');
});

test('warehouse and warehouses together, empty, non-string and duplicate lists are rejected', () => {
  assert.throws(() => withProject({ warehouse: 'w', warehouses: ['x'] }), /either warehouse or warehouses, not both/);
  assert.throws(() => withProject({ warehouses: [] }), /non-empty array/);
  assert.throws(() => withProject({ warehouses: 'x' }), /non-empty array/);
  assert.throws(() => withProject({ warehouses: ['x', 3] }), /only non-empty strings/);
  assert.throws(() => withProject({ warehouses: ['x', ''] }), /only non-empty strings/);
  assert.throws(() => withProject({ warehouses: ['x', 'x'] }), /duplicates/);
  assert.throws(() => withProject({ warehouse: '' }), /non-empty string/);
  assert.throws(() => withProject({ warehouse: 5 }), /non-empty string/);
});

test('requires a url', () => {
  assert.throws(() => validateConfig({ projects: { a: {} } }, env), /kargo.url/);
});

// ---- Section 15: dashboards ----
const dash = (extra = {}) => ({
  kargo: { url: 'https://k.example' },
  dashboards: {
    demos: { name: 'SE Demos', projects: { 'demo-rollouts': { warehouse: 'w' }, shared: {} } },
    teams: { name: 'Team Apps', projects: { 'team-ada': { warehouses: ['x', 'y'] }, shared: { displayName: 'Shared' } } },
  },
  defaultDashboard: 'demos',
  ...extra,
});

test('dashboards: ids, names, order, default and per-dashboard projects', () => {
  const c = validateConfig(dash(), env);
  assert.deepEqual(Object.keys(c.dashboards), ['demos', 'teams']);
  assert.equal(c.defaultDashboard, 'demos');
  assert.equal(c.dashboards.teams.name, 'Team Apps');
  assert.equal(c.dashboards.teams.id, 'teams');
  assert.equal(c.dashboards.teams.projects['team-ada'].plural, true);
  assert.equal(c.dashboards.teams.projects.shared.displayName, 'Shared');
  assert.deepEqual(c.warnings, []);
});

test('a project may appear in several dashboards with different views', () => {
  const c = validateConfig(dash(), env);
  assert.equal(c.dashboards.demos.projects.shared.displayName, 'shared');
  assert.equal(c.dashboards.teams.projects.shared.displayName, 'Shared');
});

test('defaultDashboard: required with several dashboards, optional with one, must exist', () => {
  const raw = dash(); delete raw.defaultDashboard;
  assert.throws(() => validateConfig(raw, env), /defaultDashboard is required when there are several dashboards \(demos, teams\)/);
  assert.throws(() => validateConfig(dash({ defaultDashboard: 'nope' }), env), /defaultDashboard "nope" is not one of the dashboards/);
  const one = { kargo: { url: 'https://k' }, dashboards: { only: { name: 'Only', projects: { a: {} } } } };
  assert.equal(validateConfig(one, env).defaultDashboard, 'only');
});

test('dashboard ids must be URL-safe; names are required', () => {
  for (const bad of ['Has Space', 'UPPER', '-lead', 'a/b', 'x'.repeat(64)]) {
    const raw = dash(); raw.dashboards = { [bad]: { name: 'N', projects: { a: {} } } }; raw.defaultDashboard = bad;
    assert.throws(() => validateConfig(raw, env), /id must match/, bad);
  }
  const raw = dash(); raw.dashboards.demos.name = '  ';
  assert.throws(() => validateConfig(raw, env), /dashboards\.demos: missing name/);
  const noName = dash(); delete noName.dashboards.teams.name;
  assert.throws(() => validateConfig(noName, env), /dashboards\.teams: missing name/);
});

test('mis-nested dashboards.projects fails with a message that names the fix', () => {
  const raw = { kargo: { url: 'https://k' }, dashboards: { projects: { 'demo-rollouts': { warehouse: 'w' } } } };
  assert.throws(() => validateConfig(raw, env), /dashboards\.projects: missing name \(did you mean dashboards\.<id>\.projects\?\)/);
});

test('each dashboard needs a non-empty projects object, validated like the legacy form', () => {
  const raw = dash(); raw.dashboards.demos.projects = {};
  assert.throws(() => validateConfig(raw, env), /dashboards\.demos\.projects must be a non-empty object/);
  const both = dash(); both.dashboards.demos.projects['demo-rollouts'] = { warehouse: 'w', warehouses: ['x'] };
  assert.throws(() => validateConfig(both, env), /dashboards\.demos\.projects\.demo-rollouts: set either warehouse or warehouses/);
  const rx = dash(); rx.dashboards.teams.projects['team-ada'].includeStages = ['regex:('];
  assert.throws(() => validateConfig(rx, env), /Invalid regular expression/);
});

test('one project must use the same token in every dashboard', () => {
  const raw = dash();
  raw.dashboards.teams.projects.shared = { tokenEnv: 'OTHER_TOKEN' };
  assert.throws(() => validateConfig(raw, env), /project shared uses tokenEnv KARGO_TOKEN in dashboard demos but OTHER_TOKEN in teams/);
});

test('legacy top-level projects becomes the "default" dashboard with a deprecation warning', () => {
  const c = validateConfig(base(), env);
  assert.deepEqual(Object.keys(c.dashboards), ['default']);
  assert.equal(c.dashboards.default.name, 'Kargo Dashboard');
  assert.equal(c.defaultDashboard, 'default');
  assert.equal(c.warnings.length, 1);
  assert.match(c.warnings[0], /deprecated/);
});

test('projects and dashboards together, or neither, are rejected', () => {
  assert.throws(() => validateConfig({ ...dash(), projects: { a: {} } }, env), /either projects \(legacy\) or dashboards, not both/);
  assert.throws(() => validateConfig({ kargo: { url: 'https://k' } }, env), /dashboards is required/);
  assert.throws(() => validateConfig({ kargo: { url: 'https://k' }, dashboards: {} }, env), /non-empty object/);
});

// ---- Section 14.4: promotion settings ----
test('promotion defaults: blue, purple, the wait-for/get-user-input pattern, animated', () => {
  const p = validateConfig(base(), env).promotion;
  assert.deepEqual(p, {
    color: '#1e6fd9', waitingColor: '#7b1fa2', waitingStepPattern: 'wait-for|^get-user-input$',
    animate: true,
  });
  const re = new RegExp(p.waitingStepPattern);
  for (const yes of ['wait-for-approval', 'git-wait-for-pr', 'snow-wait-for-condition', 'gha-wait-for-workflow', 'gh-wait-for-issue-state', 'get-user-input']) {
    assert.ok(re.test(yes), yes);
  }
  for (const no of ['helm-template', 'get-user-input-extra', 'my-get-user-input', 'git-push']) assert.ok(!re.test(no), no);
});

test('promotion settings can be overridden and are validated', () => {
  const p = (promotion) => validateConfig({ ...base(), promotion }, env).promotion;
  assert.equal(p({ color: '#ff0000', animate: false }).color, '#ff0000');
  assert.equal(p({ waitingStepPattern: '^wait-for' }).waitingStepPattern, '^wait-for');
  assert.throws(() => p({ color: 'blue' }), /promotion.color must be a #rrggbb color/);
  assert.throws(() => p({ waitingColor: '#fff' }), /promotion.waitingColor/);
  assert.throws(() => p({ waitingStepPattern: '(' }), /not a valid regex/);
  assert.throws(() => p({ animate: 'yes' }), /animate must be true or false/);
  assert.throws(() => p([]), /promotion must be an object/);
});

// ---- PLAN 17 (W4): polling settings are accepted, ignored, and warned about ----
test('the three polling settings warn once each and do nothing, even with out-of-range values', () => {
  const c = validateConfig({ ...base(), refreshIntervalSeconds: 60, idlePauseSeconds: 0, promotion: { activeRefreshIntervalSeconds: 999, animate: false } }, env);
  const deprecated = c.warnings.filter((w) => /deprecated and ignored/.test(w));
  assert.equal(deprecated.length, 3);
  for (const key of ['refreshIntervalSeconds', 'idlePauseSeconds', 'promotion.activeRefreshIntervalSeconds']) {
    assert.equal(deprecated.filter((w) => w.startsWith(`${key} `)).length, 1, key);
  }
  assert.equal(c.promotion.animate, false);
  assert.ok(!('activeRefreshIntervalSeconds' in c.promotion));
  assert.equal(validateConfig(base(), env).warnings.filter((w) => /deprecated and ignored/.test(w)).length, 0, 'no warning when unset');
});
