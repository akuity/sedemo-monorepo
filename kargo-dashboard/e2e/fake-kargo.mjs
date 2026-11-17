// A fake Kargo REST API for browser tests. It serves the repo's scrubbed fixtures, including Kargo >= 1.12's
// `?watch=true` server-sent event streams, so a test can change the world and watch the dashboard follow:
//   POST /__set { project, stage, promotion: null | { name, origin, repoURL, tag, currentStep } }
//        puts a stage into (or out of) a running promotion and emits a stage MODIFIED event
//   POST /__freight { project, freight }  adds a Freight and emits a freight ADDED event
//   GET  /__stats  -> { lists: { '<project>/<kind>': n }, watches: { '<project>/<kind>': n } } request counts
import http from 'node:http';
import { readFileSync } from 'node:fs';

const FIXTURES = new URL('../test/fixtures/', import.meta.url);
const load = (project, file) => JSON.parse(readFileSync(new URL(`${project}/${file}.json`, FIXTURES)));
export const FAKE_TOKEN = 'fake-token';

// 7 expanded steps; the last one waits for a person.
const STEPS = ['git-clone', 'git-clone', 'git-clear', 'helm-template', 'helm-template', 'git-commit', 'wait-for-approval']
  .map((uses, i) => ({ uses, as: `step-${i + 1}` }));

export function startFakeKargo(port) {
  const running = {};   // `${project}/${stage}` -> promotion
  const extraFreight = {}; // project -> [freight]
  const watchers = {};  // `${project}/${kind}` -> Set<res>
  const lists = {};
  const watches = {};
  const bump = (counter, key) => { counter[key] = (counter[key] || 0) + 1; };
  let rv = 1000;

  const stagesFor = (project) => {
    const stages = load(project, 'stages');
    for (const s of stages.items) {
      const p = running[`${project}/${s.metadata.name}`];
      if (!p) continue;
      s.status.currentPromotion = {
        name: p.name,
        freight: { name: 'incoming-freight', origin: { kind: 'Warehouse', name: p.origin }, images: [{ repoURL: p.repoURL, tag: p.tag }] },
        status: { phase: 'Running', currentStep: p.currentStep, startedAt: '2026-10-15T10:00:00Z' },
      };
    }
    stages.metadata = { resourceVersion: String(rv) };
    return stages;
  };
  const freightFor = (project) => {
    const f = load(project, 'freight');
    if (extraFreight[project]?.length) f.groups.extra = { items: extraFreight[project] };
    f.resourceVersion = String(rv);
    return f;
  };
  const emit = (project, kind, type, object) => {
    rv += 1;
    object.metadata = { ...object.metadata, resourceVersion: String(rv) };
    for (const res of watchers[`${project}/${kind}`] || []) res.write(`data: ${JSON.stringify({ type, object })}\n\n`);
  };

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    const send = (code, body) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      if (url.pathname === '/__set') {
        const b = JSON.parse(body);
        running[`${b.project}/${b.stage}`] = b.promotion;
        const stage = stagesFor(b.project).items.find((s) => s.metadata.name === b.stage);
        if (!b.promotion) delete stage.status.currentPromotion;
        emit(b.project, 'stages', 'MODIFIED', stage);
        return send(200, { ok: true });
      }
      if (url.pathname === '/__freight') {
        const b = JSON.parse(body);
        (extraFreight[b.project] ||= []).push(b.freight);
        emit(b.project, 'freight', 'ADDED', b.freight);
        return send(200, { ok: true });
      }
      if (url.pathname === '/__stats') return send(200, { lists, watches });
      if (req.headers.authorization !== `Bearer ${FAKE_TOKEN}`) return send(401, { error: 'unauthorized' });
      const m = /^\/v1beta1\/projects\/([^/]+)\/(warehouses|stages|freight|promotions\/(.+))$/.exec(url.pathname);
      if (!m) return send(404, { error: 'not found' });
      const [, project, kind, promotionName] = m;
      try {
        if (url.searchParams.get('watch') === 'true' && !promotionName) {
          const key = `${project}/${kind}`;
          bump(watches, key);
          res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', 'x-accel-buffering': 'no' });
          res.write(': keepalive\n\n');
          (watchers[key] ||= new Set()).add(res);
          res.on('close', () => watchers[key].delete(res));
          return undefined; // seeded watches (they all send a resourceVersion) start with no replay, like Kargo
        }
        if (promotionName) return send(200, { metadata: { name: promotionName }, spec: { steps: STEPS }, status: { phase: 'Running' } });
        bump(lists, `${project}/${kind}`);
        if (kind === 'warehouses') return send(200, { ...load(project, 'warehouses'), metadata: { resourceVersion: String(rv) } });
        if (kind === 'freight') return send(200, freightFor(project));
        return send(200, stagesFor(project));
      } catch (err) {
        return send(500, { error: err.message });
      }
    });
  });
  const base = `http://127.0.0.1:${port}`;
  const post = (path, payload) => fetch(`${base}${path}`, { method: 'POST', body: JSON.stringify(payload) });
  return new Promise((resolve) => server.listen(port, () => resolve({
    url: base,
    set: (project, stage, promotion) => post('/__set', { project, stage, promotion }),
    addFreight: (project, freight) => post('/__freight', { project, freight }),
    stats: async () => (await fetch(`${base}/__stats`)).json(),
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }),
  })));
}
