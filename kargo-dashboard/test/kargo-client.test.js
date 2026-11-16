import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createKargoClient, KargoApiError, KargoWatchError } from '../src/kargo-client.js';

const respond = (status, body) => async (url, init) => {
  respond.calls.push({ url, init });
  return { status, ok: status >= 200 && status < 300, json: async () => body };
};
respond.calls = [];
const client = (impl) => createKargoClient({ url: 'https://k.example/', fetchImpl: impl, timeoutMs: 50 });

test('builds URLs, sends bearer token and JSON accept', async () => {
  respond.calls.length = 0;
  const c = client(respond(200, { items: [{ metadata: { name: 'w' } }] }));
  assert.equal((await c.listWarehouses('p q', 'tok')).items.length, 1);
  await c.listStages('p', 'tok');
  await c.listFreight('p', { origins: ['a', 'b c'] }, 'tok');
  await c.listFreight('p', {}, 'tok');
  assert.deepEqual(respond.calls.map((x) => x.url), [
    'https://k.example/v1beta1/projects/p%20q/warehouses',
    'https://k.example/v1beta1/projects/p/stages',
    'https://k.example/v1beta1/projects/p/freight?origins=a&origins=b%20c',
    'https://k.example/v1beta1/projects/p/freight',
  ]);
  assert.equal(respond.calls[0].init.headers.Authorization, 'Bearer tok');
  assert.equal(respond.calls[0].init.headers.Accept, 'application/json');
});

test('lists return the resourceVersion that seeds a watch', async () => {
  assert.equal((await client(respond(200, { items: [], metadata: { resourceVersion: '42' } })).listStages('p', 't')).resourceVersion, '42');
  assert.equal((await client(respond(200, { items: [], metadata: { resourceVersion: '43' } })).listWarehouses('p', 't')).resourceVersion, '43');
  assert.equal((await client(respond(200, { groups: {}, resourceVersion: '44' })).listFreight('p', {}, 't')).resourceVersion, '44');
  assert.equal((await client(respond(200, {})).listStages('p', 't')).resourceVersion, '');
});

test('flattens all freight groups and de-duplicates by name', async () => {
  const f = (n) => ({ metadata: { name: n } });
  const c = client(respond(200, { groups: { a: { items: [f('x'), f('y')] }, b: { items: [f('y'), f('z')] } } }));
  assert.deepEqual((await c.listFreight('p', {}, 't')).items.map((x) => x.metadata.name), ['x', 'y', 'z']);
});

test('missing items/groups yield empty arrays', async () => {
  const c = client(respond(200, {}));
  assert.deepEqual((await c.listWarehouses('p', 't')).items, []);
  assert.deepEqual((await c.listFreight('p', {}, 't')).items, []);
});

test('401 and 403 become a token-access error that never contains the token', async () => {
  for (const status of [401, 403]) {
    await assert.rejects(client(respond(status, {})).listStages('proj', 'SECRET'), (e) => {
      assert.ok(e instanceof KargoApiError);
      assert.equal(e.status, status);
      assert.match(e.message, /token lacks access to project proj/);
      assert.ok(!e.message.includes('SECRET'));
      return true;
    });
  }
});

test('other HTTP errors and network failures are KargoApiErrors', async () => {
  await assert.rejects(client(respond(500, {})).listWarehouses('p', 't'), /HTTP 500/);
  await assert.rejects(client(async () => { throw new Error('boom'); }).listWarehouses('p', 't'), /boom/);
});

test('timeouts are reported as such', async () => {
  const slow = (url, init) => new Promise((_, rej) => init.signal.addEventListener('abort', () => rej(init.signal.reason)));
  await assert.rejects(client(slow).listWarehouses('p', 't'), /timed out after 50ms/);
});

// ---- watch ----
const enc = new TextEncoder();
const sseResponse = (chunks, { type = 'text/event-stream', status = 200 } = {}) => async (url, init) => {
  sseResponse.calls.push({ url, init });
  return {
    status, ok: status < 300, headers: new Headers({ 'content-type': type }),
    body: (async function* () { for (const c of chunks) yield enc.encode(c); })(),
  };
};
sseResponse.calls = [];
const drain = async (it) => { const out = []; for await (const x of it) out.push(x); return out; };

test('watch sends watch=true, extra query and resourceVersion with an event-stream accept, and yields events and keepalives', async () => {
  sseResponse.calls.length = 0;
  const c = client(sseResponse([': keepalive\n\n', 'data: {"type":"ADDED","object":{"metadata":{"name":"a"}}}\n\n', 'data: {"type":"DELETED","object":{"metadata":{"name":"a"}}}\n\n']));
  const out = await drain(c.watch('p', 'freight', { token: 'tok', query: [['origins', 'w1'], ['origins', 'w2']], resourceVersion: '9' }));
  assert.deepEqual(out.map((e) => e.keepalive ? 'keepalive' : `${e.type}:${e.object.metadata.name}`), ['keepalive', 'ADDED:a', 'DELETED:a']);
  assert.equal(sseResponse.calls[0].url, 'https://k.example/v1beta1/projects/p/freight?watch=true&origins=w1&origins=w2&resourceVersion=9');
  assert.equal(sseResponse.calls[0].init.headers.Accept, 'text/event-stream');
  assert.equal(sseResponse.calls[0].init.headers.Authorization, 'Bearer tok');
  assert.ok(c.bytesReceived() > 0);
});

test('watch without a resourceVersion omits the parameter', async () => {
  sseResponse.calls.length = 0;
  await drain(client(sseResponse([])).watch('p', 'stages', { token: 't' }));
  assert.equal(sseResponse.calls[0].url, 'https://k.example/v1beta1/projects/p/stages?watch=true');
});

test('a response that is not text/event-stream is a clear error', async () => {
  await assert.rejects(drain(client(sseResponse([], { type: 'application/json' })).watch('p', 'stages', { token: 't' })),
    (e) => e instanceof KargoApiError && /Kargo >= 1.12/.test(e.message));
});

test('an error frame becomes KargoWatchError with its code', async () => {
  const c = client(sseResponse(['event: error\ndata: {"code":"out_of_range","message":"watch resource version expired"}\n\n']));
  await assert.rejects(drain(c.watch('p', 'stages', { token: 't' })), (e) => e instanceof KargoWatchError && e.code === 'out_of_range' && /expired/.test(e.message));
});

test('watch HTTP errors: 401/403 name the project and never the token; 500 is a KargoApiError', async () => {
  const status = (s) => async () => ({ status: s, ok: false, headers: new Headers(), body: null });
  await assert.rejects(drain(client(status(403)).watch('proj', 'stages', { token: 'SECRET' })), (e) => e.status === 403 && /token lacks access to project proj/.test(e.message) && !e.message.includes('SECRET'));
  await assert.rejects(drain(client(status(500)).watch('p', 'stages', { token: 't' })), (e) => e instanceof KargoApiError && e.status === 500);
});

test('aborting the signal ends a watch with an abort error rather than a KargoApiError', async () => {
  const ac = new AbortController();
  const hanging = async (url, init) => ({
    status: 200, ok: true, headers: new Headers({ 'content-type': 'text/event-stream' }),
    body: (async function* () { yield enc.encode(': hi\n\n'); await new Promise((_, rej) => { if (init.signal.aborted) rej(init.signal.reason); init.signal.addEventListener('abort', () => rej(init.signal.reason)); }); })(),
  });
  const it = client(hanging).watch('p', 'stages', { token: 't', signal: ac.signal });
  assert.deepEqual((await it.next()).value, { keepalive: true });
  ac.abort(new Error('stop'));
  await assert.rejects(it.next(), (e) => !(e instanceof KargoApiError));
});
