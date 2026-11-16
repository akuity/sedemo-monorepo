import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createResourceWatch, backoffMs } from '../src/watcher.js';
import { KargoWatchError, KargoApiError } from '../src/kargo-client.js';

// A manual clock: timers only fire when advance() is called.
function fakeClock() {
  let now = 1_000_000;
  let seq = 0;
  const pending = new Map();
  const flush = () => new Promise((r) => setImmediate(r));
  return {
    now: () => now,
    setTimeout: (fn, ms) => { seq += 1; pending.set(seq, { at: now + ms, fn }); return seq; },
    clearTimeout: (id) => { pending.delete(id); },
    pending: () => pending.size,
    async advance(ms) {
      const target = now + ms;
      await flush();
      for (;;) {
        const due = [...pending.entries()].filter(([, t]) => t.at <= target).sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) break;
        pending.delete(due[0]);
        now = due[1].at;
        due[1].fn();
        await flush();
      }
      now = target;
      await flush();
    },
  };
}

// A controllable watch: each call to watch() gets a "session" the test pushes frames into.
function harness({ lists = [], ...opts } = {}) {
  const clock = fakeClock();
  const log = { lists: 0, watches: [], resets: [], events: [], states: [] };
  const sessions = [];
  const listFn = async () => {
    const next = lists[Math.min(log.lists, lists.length - 1)];
    log.lists += 1;
    if (next instanceof Error) throw next;
    return next;
  };
  const watch = ({ resourceVersion, signal }) => {
    log.watches.push(resourceVersion);
    const queue = [];
    let notify = null; let ended = null;
    const session = {
      push: (x) => { queue.push(x); notify?.(); },
      end: () => { ended = { done: true }; notify?.(); },
      fail: (err) => { ended = { err }; notify?.(); },
    };
    sessions.push(session);
    signal.addEventListener('abort', () => { ended = { err: signal.reason }; notify?.(); });
    return (async function* () {
      for (;;) {
        if (queue.length) { yield queue.shift(); continue; }
        if (ended) { if (ended.err) throw ended.err; return; }
        await new Promise((r) => { notify = r; });
        notify = null;
      }
    })();
  };
  const w = createResourceWatch({
    list: listFn, watch, timers: clock, random: () => 0.5,
    onReset: (items) => log.resets.push(items.map((i) => i.metadata.name)),
    onEvent: (type, o) => log.events.push(`${type}:${o.metadata.name}`),
    onState: (s) => log.states.push(s.state),
    ...opts,
  });
  return { w, clock, log, sessions, last: () => sessions[sessions.length - 1] };
}
const item = (name, rv) => ({ metadata: { name, resourceVersion: rv } });
const list = (names, resourceVersion) => ({ items: names.map((n) => item(n, '1')), resourceVersion });
const tick = () => new Promise((r) => setImmediate(r));

test('lists, resets, then watches from the list resourceVersion and reports live', async () => {
  const h = harness({ lists: [list(['a', 'b'], '100')] });
  h.w.start(); await tick();
  assert.deepEqual(h.log.resets, [['a', 'b']]);
  assert.deepEqual(h.log.watches, ['100']);
  h.last().push({ type: 'ADDED', object: item('c', '101') });
  await tick();
  assert.deepEqual(h.log.events, ['ADDED:c']);
  assert.equal(h.log.states.at(-1), 'live');
  await h.w.stop();
  assert.equal(h.clock.pending(), 0, 'no timers left after stop');
});

test('a reconnect resumes from the last resourceVersion seen, without re-listing', async () => {
  const h = harness({ lists: [list(['a'], '100')] });
  h.w.start(); await tick();
  h.last().push({ type: 'MODIFIED', object: item('a', '105') });
  h.last().push({ type: 'DELETED', object: item('a', '110') });
  await tick();
  h.last().end();
  await tick();
  assert.equal(h.log.states.at(-1), 'down');
  await h.clock.advance(1000); // first backoff: 1s (jitter midpoint)
  assert.deepEqual(h.log.watches, ['100', '110']);
  assert.equal(h.log.lists, 1);
  await h.w.stop();
});

test('out_of_range re-lists at once and watches from the new resourceVersion', async () => {
  const h = harness({ lists: [list(['a'], '100'), list(['a', 'z'], '500')] });
  h.w.start(); await tick();
  h.last().fail(new KargoWatchError('expired', 'out_of_range'));
  await tick();
  assert.equal(h.log.lists, 2, 're-listed with no delay');
  assert.deepEqual(h.log.resets, [['a'], ['a', 'z']]);
  assert.deepEqual(h.log.watches, ['100', '500']);
  await h.w.stop();
});

test('HTTP 410 is treated like an expired resourceVersion', async () => {
  const h = harness({ lists: [list(['a'], '100'), list(['a'], '200')] });
  h.w.start(); await tick();
  h.last().fail(new KargoApiError('gone', 410));
  await tick();
  assert.deepEqual(h.log.watches, ['100', '200']);
  await h.w.stop();
});

test('a stream silent for 90s is aborted and resumed; keepalives count as activity', async () => {
  const h = harness({ lists: [list(['a'], '100')] });
  h.w.start(); await tick();
  await h.clock.advance(80_000);
  h.last().push({ keepalive: true });
  await h.clock.advance(80_000); // 160s since start but only 80s since the keepalive
  assert.equal(h.log.watches.length, 1, 'still the same stream');
  await h.clock.advance(11_000); // now 91s of silence
  assert.equal(h.log.states.at(-1), 'down');
  await h.clock.advance(1000);
  assert.equal(h.log.watches.length, 2, 'reconnected');
  await h.w.stop();
});

test('backoff doubles to the cap and resets after a healthy period', async () => {
  assert.deepEqual([1, 2, 3, 4, 5, 6, 7, 8].map((n) => backoffMs(n, () => 0.5)), [1000, 2000, 4000, 8000, 16000, 32000, 60000, 60000]);
  assert.equal(backoffMs(1, () => 0), 800);
  assert.equal(backoffMs(1, () => 1), 1200);

  const h = harness({ lists: [list(['a'], '100')] });
  h.w.start(); await tick();
  h.last().fail(new Error('boom1')); await tick();
  await h.clock.advance(999); assert.equal(h.log.watches.length, 1, 'not before 1s');
  await h.clock.advance(1); assert.equal(h.log.watches.length, 2);
  h.last().fail(new Error('boom2')); await tick();
  await h.clock.advance(1999); assert.equal(h.log.watches.length, 2, '2s second time');
  await h.clock.advance(1); assert.equal(h.log.watches.length, 3);

  // healthy for 60s, then it drops: the delay starts over at 1s
  h.last().push({ keepalive: true }); await tick();
  await h.clock.advance(61_000);
  h.last().push({ keepalive: true });
  h.last().fail(new Error('boom3')); await tick();
  await h.clock.advance(1000);
  assert.equal(h.log.watches.length, 4);
  await h.w.stop();
});

test('list failures retry with backoff and the project stays down until a list works', async () => {
  const h = harness({ lists: [new KargoApiError('HTTP 500', 500), list(['a'], '7')] });
  h.w.start(); await tick();
  assert.equal(h.log.states.at(-1), 'down');
  assert.equal(h.log.watches.length, 0);
  await h.clock.advance(1000);
  assert.equal(h.log.states.at(-1), 'live');
  assert.deepEqual(h.log.watches, ['7']);
  await h.w.stop();
});

test('403 retries at the 60s cap', async () => {
  const h = harness({ lists: [new KargoApiError('token lacks access', 403), list(['a'], '7')] });
  h.w.start(); await tick();
  await h.clock.advance(59_000); assert.equal(h.log.lists, 1);
  await h.clock.advance(1_000); assert.equal(h.log.lists, 2);
  await h.w.stop();
});

test('stop() during a backoff sleep or an open stream ends cleanly with no timers left', async () => {
  const a = harness({ lists: [list(['a'], '1')] });
  a.w.start(); await tick();
  a.last().fail(new Error('x')); await tick();
  await a.w.stop();
  assert.equal(a.clock.pending(), 0);
  const b = harness({ lists: [list(['a'], '1')] });
  b.w.start(); await tick();
  await b.w.stop();
  assert.equal(b.clock.pending(), 0);
});
