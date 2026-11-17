// Keeps one Kargo resource list in sync: list -> watch from that resourceVersion -> reconnect forever.
// No Kargo knowledge beyond the error shapes; `list` and `watch` are injected (see kargo-client.js).
//
//   list()                        -> Promise<{ items, resourceVersion }>
//   watch({ resourceVersion, signal }) -> async iterable of { type, object } | { keepalive: true }
//   onReset(items)                full replacement of the known objects (after every list)
//   onEvent(type, object)         ADDED | MODIFIED | DELETED
//   onState({ state, since, error })  state: 'connecting' | 'live' | 'down'
//
// Behavior (PLAN 17.3): a stream that is silent for stallMs (events and keepalives both count) is
// aborted and resumed (W6); failures back off 1s, 2s, 4s ... capped at 60s with +-20% jitter and the
// backoff resets once a stream has been healthy for 60s (W7); an expired resourceVersion
// (KargoWatchError out_of_range, or HTTP 410) re-lists; 401/403 retry at the cap.

export const STALL_MS = 90_000;
const BACKOFF_BASE_MS = 1_000;
const BACKOFF_CAP_MS = 60_000;
const HEALTHY_MS = 60_000;

export function backoffMs(attempt, random = Math.random) {
  const base = Math.min(BACKOFF_BASE_MS * 2 ** Math.max(0, attempt - 1), BACKOFF_CAP_MS);
  return Math.round(base * (0.8 + random() * 0.4));
}

const isExpired = (err) => err?.code === 'out_of_range' || err?.status === 410;
const isAuth = (err) => err?.status === 401 || err?.status === 403;

export function createResourceWatch({
  list, watch, onReset = () => {}, onEvent = () => {}, onState = () => {},
  stallMs = STALL_MS,
  timers = { setTimeout, clearTimeout, now: Date.now },
  random = Math.random,
}) {
  let stopped = false;
  let current = null;       // AbortController of the open watch
  let wake = null;          // cancels the current backoff sleep
  let done = Promise.resolve();
  let down = null;          // { since, error } while not live

  const setState = (state, error) => {
    if (state === 'down') {
      if (!down) down = { since: timers.now(), error };
      else down.error = error;
      onState({ state, since: down.since, error });
    } else {
      down = null;
      onState({ state, since: null, error: null });
    }
  };

  const sleep = (ms) => new Promise((resolve) => {
    if (stopped) return resolve();
    const t = timers.setTimeout(() => { wake = null; resolve(); }, ms);
    wake = () => { timers.clearTimeout(t); wake = null; resolve(); };
  });

  async function run() {
    let rv = '';
    let needList = true;
    let attempt = 0;
    let skipDelay = false;
    setState('connecting');

    while (!stopped) {
      let healthySince = null;
      let failure = null;
      try {
        if (needList) {
          const r = await list();
          if (stopped) return;
          onReset(r.items);
          rv = r.resourceVersion || '';
          needList = false;
          setState('live');
        }
        const ac = new AbortController();
        current = ac;
        let stalled = false;
        let stallTimer = null;
        const armStall = () => {
          if (stallTimer) timers.clearTimeout(stallTimer);
          stallTimer = timers.setTimeout(() => { stalled = true; ac.abort(new Error('stalled')); }, stallMs);
        };
        armStall();
        try {
          for await (const item of watch({ resourceVersion: rv, signal: ac.signal })) {
            if (stopped) return;
            armStall();
            if (healthySince === null) { healthySince = timers.now(); skipDelay = false; setState('live'); }
            if (item.keepalive) continue;
            const v = item.object?.metadata?.resourceVersion;
            if (v) rv = v;
            onEvent(item.type, item.object);
          }
          failure = new Error('stream closed by server');
        } catch (err) {
          if (stopped) return;
          failure = stalled ? new Error(`no data for ${Math.round(stallMs / 1000)}s`) : err;
        } finally {
          if (stallTimer) timers.clearTimeout(stallTimer);
          current = null;
        }
      } catch (err) {
        if (stopped) return;
        failure = err;
      }

      // The stream (or the list) ended: decide how long to wait before trying again.
      if (stopped) return;
      if (healthySince !== null && timers.now() - healthySince >= HEALTHY_MS) attempt = 0;
      setState('down', failure.message);
      if (isExpired(failure)) {
        needList = true;
        if (!skipDelay) { skipDelay = true; continue; } // re-list at once, but only once in a row
      } else {
        skipDelay = false;
        if (!rv) needList = true; // never got a usable resourceVersion
      }
      attempt += 1;
      await sleep(isAuth(failure) ? BACKOFF_CAP_MS : backoffMs(attempt, random));
    }
  }

  return {
    start() { if (!stopped) done = run().catch((err) => { onState({ state: 'down', since: timers.now(), error: err.message }); }); return this; },
    async stop() {
      stopped = true;
      current?.abort(new Error('stopped'));
      wake?.();
      await done;
    },
  };
}
