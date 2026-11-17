// In-memory mirror of Kargo, kept current by watch streams (PLAN section 17). Replaces collector.js.
// For each unique project across all dashboards it keeps warehouses, stages and freight in maps that
// watcher.js updates, and builds the same per-project snapshot the polling collector produced, so
// summarize.js and everything downstream is unchanged:
//   { project, error, warehouses, stages, freightByWarehouse: Map<wh, {freight}|{error}>,
//     promotions: Map<stage, { name, ref, status, steps }> }
// It emits 'change' (no payload) whenever any snapshot may have changed; the server debounces.
import { EventEmitter } from 'node:events';
import { createResourceWatch } from './watcher.js';
import { isActivePromotion } from './promotion.js';

// Which projects to watch and which of their warehouses are needed.
// -> Map<project, { tokenEnv, all: boolean, names: Set<string> }>
// `all` is true when any dashboard asks for every warehouse of the project (no key given).
export function planProjects(config) {
  const plan = new Map();
  for (const dashboard of Object.values(config.dashboards)) {
    for (const [project, pc] of Object.entries(dashboard.projects)) {
      const entry = plan.get(project) || { tokenEnv: pc.tokenEnv, all: false, names: new Set() };
      if (pc.warehouses.length === 0) entry.all = true;
      for (const name of pc.warehouses) entry.names.add(name);
      plan.set(project, entry);
    }
  }
  return plan;
}

const byName = (a, b) => (a.metadata.name < b.metadata.name ? -1 : a.metadata.name > b.metadata.name ? 1 : 0);
const newStream = () => ({ loaded: false, settled: false, state: 'connecting', since: null, error: null });
const KINDS = ['warehouses', 'stages', 'freight'];

export function createStore({
  config, client, env = process.env, warn = () => {},
  timers = { setTimeout, clearTimeout, now: Date.now },
  promotionRetryMs = 5_000,
  watchOptions = {},
}) {
  const emitter = new EventEmitter();
  const projects = new Map();
  // Promotion steps never change for a given Promotion, so each is fetched once.
  // key: `${project}/${promotionName}` -> [{ uses, as }]
  const stepCache = new Map();
  // Status fetched for references that carry none: key -> { at, status }
  const statusCache = new Map();
  const inflight = new Set();
  let stopped = false;
  let reconnects = 0; // times any stream dropped

  const changed = () => { if (!stopped) emitter.emit('change'); };

  function reconcilePromotions(st) {
    const live = new Set();
    for (const stage of st.data.stages.values()) {
      const ref = stage.status?.currentPromotion;
      if (!isActivePromotion(ref)) continue;
      const key = `${st.project}/${ref.name}`;
      live.add(key);
      const needStatus = !ref.status?.phase;
      const cached = statusCache.get(key);
      const stale = needStatus && (!cached || timers.now() - cached.at >= promotionRetryMs);
      if (!stepCache.has(key) || stale) fetchPromotion(st, ref, key, needStatus);
    }
    st.live = live;
    // Forget promotions that are no longer current anywhere in this project.
    for (const cache of [stepCache, statusCache]) {
      for (const key of cache.keys()) if (key.startsWith(`${st.project}/`) && !live.has(key)) cache.delete(key);
    }
  }

  function scheduleRecheck(st) {
    if (st.recheck || stopped) return;
    st.recheck = timers.setTimeout(() => { st.recheck = null; reconcilePromotions(st); }, promotionRetryMs);
  }

  async function fetchPromotion(st, ref, key, needStatus) {
    if (inflight.has(key)) return;
    inflight.add(key);
    try {
      const fetched = await client.getPromotion(st.project, ref.name, st.token);
      if (stopped || !st.live.has(key)) return; // went away while we were fetching
      if (!stepCache.has(key)) {
        stepCache.set(key, (fetched.spec?.steps || []).map((s) => ({ uses: s.uses ?? s.task?.name ?? null, as: s.as ?? null })));
      }
      if (needStatus) {
        statusCache.set(key, { at: timers.now(), status: fetched.status });
        scheduleRecheck(st); // keep reading the status while the reference carries none
      }
      changed();
    } catch (err) {
      // A failed fetch degrades to "Promoting..." without steps, and is retried.
      warn(`could not read promotion ${ref.name} in ${st.project}: ${err.message}`);
      scheduleRecheck(st);
    } finally {
      inflight.delete(key);
    }
  }

  function startProject([project, wanted]) {
    const token = env[wanted.tokenEnv];
    const st = {
      project, token, wanted, live: new Set(), recheck: null,
      data: { warehouses: new Map(), stages: new Map(), freight: new Map() },
      streams: { warehouses: newStream(), stages: newStream(), freight: newStream() },
      watches: [],
    };
    const origins = wanted.all ? [] : [...wanted.names];
    const lists = {
      warehouses: () => client.listWarehouses(project, token),
      stages: () => client.listStages(project, token),
      freight: () => client.listFreight(project, { origins }, token),
    };
    for (const kind of KINDS) {
      const stream = st.streams[kind];
      st.watches.push(createResourceWatch({
        list: lists[kind],
        watch: ({ resourceVersion, signal }) => client.watch(project, kind, {
          token, resourceVersion, signal, query: kind === 'freight' ? origins.map((o) => ['origins', o]) : [],
        }),
        onReset: (items) => {
          st.data[kind] = new Map(items.map((o) => [o.metadata.name, o]));
          stream.loaded = true; stream.settled = true;
          if (kind === 'stages') reconcilePromotions(st);
          changed();
        },
        onEvent: (type, object) => {
          const map = st.data[kind];
          if (type === 'DELETED') map.delete(object.metadata.name);
          else if (type === 'ADDED' || type === 'MODIFIED') map.set(object.metadata.name, object);
          else return;
          if (kind === 'stages') reconcilePromotions(st);
          changed();
        },
        onState: ({ state, since, error }) => {
          if (state === 'down' && stream.state !== 'down') reconnects += 1;
          stream.state = state; stream.since = since; stream.error = error;
          if (state === 'down') stream.settled = true;
          changed();
        },
        timers,
        ...watchOptions,
      }));
    }
    projects.set(project, st);
  }

  function snapshot(st) {
    const { warehouses: ws, stages: ss } = st.streams;
    const notLoaded = [ws, ss].find((s) => !s.loaded);
    if (notLoaded) {
      return { project: st.project, error: notLoaded.error || 'waiting for Kargo', warehouses: [], stages: [], freightByWarehouse: new Map(), promotions: new Map() };
    }
    const warehouses = [...st.data.warehouses.values()].sort(byName);
    const stages = [...st.data.stages.values()].sort(byName);
    const available = new Set(warehouses.map((w) => w.metadata.name));
    const names = st.wanted.all ? [...available] : [...st.wanted.names].filter((n) => available.has(n));
    const fs = st.streams.freight;
    const allFreight = fs.loaded ? [...st.data.freight.values()] : [];
    const freightByWarehouse = new Map(names.map((name) => [name, fs.loaded
      ? { freight: allFreight.filter((f) => f.origin?.name === name) }
      : { error: fs.error || 'waiting for Kargo' }]));
    const promotions = new Map();
    for (const stage of stages) {
      const ref = stage.status?.currentPromotion;
      if (!isActivePromotion(ref)) continue;
      const key = `${st.project}/${ref.name}`;
      const needStatus = !ref.status?.phase;
      promotions.set(stage.metadata.name, {
        name: ref.name, ref, status: needStatus ? statusCache.get(key)?.status : ref.status, steps: stepCache.get(key) ?? null,
      });
    }
    return { project: st.project, error: null, warehouses, stages, freightByWarehouse, promotions };
  }

  return {
    start() { for (const entry of planProjects(config)) startProject(entry); for (const st of projects.values()) st.watches.forEach((w) => w.start()); return this; },
    async stop() {
      stopped = true;
      for (const st of projects.values()) if (st.recheck) timers.clearTimeout(st.recheck);
      await Promise.all([...projects.values()].flatMap((st) => st.watches.map((w) => w.stop())));
      emitter.removeAllListeners();
    },
    on: (...a) => emitter.on(...a),
    off: (...a) => emitter.off(...a),
    snapshots() { return new Map([...projects.values()].map((st) => [st.project, snapshot(st)])); },
    // ready: every project has either loaded or failed at least once, so the first payload can be built.
    // down: projects with a stream that is not live, and since when. active: some stage is promoting.
    status() {
      const all = [...projects.values()];
      const down = [];
      for (const st of all) {
        const sinces = Object.values(st.streams).filter((s) => s.state === 'down').map((s) => s.since);
        if (sinces.length) down.push({ project: st.project, since: Math.min(...sinces) });
      }
      return {
        ready: all.length > 0 && all.every((st) => Object.values(st.streams).every((s) => s.settled)),
        down,
        active: all.some((st) => [...st.data.stages.values()].some((s) => isActivePromotion(s.status?.currentPromotion))),
        streams: all.length * KINDS.length,
        reconnects,
      };
    },
  };
}
