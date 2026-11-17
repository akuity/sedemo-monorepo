// Thin wrapper over the Kargo REST API (/v1beta1). The only module that does network I/O.
// Returns plain objects; no business logic. Tokens are passed per call and never logged.
import { parseSSE } from './sse.js';

const TIMEOUT_MS = 10_000;
// A watch with no replay (it starts from a list's resourceVersion) sends nothing until Kargo's first keepalive,
// which is up to 30s away, and a proxy in front of Kargo may hold the response headers until then. So the wait
// for a watch's headers must be longer than the keepalive interval. (Found against a live Kargo: 10s here made
// every seeded watch time out and retry forever.)
const WATCH_CONNECT_TIMEOUT_MS = 60_000;

export class KargoApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'KargoApiError';
    this.status = status;
  }
}

// An `event: error` frame on a watch stream. `code` is the Connect code, e.g. 'out_of_range' when the
// resourceVersion has expired (the caller must re-list).
export class KargoWatchError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'KargoWatchError';
    this.code = code;
  }
}

// `fetchImpl` is injectable for tests.
export function createKargoClient({ url, fetchImpl = fetch, timeoutMs = TIMEOUT_MS, watchConnectTimeoutMs = WATCH_CONNECT_TIMEOUT_MS }) {
  const base = url.replace(/\/+$/, '');
  const stats = { bytes: 0 }; // bytes received from Kargo, for the periodic log line

  async function request(path, token, project, { accept, signal, connectMs = timeoutMs }) {
    const connect = new AbortController();
    const timer = setTimeout(() => connect.abort(new DOMException('timeout', 'TimeoutError')), connectMs);
    const signals = [connect.signal, ...(signal ? [signal] : [])];
    let res;
    try {
      res = await fetchImpl(`${base}${path}`, {
        headers: { Authorization: `Bearer ${token}`, Accept: accept },
        signal: AbortSignal.any(signals),
      });
    } catch (err) {
      const timedOut = err.name === 'TimeoutError' || connect.signal.reason?.name === 'TimeoutError' && connect.signal.aborted;
      throw new KargoApiError(`request failed: ${timedOut ? `timed out after ${connectMs}ms` : err.message}`, 0);
    } finally {
      clearTimeout(timer); // for a watch only the wait for response headers is bounded; the stream itself is open-ended
    }
    if (res.status === 401 || res.status === 403) {
      throw new KargoApiError(`token lacks access to project ${project}`, res.status);
    }
    if (!res.ok) {
      throw new KargoApiError(`Kargo API returned HTTP ${res.status} for project ${project}`, res.status);
    }
    return { res };
  }

  async function get(path, token, project) {
    const { res } = await request(path, token, project, { accept: 'application/json' });
    let body;
    try {
      body = await res.json();
    } catch (err) {
      const reason = err.name === 'TimeoutError' ? `timed out after ${timeoutMs}ms` : err.message;
      throw new KargoApiError(`request failed: ${reason}`, 0);
    }
    return body;
  }

  const projectPath = (project) => `/v1beta1/projects/${encodeURIComponent(project)}`;

  async function* countBytes(stream) {
    for await (const chunk of stream) {
      stats.bytes += chunk.length;
      yield chunk;
    }
  }

  return {
    // Bytes received from watch streams so far (lists are small by comparison and are not counted).
    bytesReceived: () => stats.bytes,

    // Lists return { items, resourceVersion }. The resourceVersion seeds a follow-up watch.
    async listWarehouses(project, token) {
      const body = await get(`${projectPath(project)}/warehouses`, token, project);
      return { items: body.items || [], resourceVersion: body.metadata?.resourceVersion || '' };
    },

    // All of the project's stages; callers pick the ones that request a given warehouse.
    async listStages(project, token) {
      const body = await get(`${projectPath(project)}/stages`, token, project);
      return { items: body.items || [], resourceVersion: body.metadata?.resourceVersion || '' };
    },

    // Freight for the given warehouses (all of the project's when `origins` is empty), in ONE call.
    // Comes back grouped under keys that are undocumented without groupBy, so flatten every group
    // and de-duplicate by name.
    async listFreight(project, { origins = [] } = {}, token) {
      const q = origins.map((o) => `origins=${encodeURIComponent(o)}`).join('&');
      const body = await get(`${projectPath(project)}/freight${q ? `?${q}` : ''}`, token, project);
      const seen = new Set();
      const items = [];
      for (const group of Object.values(body.groups || {})) {
        for (const f of group.items || []) {
          if (!seen.has(f.metadata.name)) {
            seen.add(f.metadata.name);
            items.push(f);
          }
        }
      }
      return { items, resourceVersion: body.resourceVersion || '' };
    },

    // One Promotion, for its (already expanded) steps and live status.
    async getPromotion(project, name, token) {
      return get(`${projectPath(project)}/promotions/${encodeURIComponent(name)}`, token, project);
    },

    // Watches `kind` ('warehouses' | 'stages' | 'freight') in a project over SSE (Kargo >= 1.12).
    // Async iterator yielding { type: 'ADDED'|'MODIFIED'|'DELETED', object } for changes and
    // { keepalive: true } for keepalive comments (so callers can detect a stalled stream).
    // `query` is a list of extra [key, value] pairs, e.g. [['origins', 'wh']].
    // Ends when the server closes the stream; throws KargoWatchError for an `event: error` frame
    // and KargoApiError for HTTP errors or a response that is not text/event-stream.
    async* watch(project, kind, { token, query = [], resourceVersion = '', signal } = {}) {
      const params = [['watch', 'true'], ...query];
      if (resourceVersion) params.push(['resourceVersion', resourceVersion]);
      const qs = params.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
      const { res } = await request(`${projectPath(project)}/${kind}?${qs}`, token, project, { accept: 'text/event-stream', signal, connectMs: watchConnectTimeoutMs });
      const type = res.headers?.get?.('content-type') || '';
      if (!type.startsWith('text/event-stream')) {
        try { await res.body?.cancel?.(); } catch { /* best effort */ }
        throw new KargoApiError('Kargo >= 1.12 with REST watch support is required (the server did not return text/event-stream)', res.status);
      }
      try {
        for await (const frame of parseSSE(countBytes(res.body))) {
          if (frame.comment !== undefined) { yield { keepalive: true }; continue; }
          let payload;
          try { payload = JSON.parse(frame.data); } catch { throw new KargoWatchError(`unreadable ${frame.event} frame`, 'unknown'); }
          if (frame.event === 'error') throw new KargoWatchError(payload.message || 'watch error', payload.code || 'unknown');
          if (payload.type && payload.object) yield { type: payload.type, object: payload.object };
        }
      } catch (err) {
        if (err instanceof KargoWatchError || err instanceof KargoApiError) throw err;
        if (signal?.aborted) throw err;
        throw new KargoApiError(`stream failed: ${err.message}`, 0);
      }
    },
  };
}
