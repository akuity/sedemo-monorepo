import { readFileSync } from 'node:fs';
import { compilePattern } from './stage-filter.js';

export const DEFAULT_THRESHOLDS = [
  { max: 0, label: 'Good', color: '#2e7d32' },
  { max: 1, label: 'OK', color: '#fdd835' },
  { max: 3, label: 'Bad', color: '#fb8c00' },
  { max: null, label: 'Worse', color: '#c62828' },
];

const DEFAULT_TOKEN_ENV = 'KARGO_TOKEN';

function validateThresholds(thresholds) {
  if (!Array.isArray(thresholds) || thresholds.length === 0) {
    throw new Error('decay.thresholds must be a non-empty array');
  }
  let prev = -1;
  thresholds.forEach((t, i) => {
    const last = i === thresholds.length - 1;
    if (t.max === null) {
      if (!last) throw new Error('decay.thresholds: only the last entry may have max null');
    } else {
      if (!Number.isInteger(t.max) || t.max < 0) {
        throw new Error(`decay.thresholds[${i}].max must be a non-negative integer`);
      }
      if (t.max <= prev) throw new Error('decay.thresholds: max values must be strictly ascending');
      prev = t.max;
    }
    if (typeof t.color !== 'string' || typeof t.label !== 'string') {
      throw new Error(`decay.thresholds[${i}] needs string label and color`);
    }
  });
  if (thresholds[thresholds.length - 1].max !== null) {
    throw new Error('decay.thresholds: the last entry must have max null');
  }
}

function validatePatterns(name, patterns) {
  if (patterns === undefined) return [];
  if (!Array.isArray(patterns)) throw new Error(`${name} must be an array`);
  patterns.forEach(compilePattern); // throws on non-strings and bad regexes
  return patterns;
}

// Normalises the warehouse selection for a project.
// `warehouse: "x"` -> { warehouses: ["x"], plural: false }
// `warehouses: [..]` -> { warehouses: [..], plural: true }
// neither -> { warehouses: [], plural: false }, meaning "every warehouse the project has".
function parseWarehouses(label, value) {
  const hasOne = value.warehouse !== undefined;
  const hasMany = value.warehouses !== undefined;
  if (hasOne && hasMany) {
    throw new Error(`${label}: set either warehouse or warehouses, not both`);
  }
  if (hasOne) {
    if (typeof value.warehouse !== 'string' || !value.warehouse) {
      throw new Error(`${label}.warehouse must be a non-empty string`);
    }
    return { warehouses: [value.warehouse], plural: false };
  }
  if (hasMany) {
    const list = value.warehouses;
    if (!Array.isArray(list) || list.length === 0) {
      throw new Error(`${label}.warehouses must be a non-empty array`);
    }
    if (list.some((w) => typeof w !== 'string' || !w)) {
      throw new Error(`${label}.warehouses must contain only non-empty strings`);
    }
    if (new Set(list).size !== list.length) {
      throw new Error(`${label}.warehouses contains duplicates`);
    }
    return { warehouses: [...list], plural: true };
  }
  return { warehouses: [], plural: false };
}

export const DEFAULT_PROMOTION = {
  color: '#1e6fd9',
  waitingColor: '#7b1fa2',
  // Steps that block on a person: any `wait-for` step, plus the get-user-input form step.
  waitingStepPattern: 'wait-for|^get-user-input$',
  animate: true,
};

const HEX_COLOR = /^#[0-9a-f]{6}$/i;
const DASHBOARD_ID = /^[a-z0-9][a-z0-9-]{0,62}$/;

// Section 14.4. Returns the promotion settings with defaults applied.
function parsePromotion(raw = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('promotion must be an object');
  const p = { ...DEFAULT_PROMOTION, ...raw };
  for (const k of ['color', 'waitingColor']) {
    if (typeof p[k] !== 'string' || !HEX_COLOR.test(p[k])) throw new Error(`promotion.${k} must be a #rrggbb color`);
  }
  try {
    new RegExp(p.waitingStepPattern); // eslint-disable-line no-new
  } catch (err) {
    throw new Error(`promotion.waitingStepPattern is not a valid regex: ${err.message}`);
  }
  if (typeof p.animate !== 'boolean') throw new Error('promotion.animate must be true or false');
  return p;
}

// Validates one `projects` map. `label` prefixes error messages ("projects" or "dashboards.<id>.projects").
// Object key order is preserved, which is the display order.
function parseProjects(rawProjects, label, kargo, env) {
  if (!rawProjects || typeof rawProjects !== 'object' || Array.isArray(rawProjects) ||
      Object.keys(rawProjects).length === 0) {
    throw new Error(`${label} must be a non-empty object`);
  }
  const projects = {};
  for (const [key, value] of Object.entries(rawProjects)) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error(`${label}.${key} must be an object`);
    }
    const tokenEnv = value.tokenEnv || kargo.tokenEnv;
    projects[key] = {
      displayName: value.displayName || key,
      ...parseWarehouses(`${label}.${key}`, value),
      tokenEnv,
      includeStages: validatePatterns(`${label}.${key}.includeStages`, value.includeStages),
      excludeStages: validatePatterns(`${label}.${key}.excludeStages`, value.excludeStages),
    };
    if (!env[tokenEnv]) {
      throw new Error(`env var ${tokenEnv} (token for project ${key}) must be set and non-empty`);
    }
  }
  return projects;
}

// Section 15.2. Returns { dashboards, defaultDashboard, warnings }. A legacy top-level `projects`
// becomes one dashboard with id "default" and a deprecation warning.
function parseDashboards(raw, kargo, env) {
  const warnings = [];
  if (raw.projects !== undefined && raw.dashboards !== undefined) {
    throw new Error('set either projects (legacy) or dashboards, not both');
  }
  if (raw.dashboards === undefined) {
    if (raw.projects === undefined) throw new Error('dashboards is required');
    warnings.push('top-level "projects" is deprecated; move it under dashboards.<id>.projects with a name');
    return {
      dashboards: {
        default: { id: 'default', name: 'Kargo Dashboard', projects: parseProjects(raw.projects, 'projects', kargo, env) },
      },
      defaultDashboard: 'default',
      warnings,
    };
  }

  const rawDash = raw.dashboards;
  if (!rawDash || typeof rawDash !== 'object' || Array.isArray(rawDash) || Object.keys(rawDash).length === 0) {
    throw new Error('dashboards must be a non-empty object');
  }
  const dashboards = {};
  for (const [id, value] of Object.entries(rawDash)) {
    if (!DASHBOARD_ID.test(id)) {
      throw new Error(`dashboards.${id}: id must match ${DASHBOARD_ID} (lowercase letters, digits and dashes; used in URLs)`);
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`dashboards.${id} must be an object`);
    if (typeof value.name !== 'string' || !value.name.trim()) {
      const hint = id === 'projects' ? ' (did you mean dashboards.<id>.projects?)' : '';
      throw new Error(`dashboards.${id}: missing name${hint}`);
    }
    dashboards[id] = { id, name: value.name, projects: parseProjects(value.projects, `dashboards.${id}.projects`, kargo, env) };
  }

  // A project listed in several dashboards is fetched once, so it must use one token.
  const tokenFor = new Map();
  for (const d of Object.values(dashboards)) {
    for (const [project, pc] of Object.entries(d.projects)) {
      const seen = tokenFor.get(project);
      if (seen && seen.tokenEnv !== pc.tokenEnv) {
        throw new Error(`project ${project} uses tokenEnv ${seen.tokenEnv} in dashboard ${seen.dashboard} but ${pc.tokenEnv} in ${d.id}; use one token per project`);
      }
      if (!seen) tokenFor.set(project, { tokenEnv: pc.tokenEnv, dashboard: d.id });
    }
  }

  const ids = Object.keys(dashboards);
  let defaultDashboard = raw.defaultDashboard;
  if (defaultDashboard === undefined) {
    if (ids.length > 1) throw new Error(`defaultDashboard is required when there are several dashboards (${ids.join(', ')})`);
    defaultDashboard = ids[0];
  } else if (!dashboards[defaultDashboard]) {
    throw new Error(`defaultDashboard "${defaultDashboard}" is not one of the dashboards (${ids.join(', ')})`);
  }
  return { dashboards, defaultDashboard, warnings };
}

// Validates a parsed config object and returns it with defaults applied.
// `env` is injectable for tests.
export function validateConfig(raw, env = process.env) {
  if (!raw || typeof raw !== 'object') throw new Error('config must be a JSON object');

  const kargo = { ...(raw.kargo || {}) };
  kargo.url = env.KARGO_URL || kargo.url;
  if (!kargo.url) throw new Error('kargo.url (or KARGO_URL) is required');
  kargo.url = kargo.url.replace(/\/+$/, '');
  kargo.tokenEnv = kargo.tokenEnv || DEFAULT_TOKEN_ENV;

  const thresholds = raw.decay?.thresholds ?? DEFAULT_THRESHOLDS;
  validateThresholds(thresholds);

  // The page is updated from Kargo watch events (PLAN section 17), so nothing polls any more. The old
  // polling settings are still accepted so an existing config keeps starting, but they do nothing.
  const deprecated = [];
  for (const key of ['refreshIntervalSeconds', 'idlePauseSeconds']) {
    if (raw[key] !== undefined) deprecated.push(key);
  }
  const rawPromotion = raw.promotion && typeof raw.promotion === 'object' && !Array.isArray(raw.promotion) ? { ...raw.promotion } : raw.promotion;
  if (rawPromotion && typeof rawPromotion === 'object' && rawPromotion.activeRefreshIntervalSeconds !== undefined) {
    deprecated.push('promotion.activeRefreshIntervalSeconds');
    delete rawPromotion.activeRefreshIntervalSeconds;
  }

  const promotion = parsePromotion(rawPromotion);
  const { dashboards, defaultDashboard, warnings } = parseDashboards(raw, kargo, env);
  for (const key of deprecated) warnings.push(`${key} is deprecated and ignored: the dashboard now updates from Kargo watch events instead of polling`);
  return { kargo, decay: { thresholds }, promotion, dashboards, defaultDashboard, warnings };
}

export function loadConfig(path = process.env.CONFIG_PATH || './config.json', env = process.env) {
  let raw;
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new Error(`cannot load config ${path}: ${err.message}`);
  }
  return validateConfig(raw, env);
}
