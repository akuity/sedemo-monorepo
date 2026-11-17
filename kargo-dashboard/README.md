# Kargo Dashboard

This project is a lightweight Node.js app that summarizes the current state of Kargo powered projects, specifically visualizing the currently deployed version of several projects across their environments.

## Visualization

- Project names are the y-axis row names
- A project that uses several warehouses is still one row, split into one lane (sub-row) per warehouse, each labeled with its warehouse name (see [Configuration](#configuration))
- Each lane may have an inconsistent number of cells, tied to the number of stages in that pipeline
- Order of cells in a row matches the dependencies defined by Kargo Stages
- Individual cells show the version of that project deployed to that stage
- Cell color is a visual indicator of the version decay (more below in Version Decay)
- The first column in every lane is the latest freight version of that lane's warehouse
- Several dashboards can be defined; the dashboard name in the page heading is a picker, and each dashboard has its own URL (see [Dashboards](#dashboards))
- A stage that has a promotion in progress turns blue and pulses, and shows the step it is on (see [Promotions in progress](#promotions-in-progress))

The visual is agnostic to stage names: there are no stage-name columns and rows are not aligned by name. Each lane is simply one warehouse's pipeline, left to right. The stage name appears as a small caption inside its cell.

Stages with no promotion steps ("control flow" stages) never hold Freight, so they are not drawn, though they still count when ordering the pipeline.

## Requirements

- Node.js 22 or later
- A Kargo API token with read access to each configured project (see [API token](#api-token))
- Customizations and settings live in `config.json`
- "Version" is determined from the warehouse's subscriptions:
  1. The first subscription that is an `image` or a `chart`: the image `Tag`, or the chart `version`, of the matching artifact in the Freight.
  2. Only if the warehouse has neither: the short (7 character) SHA of the first `git` subscription's commit.

## Promotions in progress

Each stage card checks whether a promotion is running. While one is:

- the card turns the promotion color (default blue) and gives a gentle heartbeat pulse
- the version line shows `current → target`, and each version links to its Freight
- the status line summarizes the step, e.g. `● 5 of 7: helm-template`

Some steps block until a person acts. When the current step matches `promotion.waitingStepPattern` (default `wait-for|^get-user-input$`: any `wait-for` step such as `wait-for-approval`, `git-wait-for-pr` or `snow-wait-for-condition`, plus the `get-user-input` form step) the card turns purple, pulses slowly, and reads `⏸ Waiting for input · 7 of 7: wait-for-approval`, so it is clear someone needs to respond.

Steps advance on screen as Kargo reports them (the page is pushed every change, see "How updates work"). Animation is off for visitors who prefer reduced motion and when `promotion.animate` is `false`; the color, the ●/⏸ marker and the text still carry the state.

Only a **running** promotion is shown. Promotions queued behind another one are not. A promotion deploys one Freight per warehouse the stage requests, so a running promotion appears in every lane whose warehouse is part of it, each lane showing its own incoming version. The step summary links to the promotion's own page in Kargo (`/project/<project>/promotion/<promotion-name>`), which is where approval and input prompts are answered. The stage name still links to the stage, and each version to its Freight.

## Dashboards

A config can define several named dashboards, each with its own list of projects. The dashboard name in the page heading is a picker (shown only when there is more than one dashboard), and the URL is the state:

| URL | Shows |
|---|---|
| `/` | the dashboard named by `defaultDashboard` |
| `/d/<id>` | the dashboard with that key (shareable, bookmarkable; Back and Forward work) |
| `/d/<unknown>` | a 404 page that links to the default |

A project listed on several dashboards is watched in Kargo once, so adding dashboards does not multiply API calls or Kargo connections.

## Version Decay

Version decay is a visual indicator of idle inventory; meaning versions built but not yet delivered into higher environments. The greater the count of freight objects between latest freight and currently deployed, the higher the considered "decay" to be.

Essentially this is the measure of how far out of date any environment or stage is. Only Freight from the lane's own warehouse is counted, so each lane has its own decay.

The color scheme is customizable (`decay.thresholds`), and defaults to Good, OK, Bad, Worse:

| Versions behind latest | Label | Meaning |
|---|---|---|
| 0 | Good | up to date |
| 1 | OK | 1 version behind |
| 2 to 3 | Bad | more than 1 and at most 3 behind (exactly 3 is Bad) |
| 4 or more | Worse | more than 3 behind |

A stage with nothing deployed, or whose Freight no longer exists, is shown as Worse with the label "unknown".

Freight, not version strings, is what is counted. A new commit can produce a new Freight that carries the same image tag, so a stage can show the same version as "latest" and still be 1 behind.

## Running

```sh
npm ci
cp config.example.json config.json   # then edit
export KARGO_TOKEN=...               # see "API token"
npm start                            # listens on :8080
```

| Env var | Purpose |
|---|---|
| `CONFIG_PATH` | Config file location (default `./config.json`) |
| `KARGO_URL` | Overrides `kargo.url` from the config |
| `KARGO_TOKEN` | Default API token (the variable name is configurable, see `tokenEnv`) |
| `PORT` | HTTP port (default `8080`) |

Endpoints: `/` and `/d/<id>` (the page), `/api/dashboards` (id, name and default flag for each dashboard), `/api/summary?dashboard=<id>` (the JSON behind a dashboard; the default when omitted), `/api/stream?dashboard=<id>` (the same JSON as server-sent events, pushed on every change; this is what the page uses), `/healthz` (503 until the first load from Kargo completes).

Docker: `docker build -t kargo-dashboard .`, then run it with the config mounted at `/app/config.json` and the token passed as an environment variable. The image is published as `ghcr.io/akuity/sedemo-monorepo-kargo-dashboard` by `.github/workflows/publish-kargo-dashboard.yml`.

Tests: `npm test` runs the unit tests. The tests under `test/fixtures` are scrubbed responses captured from a live Kargo API. `npm run test:e2e` drives the real server in Chrome against a fake Kargo API built on those fixtures (dashboard switching, promotion cards, reduced motion). It needs Chrome; set `CHROME_PATH` if it is not in a standard location.

## Configuration

See [`config.example.json`](config.example.json).

- `kargo.url`: the Kargo instance (or `KARGO_URL`)
- `kargo.tokenEnv`: name of the env var holding the API token (default `KARGO_TOKEN`)
- `refreshIntervalSeconds`, `idlePauseSeconds` and `promotion.activeRefreshIntervalSeconds` are **deprecated and ignored**: nothing polls any more. They are still accepted (with a startup warning) so an old config keeps starting
- `decay.thresholds`: ascending list of `{ max, label, color }`, where `max` is the highest "versions behind" count the entry covers. Only the last entry may (and must) have `max: null`
- `defaultDashboard`: the dashboard `/` shows. Required when there is more than one dashboard
- `dashboards`: a map of dashboard id to `{ name, projects }`. The id appears in URLs (`a-z`, `0-9` and dashes) and the key order is the picker order. `name` is required
- `promotion`: optional promotion-card settings, all with defaults
  - `color` (`#1e6fd9`) and `waitingColor` (`#7b1fa2`): `#rrggbb` card colors
  - `waitingStepPattern` (`wait-for|^get-user-input$`): a regex tested against the current step's type
  - `animate` (`true`): set `false` to turn the pulse off
- Each dashboard's `projects` is a map (key order is display order), with individual values:
  - `displayName`: optional label
  - `warehouse`: show one warehouse (by name). A single lane with no warehouse caption
  - `warehouses`: a list of warehouse names; each becomes its own lane inside the project's row, in list order, with its name as a caption. Use either `warehouse` or `warehouses`, not both
  - With neither, every warehouse the project has becomes a lane (sorted by name). A project with a single warehouse is a single lane with no caption
  - `tokenEnv`: optional per-project token variable, overriding `kargo.tokenEnv`. A project listed on several dashboards must use the same token everywhere
  - `excludeStages`: stages to exclude (regex if prefixed with `regex:`, or full match otherwise)
  - `includeStages`: stages to include (regex if prefixed with `regex:`, or full match otherwise)
  - Stages will first consider all includes, and then remove any excludes. Absence of defined includes will include all, and then apply excludes if any. Regexes are unanchored, so add `^` and `$` where needed.

The same project may appear on several dashboards with different `displayName`, warehouses or stage filters.

**Legacy format.** A top-level `projects` map (the format before dashboards) still works. It becomes one dashboard with id `default` named "Kargo Dashboard", and a deprecation warning is logged at startup. To migrate, move it under `dashboards.<id>.projects` and give the dashboard a `name`. Setting both `projects` and `dashboards` is an error.

A project that fails as a whole (no token access, no warehouses) shows an error row. A misspelled name in `warehouses` shows an error in just that lane. If a project's Freight can't be read, every lane of that project shows the error (Freight is one request per project), while its stages still render. Either way the other projects and lanes still render. `includeStages` and `excludeStages` apply to every lane of a project.

## API token

The dashboard only reads. The token's role needs `get`, `list` and `watch` on `warehouses`, `stages` and `freight` in each project (`watch` is new: the dashboard follows Kargo's change streams). A token that can only list projects authenticates but gets `403 ... list is not permitted` on everything else.

Kargo's API describes both project-level tokens (`POST /v1beta1/projects/{project}/roles/{role}/api-tokens`) and system-level tokens (`POST /v1beta1/system/roles/{role}/api-tokens`). If one token can't cover every project, create one per project and point each project at its variable with `tokenEnv`. The token is only ever read from the environment; it is never written to the config, logs or error messages.

# Resources

## Kargo Concepts

- Freight is an immutable tuple representing container images and supporting git configuration
- Stages define promotions into specific targets
- Promotion is an instance of moving freight into a target
- Warehouses define the source repositories and registries as subscriptions.
- Projects is the container for a pipeline or promotion flow where Warehouse, Freight, Stages, etc live.

## Kargo API

Kargo's API should expose all needed data. i.e. latest freight, what version is in each stage.

This app uses the Kargo REST API (`/v1beta1`) and **requires Kargo 1.12 or later**, which serves change streams on the same endpoints (`?watch=true`, server-sent events). For each project it makes one list call per kind and then keeps one stream open per kind (three streams per project, shared by every dashboard that shows it):

- `GET /v1beta1/projects/{project}/warehouses`, then `...?watch=true&resourceVersion=<from the list>`
- `GET /v1beta1/projects/{project}/stages` (all of the project's stages; each lane picks those that request its warehouse), then the same with `watch=true`
- `GET /v1beta1/projects/{project}/freight` (with `origins=<warehouse>` for each warehouse a dashboard names; none when a dashboard wants every warehouse), then the same with `watch=true`
- `GET /v1beta1/projects/{project}/promotions/{name}` (only for a promotion seen running, once; its steps are cached)

Starting each stream from the list's `resourceVersion` means Kargo sends only changes, not a replay. Kargo sends a keepalive every 30s, so an idle dashboard receives a few bytes a minute. A stream that goes quiet for 90s is dropped and resumed; failures retry with backoff (1s doubling to 60s). If a `resourceVersion` expires the project is listed again. While a project is unreachable the page keeps showing its last data, and after 2 minutes a banner names the project.

## How updates work

```
Kargo --(list, then watch)--> store --(debounced 250ms)--> summarize --> /api/stream --> browsers
```

The server mirrors each project's warehouses, stages and Freight in memory from the watch streams. On a change it rebuilds the dashboards and pushes only the ones whose content changed to the browsers viewing them, so a change shows up within about a second. The browser opens one `EventSource` and re-renders on each event. It never polls.

Every 10 minutes the server logs `kargo rx: <bytes> in last 10m (<n> streams, <r> reconnects)`, the bytes received from Kargo's watch streams, for comparing against network metrics.

A stage's running promotion comes from `status.currentPromotion` on the stage; its step list comes from the Promotion's `spec.steps` (already expanded from any PromotionTasks) and the live step from `status.currentStep`.

The current version of a stage comes from `status.freightHistory[0].items["Warehouse/{warehouse}"]`.
