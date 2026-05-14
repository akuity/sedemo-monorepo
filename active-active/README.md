# active-active app

Source application for the [active-active Kargo demo](https://github.com/akuity/sedemo-platform/tree/main/apps/active-active/kargo).

A simple Go web app that displays a colored tile — the color changes with each image tag, making it easy to visually confirm which version is running in each region. The app is a fork of the [argoproj/rollouts-demo](https://github.com/argoproj/rollouts-demo) image.

## Image

Published to: `ghcr.io/akuity/sedemo-monorepo-active-active`

Tags follow the pattern `^\d*-[a-z]*$` (e.g. `218-yellow`, `219-blue`). The Kargo warehouse uses `NewestBuild` strategy with a discovery limit of 5.

## Releasing

```bash
./release.sh
```

Or via GitHub Actions on push to `main`.

## Kargo Demo

This app is deployed by the active-active pipeline which demonstrates:
- Parallel multi-region dev deployments with a convergence gate
- ServiceNow change management lifecycle across `approve` and `close` stages
- Sequential prod rollout with soak times between regions

See [sedemo-platform/apps/active-active/kargo/README.md](https://github.com/akuity/sedemo-platform/tree/main/apps/active-active/kargo/README.md) for the full pipeline documentation.
