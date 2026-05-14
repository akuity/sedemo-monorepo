# rollouts-app

Source application for the [demo-rollouts Kargo pipeline](https://github.com/akuity/sedemo-platform/tree/main/apps/demo-rollouts/kargo) and the [templated-teams](https://github.com/akuity/sedemo-platform/tree/main/templated-teams) demos.

A simple Go web app that displays a colored tile. The color changes with each image tag, making it easy to visually confirm canary weight shifts and multi-region rollouts during live demos.

## Image

Published to: `ghcr.io/akuity/sedemo-monorepo-rollouts-app`

Tags follow the pattern `^\d*-[a-z]*$` (e.g. `218-yellow`, `219-blue`).

## Releasing

```bash
./release.sh
```

Or via GitHub Actions — see [`.github/workflows/publish-rollouts-app.yml`](../.github/workflows/publish-rollouts-app.yml).

## Used By

| Demo | Pipeline |
|------|----------|
| demo-rollouts | dev → staging (PR approval) → prod (multi-region: amer-east, amer-west, emea) with Jira change management |
| templated-teams | each team gets dev → staging → prod with PR-based approval and optional Argo Rollouts canary |
