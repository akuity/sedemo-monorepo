# verification-snow-demo

Source application for the [demo-snow Kargo pipeline](https://github.com/akuity/sedemo-platform/tree/main/apps/demo-snow/kargo).

A simple Go web app (same base as rollouts-app) that displays a colored tile. Used to demonstrate ServiceNow change management integration in a multi-region Kargo pipeline.

## Image

Published to: `ghcr.io/akuity/sedemo-monorepo-snow-demo`

Tags follow the pattern `^\d*-[a-z]*$` (e.g. `218-yellow`).

## Releasing

```bash
./release.sh
```

## Kargo Demo

This app is deployed by the demo-snow pipeline which demonstrates:
- Prometheus-based verification at dev, e2e verification at staging
- ServiceNow change request lifecycle at prod: create → wait for Implement → update to Review
- Multi-region fan-out to `prod-amer-east`, `prod-amer-west`, `prod-emea`

See [sedemo-platform/apps/demo-snow/kargo/README.md](https://github.com/akuity/sedemo-platform/tree/main/apps/demo-snow/kargo/README.md) for the full pipeline documentation.
