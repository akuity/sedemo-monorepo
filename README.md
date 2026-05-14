# SE Demo Monorepo

This repo houses the custom applications used by Akuity teams in customer demos. Each subdirectory is either a deployable app or a supporting config directory.

## Applications

| Directory | Image | Used By |
|-----------|-------|---------|
| [`rollouts-app`](rollouts-app/) | `ghcr.io/akuity/sedemo-monorepo-rollouts-app` | [demo-rollouts](https://github.com/akuity/sedemo-platform/tree/main/apps/demo-rollouts/kargo), [templated-teams](https://github.com/akuity/sedemo-platform/tree/main/templated-teams) |
| [`active-active`](active-active/) | `ghcr.io/akuity/sedemo-monorepo-active-active` | [active-active](https://github.com/akuity/sedemo-platform/tree/main/apps/active-active/kargo) |
| [`verification-snow-demo`](verification-snow-demo/) | `ghcr.io/akuity/sedemo-monorepo-snow-demo` | [demo-snow](https://github.com/akuity/sedemo-platform/tree/main/apps/demo-snow/kargo) |
| [`beyond-k8s/lambda-app`](beyond-k8s/lambda-app/) | ECR: `sedemo/beyond-k8s-lambda` | [beyond-k8s](https://github.com/akuity/sedemo-platform/tree/main/apps/beyond-k8s/kargo) |
| [`beyond-k8s/fargate`](beyond-k8s/fargate/) | `ghcr.io/akuity/sedemo-monorepo-fargate-app` | [beyond-k8s](https://github.com/akuity/sedemo-platform/tree/main/apps/beyond-k8s/kargo) |

## Special Directories

### `templated`

Each subdirectory spawns a dedicated Kargo project with dev → staging → prod stages. The platform team controls the Helm chart and pipeline; app teams supply a `platform/app-values.yaml` with their image and config. See [`templated/README.md`](templated/README.md) for requirements.

### `beyond-k8s`

Contains the Fargate app, Lambda app, and supporting config/env directories for the beyond-k8s demo. See [`beyond-k8s/env/README.md`](beyond-k8s/env/README.md) for AWS account and ECR details.

## Platform Repo

All Kargo pipeline definitions, Argo CD ApplicationSets, and cluster configuration live in [sedemo-platform](https://github.com/akuity/sedemo-platform).
