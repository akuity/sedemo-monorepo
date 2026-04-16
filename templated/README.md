# Templated Example

All sub-folders in this directory will spawn a dedicated Kargo workflow and set of 3 applications (dev, staging, prod).

The source of the kargo workflow is a [helm chart](https://github.com/akuity/sedemo-platform/tree/main/templated-teams/kargo-chart) in the platform team repo.

The source of the k8s manifests is also [in the platform repo](https://github.com/akuity/sedemo-platform/tree/main/templated-teams/apps-chart)

Both are triggered by [Application Sets](https://github.com/akuity/sedemo-platform/tree/main/templated-teams) using the Git Generator.

- The kargo workflow project will match directory name. 
- The directory must contain a `platform/app-values.yaml` file with location of docker image registry
- The app-values may also specify a custom domain prefix to expose on akpdemoapps.link (stage.prefix.akpdemoapps.link)
- The app-values may disable Argo Rollouts (TODO)