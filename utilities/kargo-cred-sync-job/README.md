# Kargo Credential Job

This image is used as a `PostSync` hook by templated apps to grant the Kargo warehouse and stages credentials to our GH repo and registry.

## Secrets

This script depends on secrets created by ESO (external secrets operator) in the `kargo-secrets-namespace` namespace which can be found in the [platform repo - secrets](https://github.com/akuity/sedemo-platform/tree/main/secrets) folder.

Environment Variables
- $KARGO_PASSWORD --> kargo-admin-creds
- $GITHUB_PAT --> gh-image-creds


## Invocation / Execution

This image is used by a job defined for templated apps in the [platform repo - templated teams](https://github.com/akuity/sedemo-platform/tree/main/templated-teams/project-templates/templates) folder.