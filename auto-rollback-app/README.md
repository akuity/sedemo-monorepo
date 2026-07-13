# Auto-Rollback

This uses upstream images from https://github.com/argoproj/rollouts-demo, but with a simple deployment.yaml that does not itself use progressive release.

Instead a Kargo verification runs after the "big bang" deploy to measure health.

If verification fails Kargo will be responsible to re-deploy last healthy freight.