# CI/CD Pipeline Standards

Owner: Developer Experience

## Pipeline stages

Every service pipeline runs lint, unit tests, dependency scanning, container
build, and integration tests in that order. Failed stages do not block
subsequent stages from being skipped, but they block deployment.

## Artifact integrity

Container images are signed with Sigstore and carry an SBOM attestation.
Production deploys reject unsigned images and images older than 14 days.

## Deployment policy

Progressive delivery uses 5% canary traffic for ten minutes, followed by a
25% step and then full rollout. Automated rollback triggers on error-rate or
latency regressions.

## Retention

Build logs are retained for 90 days. Release artifacts are retained for one
year. Secrets are never written to build logs.
