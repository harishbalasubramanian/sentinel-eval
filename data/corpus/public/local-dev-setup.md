# Local Development Setup

Owner: Developer Experience

## Prerequisites

Install Docker Desktop, `uv`, and `make`. Clone the monorepo and run
`make bootstrap` to install dependencies and pre-commit hooks.

## Running services

`make up` starts Postgres, Redis, Kafka, and the local Envoy gateway via
Docker Compose. `make seed` loads a small anonymized dataset. `make test`
runs the unit test suite; `make test-integration` requires the service stack.

## Configuration

Local configuration lives in `.env.local`, which is gitignored. Never commit
real credentials. Use the development identity provider seeded by
`make seed-identity` for local SSO flows.

## Troubleshooting

Port conflicts are usually caused by a previous Compose stack. Run
`make down` before restarting. Logs are available via `make logs SERVICE=name`.
