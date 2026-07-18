# Olympion Workforce OS

Workforce OS — AI workforce platform and runtime. Powers every Digital Professional.

## Technology Stack

| Layer | Choice | Notes |
|---|---|---|
| Service language | **Python 3.12** | Type-annotated, async-first |
| Service framework | **FastAPI** | OpenAPI spec auto-generated |
| Package manager | **uv** | Fast Python package resolver |
| Linter / formatter | **Ruff** | Single tool for lint + format |
| Container runtime | **Docker + Docker Compose** | Local and CI parity |
| Task runner | **GNU Make** | Thin wrapper over shell scripts |

All Phase 1 services (`identity-service`, `employee-registry`, `runtime`, `capability-gateway`, `capability-registry`, `audit-service`) follow this stack.

## Monorepo Structure

The repository is initialized according to `./Architecture_Realignment.md`.

## Local Development Setup

### 1) Prerequisites

- Docker + Docker Compose
- GNU Make
- Bash

### 2) Validate repository foundation

```bash
make lint
make test
make build
```

`make test` now runs the repository structure checks plus the identity-service and auth middleware unit/integration test suite.

### 3) Boot Phase 1 local services

```bash
docker compose up -d
docker compose ps
```

Each container publishes a local `/health` endpoint, and all services join the same `workforce-os` network and shared `workforce-os-shared-data` volume for local integration testing.

## Identity Service Reference Implementation

- `services/identity/app.py` exposes `POST /v1/auth/keys` and `POST /v1/auth/token`
- `packages/shared/workforce_os/auth.py` provides reusable JWT validation middleware and tenant-scoping helpers
- `services/scheduler/app.py` demonstrates a protected tenant-scoped endpoint that returns `401` for missing/invalid JWTs and `403` for tenant mismatches

### 4) Stop local services

```bash
docker compose down
```

## CI

CI runs on every pull request and executes:

- `make lint`
- `make test`
- `make build`

## Branch Protection

Enable branch protection for `main` in repository settings:

1. Go to **Settings → Branches**
2. Add a branch protection rule for `main`
3. Require pull request reviews and required status checks (CI)
