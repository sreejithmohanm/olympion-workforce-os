# Olympion Workforce OS

Workforce OS — AI workforce platform and runtime. Powers every Digital Professional.

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

### 3) Boot Phase 1 local services

```bash
docker compose up -d
docker compose ps
```

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
