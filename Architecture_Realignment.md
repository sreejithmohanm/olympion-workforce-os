# Architecture Realignment

This repository follows a monorepo layout so all Workforce OS services and shared assets can evolve together.

## Repository Structure

```text
.
├── .github/
│   └── workflows/
├── apps/
│   ├── api-gateway/
│   └── web-console/
├── services/
│   ├── agent-registry/
│   ├── identity/
│   ├── scheduler/
│   └── workforce-orchestrator/
├── packages/
│   ├── contracts/
│   └── shared/
├── infra/
│   └── docker/
└── scripts/
```

## Phase 1 Local Services

- `api-gateway`
- `agent-registry`
- `identity`
- `scheduler`
- `workforce-orchestrator`
