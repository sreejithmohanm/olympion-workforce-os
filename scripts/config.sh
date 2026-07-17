#!/usr/bin/env bash

phase1_services=(
  "api-gateway"
  "agent-registry"
  "identity"
  "scheduler"
  "workforce-orchestrator"
)

required_dirs=(
  "apps/api-gateway"
  "apps/web-console"
  "services/agent-registry"
  "services/identity"
  "services/scheduler"
  "services/workforce-orchestrator"
  "packages/contracts"
  "packages/shared"
  "infra/docker"
)
