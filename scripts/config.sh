#!/usr/bin/env bash

phase1_services=(
  "identity-service"
  "employee-registry"
  "runtime"
  "capability-gateway"
  "capability-registry"
  "audit-service"
)

required_dirs=(
  "apps/api-gateway"
  "api/openapi/v1"
  "apps/web-console"
  "docs/api"
  "sdk/typescript/src/types"
  "services/agent-registry"
  "services/identity"
  "services/scheduler"
  "services/workforce-orchestrator"
  "packages/contracts"
  "packages/shared"
  "infra/docker"
)
