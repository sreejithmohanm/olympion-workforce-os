#!/usr/bin/env bash
set -euo pipefail

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

for dir in "${required_dirs[@]}"; do
  [[ -d "$dir" ]] || { echo "Missing required directory: $dir"; exit 1; }
done

echo "Structure tests passed."
