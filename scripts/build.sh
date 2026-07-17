#!/usr/bin/env bash
set -euo pipefail

grep -q "api-gateway:" docker-compose.yml
grep -q "agent-registry:" docker-compose.yml
grep -q "identity:" docker-compose.yml
grep -q "scheduler:" docker-compose.yml
grep -q "workforce-orchestrator:" docker-compose.yml

echo "Build checks passed."
