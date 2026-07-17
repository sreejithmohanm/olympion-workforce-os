#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/config.sh"

for service in "${phase1_services[@]}"; do
  grep -q "${service}:" docker-compose.yml
done

echo "Build checks passed."
