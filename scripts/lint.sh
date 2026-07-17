#!/usr/bin/env bash
set -euo pipefail

required_files=(
  "README.md"
  "Architecture_Realignment.md"
  ".github/workflows/ci.yml"
  "docker-compose.yml"
)

for file in "${required_files[@]}"; do
  [[ -f "$file" ]] || { echo "Missing required file: $file"; exit 1; }
done

echo "Lint checks passed."
