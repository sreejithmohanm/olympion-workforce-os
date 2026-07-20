#!/usr/bin/env bash
set -euo pipefail

required_files=(
  "README.md"
  "Architecture_Realignment.md"
  ".github/workflows/ci.yml"
  "docker-compose.yml"
  ".gitignore"
  "LICENSE"
  ".github/CODEOWNERS"
  "api/openapi/v1/openapi.yaml"
  "docs/api/v1.html"
  "sdk/typescript/src/types/v1.ts"
)

for file in "${required_files[@]}"; do
  [[ -f "$file" ]] || { echo "Missing required file: $file"; exit 1; }
done

./scripts/openapi.sh lint

echo "Lint checks passed."
