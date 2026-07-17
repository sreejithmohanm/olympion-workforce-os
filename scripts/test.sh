#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/config.sh"

for dir in "${required_dirs[@]}"; do
  [[ -d "$dir" ]] || { echo "Missing required directory: $dir"; exit 1; }
done

echo "Structure tests passed."
