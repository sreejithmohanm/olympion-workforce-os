#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "$0")/.." && pwd)"
spec_path="${root_dir}/api/openapi/v1/openapi.yaml"
docs_path="${root_dir}/docs/api/v1.html"
types_path="${root_dir}/sdk/typescript/src/types/v1.ts"
redocly_version="2.39.0"
openapi_typescript_version="7.13.0"

run_redocly() {
  npx --yes "@redocly/cli@${redocly_version}" "$@"
}

run_openapi_typescript() {
  npx --yes "openapi-typescript@${openapi_typescript_version}" "$@"
}

generate_artifacts() {
  mkdir -p "$(dirname "$docs_path")" "$(dirname "$types_path")"
  run_redocly build-docs "$spec_path" --output="$docs_path" --title="Olympion Workforce OS Phase 1 API"
  run_openapi_typescript "$spec_path" --output "$types_path"
}

check_artifacts() {
  local tmp_dir
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT

  run_redocly build-docs "$spec_path" --output="${tmp_dir}/v1.html" --title="Olympion Workforce OS Phase 1 API" >/dev/null
  run_openapi_typescript "$spec_path" --output "${tmp_dir}/v1.ts" >/dev/null

  cmp -s "$docs_path" "${tmp_dir}/v1.html" || {
    echo "Generated API docs are out of date. Run ./scripts/openapi.sh generate"
    exit 1
  }

  cmp -s "$types_path" "${tmp_dir}/v1.ts" || {
    echo "Generated TypeScript types are out of date. Run ./scripts/openapi.sh generate"
    exit 1
  }
}

case "${1:-}" in
  lint)
    run_redocly lint "$spec_path"
    ;;
  generate)
    generate_artifacts
    ;;
  check-generated)
    check_artifacts
    ;;
  *)
    echo "Usage: $0 {lint|generate|check-generated}"
    exit 1
    ;;
esac
