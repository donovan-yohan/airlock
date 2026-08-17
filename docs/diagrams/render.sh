#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly DOCS_DIR="$(dirname -- "$SCRIPT_DIR")"
readonly OUTPUT_DIR="$DOCS_DIR/assets/diagrams"
readonly MERMAID_CLI_VERSION="11.12.0"

mkdir -p "$OUTPUT_DIR"

if [[ -z "${PUPPETEER_EXECUTABLE_PATH:-}" ]]; then
  for candidate in chromium chromium-browser google-chrome; do
    if command -v "$candidate" >/dev/null 2>&1; then
      export PUPPETEER_EXECUTABLE_PATH="$(command -v "$candidate")"
      export PUPPETEER_SKIP_DOWNLOAD=true
      break
    fi
  done
fi

sources=("$SCRIPT_DIR"/*.mmd)
for source in "${sources[@]}"; do
  name="$(basename -- "$source" .mmd)"
  npx --yes "@mermaid-js/mermaid-cli@$MERMAID_CLI_VERSION" \
    --input "$source" \
    --output "$OUTPUT_DIR/$name.svg" \
    --theme dark \
    --backgroundColor transparent
  read -r digest _ < <(sha256sum "$source")
  svg="$(<"$OUTPUT_DIR/$name.svg")"
  printf '<!-- source-sha256:%s -->\n%s\n' "$digest" "$svg" > "$OUTPUT_DIR/$name.svg"
done

printf 'Rendered %s Mermaid diagram(s) into %s\n' "${#sources[@]}" "$OUTPUT_DIR"
