#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
YAML_FILE="/tmp/devbox-cloud-init-$$.yml"

usage() {
    echo "Usage: $0 [--schema-only | --launch | --help]"
    echo ""
    echo "  --schema-only   Only validate schema (no container)"
    echo "  --launch        Launch Docker container and run cloud-init"
    echo "  --help          Show this help"
    echo ""
    echo "Default: validate schema only"
}

MODE="schema"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --schema-only) MODE="schema"; shift ;;
        --launch) MODE="launch"; shift ;;
        --help) usage; exit 0 ;;
        *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

# Generate cloud-init YAML
echo "Generating cloud-init YAML..."
node "$SCRIPT_DIR/test-cloudinit.mjs" > "$YAML_FILE"
echo "Generated: $YAML_FILE ($(wc -l < "$YAML_FILE") lines)"

# Validate schema
echo ""
echo "Validating cloud-init schema..."
SCHEMA_OUTPUT=$(nix-shell -p cloud-init --run "cloud-init schema -c '$YAML_FILE'" 2>&1 | grep -v "WARNING")
echo "$SCHEMA_OUTPUT"
if ! echo "$SCHEMA_OUTPUT" | grep -q "Valid schema"; then
    echo ""
    echo "Schema errors found. Run for details:"
    echo "  nix-shell -p cloud-init --run 'cloud-init schema -c $YAML_FILE --annotate'"
    exit 1
fi

if [[ "$MODE" == "schema" ]]; then
    echo "Done (schema-only mode). Use --launch to test with Docker."
    rm -f "$YAML_FILE"
    exit 0
fi

# Launch Docker container
echo ""
echo "Running cloud-init in Docker (debian:12)..."
docker run --rm \
    -v "$YAML_FILE":/etc/cloud/cloud.cfg.d/99_user-data.cfg \
    debian:12 \
    bash -c '
        apt-get update -qq && apt-get install -y -qq cloud-init > /dev/null 2>&1
        echo "=== Running cloud-init init ==="
        cloud-init init 2>&1 | tail -5
        echo ""
        echo "=== Running cloud-init modules (config) ==="
        cloud-init modules --mode=config 2>&1 | tail -5
        echo ""
        echo "=== Running cloud-init modules (final) ==="
        cloud-init modules --mode=final 2>&1 | tail -20
        echo ""
        echo "=== Cloud-init status ==="
        cloud-init status --long 2>&1 || true
        echo ""
        echo "=== Checking results ==="
        echo "User dev:"
        id dev 2>/dev/null && echo "  OK" || echo "  MISSING"
        echo ".devbox-ready:"
        ls -la /home/dev/.devbox-ready 2>/dev/null && echo "  OK" || echo "  MISSING"
        echo "Write files:"
        for f in /home/dev/.tmux.conf /home/dev/.claude.json /etc/caddy/Caddyfile.template; do
            printf "  %-40s " "$f"
            test -f "$f" && echo "OK" || echo "MISSING"
        done
    '

rm -f "$YAML_FILE"
echo ""
echo "Done."
