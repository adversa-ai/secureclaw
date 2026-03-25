#!/usr/bin/env bash
# Shared test helpers for SecureClaw bats test suite

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts"
CONFIGS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/configs"

setup_fake_openclaw() {
  export OPENCLAW_DIR
  OPENCLAW_DIR="$(mktemp -d)"
  mkdir -p "$OPENCLAW_DIR/workspace/skills"
  mkdir -p "$OPENCLAW_DIR/skills"
  mkdir -p "$OPENCLAW_DIR/extensions"
  echo "soul content"     > "$OPENCLAW_DIR/workspace/SOUL.md"
  echo "identity content" > "$OPENCLAW_DIR/workspace/IDENTITY.md"
  echo "tools content"    > "$OPENCLAW_DIR/workspace/TOOLS.md"
  echo "agents content"   > "$OPENCLAW_DIR/workspace/AGENTS.md"
  echo "security content" > "$OPENCLAW_DIR/workspace/SECURITY.md"
  chmod 700 "$OPENCLAW_DIR"
}

teardown_fake_openclaw() {
  rm -rf "$OPENCLAW_DIR"
}
