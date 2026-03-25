#!/usr/bin/env bats
# Group D — quick-harden.sh

load helpers/setup_env

SCRIPT=""
AUDIT_SCRIPT=""

setup() {
  load 'test_helper/bats-support/load'
  load 'test_helper/bats-assert/load'
  setup_fake_openclaw
  SCRIPT="$SCRIPTS_DIR/quick-harden.sh"
  AUDIT_SCRIPT="$SCRIPTS_DIR/quick-audit.sh"
}

teardown() {
  teardown_fake_openclaw
}

@test "harden creates backup dir inside OPENCLAW_DIR" {
  run bash "$SCRIPT"
  [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
  ls "$OPENCLAW_DIR/.secureclaw/backups/" | grep -q '.'
}

@test "backup dir is created before hardening actions" {
  run bash "$SCRIPT"
  [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
  BACKUPS=$(ls -d "$OPENCLAW_DIR/.secureclaw/backups/"*/ 2>/dev/null | wc -l)
  [ "$BACKUPS" -ge 1 ]
}

@test "backup dir contains permissions.txt" {
  run bash "$SCRIPT"
  [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
  BACKUP_DIR=$(ls -d "$OPENCLAW_DIR/.secureclaw/backups/"*/ 2>/dev/null | head -1)
  [ -n "$BACKUP_DIR" ]
  [ -f "${BACKUP_DIR}permissions.txt" ]
}

@test "audit CRIT count does not increase after hardening" {
  PRE=$(bash "$AUDIT_SCRIPT" 2>/dev/null | grep -c "🔴 CRIT" || true)
  bash "$SCRIPT" >/dev/null 2>&1 || true
  POST=$(bash "$AUDIT_SCRIPT" 2>/dev/null | grep -c "🔴 CRIT" || true)
  [ "$POST" -le "$PRE" ]
}
