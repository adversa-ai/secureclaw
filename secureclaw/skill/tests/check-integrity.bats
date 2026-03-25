#!/usr/bin/env bats
# Group A — check-integrity.sh

load helpers/setup_env

SCRIPT=""

setup() {
  load 'test_helper/bats-support/load'
  load 'test_helper/bats-assert/load'
  setup_fake_openclaw
  SCRIPT="$SCRIPTS_DIR/check-integrity.sh"
}

teardown() {
  teardown_fake_openclaw
}

@test "rebaseline with files in workspace/ creates sha256 files" {
  run bash "$SCRIPT" --rebaseline
  assert_success
  refute_output --partial "No cognitive files found"
  for f in SOUL.md IDENTITY.md TOOLS.md AGENTS.md SECURITY.md; do
    [ -f "$OPENCLAW_DIR/.secureclaw/baselines/$f.sha256" ]
  done
}

@test "integrity check passes when files are unmodified" {
  bash "$SCRIPT" --rebaseline
  run bash "$SCRIPT"
  assert_success
}

@test "integrity check detects modification to SOUL.md" {
  bash "$SCRIPT" --rebaseline
  echo "tampered" >> "$OPENCLAW_DIR/workspace/SOUL.md"
  run bash "$SCRIPT"
  [ "$status" -ne 0 ] || [[ "$output" == *"FAIL"* ]] || [[ "$output" == *"TAMPER"* ]] || [[ "$output" == *"MISMATCH"* ]]
}

@test "script uses workspace/ dir — root openclaw dir files are not required" {
  # cognitive files only in workspace/, not in root
  run bash "$SCRIPT" --rebaseline
  assert_success
  refute_output --partial "No cognitive files found"
}
