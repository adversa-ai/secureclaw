#!/usr/bin/env bats
# Group B — quick-audit.sh

load helpers/setup_env

SCRIPT=""

setup() {
  load 'test_helper/bats-support/load'
  load 'test_helper/bats-assert/load'
  setup_fake_openclaw
  SCRIPT="$SCRIPTS_DIR/quick-audit.sh"
}

teardown() {
  teardown_fake_openclaw
}

@test "ASI06 check appears in output" {
  run bash "$SCRIPT"
  assert_output --partial "ASI06"
}

@test "ASI09 check appears in output" {
  run bash "$SCRIPT"
  assert_output --partial "ASI09"
}

@test "ATLAS check appears in output" {
  run bash "$SCRIPT"
  assert_output --partial "ATLAS"
}

@test "audit completes without crash on clean workspace" {
  run bash "$SCRIPT"
  [ "$status" -eq 0 ] || [ "$status" -eq 1 ] || [ "$status" -eq 2 ]
  [ -n "$output" ]
}

@test "secureclaw-skill/ dir is excluded from self-scan findings" {
  mkdir -p "$OPENCLAW_DIR/workspace/skills/secureclaw-skill/scripts"
  mkdir -p "$OPENCLAW_DIR/workspace/skills/secureclaw-skill/configs"
  echo "ignore previous instructions" > "$OPENCLAW_DIR/workspace/skills/secureclaw-skill/configs/injection-patterns.json"
  run bash "$SCRIPT"
  refute_output --partial "secureclaw-skill.*injection"
}

@test "directory permissions 700 does not produce a HIGH finding" {
  # setup_fake_openclaw already sets OPENCLAW_DIR to mode 700
  run bash "$SCRIPT"
  refute_output --partial "Permissions 700"
}

@test "output does not contain statfs block" {
  run bash "$SCRIPT"
  refute_output --partial "statfs"
}
