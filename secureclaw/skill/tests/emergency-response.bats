#!/usr/bin/env bats
# Group E — emergency-response.sh

load helpers/setup_env

SCRIPT=""

setup() {
  load 'test_helper/bats-support/load'
  load 'test_helper/bats-assert/load'
  setup_fake_openclaw
  SCRIPT="$SCRIPTS_DIR/emergency-response.sh"
}

teardown() {
  teardown_fake_openclaw
}

@test "runs in skill-only mode without plugin detection error" {
  # No plugin installed, 'openclaw' binary absent from test env
  run bash "$SCRIPT"
  refute_output --partial "unknown command"
  refute_output --partial "error: unknown command 'secureclaw'"
  [ "$status" -ne 127 ]
}

@test "skill-only mode outputs emergency response header" {
  run bash "$SCRIPT"
  assert_output --partial "emergency"
}

@test "does not crash when extensions/secureclaw dir exists without plugin binary" {
  mkdir -p "$OPENCLAW_DIR/extensions/secureclaw"
  run bash "$SCRIPT"
  refute_output --partial "unknown command 'secureclaw'"
}
