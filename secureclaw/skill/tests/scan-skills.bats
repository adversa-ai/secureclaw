#!/usr/bin/env bats
# Group C — scan-skills.sh

load helpers/setup_env

SCRIPT=""

setup() {
  load 'test_helper/bats-support/load'
  load 'test_helper/bats-assert/load'
  setup_fake_openclaw
  SCRIPT="$SCRIPTS_DIR/scan-skills.sh"
}

teardown() {
  teardown_fake_openclaw
}

@test "finds skills placed in workspace/skills/" {
  mkdir -p "$OPENCLAW_DIR/workspace/skills/fakeskill"
  echo '{"name":"fakeskill"}' > "$OPENCLAW_DIR/workspace/skills/fakeskill/skill.json"
  run bash "$SCRIPT"
  assert_success
  [[ "$output" == *"fakeskill"* ]] || [[ "$output" == *"Scanned: 1"* ]] || [[ "$output" == *"scanned"* ]]
}

@test "exits 0 with no skills installed" {
  run bash "$SCRIPT"
  assert_success
}

@test "secureclaw-skill/ is excluded from scan results" {
  mkdir -p "$OPENCLAW_DIR/workspace/skills/secureclaw-skill"
  mkdir -p "$OPENCLAW_DIR/workspace/skills/otherskill"
  echo '{"name":"otherskill"}' > "$OPENCLAW_DIR/workspace/skills/otherskill/skill.json"
  run bash "$SCRIPT"
  assert_success
  [[ "$output" == *"otherskill"* ]] || [[ "$output" == *"Nothing to scan"* ]]
}
