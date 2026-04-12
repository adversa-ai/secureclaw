#!/usr/bin/env bats
# Group F — uninstall.sh

load helpers/setup_env

SCRIPT=""

setup() {
  load 'test_helper/bats-support/load'
  load 'test_helper/bats-assert/load'
  setup_fake_openclaw
  SCRIPT="$SCRIPTS_DIR/uninstall.sh"

  # Simulate an installed skill in both locations
  mkdir -p "$OPENCLAW_DIR/skills/secureclaw/scripts"
  echo '{"version":"2.2.0"}' > "$OPENCLAW_DIR/skills/secureclaw/skill.json"
  mkdir -p "$OPENCLAW_DIR/workspace/skills/secureclaw"
  echo '{"version":"2.2.0"}' > "$OPENCLAW_DIR/workspace/skills/secureclaw/skill.json"

  # Add secureclaw blocks to TOOLS.md and AGENTS.md
  cat >> "$OPENCLAW_DIR/workspace/TOOLS.md" <<'EOF'

<!-- Secureclaw -->
## SecureClaw Security Skill
Security audit and hardening for OpenClaw.
<!-- Secureclaw:end -->
EOF
  cat >> "$OPENCLAW_DIR/workspace/AGENTS.md" <<'EOF'

<!-- Secureclaw -->
## SecureClaw Security Skill
Security monitor.
<!-- Secureclaw:end -->
EOF

}

teardown() {
  teardown_fake_openclaw
}

@test "skills/secureclaw/ dir removed after uninstall" {
  run bash "$SCRIPT" --force
  [ "$status" -eq 0 ] || [ "$status" -eq 1 ] || [ "$status" -eq 2 ]
  [ ! -d "$OPENCLAW_DIR/skills/secureclaw" ]
}

@test "workspace/skills/secureclaw/ dir removed after uninstall" {
  run bash "$SCRIPT" --force
  [ "$status" -eq 0 ] || [ "$status" -eq 1 ] || [ "$status" -eq 2 ]
  [ ! -d "$OPENCLAW_DIR/workspace/skills/secureclaw" ]
}

@test "TOOLS.md secureclaw entry removed after uninstall" {
  run bash "$SCRIPT" --force
  [ "$status" -eq 0 ] || [ "$status" -eq 1 ] || [ "$status" -eq 2 ]
  run grep "SecureClaw Security Skill" "$OPENCLAW_DIR/workspace/TOOLS.md"
  [ "$status" -ne 0 ]
}

@test "AGENTS.md secureclaw entry removed after uninstall" {
  run bash "$SCRIPT" --force
  [ "$status" -eq 0 ] || [ "$status" -eq 1 ] || [ "$status" -eq 2 ]
  run grep "SecureClaw Security Skill" "$OPENCLAW_DIR/workspace/AGENTS.md"
  [ "$status" -ne 0 ]
}

@test "dry-run shows irreversible warning" {
  run bash "$SCRIPT"
  [ "$status" -eq 0 ]
  [[ "$output" == *"WARNING: this action is irreversible"* ]]
}

@test "--force does not show irreversible warning" {
  run bash "$SCRIPT" --force
  [ "$status" -eq 0 ] || [ "$status" -eq 1 ] || [ "$status" -eq 2 ]
  [[ "$output" != *"WARNING: this action is irreversible"* ]]
}
