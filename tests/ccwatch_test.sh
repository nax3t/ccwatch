#!/usr/bin/env bash
# ccwatch test suite — self-contained, no dependencies beyond bash
set -uo pipefail

# ─── Test Harness ────────────────────────────────────────────────────────────
_PASS=0 _FAIL=0 _TESTS=()

_assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    _PASS=$((_PASS+1))
    printf "  \033[32m✓\033[0m %s\n" "$label"
  else
    _FAIL=$((_FAIL+1))
    _TESTS+=("$label")
    printf "  \033[31m✗\033[0m %s\n" "$label"
    printf "    expected: %s\n" "$expected"
    printf "    actual:   %s\n" "$actual"
  fi
}

_assert_match() {
  local label="$1" pattern="$2" actual="$3"
  if [[ "$actual" =~ $pattern ]]; then
    _PASS=$((_PASS+1))
    printf "  \033[32m✓\033[0m %s\n" "$label"
  else
    _FAIL=$((_FAIL+1))
    _TESTS+=("$label")
    printf "  \033[31m✗\033[0m %s\n" "$label"
    printf "    pattern:  %s\n" "$pattern"
    printf "    actual:   %s\n" "$actual"
  fi
}

_assert_exit() {
  local label="$1" expected="$2"
  shift 2
  # Run in subshell to catch exit calls without killing test runner
  ("$@") &>/dev/null
  local rc=$?
  _assert_eq "$label" "$expected" "$rc"
}

_summary() {
  echo ""
  local total=$((_PASS+_FAIL))
  if [[ $_FAIL -eq 0 ]]; then
    printf "\033[32m%d/%d tests passed\033[0m\n" "$_PASS" "$total"
  else
    printf "\033[31m%d/%d tests failed:\033[0m\n" "$_FAIL" "$total"
    for t in "${_TESTS[@]}"; do printf "  - %s\n" "$t"; done
  fi
  return $_FAIL
}

# ─── Setup: sandbox environment ──────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_CACHE=$(mktemp -d)
trap 'rm -rf "$TEST_CACHE"' EXIT

CACHE="$TEST_CACHE/ccwatch"
mkdir -p "$CACHE"
chmod 700 "$CACHE"
DAEMON_STATE="$CACHE/state.json"
LOGFILE="$CACHE/ccwatch.log"
PERMS_LOG="$CACHE/permissions.jsonl"
MAX_LOG_SIZE=5242880

# Colors (copied from ccwatch.sh)
R="\033[0m"; B="\033[1m"; D="\033[2m"
CR="\033[31m"; CG="\033[32m"; CY="\033[33m"; CB="\033[34m"
CM="\033[35m"; CC="\033[36m"; CW="\033[37m"
BR="\033[41m"; BY="\033[43m"; BC="\033[46m"

# ─── Extract functions from ccwatch.sh ───────────────────────────────────────
# Use sed to extract function bodies instead of sourcing (avoids top-level side effects)

_extract_fn() {
  # Extract a bash function definition from the script using awk
  # Handles nested braces correctly (unlike simple sed)
  local fn="$1" script="$SCRIPT_DIR/ccwatch.sh"
  awk -v name="$fn" '
    $0 ~ "^"name"\\(\\)" { found=1; depth=0 }
    found {
      for(i=1;i<=length($0);i++) {
        c=substr($0,i,1)
        if(c=="{") depth++
        if(c=="}") depth--
      }
      print
      if(found && depth<=0 && /{/) { }
      if(found && depth==0 && /}/) { exit }
    }
  ' "$script"
}

# Extract and eval each function we need to test
for fn in _validate_model _validate_pane_id _check_api _check_deps \
          _detect _pane_pos _sbadge _cbar _statusbar _rotate_if_large \
          _voice_alert _log; do
  eval "$(_extract_fn "$fn")"
done

# ─── 1. Validation: _validate_model ─────────────────────────────────────────
echo ""
echo "=== _validate_model ==="

_assert_exit "valid model name" 0 _validate_model "claude-haiku-4-5-20251001"
_assert_exit "valid model with dots" 0 _validate_model "claude-3.5-sonnet"
_assert_exit "invalid: spaces" 1 _validate_model "bad model"
_assert_exit "invalid: empty" 1 _validate_model ""

long_model=$(printf 'a%.0s' {1..101})
_assert_exit "invalid: too long (101 chars)" 1 _validate_model "$long_model"

ok_model=$(printf 'a%.0s' {1..100})
_assert_exit "valid: exactly 100 chars" 0 _validate_model "$ok_model"

_assert_exit "invalid: shell metachar" 1 _validate_model 'model;rm -rf'

# ─── 2. Validation: _validate_pane_id ───────────────────────────────────────
echo ""
echo "=== _validate_pane_id ==="

_assert_exit "valid: %0" 0 _validate_pane_id "%0"
_assert_exit "valid: %123" 0 _validate_pane_id "%123"
_assert_exit "invalid: bare number" 1 _validate_pane_id "0"
_assert_exit "invalid: alpha" 1 _validate_pane_id "abc"
_assert_exit "invalid: empty" 1 _validate_pane_id ""

# ─── 3. API key check: _check_api ───────────────────────────────────────────
echo ""
echo "=== _check_api ==="

# Key set with valid prefix
ANTHROPIC_API_KEY="sk-ant-valid-key"
out=$(_check_api 2>&1)
_assert_eq "valid prefix: no output" "" "$out"

# Key set with bad prefix — warning on stderr
ANTHROPIC_API_KEY="bad-prefix-key"
out=$(_check_api 2>&1)
_assert_match "bad prefix: warning" "WARNING" "$out"

# Key unset — should exit 1
out=$(unset ANTHROPIC_API_KEY; _check_api 2>&1)
_assert_eq "unset key: exit 1" "1" "$?"

# Key set to empty string
ANTHROPIC_API_KEY=""
out=$(_check_api 2>&1)
_assert_eq "empty key: exit 1" "1" "$?"

# Restore key
ANTHROPIC_API_KEY="sk-ant-test-key-000000"

# ─── 4. Dependency check: _check_deps ───────────────────────────────────────
echo ""
echo "=== _check_deps ==="

# All deps present — use subshell with real PATH
if command -v tmux &>/dev/null && command -v curl &>/dev/null && command -v jq &>/dev/null; then
  _assert_exit "all deps present" 0 _check_deps
else
  printf "  \033[33m⊘\033[0m all deps present (skipped — missing real deps)\n"
fi

# Missing dep — use subshell with empty PATH so nothing is found
_check_deps_empty_path() {
  PATH="" _check_deps
}
_assert_exit "missing dep detected" 1 _check_deps_empty_path

# ─── 5. Pattern detection: _detect ──────────────────────────────────────────
echo ""
echo "=== _detect ==="

# Permission prompt
perm_input=$'Some output\nAllow Bash(npm test) (Y)es (N)o'
out=$(_detect "$perm_input")
_assert_match "permission: tool detected" "^permission" "$out"

# Question with trailing ?
q_input=$'Working on the task\nWhat would you like me to do next?'
out=$(_detect "$q_input")
_assert_match "question: trailing ?" "^question" "$out"

# Error pattern (anchored)
err_input=$'compiling...\nError: cannot find module'
out=$(_detect "$err_input")
_assert_eq "error: anchored Error:" "error|" "$out"

# Working state (spinner)
work_input=$'Processing files\n⏺ Reading src/main.ts'
out=$(_detect "$work_input")
_assert_eq "working: spinner char" "working|" "$out"

# Idle (no matches)
idle_input=$'$ ls\nfile1.txt  file2.txt'
out=$(_detect "$idle_input")
_assert_eq "idle: no patterns" "idle|" "$out"

# False positive: error keyword inside code (not anchored)
fp_input=$'  console.log("Error: something")\n  return null'
out=$(_detect "$fp_input")
_assert_eq "false positive: error in code" "idle|" "$out"

# Question-like text without trailing ?
noq_input=$'What would you like me to do\nDone.'
out=$(_detect "$noq_input")
[[ "$out" != question* ]]
_assert_eq "no question without trailing ?" "0" "$?"

# ─── 6. Pane position: _pane_pos ────────────────────────────────────────────
echo ""
echo "=== _pane_pos ==="

# Override tmux per-call to return geometry strings
# Format: pane_top|pane_left|pane_width|pane_height|window_width|window_height

_test_pane_pos() {
  local geo="$1"
  tmux() { echo "$geo"; }
  _pane_pos "%0"
  tmux() { :; }
}

_assert_eq "full pane" "full" "$(_test_pane_pos "0|0|200|50|200|50")"
_assert_eq "top-left" "top-left" "$(_test_pane_pos "0|0|100|25|200|50")"
_assert_eq "top-right" "top-right" "$(_test_pane_pos "0|100|100|25|200|50")"
_assert_eq "bottom-left" "bottom-left" "$(_test_pane_pos "25|0|100|25|200|50")"
_assert_eq "bottom-right" "bottom-right" "$(_test_pane_pos "25|100|100|25|200|50")"
_assert_eq "top (hsplit)" "top" "$(_test_pane_pos "0|0|200|25|200|50")"

# ─── 7. Display formatters: _sbadge and _cbar ───────────────────────────────
echo ""
echo "=== _sbadge ==="

_assert_match "sbadge working" "●" "$(_sbadge working)"
_assert_match "sbadge waiting" "◉" "$(_sbadge waiting)"
_assert_match "sbadge idle" "○" "$(_sbadge idle)"
_assert_match "sbadge error" "✖" "$(_sbadge error)"
_assert_match "sbadge done" "✔" "$(_sbadge done)"
_assert_match "sbadge unknown" "\\?" "$(_sbadge "unknown_state")"

echo ""
echo "=== _cbar ==="

_assert_match "cbar score 1" "▰" "$(_cbar 1 "trivial")"
_assert_match "cbar score 3" "▰▰▰" "$(_cbar 3 "medium")"
_assert_match "cbar score 5" "▰▰▰▰▰" "$(_cbar 5 "intense")"
_assert_match "cbar score 0" "▰" "$(_cbar 0 "none")"
_assert_match "cbar unknown" "▱▱▱▱▱" "$(_cbar "x" "unknown")"

# ─── 8. Status bar: _statusbar ───────────────────────────────────────────────
echo ""
echo "=== _statusbar ==="

# No state file
rm -f "$DAEMON_STATE"
out=$(_statusbar)
_assert_eq "no state file" "cc:--" "$out"

# Stale file (old mtime)
echo '{"count":1,"waiting":0,"questions":0,"permissions":0,"errors":0,"load":"▰▱▱▱▱","perms_logged":0}' > "$DAEMON_STATE"
touch -t 202001010000 "$DAEMON_STATE"
out=$(_statusbar)
_assert_match "stale file" "cc:stale" "$out"

# Zero sessions (fresh file)
echo '{"count":0,"waiting":0,"questions":0,"permissions":0,"errors":0,"load":"▱▱▱▱▱","perms_logged":0}' > "$DAEMON_STATE"
touch "$DAEMON_STATE"
out=$(_statusbar)
_assert_match "zero sessions" "cc:0" "$out"

# Active sessions with waiting/errors
echo '{"count":3,"waiting":2,"questions":1,"permissions":1,"errors":1,"load":"▰▱▱▱▱","perms_logged":5}' > "$DAEMON_STATE"
touch "$DAEMON_STATE"
out=$(_statusbar)
_assert_match "active: session count" "●3" "$out"
_assert_match "active: question indicator" "\\?1" "$out"
_assert_match "active: permission indicator" "!1" "$out"
_assert_match "active: error indicator" "x1" "$out"

# ─── 9. Log rotation: _rotate_if_large ───────────────────────────────────────
echo ""
echo "=== _rotate_if_large ==="

# Small file not rotated
small_f="$TEST_CACHE/small.log"
echo "hello" > "$small_f"
_rotate_if_large "$small_f"
_assert_eq "small file: not rotated" "1" "$([[ -f "$small_f" ]] && echo 1 || echo 0)"
_assert_eq "small file: no .old" "0" "$([[ -f "${small_f}.old" ]] && echo 1 || echo 0)"

# Large file (>5MB) rotated
large_f="$TEST_CACHE/large.log"
dd if=/dev/zero of="$large_f" bs=1048576 count=6 2>/dev/null
_rotate_if_large "$large_f"
_assert_eq "large file: original removed" "0" "$([[ -f "$large_f" ]] && echo 1 || echo 0)"
_assert_eq "large file: .old created" "1" "$([[ -f "${large_f}.old" ]] && echo 1 || echo 0)"

# ─── 10. Security / hardening ────────────────────────────────────────────────
echo ""
echo "=== Security ==="

# API key escaping: double quotes and backslashes
test_key='sk-ant-test"key\special'
escaped="${test_key//\\/\\\\}"
escaped="${escaped//\"/\\\"}"
_assert_eq "escape backslash+quote" 'sk-ant-test\"key\\special' "$escaped"

# Cache dir permissions
perms=$(stat -f "%Lp" "$CACHE" 2>/dev/null || stat -c "%a" "$CACHE" 2>/dev/null)
_assert_eq "cache dir is 700" "700" "$perms"

# Voice sanitization: strip ANSI and shell metachars
# Use printf to create a literal ESC byte (portable across macOS/Linux sed)
esc=$(printf '\033')
raw_msg="${esc}[31mHello; rm -rf /${esc}[0m"
sanitized=$(printf '%s' "$raw_msg" | sed "s/${esc}\[[0-9;]*m//g" | tr -cd 'a-zA-Z0-9 .,;:!?()-')
# Note: ; is in the tr allowed set, but / and backslash are stripped
_assert_eq "voice sanitize: slash stripped" "Hello; rm -rf " "$sanitized"
# Verify truly dangerous chars are stripped
raw_danger='$(rm -rf /); `evil`; "quoted"'
safe=$(printf '%s' "$raw_danger" | tr -cd 'a-zA-Z0-9 .,;:!?()-')
# () are allowed in the set, but $ ` " \ / are stripped
_assert_eq "voice sanitize: backticks+dollar stripped" "(rm -rf ); evil; quoted" "$safe"

# Temp file cleanup: verify RETURN trap pattern cleans up temp files
# Run in subshell to avoid trap leaking $body_file into outer scope under set -u
_cleanup_result=$(
  set -uo pipefail
  _inner() {
    local body_file=""
    body_file=$(mktemp "$CACHE/req.XXXXXX")
    trap 'rm -f "$body_file" 2>/dev/null' RETURN
    echo "test" > "$body_file"
  }
  _inner
  leftover=$(ls "$CACHE"/req.* 2>/dev/null | wc -l | tr -d ' ')
  echo "${leftover:-0}"
)
_assert_eq "body_file cleaned up" "0" "$_cleanup_result"

# ─── Summary ─────────────────────────────────────────────────────────────────
_summary
exit $?
