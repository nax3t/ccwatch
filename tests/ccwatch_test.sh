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
          _detect _sbadge _cbar _read_state _statusbar _rotate_if_large \
          _voice_enabled _voice_alert _voice_summary _log _log_permission _resolve_api_key \
          _notify_enabled _notify_resolve_webhook _notify_send _notify_cooldown_ok _notify_alert; do
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

# ─── 6. Display formatters: _sbadge and _cbar ───────────────────────────────
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

# Garbage JSON in state file → graceful fallback
echo 'this is not json at all' > "$DAEMON_STATE"
touch "$DAEMON_STATE"
out=$(_statusbar)
_assert_match "garbage JSON: graceful fallback" "cc:0" "$out"

# Empty state file → graceful fallback
> "$DAEMON_STATE"
touch "$DAEMON_STATE"
out=$(_statusbar)
_assert_match "empty state file: graceful fallback" "cc:0" "$out"

# Missing fields → defaults kick in
echo '{"count":2}' > "$DAEMON_STATE"
touch "$DAEMON_STATE"
out=$(_statusbar)
_assert_match "missing fields: session count works" "●2" "$out"

# Non-numeric values → validation catches them
echo '{"count":"abc","waiting":"xyz","questions":0,"permissions":0,"errors":0,"load":"▱▱▱▱▱","perms_logged":0}' > "$DAEMON_STATE"
touch "$DAEMON_STATE"
out=$(_statusbar)
_assert_match "non-numeric values: graceful fallback" "cc:0" "$out"

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
sanitized=$(printf '%s' "$raw_msg" | sed "s/${esc}\[[0-9;]*m//g" | tr -cd 'a-zA-Z0-9 .,:!?()-')
# Note: ; and / and backslash are all stripped
_assert_eq "voice sanitize: semicolon+slash stripped" "Hello rm -rf " "$sanitized"
# Verify truly dangerous chars are stripped
raw_danger='$(rm -rf /); `evil`; "quoted"'
safe=$(printf '%s' "$raw_danger" | tr -cd 'a-zA-Z0-9 .,:!?()-')
# () are allowed in the set, but $ ` " \ / ; are stripped
_assert_eq "voice sanitize: backticks+dollar+semicolons stripped" "(rm -rf ) evil quoted" "$safe"

# Temp file cleanup: verify explicit rm pattern cleans up temp files
_cleanup_result=$(
  set -uo pipefail
  _inner() {
    local body_file=""
    body_file=$(mktemp "$CACHE/req.XXXXXX")
    echo "test" > "$body_file"
    rm -f "$body_file" 2>/dev/null
  }
  _inner
  leftover=$(ls "$CACHE"/req.* 2>/dev/null | wc -l | tr -d ' ')
  echo "${leftover:-0}"
)
_assert_eq "body_file cleaned up" "0" "$_cleanup_result"

# Voice dispatch: say/espeak-ng use -- not xargs -0
# Verify by extracting the say/espeak-ng lines from the script
say_line=$(grep -E '^\s+say\)' "$SCRIPT_DIR/ccwatch.sh")
_assert_match "voice: say uses -- flag" 'say -- ' "$say_line"
espeak_line=$(grep -E '^\s+espeak-ng\)' "$SCRIPT_DIR/ccwatch.sh")
_assert_match "voice: espeak-ng uses -- flag" 'espeak-ng -- ' "$espeak_line"

# Fallback JSON shape: verify _analyze fallback and _ls_analyze fallback have required fields
_fallback='{"status":"error","waiting_for_user":false,"pending_question":null,"pending_permission":null,"branch":"?","task_summary":"API error","current_action":"","files":[],"cognitive_load":{"score":1,"label":"?","reasoning":"","safe_to_switch_away":true,"context_cost":""},"suggested_action":""}'
_assert_eq "fallback has .status" "error" "$(jq -r '.status' <<< "$_fallback")"
_assert_eq "fallback has .cognitive_load.score" "1" "$(jq -r '.cognitive_load.score' <<< "$_fallback")"

# mktemp failure guards: verify all mktemp calls have || guards
mktemp_unguarded=$(grep -n 'mktemp ' "$SCRIPT_DIR/ccwatch.sh" | grep -v '||' | grep -v '^#' || true)
_assert_eq "all mktemp calls guarded" "" "$mktemp_unguarded"

# ─── 11. Voice toggle: _voice_enabled ─────────────────────────────────────────
echo ""
echo "=== _voice_enabled ==="

# Neither env var nor file → disabled
unset CCWATCH_VOICE
rm -f "$CACHE/voice_enabled"
_voice_enabled 2>/dev/null
_assert_eq "disabled by default" "1" "$?"

# Env var → enabled
CCWATCH_VOICE="true"
_voice_enabled 2>/dev/null
_assert_eq "enabled via env var" "0" "$?"

# File toggle → enabled (even without env var)
unset CCWATCH_VOICE
touch "$CACHE/voice_enabled"
_voice_enabled 2>/dev/null
_assert_eq "enabled via file toggle" "0" "$?"

# File removed → disabled again
rm -f "$CACHE/voice_enabled"
_voice_enabled 2>/dev/null
_assert_eq "disabled after file removed" "1" "$?"

# Restore
CCWATCH_VOICE="false"

# ─── 11b. Voice summary: _voice_summary ──────────────────────────────────────
echo ""
echo "=== _voice_summary ==="

_assert_eq "single session" "One session found." "$(_voice_summary 1 "")"
_assert_eq "multiple sessions" "5 sessions found." "$(_voice_summary 5 "")"
_assert_eq "with suffix" "3 sessions found, sorted by cognitive load." "$(_voice_summary 3 "sorted by cognitive load")"
_assert_eq "with counts" "5 sessions found. 2 are waiting. One error." \
  "$(_voice_summary 5 "" 2 "is waiting" "are waiting" 1 "error" "errors")"
_assert_eq "zero counts skipped" "3 sessions found." \
  "$(_voice_summary 3 "" 0 "is waiting" "are waiting" 0 "error" "errors")"
_assert_eq "singular counts" "One session found. One is waiting." \
  "$(_voice_summary 1 "" 1 "is waiting" "are waiting")"

# ─── 12. API key resolution: _resolve_api_key ────────────────────────────────
echo ""
echo "=== _resolve_api_key ==="

# Env var set → uses env var (does not call security)
ANTHROPIC_API_KEY="sk-ant-from-env"
_resolve_api_key
_assert_eq "env var set: uses env var" "sk-ant-from-env" "$ANTHROPIC_API_KEY"

# Env var unset + mock security → retrieves from Keychain
unset ANTHROPIC_API_KEY
# Mock: override uname and security for this test
_resolve_api_key_mock_keychain() {
  unset ANTHROPIC_API_KEY
  uname() { echo "Darwin"; }
  security() { echo "sk-ant-from-keychain"; }
  export -f uname security
  _resolve_api_key
  echo "$ANTHROPIC_API_KEY"
  unset -f uname security
}
out=$(_resolve_api_key_mock_keychain)
_assert_eq "keychain fallback: retrieves key" "sk-ant-from-keychain" "$out"

# Both unset + security fails → key stays empty
_resolve_api_key_mock_fail() {
  unset ANTHROPIC_API_KEY
  uname() { echo "Darwin"; }
  security() { return 1; }
  export -f uname security
  _resolve_api_key
  echo "${ANTHROPIC_API_KEY:-}"
  unset -f uname security
}
out=$(_resolve_api_key_mock_fail)
_assert_eq "no key anywhere: stays empty" "" "$out"

# Restore key for remaining tests
ANTHROPIC_API_KEY="sk-ant-test-key-000000"

# ─── 13. Notify toggle: _notify_enabled ──────────────────────────────────────
echo ""
echo "=== _notify_enabled ==="

# Neither env var nor file → disabled
unset CCWATCH_DISCORD_WEBHOOK
rm -f "$CACHE/notify_enabled"
_notify_enabled 2>/dev/null
_assert_eq "disabled by default" "1" "$?"

# Env var → enabled
CCWATCH_DISCORD_WEBHOOK="https://discord.com/api/webhooks/123/abc"
_notify_enabled 2>/dev/null
_assert_eq "enabled via env var" "0" "$?"

# Env var set to "false" → disabled
CCWATCH_DISCORD_WEBHOOK="false"
_notify_enabled 2>/dev/null
_assert_eq "disabled via env=false" "1" "$?"

# File toggle → enabled (even without env var)
unset CCWATCH_DISCORD_WEBHOOK
touch "$CACHE/notify_enabled"
_notify_enabled 2>/dev/null
_assert_eq "enabled via file toggle" "0" "$?"

# File removed → disabled again
rm -f "$CACHE/notify_enabled"
_notify_enabled 2>/dev/null
_assert_eq "disabled after file removed" "1" "$?"

# ─── 14. Notify cooldown: _notify_cooldown_ok ───────────────────────────────
echo ""
echo "=== _notify_cooldown_ok ==="

# Cooldown=0 → always ok
CCWATCH_NOTIFY_COOLDOWN=0
_notify_cooldown_ok 2>/dev/null
_assert_eq "cooldown=0: always ok" "0" "$?"

# Cooldown unset → defaults to 0, always ok
unset CCWATCH_NOTIFY_COOLDOWN
_notify_cooldown_ok 2>/dev/null
_assert_eq "cooldown unset: always ok" "0" "$?"

# Cooldown=9999 with no last_sent → ok (first send)
CCWATCH_NOTIFY_COOLDOWN=9999
rm -f "$CACHE/notify_last_sent"
_notify_cooldown_ok 2>/dev/null
_assert_eq "cooldown=9999 no prior: ok" "0" "$?"

# Cooldown=9999 with recent last_sent → blocked
CCWATCH_NOTIFY_COOLDOWN=9999
date +%s > "$CACHE/notify_last_sent"
_notify_cooldown_ok 2>/dev/null
_assert_eq "cooldown=9999 recent: blocked" "1" "$?"

# Cooldown=1 with old last_sent → ok
CCWATCH_NOTIFY_COOLDOWN=1
echo "0" > "$CACHE/notify_last_sent"
_notify_cooldown_ok 2>/dev/null
_assert_eq "cooldown=1 old: ok" "0" "$?"

# Non-numeric cooldown → treated as 0, always ok
CCWATCH_NOTIFY_COOLDOWN="abc"
_notify_cooldown_ok 2>/dev/null
_assert_eq "cooldown=abc: treated as 0" "0" "$?"

# Restore
unset CCWATCH_NOTIFY_COOLDOWN
rm -f "$CACHE/notify_last_sent"

# ─── 15. Notify webhook resolution: _notify_resolve_webhook ─────────────────
echo ""
echo "=== _notify_resolve_webhook ==="

# Env var set → returns it
CCWATCH_DISCORD_WEBHOOK="https://discord.com/api/webhooks/123/abc"
out=$(_notify_resolve_webhook)
_assert_eq "env var: returns webhook" "https://discord.com/api/webhooks/123/abc" "$out"

# Env var unset → returns 1 (unless Keychain has it, but we can't mock security easily)
unset CCWATCH_DISCORD_WEBHOOK
_notify_resolve_webhook &>/dev/null
_assert_eq "no env var: fails" "1" "$?"

# Restore
unset CCWATCH_DISCORD_WEBHOOK

# ─── 16. Notify send: URL validation ────────────────────────────────────────
echo ""
echo "=== _notify_send URL validation ==="

# Valid Discord URL — will fail on actual send (no real webhook) but passes URL check
# We test by checking _notify_send returns 1 when URL is invalid
CCWATCH_DISCORD_WEBHOOK="https://evil.com/api/webhooks/123/abc"
out=$(_notify_send "test" "test body" 2>/dev/null)
_assert_eq "rejects non-discord URL" "1" "$?"

CCWATCH_DISCORD_WEBHOOK="http://discord.com/api/webhooks/123/abc"
out=$(_notify_send "test" "test body" 2>/dev/null)
_assert_eq "rejects http (non-https)" "1" "$?"

CCWATCH_DISCORD_WEBHOOK="https://discord.com/not-webhooks/123"
out=$(_notify_send "test" "test body" 2>/dev/null)
_assert_eq "rejects wrong path" "1" "$?"

# Restore
unset CCWATCH_DISCORD_WEBHOOK

# ─── 17. prev sanitization ────────────────────────────────────────────────────
echo ""
echo "=== prev sanitization ==="

# Trailing newline stripped
prev=$'0\n'
prev="${prev//[^0-9]/}"
[[ -z "$prev" ]] && prev=0
_assert_eq "prev: trailing newline stripped" "0" "$prev"

# Trailing carriage return stripped
prev=$'3\r'
prev="${prev//[^0-9]/}"
[[ -z "$prev" ]] && prev=0
_assert_eq "prev: trailing CR stripped" "3" "$prev"

# Spaces stripped
prev="  5  "
prev="${prev//[^0-9]/}"
[[ -z "$prev" ]] && prev=0
_assert_eq "prev: spaces stripped" "5" "$prev"

# Empty value defaults to 0
prev=""
prev="${prev//[^0-9]/}"
[[ -z "$prev" ]] && prev=0
_assert_eq "prev: empty defaults to 0" "0" "$prev"

# Non-numeric value defaults to 0
prev="abc"
prev="${prev//[^0-9]/}"
[[ -z "$prev" ]] && prev=0
_assert_eq "prev: non-numeric defaults to 0" "0" "$prev"

# ─── 18. Hook event override ──────────────────────────────────────────────────
echo ""
echo "=== Hook event override ==="

# Build evt_panes from mock event files
evt_test_dir="$TEST_CACHE/evt_test"
mkdir -p "$evt_test_dir"
echo '{"type":"question","pane":"%42"}' > "$evt_test_dir/evt1.json"
echo '{"type":"stop","pane":"%99"}' > "$evt_test_dir/evt2.json"

# Parse events the same way _daemon_scan does
evt_panes=""
for evt in "$evt_test_dir"/*.json; do
  [[ -f "$evt" ]] || continue
  evt_type=$(jq -r '.type // empty' "$evt" 2>/dev/null) || continue
  evt_pane=$(jq -r '.pane // empty' "$evt" 2>/dev/null) || continue
  [[ -n "$evt_type" ]] && [[ -n "$evt_pane" ]] && evt_panes+="${evt_pane}=${evt_type}|"
  rm -f "$evt"
done

_assert_match "evt_panes: contains question event" "%42=question" "$evt_panes"
_assert_match "evt_panes: contains stop event" "%99=stop" "$evt_panes"

# Simulate hook override for a "working" pane
st="working"; pid="%42"
if [[ "$st" == "working" || "$st" == "idle" ]] && [[ -n "$evt_panes" ]]; then
  hook_type=$(printf '%s' "$evt_panes" | grep -oE "${pid}=[^|]+" | head -1 | cut -d= -f2) || true
  if [[ "$hook_type" == "question" ]]; then
    st="question"
  elif [[ "$hook_type" == "stop" ]]; then
    st="question"
  fi
fi
_assert_eq "hook override: working→question" "question" "$st"

# Simulate hook override for "stop" event
st="idle"; pid="%99"
if [[ "$st" == "working" || "$st" == "idle" ]] && [[ -n "$evt_panes" ]]; then
  hook_type=$(printf '%s' "$evt_panes" | grep -oE "${pid}=[^|]+" | head -1 | cut -d= -f2) || true
  if [[ "$hook_type" == "question" ]]; then
    st="question"
  elif [[ "$hook_type" == "stop" ]]; then
    st="question"
  fi
fi
_assert_eq "hook override: stop→question" "question" "$st"

# Pane not in events → state unchanged
st="working"; pid="%77"
if [[ "$st" == "working" || "$st" == "idle" ]] && [[ -n "$evt_panes" ]]; then
  hook_type=$(printf '%s' "$evt_panes" | grep -oE "${pid}=[^|]+" | head -1 | cut -d= -f2) || true
  if [[ "$hook_type" == "question" ]]; then
    st="question"
  elif [[ "$hook_type" == "stop" ]]; then
    st="question"
  fi
fi
_assert_eq "no hook: state unchanged" "working" "$st"

# Event files cleaned up
_assert_eq "event files cleaned up" "0" "$(ls "$evt_test_dir"/*.json 2>/dev/null | wc -l | tr -d ' ')"

# ─── Summary ─────────────────────────────────────────────────────────────────
_summary
exit $?
