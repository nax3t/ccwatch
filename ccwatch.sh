#!/usr/bin/env bash
# ╭──────────────────────────────────────────────────────╮
# │  ccwatch — Ambient Intelligence for Claude Code      │
# │                                                      │
# │  Status bar: always visible, $0 (daemon + regex)     │
# │  Popups: on-demand AI (Haiku/Sonnet, ~$0.01/call)    │
# ╰──────────────────────────────────────────────────────╯

set -euo pipefail

# ─── Paths ────────────────────────────────────────────────────────────────────
CCWATCH_DIR="$(cd "$(dirname "$(realpath "${BASH_SOURCE[0]}")")" && pwd)"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/ccwatch"
PERMS_LOG="$CACHE/permissions.jsonl"
DAEMON_PID="$CACHE/daemon.pid"
DAEMON_STATE="$CACHE/state.json"
LOGFILE="$CACHE/ccwatch.log"
HISTORY="$CACHE/history.jsonl"
CAP="${CCWATCH_LINES:-80}"
SCAN_INT="${CCWATCH_SCAN_INTERVAL:-30}"
OBSIDIAN_VAULT="${CCWATCH_OBSIDIAN_VAULT:-$HOME/ObsidianVault}"
OBSIDIAN_DAILY="$OBSIDIAN_VAULT/daily"
OBSIDIAN_TEMPLATE="$OBSIDIAN_VAULT/templates/daily-template.md"
NOTES_LAST_RUN="$CACHE/notes_last_run"
NOTES_INTERVAL="${CCWATCH_NOTES_INTERVAL:-900}"
CLAUDE_PROJECTS="$HOME/.claude/projects"
CLAUDE_STATS="$HOME/.claude/stats-cache.json"

# Validate numeric env vars
[[ "$CAP" =~ ^[0-9]+$ ]] || { echo "ERROR: CCWATCH_LINES must be numeric" >&2; exit 1; }
[[ "$SCAN_INT" =~ ^[0-9]+$ ]] || { echo "ERROR: CCWATCH_SCAN_INTERVAL must be numeric" >&2; exit 1; }
[[ "$NOTES_INTERVAL" =~ ^[0-9]+$ ]] || { echo "ERROR: CCWATCH_NOTES_INTERVAL must be numeric" >&2; exit 1; }
# Validate vault path: absolute, no newlines or control chars
if [[ "$OBSIDIAN_VAULT" != /* ]] || [[ "$OBSIDIAN_VAULT" == *$'\n'* ]] || [[ "$OBSIDIAN_VAULT" == *$'\r'* ]]; then
  echo "ERROR: CCWATCH_OBSIDIAN_VAULT must be an absolute path" >&2; exit 1
fi

# [HARDENED #8] Restrictive permissions on cache directory
mkdir -p "$CACHE"
chmod 700 "$CACHE"

# [HARDENED #7] Max log sizes (bytes) — auto-rotated
MAX_LOG_SIZE=5242880  # 5MB

# ─── Models (two-tier: fast + think) ─────────────────────────────────────────
M_FAST="${CCWATCH_MODEL_FAST:-claude-haiku-4-5-20251001}"
M_THINK="${CCWATCH_MODEL_THINK:-claude-sonnet-4-6-20250527}"
M_OVERRIDE="${CCWATCH_MODEL:-}"

# [HARDENED #12] Validate model names — alphanumeric, hyphens, dots only
_validate_model() {
  local m="$1"
  if [[ ! "$m" =~ ^[a-zA-Z0-9._-]{1,100}$ ]]; then
    echo "ERROR: Invalid model name: $m" >&2; exit 1
  fi
}
_validate_model "$M_FAST"; _validate_model "$M_THINK"
[[ -n "$M_OVERRIDE" ]] && _validate_model "$M_OVERRIDE"

# ─── Colors ───────────────────────────────────────────────────────────────────
R="\033[0m"; B="\033[1m"; D="\033[2m"
CR="\033[31m"; CG="\033[32m"; CY="\033[33m"; CB="\033[34m"
CM="\033[35m"; CC="\033[36m"; CW="\033[37m"
BR="\033[41m"; BY="\033[43m"; BC="\033[46m"

# [HARDENED #17] Sanitize untrusted strings for echo -e display
# Doubles backslashes so \033, \n, etc. from API/state data are shown literally
_e() { printf '%s' "${1//\\/\\\\}"; }

# ─── Util ─────────────────────────────────────────────────────────────────────

# [HARDENED #7] Log rotation
_rotate_if_large() {
  local f="$1"
  [[ ! -f "$f" ]] && return
  local sz
  sz=$(stat -c %s "$f" 2>/dev/null || stat -f %z "$f" 2>/dev/null || echo 0)
  if [[ "$sz" -gt "$MAX_LOG_SIZE" ]]; then
    mv "$f" "${f}.old"
    # Keep only .old, not unlimited backups
    rm -f "${f}.old.old" 2>/dev/null || true
  fi
}

_log() {
  _rotate_if_large "$LOGFILE"
  echo "[$(date '+%H:%M:%S')] $*" >> "$LOGFILE"
}

_event() {
  _rotate_if_large "$HISTORY"
  jq -nc --arg t "$(date -Iseconds)" --arg p "$1" --arg k "$2" --arg d "${3:-}" \
    '{ts:$t,pane:$p,type:$k,detail:$d}' >> "$HISTORY"
}

_hist() { tail -n "${1:-20}" "$HISTORY" 2>/dev/null || true; }

# Voice summary builder — takes total + pairs of (count "singular" "plural")
# Usage: _voice_summary 5 "sorted by cognitive load" 3 "is working" "are working" 1 "is idle" "are idle"
# Outputs: "5 sessions found, sorted by cognitive load. 3 are working. One is idle."
_voice_summary() {
  local total="$1" suffix="${2:-}"; shift 2
  local msg
  if [[ "$total" -eq 1 ]]; then msg="One session found"
  else msg="${total} sessions found"; fi
  [[ -n "$suffix" ]] && msg+=", ${suffix}"
  msg+="."
  while [[ $# -ge 3 ]]; do
    local cnt="$1" sing="$2" plur="$3"; shift 3
    [[ "$cnt" -gt 0 ]] || continue
    if [[ "$cnt" -eq 1 ]]; then msg+=" One ${sing}."
    else msg+=" ${cnt} ${plur}."; fi
  done
  echo "$msg"
}

# Log a permission request to the JSONL log
_log_permission() {
  local pid="$1" label="$2" tool_detail="$3"
  _rotate_if_large "$PERMS_LOG"
  jq -nc --arg t "$(date -Iseconds)" --arg P "$pid" --arg l "$label" \
    --arg tool "$tool_detail" '{ts:$t,pane:$P,label:$l,tool:$tool}' >> "$PERMS_LOG" || true
}

# Read daemon state into _st_* variables via single jq call with validation
# Sets: _st_n _st_w _st_q _st_p _st_e _st_lb _st_pl
_read_state() {
  _st_n=0 _st_w=0 _st_q=0 _st_p=0 _st_e=0 _st_lb="▱▱▱▱▱" _st_pl=0
  local _f
  _f=$(jq -r '[(.count//0),(.waiting//0),(.questions//0),(.permissions//0),
    (.errors//0),(.load//"▱▱▱▱▱"),(.perms_logged//0)]|join("\t")' "$DAEMON_STATE" 2>/dev/null) || return
  [[ -n "$_f" ]] && IFS=$'\t' read -r _st_n _st_w _st_q _st_p _st_e _st_lb _st_pl <<< "$_f"
  [[ "$_st_n" =~ ^[0-9]+$ ]] || _st_n=0; [[ "$_st_w" =~ ^[0-9]+$ ]] || _st_w=0
  [[ "$_st_q" =~ ^[0-9]+$ ]] || _st_q=0; [[ "$_st_p" =~ ^[0-9]+$ ]] || _st_p=0
  [[ "$_st_e" =~ ^[0-9]+$ ]] || _st_e=0; [[ "$_st_pl" =~ ^[0-9]+$ ]] || _st_pl=0
}

_check_deps() {
  local miss=()
  for c in tmux curl jq; do command -v "$c" &>/dev/null || miss+=("$c"); done
  if [[ ${#miss[@]} -gt 0 ]]; then echo "Missing: ${miss[*]}"; exit 1; fi
}

_check_api() {
  [[ -n "${ANTHROPIC_API_KEY:-}" ]] || {
    echo "ANTHROPIC_API_KEY not set."
    echo "ccwatch uses the Anthropic API — not your Max/Pro subscription."
    echo ""
    echo "  Option 1 (macOS): ccwatch key set"
    echo "  Option 2:         export ANTHROPIC_API_KEY=sk-ant-..."
    echo ""
    echo "Get a key at https://console.anthropic.com/settings/keys"
    exit 1
  }
  if [[ ! "$ANTHROPIC_API_KEY" =~ ^sk-ant- ]]; then
    echo "WARNING: ANTHROPIC_API_KEY doesn't look like a valid key (expected sk-ant-...)." >&2
    echo "  Current value starts with: ${ANTHROPIC_API_KEY:0:10}..." >&2
    echo "  If using macOS Keychain, ensure you use: security find-generic-password -w ..." >&2
  fi
}

_resolve_api_key() {
  # Env var takes priority
  [[ -n "${ANTHROPIC_API_KEY:-}" ]] && return
  # macOS Keychain fallback
  if [[ "$(uname)" == "Darwin" ]] && command -v security &>/dev/null; then
    ANTHROPIC_API_KEY=$(security find-generic-password -s ccwatch -a anthropic-api-key -w 2>/dev/null) || true
  fi
}

# [HARDENED #6] Validate pane ID format — must match tmux pane_id pattern
_validate_pane_id() {
  local id="$1"
  if [[ ! "$id" =~ ^%[0-9]+$ ]]; then
    echo "ERROR: Invalid pane ID: $id" >&2; return 1
  fi
}

# ─── API ──────────────────────────────────────────────────────────────────────
_call() {
  local tier="$1" sys="$2" usr="$3" tok="${4:-400}"
  local model
  if [[ -n "$M_OVERRIDE" ]]; then model="$M_OVERRIDE"
  elif [[ "$tier" == "think" ]]; then model="$M_THINK"
  else model="$M_FAST"; fi

  _log "api tier=$tier model=$model tokens=$tok"

  # [HARDENED #4] Build JSON body to a temp file to avoid API key in ps
  # jq --arg safely handles all escaping — no shell injection possible
  local body_file=""
  body_file=$(mktemp "$CACHE/req.XXXXXX") || { _log "mktemp failed in _call"; return 1; }
  chmod 600 "$body_file"
  jq -n --arg m "$model" --arg s "$sys" --arg c "$usr" --argjson t "$tok" \
    '{model:$m,max_tokens:$t,system:$s,messages:[{role:"user",content:$c}]}' > "$body_file"

  local resp
  # [HARDENED #4] Pass API key via stdin curl config to hide from ps
  # [HARDENED #16] Strip control chars (newlines could inject curl config directives)
  local escaped_key="${ANTHROPIC_API_KEY}"
  escaped_key="${escaped_key//$'\n'/}"; escaped_key="${escaped_key//$'\r'/}"
  escaped_key="${escaped_key//\\/\\\\}"
  escaped_key="${escaped_key//\"/\\\"}"
  resp=$(printf 'header = "x-api-key: %s"\n' "$escaped_key" | \
    curl -s --max-time 30 -K - \
    -H "content-type: application/json" \
    -H "anthropic-version: 2023-06-01" \
    -d @"$body_file" \
    "https://api.anthropic.com/v1/messages" 2>/dev/null) || {
    rm -f "$body_file" 2>/dev/null
    echo "ERROR: API failed"; return 1
  }
  rm -f "$body_file" 2>/dev/null

  # [HARDENED #11] Validate API response structure
  local text
  text=$(echo "$resp" | jq -r '.content[0].text // empty' 2>/dev/null)
  if [[ -z "$text" ]]; then
    local err_msg
    err_msg=$(echo "$resp" | jq -r '.error.message // "Unknown API error"' 2>/dev/null)
    _log "api error: $err_msg"
    echo "ERROR: $err_msg"
    return 1
  fi
  # Strip markdown fences if model wraps JSON in ```json ... ```
  text=$(echo "$text" | sed '/^```/d')
  echo "$text"
}

# ─── Session discovery ────────────────────────────────────────────────────────
_is_cc() {
  _validate_pane_id "$1" || return 1
  local pid
  pid=$(tmux display-message -t "$1" -p '#{pane_pid}' 2>/dev/null) || return 1
  # Validate pid is numeric
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  # Portable: try Linux pstree -p, macOS pstree, then ps-based tree walk
  { pstree -p "$pid" 2>/dev/null || pstree "$pid" 2>/dev/null ||
    ps -A -o pid= -o ppid= -o comm= 2>/dev/null |
    awk -v p="$pid" 'BEGIN{a[p]=1} a[$2]{a[$1]=1; print $3}'; } |
    grep -qi "claude" && return 0
  return 1
}

_cap() {
  _validate_pane_id "$1" || { echo "[invalid]"; return; }
  tmux capture-pane -t "$1" -p -S "-${CAP}" 2>/dev/null || echo "[gone]"
}

_discover() {
  while IFS='|' read -r pid sn wi pi pp pt; do
    [[ -z "$pid" ]] && continue
    # Validate pane ID format from tmux output
    [[ "$pid" =~ ^%[0-9]+$ ]] || continue
    # Sanitize label: alphanumeric, colon, dot, hyphen, underscore only
    local label="${sn}:${wi}.${pi}"
    [[ "$label" =~ ^[a-zA-Z0-9:._-]+$ ]] || continue
    if _is_cc "$pid"; then
      echo "${pid}|${label}"
    fi
  done < <(tmux list-panes -a -F \
    '#{pane_id}|#{session_name}|#{window_index}|#{pane_index}|#{pane_pid}|#{pane_title}' 2>/dev/null)
}

# ─── Pattern-based state detection (no AI) ────────────────────────────────────
_detect() {
  local tail; tail=$(tail -20 <<< "$1")
  # Regex patterns stored in variables for [[ =~ ]] (avoids quoting issues)
  local _re_perm='Allow .+\(|Approve .+\(|\(Y\)es.*\(N\)o|❯ .*(Yes|No|Always)'
  local _re_ques='(What would you|How should I|Which approach|Do you prefer|Should I |Would you like me to|Could you clarify).*\?'
  local _re_work='⏺|╭──|⠋|⠙|⠹|⠸|⠼|⠴|⠦|⠧|⠇|⠏'
  # Permission: look for Claude Code tool-approval patterns
  if [[ "$tail" =~ $_re_perm ]]; then
    local t; t=$(grep -oE '(Bash|Read|Write|Edit|MultiEdit|WebFetch|Task|Glob|Grep|LS|WebSearch|NotebookEdit)\([^)]+\)' <<< "$tail" | tail -1)
    echo "permission|${t:-unknown}"; return
  fi
  # Question: require trailing ? to reduce false positives from code output
  # Keep grep -qiE here — case-insensitive [[ =~ ]] requires Bash 4+
  if grep -qiE "$_re_ques" <<< "$tail"; then
    local q; q=$(grep -iE '(What|How|Which|Should|Would|Could|Do you).*\?' <<< "$tail" | tail -1 | sed 's/^[[:space:]]*//' | head -c 120)
    echo "question|$q"; return
  fi
  # Error: anchor patterns — keep grep for per-line ^ anchoring
  if grep -qE '(^Error:|^ERROR[ :]|FAILED|^panic:|^Traceback \(most recent)' <<< "$tail"; then
    echo "error|"; return
  fi
  # Working: use Claude Code-specific indicators (⏺ bullet, box drawing, spinners)
  if [[ "$tail" =~ $_re_work ]]; then
    echo "working|"; return
  fi
  echo "idle|"
}

# ─── DAEMON ───────────────────────────────────────────────────────────────────
_daemon_scan() {
  local n=0 w=0 q=0 p=0 e=0 notify_body=""
  local scan_tmp
  scan_tmp=$(mktemp "$CACHE/scan.XXXXXX") || { _log "mktemp failed in _daemon_scan"; return; }

  # Process hook events into a pane→type lookup (bash 3.2: no associative arrays)
  local events_dir="$CACHE/events"
  local evt_panes=""
  if [[ -d "$events_dir" ]]; then
    local evt
    for evt in "$events_dir"/*.json; do
      [[ -f "$evt" ]] || continue
      local evt_type evt_pane
      evt_type=$(jq -r '.type // empty' "$evt" 2>/dev/null) || { rm -f "$evt"; continue; }
      evt_pane=$(jq -r '.pane // empty' "$evt" 2>/dev/null) || { rm -f "$evt"; continue; }
      [[ -n "$evt_type" ]] && [[ -n "$evt_pane" ]] && evt_panes+="${evt_pane}=${evt_type}|"
      rm -f "$evt"
    done
  fi

  while IFS='|' read -r pid label; do
    [[ -z "$pid" ]] && continue; n=$((n+1))
    local content; content=$(tmux capture-pane -t "$pid" -p -S -30 2>/dev/null) || { _log "pane $pid gone"; continue; }
    local si st sd; si=$(_detect "$content"); st=${si%%|*}; sd=${si#*|}
    # Hook override: if regex says working/idle but hook says question/stop, trust the hook
    if [[ "$st" == "working" || "$st" == "idle" ]] && [[ -n "$evt_panes" ]]; then
      local hook_type=""
      hook_type=$(printf '%s' "$evt_panes" | grep -oE "${pid}=[^|]+" | head -1 | cut -d= -f2) || true
      if [[ "$hook_type" == "question" ]]; then
        st="question"; sd="(detected via hook)"
      elif [[ "$hook_type" == "stop" ]]; then
        st="question"; sd="session stopped — may need input"
      fi
    fi
    # Grab last few non-empty lines for notification context
    local tail_lines=""
    if [[ "$st" == "permission" || "$st" == "question" || "$st" == "error" ]]; then
      tail_lines=$(printf '%s' "$content" | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' | grep -v '^[[:space:]]*$' | tail -4 | head -c 300)
    fi
    case "$st" in
      permission) p=$((p+1)); w=$((w+1))
        _log_permission "$pid" "$label" "$sd"
        notify_body+="${label} — permission"$'\n'"${tail_lines}"$'\n\n' ;;
      question) q=$((q+1)); w=$((w+1))
        notify_body+="${label} — question"$'\n'"${tail_lines}"$'\n\n' ;;
      error) e=$((e+1)); w=$((w+1))
        notify_body+="${label} — error"$'\n'"${tail_lines}"$'\n\n' ;;
    esac
    jq -nc --arg P "$pid" --arg l "$label" --arg s "$st" --arg d "$sd" \
      '{pane:$P,label:$l,state:$s,detail:$d}' >> "$scan_tmp"
  done < <(_discover)

  local sj
  if [[ ! -s "$scan_tmp" ]]; then sj="[]"
  elif ! sj=$(jq -s '.' "$scan_tmp" 2>/dev/null); then _log "scan: corrupt scan_tmp"; rm -f "$scan_tmp" 2>/dev/null; return
  fi

  rm -f "$scan_tmp" 2>/dev/null

  local lb="▱▱▱▱▱"; local a=$((n-w))
  [[ $a -ge 1 ]] && lb="▰▱▱▱▱"; [[ $a -ge 2 ]] && lb="▰▰▱▱▱"
  [[ $a -ge 3 ]] && lb="▰▰▰▱▱"; [[ $a -ge 4 ]] && lb="▰▰▰▰▱"
  [[ $a -ge 5 ]] && lb="▰▰▰▰▰"
  # Trim whitespace from wc -l (macOS pads with spaces)
  local pl; pl=$(wc -l < "$PERMS_LOG" 2>/dev/null || echo 0); pl="${pl// /}"
  [[ "$pl" =~ ^[0-9]+$ ]] || pl=0

  # [HARDENED #9] Atomic write via temp + rename — only replace if valid
  local tmp_state
  tmp_state=$(mktemp "$CACHE/state.XXXXXX") || { _log "mktemp failed for state write"; return; }
  chmod 600 "$tmp_state"
  if jq -n --argjson ss "$sj" --argjson n "$n" --argjson w "$w" \
    --argjson q "$q" --argjson p "$p" --argjson e "$e" \
    --arg lb "$lb" --argjson pl "$pl" --arg u "$(date -Iseconds)" \
    '{sessions:$ss,count:$n,waiting:$w,questions:$q,permissions:$p,
      errors:$e,load:$lb,perms_logged:$pl,updated:$u}' > "$tmp_state" \
    && [[ -s "$tmp_state" ]]; then
    mv "$tmp_state" "$DAEMON_STATE"
  else
    _log "scan: jq state write failed (n=$n w=$w)"
    rm -f "$tmp_state"
  fi

  tmux set-option -g @ccw_count "$n" 2>/dev/null || true
  tmux set-option -g @ccw_waiting "$w" 2>/dev/null || true
  tmux set-option -g @ccw_questions "$q" 2>/dev/null || true
  tmux set-option -g @ccw_permissions "$p" 2>/dev/null || true
  tmux set-option -g @ccw_errors "$e" 2>/dev/null || true
  tmux set-option -g @ccw_load "$lb" 2>/dev/null || true
  tmux set-option -g @ccw_perms_logged "$pl" 2>/dev/null || true

  local prev; prev=$(tmux show-option -gqv @ccw_prev_w 2>/dev/null || echo 0)
  prev="${prev//[^0-9]/}"
  [[ -z "$prev" ]] && prev=0
  if [[ "$w" -gt "${prev:-0}" ]] && [[ "$w" -gt 0 ]]; then
    echo -ne '\a'
    _bell_alert
    if [[ "$w" -eq 1 ]]; then
      _voice_alert "One session needs attention."
      _notify_alert "1 session needs attention" "$notify_body"
    else
      _voice_alert "$w sessions need attention."
      _notify_alert "$w sessions need attention" "$notify_body"
    fi
  fi
  tmux set-option -g @ccw_prev_w "$w" 2>/dev/null || true
}

_daemon_start() {
  # [HARDENED #5] Atomic mkdir-based locking to prevent race conditions
  local lockdir="$CACHE/daemon.lock"
  if [[ -f "$DAEMON_PID" ]]; then
    local existing_pid
    existing_pid=$(cat "$DAEMON_PID" 2>/dev/null || echo "")
    if [[ -n "$existing_pid" ]] && [[ "$existing_pid" =~ ^[0-9]+$ ]] && kill -0 "$existing_pid" 2>/dev/null; then
      echo "Already running (PID $existing_pid)"; return
    fi
    # Stale PID file — clean up
    rm -f "$DAEMON_PID"
  fi

  # Atomic lock — prevents two concurrent starts from racing
  if ! mkdir "$lockdir" 2>/dev/null; then
    local lock_mod
    lock_mod=$(stat -c %Y "$lockdir" 2>/dev/null || stat -f %m "$lockdir" 2>/dev/null || echo 0)
    [[ "$lock_mod" =~ ^[0-9]+$ ]] || lock_mod=0
    if [[ $(( $(date +%s) - lock_mod )) -gt 60 ]]; then
      rmdir "$lockdir" 2>/dev/null || rm -rf "$lockdir" 2>/dev/null
      mkdir "$lockdir" 2>/dev/null || { echo "Lock contention"; return 1; }
    else
      echo "Another daemon is starting (lock: $lockdir)"; return 1
    fi
  fi

  (
    trap 'rm -f "$DAEMON_PID"; exit 0' INT TERM HUP
    while true; do _daemon_scan 2>>"$LOGFILE" || _log "scan: failed"; sleep "$SCAN_INT"; done
  ) &
  local child_pid=$!
  disown

  # Write PID from parent — $! is the correct subshell PID (portable, no BASHPID needed)
  local tmp_pid; tmp_pid=$(mktemp "$CACHE/pid.XXXXXX") || { _log "mktemp failed for PID write"; return 1; }
  echo "$child_pid" > "$tmp_pid"
  mv "$tmp_pid" "$DAEMON_PID"

  # Release startup lock
  rmdir "$lockdir" 2>/dev/null || true

  _log "daemon start pid=$child_pid interval=${SCAN_INT}s"
  echo "Daemon started (PID $child_pid, every ${SCAN_INT}s)"
}

_daemon_stop() {
  [[ -f "$DAEMON_PID" ]] || { echo "Not running"; return; }
  local p; p=$(cat "$DAEMON_PID")
  # [HARDENED] Validate PID is numeric before kill
  [[ "$p" =~ ^[0-9]+$ ]] || { echo "Corrupt PID file"; rm -f "$DAEMON_PID"; return; }
  kill "$p" 2>/dev/null && echo "Stopped (PID $p)" || echo "Stale PID"
  rm -f "$DAEMON_PID"
}

_daemon_status() {
  if [[ -f "$DAEMON_PID" ]]; then
    local p; p=$(cat "$DAEMON_PID")
    [[ "$p" =~ ^[0-9]+$ ]] || { echo "Corrupt PID file"; return; }
    if kill -0 "$p" 2>/dev/null; then
      echo "Running (PID $p)"
      [[ -f "$DAEMON_STATE" ]] && jq '{sessions:.count,waiting:.waiting,perms:.perms_logged}' "$DAEMON_STATE"
    else echo "Not running (stale PID)"; rm -f "$DAEMON_PID"; fi
  else echo "Not running"; fi
}

# ─── STATUS BAR (called by tmux, must be <50ms) ──────────────────────────────
_statusbar() {
  [[ ! -f "$DAEMON_STATE" ]] && { echo "cc:--"; return; }
  local age=0
  if command -v stat &>/dev/null; then
    local mod; mod=$(stat -c %Y "$DAEMON_STATE" 2>/dev/null || stat -f %m "$DAEMON_STATE" 2>/dev/null || echo 0)
    # [HARDENED #15] Fallback if stat fails
    [[ "$mod" =~ ^[0-9]+$ ]] || mod=0
    age=$(( $(date +%s) - mod ))
  fi
  [[ $age -gt 120 ]] && { echo "#[fg=colour8]cc:stale#[default]"; return; }

  _read_state
  local n=$_st_n w=$_st_w q=$_st_q p=$_st_p e=$_st_e lb=$_st_lb pl=$_st_pl

  [[ "$n" -eq 0 ]] && { echo "#[fg=colour8]cc:0#[default]"; return; }

  local o=""
  if [[ "$w" -gt 0 ]]; then o+="#[fg=colour0,bold]●${n}#[default]"
  else o+="#[fg=colour0]●${n}#[default]"; fi
  [[ "$q" -gt 0 ]] && o+=" #[fg=colour0]?${q}#[default]"
  [[ "$p" -gt 0 ]] && o+=" #[fg=colour0,bold]!${p}#[default]"
  [[ "$e" -gt 0 ]] && o+=" #[fg=colour0]x${e}#[default]"
  local ac=$((n-w))
  if [[ $ac -gt 3 ]]; then o+=" #[fg=colour0,bold]${lb}#[default]"
  else o+=" #[fg=colour0]${lb}#[default]"; fi
  [[ "$pl" -gt 20 ]] && o+=" #[fg=colour0]P${pl}#[default]"
  echo "$o"
}

# ─── AI ANALYSIS ──────────────────────────────────────────────────────────────
_APROMPT='Analyze this Claude Code terminal. Return ONLY JSON:
{"status":"working|waiting|idle|error|done","waiting_for_user":false,"waiting_reason":null,"pending_question":null,"pending_permission":null,"branch":"unknown","task_summary":"","current_action":"","files":[],"cognitive_load":{"score":1,"label":"trivial","reasoning":"","safe_to_switch_away":true,"context_cost":""},"suggested_action":""}
Fill all fields. pending_question = verbatim question text if Claude is asking user something. pending_permission = {"tool":"","detail":"","description":""} if asking for tool approval. cognitive_load.score: 1=trivial 2=low 3=medium 4=high 5=intense. ONLY JSON output.'

_analyze() {
  local result
  if result=$(_call "think" "$_APROMPT" "Session: $2\n\nTerminal:\n$1\n\nHistory:\n$3" 500); then
    echo "$result"
  else
    echo '{"status":"error","waiting_for_user":false,"pending_question":null,"pending_permission":null,"branch":"?","task_summary":"API error","current_action":"","files":[],"cognitive_load":{"score":1,"label":"?","reasoning":"","safe_to_switch_away":true,"context_cost":""},"suggested_action":""}'
  fi
}

_cbar() { case "$1" in
  0|1) echo -e "${CG}▰${D}▱▱▱▱${R} ${CG}${2}${R}";; 2) echo -e "${CG}▰▰${D}▱▱▱${R} ${CG}${2}${R}";;
  3) echo -e "${CY}▰▰▰${D}▱▱${R} ${CY}${2}${R}";; 4) echo -e "${CR}▰▰▰▰${D}▱${R} ${CR}${2}${R}";;
  5) echo -e "${CR}${B}▰▰▰▰▰${R} ${CR}${B}${2}${R}";; *) echo -e "${D}▱▱▱▱▱${R} ${D}${2}${R}";; esac; }
_sbadge() { case "$1" in
  working) echo -e "${CG}●${R}";; waiting) echo -e "${CY}${B}◉${R}";; idle) echo -e "${D}○${R}";;
  error) echo -e "${CR}✖${R}";; done) echo -e "${CC}✔${R}";; *) echo -e "${D}?${R}";; esac; }

# ─── CMD: (default) ──────────────────────────────────────────────────────────
_cmd_default() {
  [[ ! -f "$DAEMON_STATE" ]] && { echo "Run: ccwatch setup"; return; }
  _read_state
  local n=$_st_n w=$_st_w q=$_st_q p=$_st_p e=$_st_e lb=$_st_lb pl=$_st_pl
  echo -e "${CG}●${R} ${n} sessions  ${lb}"
  # Show per-session details from daemon state
  local _line
  while IFS=$'\t' read -r _line; do
    [[ -z "$_line" ]] && continue
    local _sl _ss _sd
    IFS=$'\t' read -r _sl _ss _sd <<< "$_line"
    case "$_ss" in
      permission) echo -e "  ${CY}🔑 ${_sl}${R} ${D}— $(_e "$_sd")${R}" ;;
      question)   echo -e "  ${CC}❓ ${_sl}${R} ${D}— $(_e "${_sd:0:80}")${R}" ;;
      error)      echo -e "  ${CR}✖ ${_sl}${R}" ;;
    esac
  done < <(jq -r '.sessions[]? | [.label,.state,.detail] | @tsv' "$DAEMON_STATE" 2>/dev/null)
  [[ "$pl" -gt 10 ]] && echo -e "  ${CM}📋 ${pl} perms → ccwatch permissions${R}"
  if _voice_enabled; then
    local vmsg
    vmsg=$(_voice_summary "$n" "" \
      "$w" "is waiting" "are waiting" \
      "$q" "question pending" "questions pending" \
      "$p" "permission request" "permission requests" \
      "$e" "error" "errors")
    [[ "$w" -eq 0 ]] && [[ "$e" -eq 0 ]] && vmsg+=" All sessions running smoothly."
    _voice_alert "$vmsg"
  fi
  return 0
}

# ─── CMD: ls ──────────────────────────────────────────────────────────────────
# Sub-functions share caller's namespace (_LS_S, _LS_A arrays)

_ls_analyze() {
  local h; h=$(_hist 20)
  while IFS='|' read -r pid lbl; do [[ -z "$pid" ]] && continue
    _LS_S+=("$pid|$lbl")
    _event "$pid" "scan" ""
  done < <(_discover)
  [[ ${#_LS_S[@]} -eq 0 ]] && { echo -e "${D}No Claude Code sessions.${R}"; return 1; }

  echo -e "${D}Analyzing ${#_LS_S[@]} session(s)...${R}"
  local _adir; _adir=$(mktemp -d "$CACHE/par.XXXXXX") || { echo "ERROR: mktemp failed"; return 1; }
  for i in "${!_LS_S[@]}"; do
    local pid lbl; IFS='|' read -r pid lbl <<< "${_LS_S[$i]}"
    ( _analyze "$(_cap "$pid")" "$lbl" "$h" > "$_adir/$i" ) &
  done
  wait
  local _fallback='{"status":"error","waiting_for_user":false,"pending_question":null,"pending_permission":null,"branch":"?","task_summary":"API error","current_action":"","files":[],"cognitive_load":{"score":1,"label":"?","reasoning":"","safe_to_switch_away":true,"context_cost":""},"suggested_action":""}'
  for i in "${!_LS_S[@]}"; do
    local result; result=$(cat "$_adir/$i" 2>/dev/null)
    if [[ -z "$result" ]] || ! jq -e '.status' <<< "$result" &>/dev/null; then
      _LS_A+=("$_fallback")
    else
      _LS_A+=("$result")
    fi
  done
  rm -rf "$_adir" 2>/dev/null
}

_ls_render_session() {
  # Mutates caller vars: _ls_lo[], _ls_pn, _ls_vw, _ls_vwt, _ls_vi, _ls_ve, _ls_vd, _ls_focus_*
  local idx="$1" first="$2"
  local pid lbl; IFS='|' read -r pid lbl <<< "${_LS_S[$idx]}"
  local a="${_LS_A[$idx]}"
  local st ts na br cs cl ss sa
  local _sf
  _sf=$(jq -r '[(.status//"?"),(.task_summary//"?"),(.current_action//"?"),
    (.branch//"?"),(.cognitive_load.score//0),(.cognitive_load.label//"?"),
    (.cognitive_load.safe_to_switch_away//false),(.suggested_action//"")
  ]|join("\t")' <<< "$a" 2>/dev/null) || true
  IFS=$'\t' read -r st ts na br cs cl ss sa <<< "$_sf"
  [[ "$cs" -le 2 ]] && _ls_lo+=("$lbl")
  case "$st" in working) _ls_vw=$((_ls_vw+1));; waiting) _ls_vwt=$((_ls_vwt+1));;
    idle) _ls_vi=$((_ls_vi+1));; error) _ls_ve=$((_ls_ve+1));; esac

  [[ "$first" -ne 1 ]] && echo -e "  ${D}──────────────────────────────────────────────────────────────${R}"

  local sw; if [[ "$ss" == "true" ]]; then sw="${CG}↔${R}"; else sw="${CY}⚠${R}"; fi
  echo -e "  $(_sbadge "$st") ${B}${lbl}${R}  ${D}[$(_e "$br")]${R}  $(_cbar "$cs" "$cl")  $sw"
  echo -e "  ${D}│${R} $(_e "$ts")"
  echo -e "  ${D}│${R} ${D}↳ $(_e "$na")${R}"
  [[ -n "$sa" ]] && echo -e "  ${D}│${R} ${CC}→ $(_e "$sa")${R}"

  local qq tn pd _af
  _af=$(jq -r '[(.pending_question//"null"),
    (.pending_permission.tool//"null"),(.pending_permission.detail//"null")
  ]|join("\t")' <<< "$a" 2>/dev/null) || true
  IFS=$'\t' read -r qq tn pd <<< "$_af"
  if [[ "$qq" != "null" ]] && [[ -n "$qq" ]]; then
    echo -e "  ${D}│${R} ${BC}${CW} ❓ ${R} ${CC}$(_e "$qq")${R}"; _ls_pn=$((_ls_pn+1))
  fi
  if [[ "$tn" != "null" ]] && [[ -n "$tn" ]]; then
    echo -e "  ${D}│${R} ${BY}${CW} 🔑 ${R} ${CY}$(_e "$tn")($(_e "$pd"))${R}"
    _ls_pn=$((_ls_pn+1))
  fi

  # Track "Focus next" candidate: permission(3) > question(2) > error(1), tiebreak by cognitive load
  local _fpri=0 _fdesc=""
  if [[ "$tn" != "null" ]] && [[ -n "$tn" ]]; then
    _fpri=3; _fdesc="permission — ${tn}(${pd})"
  elif [[ "$qq" != "null" ]] && [[ -n "$qq" ]]; then
    _fpri=2; _fdesc="question"
  elif [[ "$st" == "error" ]]; then
    _fpri=1; _fdesc="error"
  fi
  if [[ $_fpri -gt ${_ls_focus_pri:-0} ]] || { [[ $_fpri -eq ${_ls_focus_pri:-0} ]] && [[ $_fpri -gt 0 ]] && [[ "${cs:-0}" -gt "${_ls_focus_cs:-0}" ]]; }; then
    _ls_focus_lbl="$lbl"; _ls_focus_pri=$_fpri; _ls_focus_desc="$_fdesc"; _ls_focus_cs="${cs:-0}"
  fi

  if _voice_enabled; then
    _ls_vd+=" Session ${lbl}, status ${st}, ${cl} cognitive load. ${ts}. Currently ${na}."
    [[ "$qq" != "null" ]] && [[ -n "$qq" ]] && _ls_vd+=" Asking: ${qq}"
    [[ "$tn" != "null" ]] && [[ -n "$tn" ]] && _ls_vd+=" Waiting for permission to use ${tn}."
    [[ -n "$sa" ]] && _ls_vd+=" Suggested action: ${sa}."
  fi
}

_ls_footer_and_voice() {
  echo -e "  ${D}──────────────────────────────────────────────────────────────${R}"
  [[ $_ls_pn -gt 0 ]] && echo -e "  ${CY}${B}⚡ ${_ls_pn} need attention${R}"
  [[ ${#_ls_lo[@]} -gt 0 ]] && echo -e "  ${D}💡 Quick switch: ${_ls_lo[*]}${R}"
  [[ ${_ls_focus_pri:-0} -gt 0 ]] && echo -e "  ${CC}→ Focus next: ${_ls_focus_lbl} ($(_e "$_ls_focus_desc"))${R}"
  echo ""
  if _voice_enabled; then
    local vmsg
    vmsg=$(_voice_summary "${#_LS_S[@]}" "sorted by cognitive load" \
      "$_ls_vw" "is working" "are working" \
      "$_ls_vi" "is idle" "are idle" \
      "$_ls_vwt" "is waiting" "are waiting" \
      "$_ls_ve" "has errors" "have errors" \
      "$_ls_pn" "session needs attention" "sessions need attention")
    vmsg+="$_ls_vd"
    _voice_alert "$vmsg"
  fi
}

_cmd_ls() {
  _check_deps; _check_api
  local _LS_S=() _LS_A=()
  _ls_analyze || return

  # Sort by cognitive load (bash insertion sort — 0 forks)
  local SC=(); for i in "${!_LS_A[@]}"; do
    SC+=($(jq -r '.cognitive_load.score // 0' <<< "${_LS_A[$i]}" 2>/dev/null || echo 0)); done
  local SI=()
  for i in "${!SC[@]}"; do
    local j=0
    while [[ $j -lt ${#SI[@]} ]] && [[ ${SC[${SI[$j]}]} -le ${SC[$i]} ]]; do j=$((j+1)); done
    SI=("${SI[@]:0:$j}" "$i" "${SI[@]:$j}")
  done

  echo ""
  echo -e "  ${B}${CC}🔭 Sessions${R}  ${D}(${#_LS_S[@]} found, sorted by cognitive load)${R}"
  echo -e "  ${D}──────────────────────────────────────────────────────────────${R}"
  local _ls_pn=0 _ls_lo=() _ls_vw=0 _ls_vwt=0 _ls_vi=0 _ls_ve=0 _ls_vd="" first=1
  local _ls_focus_lbl="" _ls_focus_pri=0 _ls_focus_desc="" _ls_focus_cs=0
  for idx in "${SI[@]}"; do
    _ls_render_session "$idx" "$first"
    first=0
  done
  _ls_footer_and_voice
}

# ─── CMD: status ──────────────────────────────────────────────────────────────
_cmd_status() {
  _check_deps; _check_api
  local t="${1:-$(tmux display-message -p '#{pane_id}' 2>/dev/null)}"
  [[ "$t" != %* ]] && t=$(tmux display-message -t "$t" -p '#{pane_id}' 2>/dev/null)
  _validate_pane_id "$t" || { echo "Invalid pane: $t"; return 1; }
  local l; l=$(tmux display-message -t "$t" -p '#{session_name}:#{window_index}.#{pane_index}')
  echo -e "${D}Analyzing ${l}...${R}"
  local a; a=$(_analyze "$(_cap "$t")" "$l" "$(_hist 20)")
  # Single jq call extracts all fields as tab-separated
  local st br cs cl cr cc sa ts na f qq pp_tool pp_detail pp_desc
  local _sf
  _sf=$(jq -r '[(.status//"?"),(.branch//"?"),(.cognitive_load.score//0),
    (.cognitive_load.label//"?"),(.cognitive_load.reasoning//""),
    (.cognitive_load.context_cost//""),(.suggested_action//""),
    (.task_summary//"?"),(.current_action//"?"),
    ((.files//[])|join(", ")),(.pending_question//"null"),
    (.pending_permission.tool//"null"),(.pending_permission.detail//"null"),
    (.pending_permission.description//"null")
  ]|join("\t")' <<< "$a" 2>/dev/null) || true
  IFS=$'\t' read -r st br cs cl cr cc sa ts na f qq pp_tool pp_detail pp_desc <<< "$_sf"

  echo ""
  echo -e "  $(_sbadge "$st") ${B}${l}${R} ${D}[$(_e "$br")]${R}"
  echo -e "  $(_cbar "$cs" "$cl")"; echo -e "  ${D}$(_e "$cr")${R}"
  [[ -n "$cc" ]] && echo -e "  ${D}Switch cost: $(_e "$cc")${R}"
  echo ""; echo -e "  ${B}Task:${R}  $(_e "$ts")"
  echo -e "  ${B}Now:${R}   $(_e "$na")"
  [[ -n "$f" ]] && echo -e "  ${B}Files:${R} $(_e "$f")"
  [[ -n "$sa" ]] && echo -e "  ${B}Next:${R}  ${CC}$(_e "$sa")${R}"
  [[ "$qq" != "null" ]] && { echo ""; echo -e "  ${BC}${CW} ❓ ${R} ${CC}$(_e "$qq")${R}"; }
  [[ "$pp_tool" != "null" ]] && { echo ""; echo -e "  ${BY}${CW} 🔑 ${R} ${CY}$(_e "$pp_tool")($(_e "$pp_detail")): $(_e "$pp_desc")${R}"; }
  if _voice_enabled; then
    local vmsg="Session ${l} on branch ${br}. Status is ${st}, with ${cl} cognitive load."
    vmsg+=" Task: ${ts}. Currently: ${na}."
    [[ -n "$cr" ]] && vmsg+=" ${cr}."
    [[ -n "$cc" ]] && vmsg+=" Switch cost: ${cc}."
    [[ -n "$f" ]] && vmsg+=" Files involved: ${f}."
    [[ -n "$sa" ]] && vmsg+=" Suggested next step: ${sa}."
    [[ "$qq" != "null" ]] && vmsg+=" Claude is asking: ${qq}."
    [[ "$pp_tool" != "null" ]] && vmsg+=" Waiting for permission approval."
    _voice_alert "$vmsg"
  fi
}

# ─── CMD: permissions ─────────────────────────────────────────────────────────
_cmd_perms() {
  _check_deps; _check_api
  [[ ! -f "$PERMS_LOG" ]] || [[ $(wc -l < "$PERMS_LOG") -eq 0 ]] && {
    echo -e "${D}No permissions logged yet. Run 'ccwatch daemon start' and use Claude Code.${R}"; return; }
  local agg; agg=$(jq -s 'group_by(.tool)|map({tool:.[0].tool,count:length,
    sessions:([.[].label]|unique),first:(sort_by(.ts)|.[0].ts),
    last:(sort_by(.ts)|.[-1].ts)})|sort_by(-.count)' "$PERMS_LOG" 2>/dev/null)
  local total; total=$(echo "$agg" | jq 'length')
  echo -e "${B}${CC}  Permission Summary${R}"; echo ""
  echo "$agg" | jq -r '.[]|"  \(.count)x  \(.tool)  (\(.sessions|length) sessions)"' | head -20
  echo ""; echo -e "${D}  ${total} patterns from $(wc -l < "$PERMS_LOG") requests${R}"; echo ""

  local cur="{}"; [[ -f "$HOME/.claude/settings.json" ]] && cur=$(cat "$HOME/.claude/settings.json" 2>/dev/null)
  echo -e "${D}Generating settings.json suggestions...${R}"
  local r; r=$(_call "think" \
'Claude Code permissions expert. Given permission request data, generate settings.json changes.
Rules: permissions go in {"permissions":{"allow":["Tool(pattern)",...]}}
Tool names: Read, Write, Edit, MultiEdit, Bash, Glob, Grep, LS, WebFetch, WebSearch, Task
Bash supports patterns: Bash(npm:*), Bash(git *), Bash(python *)
Be conservative — narrowest pattern that covers usage. Never allow Bash(rm -rf *) or Bash(sudo *).
Output JSON only (no fences):
{"global":{"description":"~/.claude/settings.json","permissions":{"allow":[]}},"project":{"description":".claude/settings.json","permissions":{"allow":[]}},"summary":"1-2 sentences","warnings":[]}' \
    "Requests:\n$agg\n\nCurrent settings:\n$cur" 500) || { echo "API error"; return 1; }

  # [HARDENED #19] Atomic write via temp + rename (consistent with other file writes)
  local tmp_sug
  tmp_sug=$(mktemp "$CACHE/perm-sug.XXXXXX") || { echo "ERROR: mktemp failed"; return 1; }
  chmod 600 "$tmp_sug"
  echo "$r" > "$tmp_sug"
  mv "$tmp_sug" "$CACHE/perm-suggestions.json"
  local sum; sum=$(echo "$r" | jq -r '.summary // ""' 2>/dev/null)
  echo ""
  echo -e "  ${B}Global (~/.claude/settings.json):${R}"
  echo "$r" | jq -r '.global.permissions // empty' 2>/dev/null | sed 's/^/    /'
  echo ""
  echo -e "  ${B}Project (.claude/settings.json):${R}"
  echo "$r" | jq -r '.project.permissions // empty' 2>/dev/null | sed 's/^/    /'
  echo ""
  [[ -n "$sum" ]] && echo -e "  ${CC}${sum}${R}"
  local warns; warns=$(echo "$r" | jq -r '.warnings[]? // empty' 2>/dev/null)
  [[ -n "$warns" ]] && { echo ""; echo "$warns" | while IFS= read -r w; do echo -e "  ${CY}⚠ ${w}${R}"; done; }
  echo ""; echo -e "  ${D}Apply: ccwatch permissions --apply [user|project]${R}"
}

_cmd_perms_apply() {
  local scope="${1:-user}"
  # [HARDENED] Validate scope
  [[ "$scope" == "user" ]] || [[ "$scope" == "project" ]] || { echo "Usage: --apply [user|project]"; return 1; }
  [[ ! -f "$CACHE/perm-suggestions.json" ]] && { echo "Run 'ccwatch permissions' first."; return 1; }
  local sug; sug=$(cat "$CACHE/perm-suggestions.json")
  local tf rules
  if [[ "$scope" == "user" ]]; then tf="$HOME/.claude/settings.json"
    rules=$(echo "$sug" | jq '.global.permissions' 2>/dev/null)
  else tf=".claude/settings.json"
    rules=$(echo "$sug" | jq '.project.permissions' 2>/dev/null)
  fi
  [[ -z "$rules" ]] || [[ "$rules" == "null" ]] && { echo "No rules for $scope."; return; }

  # [HARDENED] Validate the rules are well-formed JSON with expected structure
  if ! echo "$rules" | jq -e '.allow // empty | type == "array"' &>/dev/null; then
    echo "ERROR: Malformed permission rules. Aborting."; return 1
  fi

  # [HARDENED #18] Reject dangerous permission patterns from AI suggestions
  local _dangerous
  _dangerous=$(echo "$rules" | jq -r '.allow[]? // empty' 2>/dev/null | grep -E '^\w+\(\*\)$|^Bash\((sudo|rm -rf|chmod 777|curl.*\|.*sh)' || true)
  if [[ -n "$_dangerous" ]]; then
    echo -e "${CR}ERROR: Dangerous permission patterns detected — aborting:${R}"
    echo "$_dangerous" | while IFS= read -r d; do echo -e "  ${CR}✖ ${d}${R}"; done
    return 1
  fi

  echo -e "${B}Adding to ${tf}:${R}"; echo "$rules" | jq .; echo ""
  echo -e "${CY}Apply? [y/N]${R}"; read -rsn1 c; echo ""
  [[ "$c" != "y" ]] && [[ "$c" != "Y" ]] && { echo "Cancelled."; return; }
  mkdir -p "$(dirname "$tf")"
  if [[ -f "$tf" ]]; then
    cp "$tf" "${tf}.bak.$(date +%s)"
    # [HARDENED #10] Atomic write for settings
    local tmp_settings
    tmp_settings=$(mktemp "$(dirname "$tf")/settings.XXXXXX") || { echo "ERROR: mktemp failed"; return 1; }
    chmod 600 "$tmp_settings"
    if jq --argjson new "$rules" '.permissions//={}|.permissions.allow=((.permissions.allow//[])+($new.allow//[])|unique)' "$tf" > "$tmp_settings" 2>/dev/null; then
      mv "$tmp_settings" "$tf"
    else
      rm -f "$tmp_settings"
      echo "ERROR: Failed to merge settings. Original unchanged."; return 1
    fi
  else
    local tmp_new
    tmp_new=$(mktemp "$(dirname "$tf")/settings.XXXXXX") || { echo "ERROR: mktemp failed"; return 1; }
    chmod 600 "$tmp_new"
    if jq -n --argjson p "$rules" '{permissions:$p}' > "$tmp_new" 2>/dev/null; then
      mv "$tmp_new" "$tf"
    else
      rm -f "$tmp_new"
      echo "ERROR: Failed to create settings. Aborting."; return 1
    fi
  fi
  echo -e "${CG}✓ Applied to ${tf}${R}"
  echo -e "${D}Backup: ${tf}.bak.*  Takes effect in new Claude Code sessions.${R}"
}

_cmd_perms_reset() {
  echo -e "${CY}Clear permission logs? [y/N]${R}"; read -rsn1 c; echo ""
  [[ "$c" == "y" ]] && { rm -f "$PERMS_LOG" "$CACHE/perm-suggestions.json"; echo "Cleared."; }
}

# ─── VOICE (optional) ────────────────────────────────────────────────────────
_voice_tts() {
  command -v piper &>/dev/null && { echo "piper"; return; }
  [[ "$(uname)" == "Darwin" ]] && command -v say &>/dev/null && { echo "say"; return; }
  command -v espeak-ng &>/dev/null && { echo "espeak-ng"; return; }
  echo "none"
}

_voice_enabled() {
  # Check env var first, then persistent file toggle
  [[ "${CCWATCH_VOICE:-}" == "true" ]] && return 0
  [[ -f "$CACHE/voice_enabled" ]] && return 0
  return 1
}

_bell_enabled() {
  [[ "${CCWATCH_BELL:-}" == "true" ]] && return 0
  [[ -f "$CACHE/bell_enabled" ]] && return 0
  return 1
}

_bell_alert() {
  _bell_enabled || return
  # macOS system sound; fallback to terminal bell
  if [[ "$(uname)" == "Darwin" ]]; then
    afplay /System/Library/Sounds/Glass.aiff &>/dev/null &
  else
    echo -ne '\a'
  fi
}

_voice_alert() {
  _voice_enabled || return
  local msg="$1" be; be=$(_voice_tts); [[ "$be" == "none" ]] && return

  # [HARDENED #1 #2] Sanitize TTS input — strip ANSI, shell metacharacters,
  # and anything that could be interpreted by the shell.
  # Only allow: alphanumeric, spaces, periods, commas, hyphens, colons
  msg=$(sed 's/\x1b\[[0-9;]*m//g; s/[^a-zA-Z0-9 .,:!?()-]//g' <<< "$msg")
  # Truncate to prevent abuse
  msg="${msg:0:2000}"
  # Reject empty after sanitization
  [[ -z "$msg" ]] && return

  # [HARDENED #3] Use $CACHE for temp audio, not /tmp
  local audio_tmp="$CACHE/voice.wav"

  case "$be" in
    # msg is already sanitized to [a-zA-Z0-9 .,:!?()-]; -- is defense-in-depth
    say) say -- "$msg" &>/dev/null & ;;
    espeak-ng) espeak-ng -- "$msg" &>/dev/null & ;;
    piper)
      printf '%s' "$msg" | piper --output_file "$audio_tmp" 2>/dev/null \
        && play -q "$audio_tmp" 2>/dev/null &
      ;;
  esac
}

_cmd_voice() {
  local sub="${1:-}"
  case "$sub" in
    on)
      touch "$CACHE/voice_enabled"
      local be; be=$(_voice_tts)
      if [[ "$be" == "none" ]]; then
        echo -e "${CY}Voice enabled but no TTS backend found.${R}"
        echo "  macOS: built-in 'say' | Linux: sudo apt install espeak-ng"
      else
        echo -e "${CG}Voice on${R} (backend: $be)"
        _voice_alert "Voice enabled"
      fi
      ;;
    off)
      rm -f "$CACHE/voice_enabled"
      echo -e "${D}Voice off${R}"
      ;;
    *)
      local be; be=$(_voice_tts)
      if _voice_enabled; then echo -e "Voice: ${CG}on${R} (backend: $be)"
      else echo -e "Voice: ${D}off${R} (backend: $be)"; fi
      [[ "$be" == "none" ]] && {
        echo ""; echo "  Install: macOS → built-in 'say' | Linux → sudo apt install espeak-ng"
        echo "  Fast: pip install piper-tts"; }
      echo ""; echo "  ccwatch voice on    Enable voice"
      echo "  ccwatch voice off   Disable voice"
      ;;
  esac
}

_cmd_bell() {
  local sub="${1:-}"
  case "$sub" in
    on)
      touch "$CACHE/bell_enabled"
      echo -e "${CG}Bell on${R}"
      _bell_alert
      ;;
    off)
      rm -f "$CACHE/bell_enabled"
      echo -e "${D}Bell off${R}"
      ;;
    *)
      if _bell_enabled; then echo -e "Bell: ${CG}on${R}"
      else echo -e "Bell: ${D}off${R}"; fi
      echo ""; echo "  ccwatch bell on     Enable bell sound"
      echo "  ccwatch bell off    Disable bell sound"
      ;;
  esac
}

# ─── NOTIFY (optional Slack webhooks) ─────────────────────────────────────
_notify_enabled() {
  [[ "${CCWATCH_SLACK_WEBHOOK:-}" == "false" ]] && return 1
  [[ -f "$CACHE/notify_enabled" ]] && return 0
  [[ -n "${CCWATCH_SLACK_WEBHOOK:-}" ]] && return 0
  return 1
}

_notify_resolve_webhook() {
  [[ -n "${CCWATCH_SLACK_WEBHOOK:-}" ]] && { echo "$CCWATCH_SLACK_WEBHOOK"; return 0; }
  if [[ "$(uname)" == "Darwin" ]] && command -v security &>/dev/null; then
    security find-generic-password -s ccwatch -a slack-webhook -w 2>/dev/null && return 0
  fi
  return 1
}

_notify_resolve_user_id() {
  [[ -n "${CCWATCH_SLACK_USER_ID:-}" ]] && { echo "$CCWATCH_SLACK_USER_ID"; return 0; }
  if [[ "$(uname)" == "Darwin" ]] && command -v security &>/dev/null; then
    security find-generic-password -s ccwatch -a slack-user-id -w 2>/dev/null && return 0
  fi
  return 1
}

_notify_send() {
  local title="$1" body="$2"
  local webhook
  webhook=$(_notify_resolve_webhook) || return 1
  # Validate webhook URL pattern
  [[ "$webhook" =~ ^https://hooks\.slack\.com/services/ ]] || return 1
  # Sanitize body: strip all ANSI/OSC/CSI sequences, limit length
  body=$(printf '%s' "$body" | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g; s/\x1b][^\x07]*\x07//g; s/\x1b[^[][^a-zA-Z]*[a-zA-Z]//g' | head -c 1900)
  local mention_uid=""
  mention_uid=$(_notify_resolve_user_id 2>/dev/null) || true
  local fallback_text="$title: $body"
  mention_uid=$(printf '%s' "$mention_uid" | tr '[:lower:]' '[:upper:]')
  if [[ -n "$mention_uid" ]] && [[ "$mention_uid" =~ ^[A-Z0-9]+$ ]]; then
    fallback_text="<@${mention_uid}> ${fallback_text}"
  fi
  local payload
  payload=$(jq -nc --arg t "$title" --arg d "$body" --arg ts "$(date '+%Y-%m-%d %H:%M:%S')" --arg fb "$fallback_text" \
    '{text:$fb,blocks:[{type:"section",text:{type:"mrkdwn",text:("*"+$t+"*\n\n"+$d)}},{type:"context",elements:[{type:"mrkdwn",text:("ccwatch · "+$ts)}]}]}')
  # [HARDENED] Pass webhook URL via curl config to hide from ps
  local curl_cfg
  curl_cfg=$(mktemp "$CACHE/curl.XXXXXX") || { _log "notify: mktemp failed"; return 1; }
  chmod 600 "$curl_cfg"
  printf 'url = "%s"\n' "$webhook" > "$curl_cfg"
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Content-Type: application/json" \
    -d "$payload" -K "$curl_cfg" 2>/dev/null) || true
  rm -f "$curl_cfg"
  echo "$code"
}

_notify_cooldown_ok() {
  local cooldown="${CCWATCH_NOTIFY_COOLDOWN:-0}"
  [[ "$cooldown" =~ ^[0-9]+$ ]] || cooldown=0
  [[ "$cooldown" -eq 0 ]] && return 0
  local last=0
  [[ -f "$CACHE/notify_last_sent" ]] && last=$(cat "$CACHE/notify_last_sent" 2>/dev/null || echo 0)
  [[ "$last" =~ ^[0-9]+$ ]] || last=0
  local now; now=$(date +%s)
  (( now - last >= cooldown ))
}

_notify_alert() {
  _notify_enabled || { _log "notify: disabled"; return 0; }
  _notify_cooldown_ok || { _log "notify: cooldown active"; return 0; }
  local title="$1" body="$2"
  local code
  code=$(_notify_send "$title" "$body") || { _log "notify: _notify_send failed (exit $?)"; return 0; }
  if [[ "$code" =~ ^2 ]]; then
    _log "notify: sent (HTTP $code)"
    date +%s > "$CACHE/notify_last_sent"
  else
    _log "notify: Slack webhook returned $code"
  fi
}

_cmd_notify() {
  local sub="${1:-}"
  case "$sub" in
    on)
      touch "$CACHE/notify_enabled"
      echo -e "${CG}Slack notifications on${R}"
      ;;
    off)
      rm -f "$CACHE/notify_enabled"
      echo -e "${D}Slack notifications off${R}"
      ;;
    set)
      if [[ "$(uname)" != "Darwin" ]] || ! command -v security &>/dev/null; then
        echo "macOS Keychain not available. Use: export CCWATCH_SLACK_WEBHOOK=https://hooks.slack.com/services/..."
        return 1
      fi
      echo "Slack → Apps → Incoming Webhooks → Add to Slack → choose channel or your own DM"
      echo -n "Paste your Slack webhook URL: "
      read -rs url; echo ""
      [[ -z "$url" ]] && { echo "Empty URL. Aborted."; return 1; }
      if [[ ! "$url" =~ ^https://hooks\.slack\.com/services/ ]]; then
        echo -e "${CR}Invalid webhook URL. Must start with https://hooks.slack.com/services/${R}"
        return 1
      fi
      if ! security add-generic-password -s ccwatch -a slack-webhook -w "$url" -U 2>/dev/null; then
        echo -e "${CR}Failed to store webhook in Keychain.${R}"
        return 1
      fi
      echo -e "${CG}Webhook stored in macOS Keychain.${R}"
      echo -e "${D}Test it: ccwatch notify test${R}"
      ;;
    set-user)
      if [[ "$(uname)" != "Darwin" ]] || ! command -v security &>/dev/null; then
        echo "macOS Keychain not available. Use: export CCWATCH_SLACK_USER_ID=<your_id>"
        return 1
      fi
      echo "Profile → ⋮ → Copy member ID"
      echo -n "Paste your Slack member ID: "
      read -r uid; echo ""
      [[ -z "$uid" ]] && { echo "Empty ID. Aborted."; return 1; }
      if [[ ! "$uid" =~ ^[A-Z0-9]+$ ]]; then
        echo -e "${CR}Invalid member ID. Must be alphanumeric (e.g. U024BE7LH).${R}"
        return 1
      fi
      if ! security add-generic-password -s ccwatch -a slack-user-id -w "$uid" -U 2>/dev/null; then
        echo -e "${CR}Failed to store user ID in Keychain.${R}"
        return 1
      fi
      echo -e "${CG}User ID stored in macOS Keychain.${R}"
      echo -e "${D}Notifications will now mention you directly.${R}"
      ;;
    test)
      local code
      code=$(_notify_send "ccwatch test" "Slack notifications are working.") || {
        echo -e "${CR}Failed — no webhook configured.${R}"
        echo "  ccwatch notify set     Store webhook in Keychain"
        echo "  export CCWATCH_SLACK_WEBHOOK=https://hooks.slack.com/services/..."
        return 1
      }
      if [[ "$code" =~ ^2 ]]; then
        echo -e "${CG}Test notification sent (HTTP $code)${R}"
      else
        echo -e "${CR}Slack returned HTTP $code${R}"
      fi
      ;;
    delete|rm)
      local deleted=0
      if security delete-generic-password -s ccwatch -a slack-webhook &>/dev/null; then
        echo -e "${CG}Webhook removed from Keychain.${R}"; deleted=1
      fi
      if security delete-generic-password -s ccwatch -a slack-user-id &>/dev/null; then
        echo -e "${CG}User ID removed from Keychain.${R}"; deleted=1
      fi
      [[ "$deleted" -eq 0 ]] && echo "No webhook or user ID found in Keychain."
      ;;
    *)
      local src="none"
      if [[ -n "${CCWATCH_SLACK_WEBHOOK:-}" ]]; then
        src="env"
      elif [[ "$(uname)" == "Darwin" ]] && command -v security &>/dev/null; then
        security find-generic-password -s ccwatch -a slack-webhook -w &>/dev/null && src="keychain"
      fi
      local uid_src="none"
      if [[ -n "${CCWATCH_SLACK_USER_ID:-}" ]]; then
        uid_src="env"
      elif [[ "$(uname)" == "Darwin" ]] && command -v security &>/dev/null; then
        _notify_resolve_user_id &>/dev/null && uid_src="keychain"
      fi
      echo -e "${B}Slack Notifications${R}"
      if _notify_enabled; then echo -e "  Status: ${CG}on${R}"
      else echo -e "  Status: ${D}off${R}"; fi
      echo -e "  Webhook: ${B}${src}${R}"
      echo -e "  Mention: ${B}${uid_src}${R}"
      echo ""
      echo "  ccwatch notify on       Enable notifications"
      echo "  ccwatch notify off      Disable notifications"
      echo "  ccwatch notify set      Store webhook in macOS Keychain"
      echo "  ccwatch notify set-user Store Slack member ID for @mention"
      echo "  ccwatch notify test     Send a test notification"
      echo "  ccwatch notify delete   Remove webhook from Keychain"
      ;;
  esac
}

# ─── CMD: setup ───────────────────────────────────────────────────────────────
_cmd_setup() {
  echo -e "${B}${CC}ccwatch setup${R}"; echo ""

  echo -n "Checking dependencies... "
  local miss=()
  for c in tmux curl jq; do command -v "$c" &>/dev/null || miss+=("$c"); done
  if [[ ${#miss[@]} -gt 0 ]]; then
    echo -e "${CR}missing: ${miss[*]}${R}"
    echo ""
    echo "Install them first:"
    [[ " ${miss[*]} " == *" tmux "* ]] && echo "  brew install tmux   OR   sudo apt install tmux"
    [[ " ${miss[*]} " == *" jq "* ]]   && echo "  brew install jq     OR   sudo apt install jq"
    [[ " ${miss[*]} " == *" curl "* ]] && echo "  brew install curl   OR   sudo apt install curl"
    exit 1
  fi
  if ! command -v pstree &>/dev/null; then
    echo -e "${CY}pstree not found (optional but recommended)${R}"
    echo "  brew install pstree  OR  sudo apt install psmisc"
  fi
  echo -e "${CG}ok${R}"

  echo -n "Checking API key... "
  # _resolve_api_key already ran at entry point (env var → Keychain fallback)
  if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    echo -e "${CR}not set${R}"
    echo ""
    echo "ccwatch uses the Anthropic API (not your Max/Pro subscription)."
    echo "Cost: ~\$0.01/call (Sonnet think tier), ~\$0.001/call (Haiku fast tier)"
    echo ""
    echo "  1. Get a key: https://console.anthropic.com/settings/keys"
    if [[ "$(uname)" == "Darwin" ]]; then
      echo "  2. Store in Keychain (recommended):"
      echo "     ccwatch key set"
      echo "  3. Or add to your shell profile:"
      echo "     export ANTHROPIC_API_KEY=sk-ant-..."
    else
      echo "  2. Add to your shell profile:"
      echo "     export ANTHROPIC_API_KEY=sk-ant-..."
    fi
    echo "  Re-run: ccwatch setup"
    exit 1
  fi
  echo -e "${CG}ok${R}"

  local bin="$HOME/.local/bin"
  mkdir -p "$bin"
  chmod +x "$CCWATCH_DIR/ccwatch.sh"
  # [HARDENED #14] Check for unexpected existing file at symlink target
  if [[ -e "$bin/ccwatch" ]] && [[ ! -L "$bin/ccwatch" ]]; then
    echo -e "${CY}Warning: $bin/ccwatch exists and is not a symlink. Overwrite? [y/N]${R}"
    read -rsn1 ow; echo ""
    [[ "$ow" != "y" ]] && { echo "Skipping install."; return; }
    rm -f "$bin/ccwatch"
  fi
  ln -sf "$CCWATCH_DIR/ccwatch.sh" "$bin/ccwatch"
  echo -e "Installed: ${CG}ccwatch${R} → $bin/ccwatch"
  if [[ ":$PATH:" != *":$bin:"* ]]; then
    echo -e "${CY}  Add to PATH — put this in your ~/.zshrc or ~/.bashrc:${R}"
    echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
  fi

  _daemon_start
  sleep 1
  if [[ -f "$DAEMON_PID" ]]; then
    local dp; dp=$(cat "$DAEMON_PID")
    if [[ "$dp" =~ ^[0-9]+$ ]] && kill -0 "$dp" 2>/dev/null; then
      echo -e "${CG}Daemon verified (PID $dp)${R}"
    else
      echo -e "${CY}Warning: Daemon may not have started. Run: ccwatch daemon status${R}"
    fi
  else
    echo -e "${CY}Warning: Daemon PID file not found. Run: ccwatch daemon status${R}"
  fi

  echo ""
  echo -e "${B}Session persistence:${R}"
  if [[ -d "$HOME/.tmux/plugins/tpm" ]]; then
    echo -e "  ${CG}✓ TPM found${R}"
  else
    echo -e "  ${CY}Install TPM for session persistence? [Y/n]${R}"
    read -rsn1 tpm_yn; echo ""
    if [[ "$tpm_yn" != "n" ]] && [[ "$tpm_yn" != "N" ]]; then
      # [HARDENED #13] Clone with --depth 1 and verify expected files exist
      git clone --depth 1 https://github.com/tmux-plugins/tpm "$HOME/.tmux/plugins/tpm" 2>/dev/null
      if [[ -f "$HOME/.tmux/plugins/tpm/tpm" ]]; then
        echo -e "  ${CG}✓ TPM installed${R}"
      else
        echo -e "  ${CR}Clone succeeded but tpm script not found. Verify manually.${R}"
        rm -rf "$HOME/.tmux/plugins/tpm"
      fi
    else
      echo -e "  ${D}Skipped. Install manually: git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm${R}"
    fi
  fi

  local me; me="$(realpath "${BASH_SOURCE[0]}")"
  # Escape single quotes in path for tmux config safety
  local me_escaped="${me//\'/\'\\\'\'}"
  local conf_block
  conf_block=$(cat << TMUX

# ── ccwatch ───────────────────────────────────────────
# Status bar
set -g status-right "#(bash '${me_escaped}' --statusbar) │ %H:%M"
set -g status-interval 30

# Daemon (auto-start)
run-shell -b "bash '${me_escaped}' daemon start"

# Keybindings
bind-key S display-popup -E "bash '${me_escaped}' --popup status"
bind-key A display-popup -E "bash '${me_escaped}' --popup ls"
bind-key P display-popup -E "bash '${me_escaped}' --popup permissions"
bind-key N display-popup -E "bash '${me_escaped}' --popup notes"

# Session persistence (panes + directories survive reboots)
set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-resurrect'
set -g @plugin 'tmux-plugins/tmux-continuum'
set -g @continuum-restore 'on'
set -g @continuum-save-interval '15'
run '~/.tmux/plugins/tpm/tpm'
# ── /ccwatch ──────────────────────────────────────────
TMUX
)

  local tmux_conf="$HOME/.tmux.conf"
  echo ""
  if [[ -f "$tmux_conf" ]] && grep -q "ccwatch" "$tmux_conf"; then
    echo -e "${CG}✓ tmux.conf already has ccwatch config${R}"
  else
    echo -e "${B}Add to ~/.tmux.conf?${R}"
    echo -e "${D}This adds: status bar, daemon auto-start, keybindings, session persistence${R}"
    echo ""
    echo -e "${CY}Append to ${tmux_conf}? [Y/n]${R}"
    read -rsn1 yn; echo ""
    if [[ "$yn" != "n" ]] && [[ "$yn" != "N" ]]; then
      echo "$conf_block" >> "$tmux_conf"
      echo -e "${CG}✓ Appended to ${tmux_conf}${R}"
      echo -e "${D}  Reload: tmux source ~/.tmux.conf${R}"
      echo -e "${D}  Then:   prefix + I  to install TPM plugins${R}"
    else
      echo -e "${D}Manual setup — add this to ${tmux_conf}:${R}"
      echo "$conf_block"
    fi
  fi

  tmux bind-key S display-popup -E "bash '${me_escaped}' --popup status" 2>/dev/null || true
  tmux bind-key A display-popup -E "bash '${me_escaped}' --popup ls" 2>/dev/null || true
  tmux bind-key P display-popup -E "bash '${me_escaped}' --popup permissions" 2>/dev/null || true
  tmux bind-key N display-popup -E "bash '${me_escaped}' --popup notes" 2>/dev/null || true

  # ── Claude Code hooks ──────────────────────────────────
  echo ""
  echo -e "${B}Claude Code hooks:${R}"
  local hooks_dir="$CACHE/hooks"
  mkdir -p "$hooks_dir"
  # Create the hook script
  cat > "$hooks_dir/ccwatch-notify.sh" << 'HOOKEOF'
#!/usr/bin/env bash
# Claude Code hook — writes event marker for ccwatch daemon
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/ccwatch"
EVENTS="$CACHE/events"
mkdir -p "$EVENTS"
type="${1:-unknown}"
pane=$(tmux display-message -p '#{pane_id}' 2>/dev/null || echo "unknown")
ts=$(date +%s)
# Sanitize pane ID and timestamp for safe filename (digits only)
safe_pane="${pane//[^0-9]/}"
jq -nc --arg ts "$ts" --arg type "$type" --arg pane "$pane" \
  '{ts:$ts,type:$type,pane:$pane}' > "$EVENTS/${ts}-${safe_pane}.json" 2>/dev/null || true
HOOKEOF
  chmod +x "$hooks_dir/ccwatch-notify.sh"
  echo -e "  ${CG}✓ Hook script created${R}"

  # Merge hooks into ~/.claude/settings.json
  local claude_settings="$HOME/.claude/settings.json"
  local hook_cmd="$hooks_dir/ccwatch-notify.sh"
  if [[ -f "$claude_settings" ]] && grep -q "ccwatch-notify" "$claude_settings"; then
    echo -e "  ${CG}✓ Hooks already in settings.json${R}"
  else
    echo -e "${CY}  Add ccwatch hooks to Claude Code settings? [Y/n]${R}"
    echo -e "  ${D}Hooks notify ccwatch when Claude asks questions or stops.${R}"
    read -rsn1 hook_yn; echo ""
    if [[ "$hook_yn" != "n" ]] && [[ "$hook_yn" != "N" ]]; then
      local hooks_json
      hooks_json=$(jq -nc --arg cmd "$hook_cmd" '{
        hooks: {
          PreToolUse: [{
            matcher: "AskUserQuestion",
            hooks: [{type:"command",command:($cmd + " question")}]
          }],
          Stop: [{
            hooks: [{type:"command",command:($cmd + " stop")}]
          }]
        }
      }')
      mkdir -p "$(dirname "$claude_settings")"
      if [[ -f "$claude_settings" ]]; then
        local tmp_claude
        tmp_claude=$(mktemp "$(dirname "$claude_settings")/settings.XXXXXX") || { echo "ERROR: mktemp failed"; return 1; }
        chmod 600 "$tmp_claude"
        if jq --argjson new "$hooks_json" '
          .hooks.PreToolUse = ((.hooks.PreToolUse // []) + $new.hooks.PreToolUse) |
          .hooks.Stop = ((.hooks.Stop // []) + $new.hooks.Stop)
        ' "$claude_settings" > "$tmp_claude" 2>/dev/null; then
          mv "$tmp_claude" "$claude_settings"
          echo -e "  ${CG}✓ Hooks added to settings.json${R}"
        else
          rm -f "$tmp_claude"
          echo -e "  ${CR}Failed to merge hooks. Add manually.${R}"
        fi
      else
        echo "$hooks_json" | jq '.' > "$claude_settings"
        echo -e "  ${CG}✓ Created settings.json with hooks${R}"
      fi
    else
      echo -e "  ${D}Skipped. Add hooks manually: see ccwatch help${R}"
    fi
  fi

  # ── Slack notifications (optional) ───────────────────
  echo ""
  echo -e "${B}Slack notifications (optional):${R}"
  echo -e "  ${D}Get notified on your phone when sessions need attention.${R}"
  echo -e "  ${D}1. Slack → Apps → Incoming Webhooks → Add to Slack → choose channel or DM${R}"
  echo -e "  ${D}2. Run: ccwatch notify set${R}"
  echo -e "  ${D}3. Run: ccwatch notify on${R}"

  echo ""
  echo -e "${B}${CC}╭──────────────────────────────────────────────╮${R}"
  echo -e "${B}${CC}│  ✓ ccwatch is ready                          │${R}"
  echo -e "${B}${CC}╰──────────────────────────────────────────────╯${R}"
  echo ""
  echo -e "  ${B}Status bar${R} (ambient, \$0):"
  echo -e "    ●4 ?1 !2 ▰▰▱▱▱   ${D}← always visible in tmux${R}"
  echo ""
  echo -e "  ${B}Keybindings${R} (on-demand, ~\$0.01):"
  echo -e "    prefix+S  status     prefix+A  list all     prefix+P  permissions     prefix+N  notes"
  echo ""
  echo -e "  ${B}CLI${R}:"
  echo -e "    ccwatch              quick glance"
  echo -e "    ccwatch ls           full analysis"
  echo -e "    ccwatch permissions  fix your settings.json"
  echo ""
  echo -e "  ${D}Voice:   ccwatch voice on${R}"
  echo -e "  ${D}Bell:    ccwatch bell on${R}"
  echo -e "  ${D}Slack:   ccwatch notify set${R}"
  echo -e "  ${D}Logs:    $CACHE/${R}"
}

# ─── CMD: key ─────────────────────────────────────────────────────────────────
_cmd_key() {
  local sub="${1:-}"
  case "$sub" in
    set)
      if [[ "$(uname)" != "Darwin" ]] || ! command -v security &>/dev/null; then
        echo "macOS Keychain not available. Use: export ANTHROPIC_API_KEY=sk-ant-..."
        return 1
      fi
      echo -n "Paste your Anthropic API key: "
      read -rs key; echo ""
      [[ -z "$key" ]] && { echo "Empty key. Aborted."; return 1; }
      if ! security add-generic-password -s ccwatch -a anthropic-api-key -w "$key" -U 2>/dev/null; then
        echo -e "${CR}Failed to store key in Keychain.${R}"
        return 1
      fi
      echo -e "${CG}Key stored in macOS Keychain.${R}"
      echo -e "${D}Verify: ccwatch key${R}"
      ;;
    delete|rm)
      if security delete-generic-password -s ccwatch -a anthropic-api-key &>/dev/null; then
        echo -e "${CG}Key removed from Keychain.${R}"
      else
        echo "No key found in Keychain."
      fi
      ;;
    *)
      local src="none" partial=""
      if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
        src="env"
        partial="${ANTHROPIC_API_KEY:0:12}...${ANTHROPIC_API_KEY: -4}"
      elif [[ "$(uname)" == "Darwin" ]] && command -v security &>/dev/null; then
        local kc_key
        kc_key=$(security find-generic-password -s ccwatch -a anthropic-api-key -w 2>/dev/null) || true
        if [[ -n "$kc_key" ]]; then
          src="keychain"
          partial="${kc_key:0:12}...${kc_key: -4}"
        fi
      fi
      echo -e "${B}API Key${R}"
      echo -e "  Source: ${B}${src}${R}"
      [[ -n "$partial" ]] && echo -e "  Key:    ${D}${partial}${R}"
      echo ""
      echo "  ccwatch key set      Store key in macOS Keychain"
      echo "  ccwatch key delete   Remove key from Keychain"
      ;;
  esac
}

# ─── NOTES (Obsidian daily note generation) ──────────────────────────────────

# Find today's transcript files across all Claude projects
_notes_find_todays_transcripts() {
  local today; today=$(date +%Y-%m-%d)
  local proj_dir
  for proj_dir in "$CLAUDE_PROJECTS"/*/; do
    [[ -d "$proj_dir" ]] || continue
    local dirname; dirname=$(basename "$proj_dir")
    local f
    for f in "$proj_dir"*.jsonl; do
      [[ -f "$f" ]] || continue
      # Check if file was modified today (fast stat check)
      local fdate
      fdate=$(stat -f '%Sm' -t '%Y-%m-%d' "$f" 2>/dev/null || stat -c '%y' "$f" 2>/dev/null | cut -d' ' -f1) || continue
      [[ "$fdate" == "$today" ]] || continue
      # Verify file actually contains today's entries (grep is faster than jq for large files)
      grep -qF "$today" "$f" 2>/dev/null || continue
      echo "${dirname}|${f}"
    done
  done
}

# Map project directory name to agent/worktree name
_notes_extract_agent() {
  local dirname="$1"
  # Pattern: -Users-ian-compass-worktrees-AGENT-clients-web → AGENT
  if [[ "$dirname" =~ -worktrees-([^-]+)- ]]; then
    echo "${BASH_REMATCH[1]}"
  else
    # Fallback: last meaningful segment
    echo "$dirname" | rev | cut -d'-' -f1 | rev
  fi
}

# Extract structured data from one transcript file (today's entries only)
_notes_extract_session() {
  local filepath="$1"
  local today; today=$(date +%Y-%m-%d)
  local filesize
  filesize=$(stat -f %z "$filepath" 2>/dev/null || stat -c %s "$filepath" 2>/dev/null || echo 0)

  local jq_filter
  jq_filter='
    select(.timestamp and (.timestamp | startswith($today))) |
    if .type == "user" then
      (if (.message | type) == "string" then .message
       elif (.message.content | type) == "string" then .message.content
       elif (.message.content | type) == "array" then ([.message.content[] | select(.type == "text") | .text] | join(" "))
       else null end) as $text |
      if $text and ($text | length) > 0 then
        {t:"prompt", ts:.timestamp, branch:(.gitBranch // null), text:$text[:150]}
      else empty end
    elif .type == "assistant" then
      .message.content[]? | select(.type == "tool_use") |
      {t:"tool", name:.name, target:((.input.file_path // .input.path // .input.pattern // (.input.command // "")[:100]) // "")}
    elif .type == "file-history-snapshot" then
      {t:"files", files:[.snapshot.trackedFileBackups[]?.path // empty][:10]}
    else empty end
  '

  if [[ "$filesize" -gt 2097152 ]]; then
    # Large file: pre-filter lines containing today's date
    grep -F "$today" "$filepath" 2>/dev/null | jq -c --arg today "$today" "$jq_filter" 2>/dev/null
  else
    jq -c --arg today "$today" "$jq_filter" "$filepath" 2>/dev/null
  fi
}

# Gather all activity data into a single JSON object
_notes_gather_all() {
  local today; today=$(date +%Y-%m-%d)
  local agents_json="[]"

  # Collect all session data per agent into temp files
  local gather_tmp
  gather_tmp=$(mktemp -d "$CACHE/gather.XXXXXX") || { _log "notes: mktemp failed"; return 1; }
  trap 'rm -rf "$gather_tmp" 2>/dev/null' RETURN

  while IFS='|' read -r dirname filepath; do
    [[ -z "$dirname" ]] && continue
    local agent; agent=$(_notes_extract_agent "$dirname")
    local session_data
    session_data=$(_notes_extract_session "$filepath") || continue
    [[ -z "$session_data" ]] && continue
    # Append to per-agent file (consolidates multiple transcripts)
    echo "$session_data" >> "$gather_tmp/$agent"
  done < <(_notes_find_todays_transcripts)

  # Build per-agent summaries
  local agent_file
  for agent_file in "$gather_tmp"/*; do
    [[ -f "$agent_file" ]] || continue
    local agent; agent=$(basename "$agent_file")
    local agent_summary
    agent_summary=$(jq -sc --arg agent "$agent" '
      {
        agent: $agent,
        branch: ([.[] | select(.t=="prompt" and .branch) | .branch] | first // "unknown"),
        prompts: [.[] | select(.t=="prompt") | {ts:.ts, text:.text}] | unique_by(.ts),
        tools: ([.[] | select(.t=="tool") | .name] | group_by(.) | map({tool:.[0], count:length}) | sort_by(-.count)),
        files: ([.[] | select(.t=="files") | .files[]?] | unique)
      }
    ' "$agent_file" 2>/dev/null) || continue
    [[ -z "$agent_summary" ]] && continue
    agents_json=$(echo "$agents_json" | jq --argjson new "$agent_summary" '. + [$new]' 2>/dev/null)
  done

  rm -rf "$gather_tmp" 2>/dev/null

  # Include stats-cache daily stats if available
  local stats="{}"
  if [[ -f "$CLAUDE_STATS" ]]; then
    local _s
    _s=$(jq --arg today "$today" '[.dailyActivity[]? | select(.date==$today)] | if length > 0 then .[0] else {} end' "$CLAUDE_STATS" 2>/dev/null) || _s="{}"
    [[ -n "$_s" ]] && stats="$_s"
  fi

  # Include daemon state if available
  local daemon="{}"
  if [[ -f "$DAEMON_STATE" ]]; then
    daemon=$(jq '{sessions:.count, waiting:.waiting, load:.load}' "$DAEMON_STATE" 2>/dev/null) || daemon="{}"
  fi

  jq -nc --argjson agents "$agents_json" --argjson stats "$stats" --argjson daemon "$daemon" --arg date "$today" \
    '{date:$date, agents:$agents, stats:$stats, daemon:$daemon}'
}

_NOTES_SYSTEM='You update an Obsidian daily note with Claude Code session activity data.

Structure (top to bottom):
1. **Status** — one line per active agent: "- **agentN** on `branch` — [current status phrase]". Status reflects the LATEST activity (e.g. "implementing auth grid" not "started work").
2. **Per-agent sections** — each active agent gets an ## agentN section containing:
   - Branch name as a bold line
   - Bulleted accomplishments (past tense, grouped by outcome not by tool call)
   - "Currently:" line if there is clearly in-progress work
   - Do NOT create sections for agents with no activity today
3. **Open Items** — single section replacing Decisions/Blockers/Follow-ups. Only include when data evidences them. Prefix: "- **Decision:** ...", "- **Blocker:** ...", "- **Follow-up:** ...". Omit the section entirely if empty.
4. **Notes** — freeform section for manual entries (always preserved)
5. **Timeline** — chronological "- **HH:MM** [agentN] description" entries as a reference appendix. LAST section.

Rules:
- PRESERVE all existing manually-written content in the note. Never remove or modify manual entries.
- MERGE new session data into the correct sections.
- Keep %% %% Obsidian comments in sections that remain empty (Status, Notes, Timeline)
- Output the COMPLETE note — no markdown fences, no preamble, no explanation
- Be concise — summarize tool usage patterns (e.g. "edited 5 files in products/"), do not list every tool call
- Group related prompts into single timeline entries where possible
- If a timeline entry already exists for an agent at a similar time, do not duplicate it'

_notes_generate() {
  local dry_run="${1:-0}"
  local today; today=$(date +%Y-%m-%d)
  local day_name; day_name=$(date +%A)
  # Validate day_name is alphabetic (locale safety)
  [[ "$day_name" =~ ^[A-Za-z]+$ ]] || day_name="Unknown"
  local note_path="$OBSIDIAN_DAILY/${today}.md"

  # S2: Validate vault path exists
  if [[ ! -d "$OBSIDIAN_VAULT" ]]; then
    echo "ERROR: Obsidian vault not found at $OBSIDIAN_VAULT" >&2
    echo "  Set CCWATCH_OBSIDIAN_VAULT to your vault path" >&2
    return 1
  fi

  # Create daily directory if vault exists
  mkdir -p "$OBSIDIAN_DAILY"

  # Create daily note from template if it doesn't exist (atomic write)
  if [[ ! -f "$note_path" ]]; then
    local tmp_init
    tmp_init=$(mktemp "$OBSIDIAN_DAILY/.note-init.XXXXXX") || { echo "ERROR: mktemp failed" >&2; return 1; }
    if [[ -f "$OBSIDIAN_TEMPLATE" ]]; then
      sed "s|{{date}}|${today}|g; s|{{day}}|${day_name}|g" "$OBSIDIAN_TEMPLATE" > "$tmp_init"
    else
      cat > "$tmp_init" << TMPL
# ${today} ${day_name}

## Status
%% One-line status per agent — auto-generated %%

## Notes
%% Manual notes, links, context %%

## Timeline
%% Chronological log of all activity %%
TMPL
    fi
    chmod 644 "$tmp_init"
    mv "$tmp_init" "$note_path"
  fi

  # Read current note content (cap at 50KB to limit API cost)
  local current_note
  current_note=$(head -c 51200 "$note_path")

  # Gather activity data
  echo -e "${D}Scanning transcripts...${R}" >&2
  local activity
  activity=$(_notes_gather_all)

  # Check if there are any agents
  local agent_count
  agent_count=$(echo "$activity" | jq '.agents | length' 2>/dev/null) || agent_count=0
  if [[ "$agent_count" -eq 0 ]]; then
    echo -e "${D}No Claude Code activity found for today.${R}" >&2
    return 0
  fi

  echo -e "${D}Found ${agent_count} agent(s), calling API...${R}" >&2

  # S3: Cap payload size (50KB max)
  local payload
  payload=$(jq -c '.' <<< "$activity" 2>/dev/null)
  if [[ ${#payload} -gt 51200 ]]; then
    # Truncate: keep agent names/branches/tools, drop individual prompts
    payload=$(echo "$activity" | jq -c '.agents |= map({agent, branch, tools, files, prompt_count: (.prompts | length)})' 2>/dev/null)
  fi

  local user_msg
  user_msg=$(jq -nc --arg note "$current_note" --arg data "$payload" \
    '"CURRENT NOTE:\n" + $note + "\n\nACTIVITY DATA:\n" + $data')
  # jq wraps in quotes — unwrap for the API call
  user_msg=$(echo "$user_msg" | jq -r '.')

  local result
  result=$(_call "think" "$_NOTES_SYSTEM" "$user_msg" 4000) || {
    echo "ERROR: API call failed" >&2
    return 1
  }

  # S4: Validate AI response
  if [[ -z "$result" ]]; then
    echo "ERROR: Empty response from API" >&2; return 1
  fi
  if [[ ! "$result" =~ ^#\  ]]; then
    echo "ERROR: Response doesn't look like a valid note (missing H1)" >&2; return 1
  fi
  if [[ ${#result} -lt 50 ]]; then
    echo "ERROR: Response too short (${#result} chars)" >&2; return 1
  fi
  if [[ ${#result} -gt 102400 ]]; then
    echo "ERROR: Response too large (${#result} chars)" >&2; return 1
  fi
  # S4b: Reject responses containing Obsidian-executable directives
  if grep -qE '<%|```dataviewjs|obsidian://' <<< "$result"; then
    _log "notes: API response contained suspicious Obsidian directives, rejecting"
    echo "ERROR: Response contained suspicious content" >&2; return 1
  fi

  if [[ "$dry_run" -eq 1 ]]; then
    echo "$result"
    return 0
  fi

  # S5: Atomic write — temp in same dir as target (guarantees same-filesystem rename)
  local tmp_note
  tmp_note=$(mktemp "$OBSIDIAN_DAILY/.note.XXXXXX") || { echo "ERROR: mktemp failed" >&2; return 1; }
  echo "$result" > "$tmp_note"
  chmod 644 "$tmp_note"
  mv "$tmp_note" "$note_path"

  # Record timestamp
  date +%s > "$NOTES_LAST_RUN"

  echo -e "${CG}✓ Updated ${note_path}${R}"
}

_notes_watch() {
  _check_api
  echo -e "${B}${CC}ccwatch notes --watch${R}"
  echo -e "${D}Updating every ${NOTES_INTERVAL}s. Ctrl+C to stop.${R}"
  echo ""
  trap 'echo ""; echo "Stopped."; exit 0' INT TERM
  while true; do
    local now; now=$(date +%s)
    local last=0
    [[ -f "$NOTES_LAST_RUN" ]] && last=$(cat "$NOTES_LAST_RUN" 2>/dev/null || echo 0)
    [[ "$last" =~ ^[0-9]+$ ]] || last=0
    if [[ $(( now - last )) -ge "$NOTES_INTERVAL" ]]; then
      echo -e "${D}[$(date '+%H:%M')] Generating notes...${R}"
      _notes_generate 0 || _log "notes: generate failed"
    fi
    sleep 60
  done
}

_cmd_notes() {
  _check_api
  case "${1:-}" in
    --dry-run) _notes_generate 1 ;;
    --watch) _notes_watch ;;
    *) _notes_generate 0 ;;
  esac
}

# ─── ENTRY ────────────────────────────────────────────────────────────────────
_resolve_api_key

case "${1:-}" in
  "") _cmd_default ;;
  ls|list) _cmd_ls ;;
  status|s) _cmd_status "${2:-}" ;;
  permissions|perm) shift; case "${1:-}" in
    --apply) _cmd_perms_apply "${2:-user}" ;; --reset) _cmd_perms_reset ;; *) _cmd_perms ;; esac ;;
  daemon|d) shift; case "${1:-status}" in
    start) _daemon_start ;; stop) _daemon_stop ;; restart) _daemon_stop; sleep 1; _daemon_start ;; *) _daemon_status ;; esac ;;
  --statusbar) _statusbar ;;
  --popup) shift
    # Wrapper for tmux display-popup: pipe output through less for scrolling.
    # Subshell uses set +e so errors produce visible output instead of killing the process.
    # less -R preserves ANSI colors; -P sets a footer with navigation hints.
    # User presses q to close (popup -E flag closes on command exit).
    (
      set +e
      case "${1:-}" in
        status|s) _cmd_status "${2:-}" ;;
        ls|list) _cmd_ls ;;
        permissions|perm) shift; case "${1:-}" in
          --apply) _cmd_perms_apply "${2:-user}" ;; --reset) _cmd_perms_reset ;; *) _cmd_perms ;; esac ;;
        notes) shift; _cmd_notes "$@" ;;
      esac
      echo ""
      echo -e "  ${D}prefix+S status  prefix+A list all  prefix+P permissions  prefix+N notes${R}"
    ) 2>&1 | less -R -P " q close | ↑↓ scroll | / search"
    ;;
  key|k) _cmd_key "${2:-}" ;;
  voice|v) _cmd_voice "${2:-}" ;;
  bell|b) _cmd_bell "${2:-}" ;;
  notes) shift; _cmd_notes "$@" ;;
  notify|n) shift; _cmd_notify "$@" ;;
  setup) _cmd_setup ;;
  help|--help|-h) cat << 'H'
ccwatch — Ambient Intelligence for Claude Code Sessions

  ccwatch                Quick glance (reads daemon, no API)
  ccwatch ls             Sessions sorted by cognitive load
  ccwatch status [ID]    Deep analysis of one session
  ccwatch permissions    Permission log → settings.json suggestions
  ccwatch key            API key status (source + partial key)
  ccwatch key set        Store API key in macOS Keychain
  ccwatch key delete     Remove API key from Keychain
  ccwatch notes            Generate/update Obsidian daily note
  ccwatch notes --dry-run  Preview note without writing
  ccwatch notes --watch    Auto-update every 15 min
  ccwatch voice on|off   Toggle voice narration
  ccwatch bell on|off    Toggle bell sound on attention
  ccwatch notify on|off  Toggle Slack notifications
  ccwatch notify set     Configure Slack webhook
  ccwatch notify test    Send a test notification
  ccwatch daemon start|stop|restart|status   Manage background scanner
  ccwatch setup          One-time install

Status bar (always visible, $0):
  ●4 ?1 !2 ▰▰▱▱▱ P47

Keybindings (on-demand, ~$0.01/call):
  prefix+S  status     prefix+A  list all     prefix+P  permissions

Models: Haiku (fast tier), Sonnet (think tier: ls, status, permissions)
Cost: ~$0.10-0.50/day with heavy use
API: Uses ANTHROPIC_API_KEY — resolved from env var or macOS Keychain

Env:
  ANTHROPIC_API_KEY              Required (or use: ccwatch key set)
  CCWATCH_MODEL_FAST             Override Haiku model
  CCWATCH_MODEL_THINK            Override think-tier model
  CCWATCH_MODEL                  Force single model for everything
  CCWATCH_VOICE=true             Enable voice (or: ccwatch voice on)
  CCWATCH_BELL=true              Enable bell sound (or: ccwatch bell on)
  CCWATCH_SLACK_WEBHOOK          Slack webhook URL (or: ccwatch notify set)
  CCWATCH_NOTIFY_COOLDOWN=0      Min seconds between notifications (0=off)
  CCWATCH_SCAN_INTERVAL=30       Daemon scan interval (seconds)
  CCWATCH_OBSIDIAN_VAULT         Obsidian vault path (default: ~/ObsidianVault)
  CCWATCH_NOTES_INTERVAL=900     Notes watch interval in seconds (default: 15 min)
H
  ;; *) echo "Unknown: $1 — try: ccwatch help" ;;
esac
