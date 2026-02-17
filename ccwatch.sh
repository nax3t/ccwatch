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

# Validate numeric env vars
[[ "$CAP" =~ ^[0-9]+$ ]] || { echo "ERROR: CCWATCH_LINES must be numeric" >&2; exit 1; }
[[ "$SCAN_INT" =~ ^[0-9]+$ ]] || { echo "ERROR: CCWATCH_SCAN_INTERVAL must be numeric" >&2; exit 1; }

# [HARDENED #8] Restrictive permissions on cache directory
mkdir -p "$CACHE"
chmod 700 "$CACHE"

# [HARDENED #7] Max log sizes (bytes) — auto-rotated
MAX_LOG_SIZE=5242880  # 5MB

# ─── Models (two-tier: fast + think) ─────────────────────────────────────────
M_FAST="${CCWATCH_MODEL_FAST:-claude-haiku-4-5-20251001}"
M_THINK="${CCWATCH_MODEL_THINK:-claude-sonnet-4-5-20250929}"
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

_check_deps() {
  local miss=()
  for c in tmux curl jq; do command -v "$c" &>/dev/null || miss+=("$c"); done
  if [[ ${#miss[@]} -gt 0 ]]; then echo "Missing: ${miss[*]}"; exit 1; fi
}

_check_api() {
  [[ -n "${ANTHROPIC_API_KEY:-}" ]] || {
    echo "ANTHROPIC_API_KEY not set."
    echo "ccwatch uses the Anthropic API — not your Max/Pro subscription."
    echo "Get one at https://console.anthropic.com/settings/keys"
    exit 1
  }
  if [[ ! "$ANTHROPIC_API_KEY" =~ ^sk-ant- ]]; then
    echo "WARNING: ANTHROPIC_API_KEY doesn't look like a valid key (expected sk-ant-...)." >&2
    echo "  Current value starts with: ${ANTHROPIC_API_KEY:0:10}..." >&2
    echo "  If using macOS Keychain, ensure you use: security find-generic-password -w ..." >&2
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
  body_file=$(mktemp "$CACHE/req.XXXXXX")
  trap 'rm -f "$body_file" 2>/dev/null' RETURN
  chmod 600 "$body_file"
  jq -n --arg m "$model" --arg s "$sys" --arg c "$usr" --argjson t "$tok" \
    '{model:$m,max_tokens:$t,system:$s,messages:[{role:"user",content:$c}]}' > "$body_file"

  local resp
  # [HARDENED #4] Pass API key via stdin curl config to hide from ps
  # Escape backslashes and double quotes for curl config format
  local escaped_key="${ANTHROPIC_API_KEY//\\/\\\\}"
  escaped_key="${escaped_key//\"/\\\"}"
  resp=$(printf 'header = "x-api-key: %s"\n' "$escaped_key" | \
    curl -s --max-time 30 -K - \
    -H "content-type: application/json" \
    -H "anthropic-version: 2023-06-01" \
    -d @"$body_file" \
    "https://api.anthropic.com/v1/messages" 2>/dev/null) || {
    echo "ERROR: API failed"; return 1
  }

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
  tmux capture-pane -t "$1" -p -S -15 2>/dev/null | \
    grep -qiE '(claude>|⏺|╭.*─|Tool|Bash\(|Read\(|Write\(|Edit\()' && return 0
  return 1
}

_cap() {
  _validate_pane_id "$1" || { echo "[invalid]"; return; }
  tmux capture-pane -t "$1" -p -S "-${CAP}" 2>/dev/null || echo "[gone]"
}

_pane_pos() {
  # Determine human-readable pane position from geometry
  local pane_id="$1"
  local info
  info=$(tmux display-message -t "$pane_id" -p \
    '#{pane_top}|#{pane_left}|#{pane_width}|#{pane_height}|#{window_width}|#{window_height}' 2>/dev/null) || { echo ""; return; }
  local pt pl pw ph ww wh
  IFS='|' read -r pt pl pw ph ww wh <<< "$info"
  # Determine vertical position
  local vpos=""; local hpos=""
  if [[ "$ph" -ge "$wh" ]] 2>/dev/null; then vpos="full"
  elif [[ "$pt" -le 1 ]]; then vpos="top"
  else vpos="bottom"; fi
  # Determine horizontal position
  if [[ "$pw" -ge "$ww" ]] 2>/dev/null; then hpos=""
  elif [[ "$pl" -le 1 ]]; then hpos="left"
  else hpos="right"; fi
  # Combine
  if [[ "$vpos" == "full" ]] && [[ -z "$hpos" ]]; then echo "full"
  elif [[ "$vpos" == "full" ]]; then echo "$hpos"
  elif [[ -z "$hpos" ]]; then echo "$vpos"
  else echo "${vpos}-${hpos}"; fi
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
      local pos; pos=$(_pane_pos "$pid")
      echo "${pid}|${label}|${pos}"
    fi
  done < <(tmux list-panes -a -F \
    '#{pane_id}|#{session_name}|#{window_index}|#{pane_index}|#{pane_pid}|#{pane_title}' 2>/dev/null)
}

# ─── Pattern-based state detection (no AI) ────────────────────────────────────
_detect() {
  local tail; tail=$(echo "$1" | tail -20)
  # Permission: look for Claude Code tool-approval patterns
  if echo "$tail" | grep -qE 'Allow .+\(|Approve .+\(|\(Y\)es.*\(N\)o|❯ .*(Yes|No|Always)'; then
    local t; t=$(echo "$tail" | grep -oE '(Bash|Read|Write|Edit|MultiEdit|WebFetch|Task|Glob|Grep|LS|WebSearch|NotebookEdit)\([^)]+\)' | tail -1)
    echo "permission|${t:-unknown}"; return
  fi
  # Question: require trailing ? to reduce false positives from code output
  if echo "$tail" | grep -qiE '(What would you|How should I|Which approach|Do you prefer|Should I |Would you like me to|Could you clarify).*\?'; then
    local q; q=$(echo "$tail" | grep -iE '(What|How|Which|Should|Would|Could|Do you).*\?' | tail -1 | sed 's/^[[:space:]]*//' | head -c 120)
    echo "question|$q"; return
  fi
  # Error: anchor patterns to reduce false positives from displayed code/logs
  if echo "$tail" | grep -qE '(^Error:|^ERROR[ :]|FAILED|^panic:|^Traceback \(most recent)'; then
    echo "error|"; return
  fi
  # Working: use Claude Code-specific indicators (⏺ bullet, box drawing, spinners)
  if echo "$tail" | grep -qE '(⏺|╭──|⠋|⠙|⠹|⠸|⠼|⠴|⠦|⠧|⠇|⠏)'; then
    echo "working|"; return
  fi
  echo "idle|"
}

# ─── DAEMON ───────────────────────────────────────────────────────────────────
_daemon_scan() {
  local n=0 w=0 q=0 p=0 e=0
  local scan_tmp
  scan_tmp=$(mktemp "$CACHE/scan.XXXXXX")
  trap 'rm -f "$scan_tmp" 2>/dev/null' RETURN
  while IFS='|' read -r pid label _pos; do
    [[ -z "$pid" ]] && continue; n=$((n+1))
    local content; content=$(tmux capture-pane -t "$pid" -p -S -30 2>/dev/null || true)
    local si st sd; si=$(_detect "$content"); st=${si%%|*}; sd=${si#*|}
    case "$st" in
      permission) p=$((p+1)); w=$((w+1))
        _rotate_if_large "$PERMS_LOG"
        jq -nc --arg t "$(date -Iseconds)" --arg P "$pid" --arg l "$label" \
          --arg tool "$sd" '{ts:$t,pane:$P,label:$l,tool:$tool}' >> "$PERMS_LOG" ;;
      question) q=$((q+1)); w=$((w+1)) ;;
      error) e=$((e+1)); w=$((w+1)) ;;
    esac
    jq -nc --arg P "$pid" --arg l "$label" --arg s "$st" --arg d "$sd" \
      '{pane:$P,label:$l,state:$s,detail:$d}' >> "$scan_tmp"
  done < <(_discover)

  local sj
  sj=$(jq -s '.' "$scan_tmp" 2>/dev/null || echo "[]")

  local lb="▱▱▱▱▱"; local a=$((n-w))
  [[ $a -ge 1 ]] && lb="▰▱▱▱▱"; [[ $a -ge 2 ]] && lb="▰▰▱▱▱"
  [[ $a -ge 3 ]] && lb="▰▰▰▱▱"; [[ $a -ge 4 ]] && lb="▰▰▰▰▱"
  [[ $a -ge 5 ]] && lb="▰▰▰▰▰"
  # Trim whitespace from wc -l (macOS pads with spaces)
  local pl; pl=$(wc -l < "$PERMS_LOG" 2>/dev/null || echo 0); pl="${pl// /}"
  [[ "$pl" =~ ^[0-9]+$ ]] || pl=0

  # [HARDENED #9] Atomic write via temp + rename — only replace if valid
  local tmp_state
  tmp_state=$(mktemp "$CACHE/state.XXXXXX")
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

  for v in count waiting questions permissions errors load perms_logged; do
    tmux set-option -g @ccw_$v "$(jq -r ".$v" "$DAEMON_STATE")" 2>/dev/null || true
  done

  local prev; prev=$(tmux show-option -gqv @ccw_prev_w 2>/dev/null || echo 0)
  if [[ "$w" -gt "${prev:-0}" ]] && [[ "$w" -gt 0 ]]; then
    echo -ne '\a'
    _voice_alert "$w session$([ "$w" -gt 1 ] && echo s) need attention"
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
  local tmp_pid; tmp_pid=$(mktemp "$CACHE/pid.XXXXXX")
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

  # Single jq call for <50ms budget instead of 7 separate forks
  local n=0 w=0 q=0 p=0 e=0 lb="▱▱▱▱▱" pl=0
  local _fields
  _fields=$(jq -r '[
    (.count // 0), (.waiting // 0), (.questions // 0),
    (.permissions // 0), (.errors // 0), (.load // "▱▱▱▱▱"),
    (.perms_logged // 0)
  ] | join("\t")' "$DAEMON_STATE" 2>/dev/null) || true
  if [[ -n "$_fields" ]]; then
    IFS=$'\t' read -r n w q p e lb pl <<< "$_fields"
  fi

  # Validate numeric fields
  [[ "$n" =~ ^[0-9]+$ ]] || n=0; [[ "$w" =~ ^[0-9]+$ ]] || w=0
  [[ "$q" =~ ^[0-9]+$ ]] || q=0; [[ "$p" =~ ^[0-9]+$ ]] || p=0
  [[ "$e" =~ ^[0-9]+$ ]] || e=0; [[ "$pl" =~ ^[0-9]+$ ]] || pl=0

  [[ "$n" -eq 0 ]] && { echo "#[fg=colour8]cc:0#[default]"; return; }

  local o=""
  if [[ "$w" -gt 0 ]]; then o+="#[fg=colour0,bold]●${n}#[default]"
  else o+="#[fg=colour0]●${n}#[default]"; fi
  [[ "$q" -gt 0 ]] && o+=" #[fg=colour0]?${q}#[default]"
  [[ "$p" -gt 0 ]] && o+=" #[fg=colour0,bold]!${p}#[default]"
  [[ "$e" -gt 0 ]] && o+=" #[fg=colour0]x${e}#[default]"
  local ac=$((n-w))
  if [[ $ac -le 1 ]]; then o+=" #[fg=colour0]${lb}#[default]"
  elif [[ $ac -le 3 ]]; then o+=" #[fg=colour0]${lb}#[default]"
  else o+=" #[fg=colour0,bold]${lb}#[default]"; fi
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
  local n w q p e lb pl
  n=$(jq -r '.count // 0' "$DAEMON_STATE" 2>/dev/null || echo 0)
  w=$(jq -r '.waiting // 0' "$DAEMON_STATE" 2>/dev/null || echo 0)
  q=$(jq -r '.questions // 0' "$DAEMON_STATE" 2>/dev/null || echo 0)
  p=$(jq -r '.permissions // 0' "$DAEMON_STATE" 2>/dev/null || echo 0)
  e=$(jq -r '.errors // 0' "$DAEMON_STATE" 2>/dev/null || echo 0)
  lb=$(jq -r '.load // "▱▱▱▱▱"' "$DAEMON_STATE" 2>/dev/null || echo "▱▱▱▱▱")
  pl=$(jq -r '.perms_logged // 0' "$DAEMON_STATE" 2>/dev/null || echo 0)
  echo -e "${CG}●${R} ${n} sessions  ${lb}"
  [[ "$q" -gt 0 ]] && echo -e "  ${CC}❓ ${q} question(s)${R}"
  [[ "$p" -gt 0 ]] && echo -e "  ${CY}🔑 ${p} permission(s)${R}"
  [[ "$e" -gt 0 ]] && echo -e "  ${CR}✖ ${e} error(s)${R}"
  [[ "$pl" -gt 10 ]] && echo -e "  ${CM}📋 ${pl} perms → ccwatch permissions${R}"
  return 0
}

# ─── CMD: ls ──────────────────────────────────────────────────────────────────
_cmd_ls() {
  _check_deps; _check_api
  local S=() P=() A=(); local h; h=$(_hist 20)
  echo -e "${D}Analyzing...${R}"
  while IFS='|' read -r pid lbl pos; do [[ -z "$pid" ]] && continue
    S+=("$pid|$lbl"); P+=("$pos"); A+=("$(_analyze "$(_cap "$pid")" "$lbl" "$h")")
    _event "$pid" "scan" ""
  done < <(_discover)
  if [[ ${#S[@]} -eq 0 ]]; then echo -e "${D}No Claude Code sessions.${R}"; return; fi

  local SC=(); for i in "${!A[@]}"; do
    SC+=($(echo "${A[$i]}" | jq -r '.cognitive_load.score // 0' 2>/dev/null || echo 0)); done
  local SI=($(for i in "${!SC[@]}"; do echo "$i ${SC[$i]}"; done | sort -k2 -n | awk '{print $1}'))

  echo ""
  echo -e "  ${B}${CC}🔭 Sessions${R}  ${D}(${#S[@]} found, sorted by cognitive load)${R}"
  echo -e "  ${D}──────────────────────────────────────────────────────────────${R}"
  local pn=0 lo=() first=1
  for idx in "${SI[@]}"; do
    local pid lbl; IFS='|' read -r pid lbl <<< "${S[$idx]}"
    local a="${A[$idx]}" pos="${P[$idx]}"
    local st ts na br cs cl ss sa
    st=$(echo "$a"|jq -r '.status//"?"' 2>/dev/null) || st="?"
    ts=$(echo "$a"|jq -r '.task_summary//"?"' 2>/dev/null) || ts="?"
    na=$(echo "$a"|jq -r '.current_action//"?"' 2>/dev/null) || na="?"
    br=$(echo "$a"|jq -r '.branch//"?"' 2>/dev/null) || br="?"
    cs=$(echo "$a"|jq -r '.cognitive_load.score//0' 2>/dev/null) || cs=0
    cl=$(echo "$a"|jq -r '.cognitive_load.label//"?"' 2>/dev/null) || cl="?"
    ss=$(echo "$a"|jq -r '.cognitive_load.safe_to_switch_away//false' 2>/dev/null) || ss="false"
    sa=$(echo "$a"|jq -r '.suggested_action//""' 2>/dev/null) || sa=""
    if [[ "$cs" -le 2 ]]; then lo+=("$lbl"); fi

    if [[ "$first" -ne 1 ]]; then
      echo -e "  ${D}──────────────────────────────────────────────────────────────${R}"
    fi
    first=0

    # Header: badge + label + position + branch
    local pos_tag=""
    if [[ -n "$pos" ]]; then pos_tag=" ${D}(${pos})${R}"; fi
    local sw; if [[ "$ss" == "true" ]]; then sw="${CG}↔${R}"; else sw="${CY}⚠${R}"; fi
    echo -e "  $(_sbadge "$st") ${B}${lbl}${R}${pos_tag}  ${D}[${br}]${R}  $(_cbar "$cs" "$cl")  $sw"

    # Task + action
    echo -e "  ${D}│${R} ${ts}"
    echo -e "  ${D}│${R} ${D}↳ ${na}${R}"
    if [[ -n "$sa" ]]; then
      echo -e "  ${D}│${R} ${CC}→ ${sa}${R}"
    fi

    # Alerts
    local qq; qq=$(echo "$a"|jq -r '.pending_question//"null"' 2>/dev/null) || qq="null"
    if [[ "$qq" != "null" ]] && [[ -n "$qq" ]]; then
      echo -e "  ${D}│${R} ${BC}${CW} ❓ ${R} ${CC}${qq}${R}"; pn=$((pn+1))
    fi
    local pp; pp=$(echo "$a"|jq -r '.pending_permission//"null"' 2>/dev/null) || pp="null"
    if [[ "$pp" != "null" ]] && [[ -n "$pp" ]]; then
      local tn pd
      tn=$(echo "$pp"|jq -r '.tool' 2>/dev/null) || tn="?"
      pd=$(echo "$pp"|jq -r '.detail' 2>/dev/null) || pd="?"
      echo -e "  ${D}│${R} ${BY}${CW} 🔑 ${R} ${CY}${tn}(${pd})${R}"
      _rotate_if_large "$PERMS_LOG"
      jq -nc --arg t "$(date -Iseconds)" --arg P "$pid" --arg l "$lbl" --arg tool "${tn}(${pd})" \
        '{ts:$t,pane:$P,label:$l,tool:$tool}' >> "$PERMS_LOG" || true
      pn=$((pn+1))
    fi
  done
  echo -e "  ${D}──────────────────────────────────────────────────────────────${R}"
  if [[ $pn -gt 0 ]]; then echo -e "  ${CY}${B}⚡ ${pn} need attention${R}"; fi
  if [[ ${#lo[@]} -gt 0 ]]; then echo -e "  ${D}💡 Quick switch: ${lo[*]}${R}"; fi
  echo ""
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
  echo ""
  echo -e "  $(_sbadge "$(echo "$a"|jq -r '.status')") ${B}${l}${R} ${D}[$(echo "$a"|jq -r '.branch')]${R}"
  local cs cl cr cc sa
  cs=$(echo "$a"|jq -r '.cognitive_load.score//0'); cl=$(echo "$a"|jq -r '.cognitive_load.label//"?"')
  cr=$(echo "$a"|jq -r '.cognitive_load.reasoning//""'); cc=$(echo "$a"|jq -r '.cognitive_load.context_cost//""')
  sa=$(echo "$a"|jq -r '.suggested_action//""')
  echo -e "  $(_cbar "$cs" "$cl")"; echo -e "  ${D}${cr}${R}"
  [[ -n "$cc" ]] && echo -e "  ${D}Switch cost: ${cc}${R}"
  echo ""; echo -e "  ${B}Task:${R}  $(echo "$a"|jq -r '.task_summary')"
  echo -e "  ${B}Now:${R}   $(echo "$a"|jq -r '.current_action')"
  local f; f=$(echo "$a"|jq -r '(.files//[])|join(", ")'); [[ -n "$f" ]] && echo -e "  ${B}Files:${R} ${f}"
  [[ -n "$sa" ]] && echo -e "  ${B}Next:${R}  ${CC}${sa}${R}"
  local qq; qq=$(echo "$a"|jq -r '.pending_question//"null"')
  [[ "$qq" != "null" ]] && { echo ""; echo -e "  ${BC}${CW} ❓ ${R} ${CC}${qq}${R}"; }
  local pp; pp=$(echo "$a"|jq -r '.pending_permission//"null"')
  [[ "$pp" != "null" ]] && { echo ""; echo -e "  ${BY}${CW} 🔑 ${R} ${CY}$(echo "$pp"|jq -r '"\(.tool)(\(.detail)): \(.description)"')${R}"; }
}

# ─── CMD: suggest ─────────────────────────────────────────────────────────────
_cmd_suggest() {
  _check_deps; _check_api
  local all="" n=0
  echo -e "${D}Analyzing all sessions...${R}"
  while IFS='|' read -r pid lbl _pos; do [[ -z "$pid" ]] && continue
    all+="\n--- ${lbl} ---\n$(_analyze "$(_cap "$pid")" "$lbl" "")\n"; n=$((n+1))
  done < <(_discover)
  [[ $n -eq 0 ]] && { echo "No sessions."; return; }
  local r; r=$(_call "think" \
    'Developer workflow advisor. Given session analyses + history, provide:
PRIORITY: Which sessions to address first (1 line each, blocked first)
STRATEGY: 2-3 sentences on optimal switching order by cognitive load.
BATCH: Group related work. Mark quick check-ins vs deep focus. Be direct.' \
    "Sessions:\n${all}\n\nHistory:\n$(_hist 30)" 500) || { echo "API error"; return 1; }
  echo ""; echo -e "${B}${CC}  💡 What to do next${R}"; echo ""
  echo "$r" | while IFS= read -r line; do echo -e "  $line"; done; echo ""
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

  echo "$r" > "$CACHE/perm-suggestions.json"
  chmod 600 "$CACHE/perm-suggestions.json"
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

  echo -e "${B}Adding to ${tf}:${R}"; echo "$rules" | jq .; echo ""
  echo -e "${CY}Apply? [y/N]${R}"; read -rsn1 c; echo ""
  [[ "$c" != "y" ]] && [[ "$c" != "Y" ]] && { echo "Cancelled."; return; }
  mkdir -p "$(dirname "$tf")"
  if [[ -f "$tf" ]]; then
    cp "$tf" "${tf}.bak.$(date +%s)"
    # [HARDENED #10] Atomic write for settings
    local tmp_settings
    tmp_settings=$(mktemp "$(dirname "$tf")/settings.XXXXXX")
    chmod 600 "$tmp_settings"
    if jq --argjson new "$rules" '.permissions//={}|.permissions.allow=((.permissions.allow//[])+($new.allow//[])|unique)' "$tf" > "$tmp_settings" 2>/dev/null; then
      mv "$tmp_settings" "$tf"
    else
      rm -f "$tmp_settings"
      echo "ERROR: Failed to merge settings. Original unchanged."; return 1
    fi
  else
    local tmp_new
    tmp_new=$(mktemp "$(dirname "$tf")/settings.XXXXXX")
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

_voice_alert() {
  [[ "${CCWATCH_VOICE:-false}" != "true" ]] && return
  local msg="$1" be; be=$(_voice_tts); [[ "$be" == "none" ]] && return

  # [HARDENED #1 #2] Sanitize TTS input — strip ANSI, shell metacharacters,
  # and anything that could be interpreted by the shell.
  # Only allow: alphanumeric, spaces, periods, commas, hyphens, colons
  msg=$(echo "$msg" | sed 's/\x1b\[[0-9;]*m//g')
  msg=$(echo "$msg" | tr -cd 'a-zA-Z0-9 .,;:!?()-')
  # Truncate to prevent abuse
  msg="${msg:0:200}"
  # Reject empty after sanitization
  [[ -z "$msg" ]] && return

  # [HARDENED #3] Use $CACHE for temp audio, not /tmp
  local audio_tmp="$CACHE/voice.wav"

  case "$be" in
    # Use printf %s to avoid any shell interpretation of msg content
    say) printf '%s' "$msg" | xargs -0 say &>/dev/null & ;;
    espeak-ng) printf '%s' "$msg" | xargs -0 espeak-ng &>/dev/null & ;;
    piper)
      printf '%s' "$msg" | piper --output_file "$audio_tmp" 2>/dev/null \
        && play -q "$audio_tmp" 2>/dev/null &
      ;;
  esac
}

_cmd_voice_setup() {
  echo -e "${B}Voice Setup${R}"; echo ""
  local t; t=$(_voice_tts); echo "TTS: $t"
  [[ "$t" == "none" ]] && {
    echo "  Install: macOS → built-in 'say' | Linux → sudo apt install espeak-ng"
    echo "  Fast: pip install piper-tts"; }
  echo ""; echo "Enable: export CCWATCH_VOICE=true"
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
  if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    echo -e "${CR}not set${R}"
    echo ""
    echo "ccwatch uses the Anthropic API (not your Max/Pro subscription)."
    echo "Cost: ~\$0.001/scan (Haiku), ~\$0.01/suggestion (Sonnet)"
    echo ""
    echo "  1. Get a key: https://console.anthropic.com/settings/keys"
    echo "  2. Add to your shell profile:"
    echo "     export ANTHROPIC_API_KEY=sk-ant-..."
    echo "  3. Re-run: ccwatch setup"
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
bind-key S display-popup -w 78 -h 22 -E "bash '${me_escaped}' --popup status"
bind-key A display-popup -w 92 -h 35 -E "bash '${me_escaped}' --popup ls"
bind-key G display-popup -w 82 -h 25 -E "bash '${me_escaped}' --popup suggest"
bind-key P display-popup -w 86 -h 30 -E "bash '${me_escaped}' --popup permissions"

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

  tmux bind-key S display-popup -w 78 -h 22 -E "bash '${me_escaped}' --popup status" 2>/dev/null || true
  tmux bind-key A display-popup -w 92 -h 35 -E "bash '${me_escaped}' --popup ls" 2>/dev/null || true
  tmux bind-key G display-popup -w 82 -h 25 -E "bash '${me_escaped}' --popup suggest" 2>/dev/null || true
  tmux bind-key P display-popup -w 86 -h 30 -E "bash '${me_escaped}' --popup permissions" 2>/dev/null || true

  echo ""
  echo -e "${B}${CC}╭──────────────────────────────────────────────╮${R}"
  echo -e "${B}${CC}│  ✓ ccwatch is ready                          │${R}"
  echo -e "${B}${CC}╰──────────────────────────────────────────────╯${R}"
  echo ""
  echo -e "  ${B}Status bar${R} (ambient, \$0):"
  echo -e "    ●4 ?1 !2 ▰▰▱▱▱   ${D}← always visible in tmux${R}"
  echo ""
  echo -e "  ${B}Keybindings${R} (on-demand, ~\$0.01):"
  echo -e "    prefix+S  status of current pane"
  echo -e "    prefix+A  list all sessions (cognitive load)"
  echo -e "    prefix+G  what to do next"
  echo -e "    prefix+P  permission analysis → settings.json"
  echo ""
  echo -e "  ${B}CLI${R}:"
  echo -e "    ccwatch              quick glance"
  echo -e "    ccwatch ls           full analysis"
  echo -e "    ccwatch suggest      workflow advice"
  echo -e "    ccwatch permissions  fix your settings.json"
  echo ""
  echo -e "  ${D}Voice: export CCWATCH_VOICE=true (run 'ccwatch voice-setup' first)${R}"
  echo -e "  ${D}Logs:  $CACHE/${R}"
}

# ─── ENTRY ────────────────────────────────────────────────────────────────────
case "${1:-}" in
  "") _cmd_default ;;
  ls|list) _cmd_ls ;;
  status|s) _cmd_status "${2:-}" ;;
  suggest|sg) _cmd_suggest ;;
  permissions|perm) shift; case "${1:-}" in
    --apply) _cmd_perms_apply "${2:-user}" ;; --reset) _cmd_perms_reset ;; *) _cmd_perms ;; esac ;;
  daemon|d) shift; case "${1:-status}" in
    start) _daemon_start ;; stop) _daemon_stop ;; *) _daemon_status ;; esac ;;
  --statusbar) _statusbar ;;
  --popup) shift
    # Wrapper for tmux display-popup: runs subcommand in bash, then waits for keypress.
    # Needed because tmux popups use the default shell (often zsh), where
    # bash-specific `read -rsn1` is invalid.
    case "${1:-}" in
      status|s) _cmd_status "${2:-}" ;;
      ls|list) _cmd_ls ;;
      suggest|sg) _cmd_suggest ;;
      permissions|perm) shift; case "${1:-}" in
        --apply) _cmd_perms_apply "${2:-user}" ;; --reset) _cmd_perms_reset ;; *) _cmd_perms ;; esac ;;
    esac
    echo ""; read -rsn1 -p $'↵ '
    ;;
  voice|v) _check_deps; _check_api; export CCWATCH_VOICE=true
    echo "Voice mode — say commands aloud (WIP: install whisper-cpp for STT)"
    echo "For now, use keybindings. Voice alerts work with: export CCWATCH_VOICE=true" ;;
  voice-setup|vs) _cmd_voice_setup ;;
  setup) _cmd_setup ;;
  help|--help|-h) cat << 'H'
ccwatch — Ambient Intelligence for Claude Code Sessions

  ccwatch                Quick glance (reads daemon, no API)
  ccwatch ls             Sessions sorted by cognitive load
  ccwatch status [ID]    Deep analysis of one session
  ccwatch suggest        What to do next (Sonnet)
  ccwatch permissions    Permission log → settings.json suggestions
  ccwatch daemon start   Background scanner (auto-started by setup)
  ccwatch setup          One-time install

Status bar (always visible, $0):
  ●4 ?1 !2 ▰▰▱▱▱ P47

Keybindings (on-demand, ~$0.01/call):
  prefix+S  status     prefix+A  list all
  prefix+G  suggest    prefix+P  permissions

Models: Haiku (fast scans) + Sonnet (analysis/suggestions)
Cost: ~$0.10-0.50/day with heavy use
API: Uses ANTHROPIC_API_KEY, not your Max/Pro subscription

Env:
  ANTHROPIC_API_KEY          Required
  CCWATCH_MODEL_FAST         Override Haiku model
  CCWATCH_MODEL_THINK        Override Sonnet model
  CCWATCH_MODEL              Force single model for everything
  CCWATCH_VOICE=true         Enable voice alerts
  CCWATCH_SCAN_INTERVAL=30   Daemon scan interval (seconds)
H
  ;; *) echo "Unknown: $1 — try: ccwatch help" ;;
esac
