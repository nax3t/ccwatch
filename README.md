# ccwatch

Ambient intelligence for Claude Code sessions in tmux.

One status bar line. Four keybindings. No TUI to manage.

```
●4 ?1 !2 ▰▰▱▱▱ │ 14:32     ← always visible, $0
prefix+A                       ← full analysis on demand, ~$0.01
```

## Install

```bash
git clone https://github.com/YOU/ccwatch ~/.local/share/ccwatch
cd ~/.local/share/ccwatch
bash ccwatch.sh setup
```

That's it. `setup` handles everything:
- Checks dependencies (tmux, curl, jq)
- Checks your API key
- Installs `ccwatch` to `~/.local/bin`
- Starts the background daemon
- Installs TPM if missing
- Appends config to `~/.tmux.conf` (asks first)
- Sets live keybindings for current session

After setup, reload tmux and install plugins:
```bash
tmux source ~/.tmux.conf
# Then press: prefix + I (capital i) to install TPM plugins
```

## Requirements

- `tmux` (3.3+ recommended for popups)
- `curl`, `jq`
- `ANTHROPIC_API_KEY` — this uses the API, **not** your Max/Pro subscription
  - Get one: https://console.anthropic.com/settings/keys
  - Cost: ~$0.10-0.50/day with heavy use

## How It Works

**Two layers, zero overlap:**

| Layer | What | Cost | When |
|---|---|---|---|
| **Daemon** | Scans panes every 30s via regex. Updates tmux status bar. Logs permission requests. Sends bell on blocked sessions. | $0 | Always |
| **AI popups** | Haiku/Sonnet analysis triggered by keypress. Cognitive load scoring, workflow suggestions, permission aggregation. | ~$0.01/call | When you ask |

The daemon never calls the API. The AI layer only fires when you press a key.

## Usage

### Status bar (always visible)
```
●4 ?1 !2 ▰▰▱▱▱ P47 │ 14:32
│  │  │  │         │
│  │  │  │         └─ 47 permissions logged (run ccwatch permissions)
│  │  │  └─ load bar (green/yellow/red)
│  │  └─ 2 permission prompts waiting
│  └─ 1 question waiting
└─ 4 sessions (green=clear, yellow=needs attention)
```

### Keybindings
| Key | What | Model |
|---|---|---|
| `prefix + S` | Status of current pane | Sonnet |
| `prefix + A` | All sessions, sorted by cognitive load | Sonnet |
| `prefix + G` | "What should I do next?" | Sonnet |
| `prefix + P` | Permission analysis → settings.json | Sonnet |

### CLI
```bash
ccwatch              # quick glance (no API)
ccwatch ls           # full AI analysis
ccwatch status       # deep dive current pane
ccwatch status 0:1.0 # deep dive specific pane
ccwatch suggest      # workflow advice
ccwatch permissions  # analyze logged perms → settings.json suggestions
ccwatch permissions --apply user     # apply to ~/.claude/settings.json
ccwatch permissions --apply project  # apply to .claude/settings.json
ccwatch permissions --reset          # clear logs
ccwatch daemon start/stop/status
```

## Cognitive Load Scoring

Each session gets rated 1-5 by Sonnet:

| Score | Label | Switch away? |
|---|---|---|
| ▰▱▱▱▱ | trivial | freely |
| ▰▰▱▱▱ | low | easy resume |
| ▰▰▰▱▱ | medium | some context needed |
| ▰▰▰▰▱ | high | significant context loss |
| ▰▰▰▰▰ | intense | full attention required |

Sessions are sorted low→high so quick check-ins appear first.

## Permission Aggregation

Instead of auto-approving permissions (risky), ccwatch logs every permission
request it sees across all sessions. When you run `ccwatch permissions`:

1. Aggregates patterns ("Bash(npm test) asked 47x across 3 sessions")
2. Sonnet generates the narrowest `settings.json` rules to cover them
3. `ccwatch permissions --apply user` merges into `~/.claude/settings.json`
4. Permissions stop coming up. One-time fix.

## Voice (Optional)

```bash
ccwatch voice-setup         # check what's available
export CCWATCH_VOICE=true   # enable
```

When enabled, the daemon speaks alerts when sessions transition to waiting.
Uses local TTS only (Piper, say, espeak-ng) — no API calls for voice.

## Architecture

```
tmux status bar ← ●4 ?1 !2 ▰▰▱▱▱    (daemon writes tmux vars)
                      │
         ┌────────────┴────────────┐
         │    daemon (background)   │
         │  • regex pane scanning   │   ← $0, every 30s
         │  • permission logging    │
         │  • bell/voice on waiting │
         │  • NO api calls          │
         └────────────┬────────────┘
                      │
         ┌────────────┴────────────┐
         │   AI layer (on demand)   │
         │  • Haiku: fast scans     │   ← ~$0.001/call
         │  • Sonnet: analysis,     │   ← ~$0.01/call
         │    suggestions, perms    │
         │  • triggered by keypress │
         └─────────────────────────┘
```

## Config

| Variable | Default | What |
|---|---|---|
| `ANTHROPIC_API_KEY` | (required) | API key |
| `CCWATCH_MODEL_FAST` | `claude-haiku-4-5-20251001` | Fast tier |
| `CCWATCH_MODEL_THINK` | `claude-sonnet-4-5-20250929` | Think tier |
| `CCWATCH_MODEL` | (none) | Override: force one model for everything |
| `CCWATCH_VOICE` | `false` | Enable voice alerts |
| `CCWATCH_SCAN_INTERVAL` | `30` | Daemon scan interval (seconds) |
| `CCWATCH_LINES` | `80` | Terminal lines captured per pane |

## Single file

ccwatch is one 642-line bash script. No build step, no compile, no node_modules.
Fork it, hack it, extend it.
