# ccwatch

Monitor all your Claude Code sessions from one tmux status bar. Get notified when any session needs attention — permission prompts, questions, errors — without switching panes.

![status bar](assets/statusbar.png)

## What it does

- **Status bar** shows session count, waiting prompts, and load at a glance — always visible, zero cost
- **Slack notifications** ping you when a session needs attention (permission, question, error)
- **AI popups** give deep analysis on demand — cognitive load scoring, permission suggestions (~$0.01/call)
- **Permission aggregation** logs every permission request across sessions and generates `settings.json` rules so they stop coming up

The background daemon scans tmux panes every 30 seconds using regex — no API calls. AI analysis only runs when you press a keybinding.

## Install

```bash
git clone https://github.com/Compass-Regulatory/ccwatch ~/.local/share/ccwatch
cd ~/.local/share/ccwatch
bash ccwatch.sh setup
```

`setup` is interactive and handles everything:
- Checks dependencies (tmux, curl, jq)
- Prompts for your API key
- Installs `ccwatch` to `~/.local/bin`
- Starts the background daemon
- Installs TPM for session persistence (optional)
- Appends config to `~/.tmux.conf` (asks first)
- Installs Claude Code hooks for faster event detection (optional)

After setup, reload tmux and install plugins:
```bash
tmux source ~/.tmux.conf
# Then press: prefix + I (capital i) to install TPM plugins
```

### Requirements

- **tmux** (3.3+ recommended for popup support)
- **curl**, **jq**
- **pstree** (optional, improves session detection)
- **Anthropic API key** — uses the API, **not** your Max/Pro subscription
  - Get one: https://console.anthropic.com/settings/keys
  - Store it: `ccwatch key set` (macOS Keychain) or `export ANTHROPIC_API_KEY=sk-ant-...`
  - Cost: ~$0.10–0.50/day with heavy use

## Status bar

Always visible in tmux, updated every 30 seconds:

```
●4 ?1 !2 ▰▰▱▱▱ P47 | 14:32
 |  |  |  |       |
 |  |  |  |       +-- 47 permissions logged (run ccwatch permissions)
 |  |  |  +-- load bar (2 of 4 sessions actively working)
 |  |  +-- 2 permission prompts waiting
 |  +-- 1 question waiting
 +-- 4 sessions detected (bold = needs attention)
```

## Keybindings

| Key | What | Cost |
|---|---|---|
| `prefix + S` | Deep analysis of current pane | ~$0.01 |
| `prefix + A` | All sessions sorted by cognitive load | ~$0.01 |
| `prefix + P` | Permission analysis → settings.json suggestions | ~$0.01 |
| `prefix + N` | Generate/update Obsidian daily note | ~$0.01 |

## CLI

```bash
# Quick glance (no API call)
ccwatch                          # session summary from daemon state

# AI analysis
ccwatch ls                       # all sessions, sorted by cognitive load
ccwatch status                   # deep dive on current pane
ccwatch status 0:1.0             # deep dive on specific pane

# Permissions
ccwatch permissions              # analyze logged perms → settings.json suggestions
ccwatch permissions --apply user # apply suggestions to ~/.claude/settings.json
ccwatch permissions --reset      # clear permission logs

# Notifications
ccwatch notify                   # show notification status
ccwatch notify set               # store Slack webhook in macOS Keychain
ccwatch notify set-user          # store Slack member ID for @mentions
ccwatch notify on|off            # toggle notifications
ccwatch notify test              # send a test notification
ccwatch notify delete            # remove webhook + user ID from Keychain

# Other
ccwatch voice on|off             # toggle voice narration (local TTS)
ccwatch bell on|off              # toggle bell sound on attention
ccwatch notes                    # generate Obsidian daily note from session activity
ccwatch key set                  # store API key in macOS Keychain
ccwatch daemon start|stop|restart|status  # manage background daemon
ccwatch setup                    # run interactive setup
```

## Slack Notifications

Get notified on your phone/desktop when any session needs attention.

### Setup

1. Go to https://api.slack.com/apps → **Create New App** → **From scratch**
2. Name it (e.g. "ccwatch"), pick your workspace
3. Click **Incoming Webhooks** → toggle **On**
4. Click **Add New Webhook to Workspace** → select your own DM (for personal notifications) or a channel
5. Copy the webhook URL

Then:
```bash
ccwatch notify set          # paste the webhook URL
ccwatch notify on           # enable notifications
ccwatch notify test         # verify it works
```

### When do notifications fire?

The daemon sends a notification when the **waiting session count increases**. You'll get notified when:
- Claude asks for permission (e.g. Allow Bash(npm test)?)
- Claude asks you a question
- A session hits an error

You won't get notified for sessions that are working normally, finish successfully, or if the waiting count stays the same.

When `ANTHROPIC_API_KEY` is set, notification bodies are summarized by Haiku (~$0.001/notification) into a clean 1-2 sentence description per session, with sensitive content (API keys, tokens, file paths) automatically redacted. If the API key is not set or the call fails, notifications fall back to the raw label + state type.

### Optional: @mentions for mobile push

If you're sending notifications to a **channel** (not your DM), add your Slack member ID so you get @mentioned and receive mobile push notifications:

```bash
ccwatch notify set-user     # paste your member ID
```

To find your member ID: click your profile picture in Slack → **Profile** → **⋮** menu → **Copy member ID**.

If the webhook already posts to your own DM, you don't need this — Slack sends push notifications for all DMs by default. If you're not getting mobile pushes, check **Slack → Preferences → Notifications** and disable the "only notify on mobile when inactive on desktop" setting.

## Cognitive Load Scoring

`ccwatch ls` rates each session 1–5 using Sonnet:

| Score | Label | Safe to switch away? |
|---|---|---|
| ▰▱▱▱▱ | trivial | freely |
| ▰▰▱▱▱ | low | easy resume |
| ▰▰▰▱▱ | medium | some context needed |
| ▰▰▰▰▱ | high | significant context loss |
| ▰▰▰▰▰ | intense | full attention required |

Sessions are sorted low→high so quick check-ins appear first. The footer recommends which session to focus next (permissions > questions > errors).

## Permission Aggregation

Instead of auto-approving permissions (risky), ccwatch logs every permission request across all sessions. Run `ccwatch permissions` to:

1. See aggregated patterns ("Bash(npm test) asked 47x across 3 sessions")
2. Get Sonnet-generated `settings.json` rules — narrowest patterns that cover your usage
3. Dangerous patterns like `Bash(*)` or `Bash(sudo ...)` are rejected automatically
4. Apply with `ccwatch permissions --apply user` — permissions stop coming up

## Architecture

```
tmux status bar  ←  ●4 ?1 !2 ▰▰▱▱▱    (daemon writes tmux vars)
                          |
            +-------------+-------------+
            |    daemon (background)     |
            |  - regex pane scanning     |   ← $0, every 30s
            |  - Claude Code hook events |
            |  - permission logging      |
            |  - bell/voice/slack alerts |
            |  - NO api calls            |
            +-------------+-------------+
                          |
            +-------------+-------------+
            |   AI layer (on demand)     |
            |  - Sonnet: analysis,       |   ← ~$0.01/call
            |    suggestions, perms      |
            |  - triggered by keypress   |
            +---------------------------+
```

## Config

All config is optional. Defaults work out of the box.

| Variable | Default | What |
|---|---|---|
| `ANTHROPIC_API_KEY` | (required) | API key — or use `ccwatch key set` for Keychain. Also enables AI-summarized Slack notifications |
| `CCWATCH_MODEL_FAST` | `claude-haiku-4-5-20251001` | Model for fast tier |
| `CCWATCH_MODEL_THINK` | `claude-sonnet-4-6` | Model for analysis (ls, status, permissions) |
| `CCWATCH_MODEL` | (none) | Override: force one model for everything |
| `CCWATCH_VOICE` | `false` | Enable voice alerts — or use `ccwatch voice on` |
| `CCWATCH_BELL` | `false` | Enable bell sound — or use `ccwatch bell on` |
| `CCWATCH_SLACK_WEBHOOK` | (none) | Slack webhook URL — or use `ccwatch notify set` |
| `CCWATCH_SLACK_USER_ID` | (none) | Slack member ID for @mentions — or use `ccwatch notify set-user` |
| `CCWATCH_NOTIFY_COOLDOWN` | `0` | Minimum seconds between notifications (0 = no limit) |
| `CCWATCH_SCAN_INTERVAL` | `30` | Daemon scan interval in seconds |
| `CCWATCH_LINES` | `80` | Terminal lines captured per pane |
| `CCWATCH_OBSIDIAN_VAULT` | `~/ObsidianVault` | Obsidian vault path for notes |
| `CCWATCH_NOTES_INTERVAL` | `900` | Notes watch-mode interval in seconds |

## FAQ

**Do I need an Anthropic API key?**
Yes, but only for AI features (keybindings, `ccwatch ls`, `ccwatch status`, `ccwatch permissions`, `ccwatch notes`). The daemon, status bar, Slack notifications, bell, and voice all work without an API key and cost nothing.

**Does the daemon use the API?**
No. The daemon only uses regex pattern matching on terminal output. It never calls the Anthropic API. AI analysis only runs when you press a keybinding or run an AI command.

**How much does it cost?**
The daemon is free. Each AI call (keybinding press or CLI command) costs ~$0.01. Typical usage is $0.10–0.50/day.

**Does it work with multiple Claude Code sessions?**
Yes, that's the main use case. The daemon detects all Claude Code sessions across all tmux panes automatically.

**What happens after a reboot?**
If you accepted the tmux.conf changes during setup, the daemon auto-starts with tmux. If not, run `ccwatch daemon start`. If you installed TPM plugins (tmux-resurrect + tmux-continuum), your panes and sessions are also restored.

**I'm not getting Slack notifications.**
Check: `ccwatch daemon status` (daemon must be running), `ccwatch notify` (must show "on" with a webhook source), and `ccwatch notify test` (should send a test message). The daemon only notifies when the waiting count *increases* — if a session was already waiting before the daemon started, it won't trigger.

**I get desktop Slack notifications but not mobile push.**
Slack suppresses mobile push when you're active on desktop by default. Fix: **Slack → Preferences → Notifications → Use different settings for my mobile devices** → set to notify on all new messages. Alternatively, `ccwatch notify set-user` adds an @mention to each notification, which overrides quiet settings.

**Can I use this without tmux?**
No. ccwatch relies on tmux for pane discovery, terminal capture, status bar, and popup keybindings.

**How do I uninstall?**
Remove the ccwatch block from `~/.tmux.conf`, run `ccwatch daemon stop`, then `rm -rf ~/.local/share/ccwatch ~/.local/bin/ccwatch ~/.cache/ccwatch`. Optionally remove hooks from `~/.claude/settings.json`.

## Single file

ccwatch is one bash script (~1800 lines). No build step, no compile, no node_modules.
