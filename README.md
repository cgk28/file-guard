# TrustMe — Tamper Wall for AI Agents

> An agent that reads the web can be talked into anything. TrustMe makes sure that even a fooled agent cannot touch its own brain, leak your secrets or plant a backdoor — and tells you the moment someone tries.

Three layers, each honest about what it does and does not do:

| Layer | Part | Does | Does NOT do |
|---|---|---|---|
| 1 Detect | `file-guard` skill (signed baseline) | Finds changed core files (AGENTS/SOUL/TOOLS/…); re-signing needs a one-time code sent to the owner; `extscan` adds trufflehog + strings secret scan | Prevent a change; it reports after |
| 2 Block | `file-guard-wall` plugin ("TrustMe wall") | Denies tool calls **before** they run: writes to protected files, dangerous commands, outbound actions after untrusted content was read | Stop a determined, creative attacker; regex rules can be evaded |
| 3 Alarm | `Chu-FileGuardWatch` task (hourly) + Live server | Runs layer 1 with no agent running; Telegram alert once per new change or late-taint event | Block anything |

![TrustMe](docs/thumbnail.png)

## What makes it stand out

- **Taint tracking, not just a blocklist.** The moment the agent calls a web/peer/browser tool, the run is marked *tainted*. From then on, anything that could exfiltrate or persist (network, installs, messaging, vault, cron, gateway, executable writes) is denied until the owner sends a new message. This is the prompt-injection brake.
- **Taint at CALL time.** The flag is set when the web tool is *called*, not when it returns, so a parallel step cannot slip past. Sensitive commands wait 0.4 s and re-check; late taint is logged and alerted.
- **Content scan (layer D).** A file written under taint is scanned before it may run: clean = allowed, dirty/unreadable = blocked. Rename-then-run does not help.
- **Rules as data.** Edit `plugin/rules.json`, run `node plugin/build.js`, done. Quote/concat tricks are normalised before matching.
- **Three modes.** `strict`, `normal` (default), `lenient` via option or `TRUSTME_MODE`.
- **Audit trail.** `~/.trustme/audit.jsonl` (deny / mark / scanned-clean), rotates at 2 MB.
- **OpenClaw adapter** (`adapters/claude-code`) — the same wall as a hook.
- **Secrets never in the kit.** `extscan` (trufflehog + strings) and ripgrep gate every upload.

## Live window

`powershell -File live/open-live.ps1` opens a small always-on-top app (own icon, taskbar button) on 127.0.0.1:7077: every tool call the agent makes, blocked count, mode, red-team score, 24 h audit counts, scanner status. Local only; sends nothing out.

![Live monitor](docs/live.png)

Optional phone alert: copy `live/notify.example.ps1` to `live/notify.ps1`, set `TRUSTME_TG_TOKEN` and `TRUSTME_TG_CHAT`.

## Rules in the plugin
- **files**: no write/edit/move/delete on AGENTS.md, SOUL.md, TOOLS.md, HEARTBEAT.md, IDENTITY.md, the file-guard skill and its baseline.
- **danger**: remote code piped to a shell, encoded PowerShell, credential stores, uploads/POST, raw transfer tools, scheduled-task/autorun persistence, destructive deletes, force push, weakening Defender.
- **trust**: see taint tracking above.

A denied agent is told to stop and ask the owner.

## Use
`powershell -File trustme.ps1 status` shows the three layers; `install` (re)creates the hourly task. The plugin is turned on only by the owner.

## Red-team score (our own corpus)
`node tests/redteam.js` writes `REDTEAM.md`. Normal mode: **46/46 attacks blocked, 21/21 benign passed**. Strict: 46/46, 19/21 benign. Lenient trades 4 two-stage attacks for fewer false stops. A regression guard we wrote ourselves, not an independent audit.

## Known limits (honest list)
- A dangerous command in the same parallel step as the web call can still run; the wall records a late-taint alert but cannot undo it.
- A clean script that writes another file when run is not seen by the plugin; the live server watcher scans new executables while tainted (detection, not blocking).
- The plugin host has no fs: clean verdicts come from Write tool content.
- Flags live in the plugin store for 6 h and survive restart; the owner cannot clear them while the gateway runs.
- Cannot read other tools' MCP or browser clicks.
