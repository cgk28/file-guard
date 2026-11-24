# file-guard v3.2 (free edition)

Tamper wall for AI agents: signed baseline of your agent's core files, content scan of changes, auto-restore with quarantine, tamper-evident log, encrypted backups. Zero dependencies, Node 18+.

## Quick start
```
node scripts/file-guard.mjs install --dir <your-agent-workspace>
node scripts/file-guard.mjs check   --dir <your-agent-workspace>
```
`install` signs a baseline, runs a check, makes an encrypted backup and proves the restore works. Add `--restore 1` to `check` to put tampered files back (the bad copy goes to `quarantine/`). `doctor` prints a plain-language health report. Run with no arguments for all commands.

## What's new in v3.2 (vs v3.1)
- Content scan now normalises Unicode (NFKC) and drops invisible/zero-width characters before matching.
- Scans decoded base64 payloads, not just the raw text.
- Bug fixes.

## Free (v3.2) vs Full (v3.3)
| | Free v3.2 | Full v3.3 |
|---|---|---|
| Signed baseline, check, auto-restore, quarantine | yes | yes |
| Tamper-evident log, encrypted backups, restore drill, doctor | yes | yes |
| Scan: NFKC + invisible chars + base64 | yes | yes |
| Scan: shell obfuscation (`c${u}rl`, quotes, `^`), UTF-16 files | no | yes |
| External JSON config compared in canonical form (no false alarms on reshuffle) | basic | yes |
| `anchor`: daily log fingerprint sent to your phone (catches full log rewrite) | no | yes |
| `watch`: scheduled background watchdog (Windows) | no | yes |
| `detonate`: run a new script in a network-less container with decoy secrets | no | yes |

## Want the full edition?
**file-guard full v3.3 - $15 one-time on [agensi.io](https://agensi.io)** (search "file-guard"). Same install steps; you get all scripts above and all future v3.x fixes.

## Limits (honest)
Default mode keeps the signing secret sealed by the OS: it stops accidental and naive tampering, not a fully hijacked agent that can unseal it. The scan is heuristic and does not execute code. It detects, it does not prevent reads. Tested on Windows; macOS/Linux paths are written but less tested.

MIT licence, see LICENSE.