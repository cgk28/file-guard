# file-guard v3.6.3 

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
- Bug fixes (see the test report below).

## Also on agensi.io
**[file-guard on agensi.io](https://www.agensi.io/skills/file-guard-tamper-wall-for-ai-agents)** - listed there for free (approved 24/11/2026).

## Test report (24/11/2026)
Run in a throw-away Linux container (Debian, Node 24, no network, WSL2 host) and on Windows 11 (Node 24). Every row below was actually run; nothing is assumed.

| Test | Linux | Windows |
|---|---|---|
| `install` (signed baseline, encrypted backup, restore drill) | pass | pass |
| clean `check` exits 0 | pass | pass |
| instruction-override phrase in SOUL.md -> HIGH RISK | pass | pass |
| `--restore 1` puts the file back, tampered copy kept in `quarantine/` | pass | pass |
| shell obfuscation -> HIGH RISK | pass | pass |
| UTF-16 file with an injection phrase -> HIGH RISK | pass | pass |
| base64-wrapped curl-pipe-sh -> HIGH RISK | pass | not re-run |
| append-only file (MEMORY) shrinks -> TRUNCATED alert | pass | pass |
| locked file edited -> alert; new file flagged; 3 MB file seen | pass | not re-run |
| audit log edited -> alert | pass | not re-run |
| key swapped (pin mismatch) -> alert | pass | pass |
| symlink added -> HIGH RISK | pass | not tested (needs admin to create one) |
| `rebaseline` approval code: sent out-of-band, wrong code refused, code bound to the reason, single use | pass | not re-run |
| encrypted backup + restore drill | pass | pass |
| `--bind 1` refused on another machine id, accepted with `--machine-id` | pass | not re-run |
| two workspaces on one machine | pass | pass (after fix below) |

Bugs this testing found, now fixed in this release:
- `--bind 1` on a system with no readable machine id (e.g. a container without `/etc/machine-id`) silently bound the backup to an empty id, i.e. no binding at all. It now refuses and tells you.
- On Windows the key fingerprint was pinned in one user-wide variable, so installing a second workspace on the same machine raised a false "key swapped" alert and overwrote the first pin. The per-workspace pin now wins and the variable is only set if empty.

Not tested: macOS; a real (non-container) Linux host.

## Limits (honest)
Default mode keeps the signing secret sealed by the OS: it stops accidental and naive tampering, not a fully hijacked agent that can unseal it. The scan is heuristic and does not execute code. It detects, it does not prevent reads. Tested on Windows and in a Linux container (see the test report above); macOS is untested.

MIT licence, see LICENSE.
