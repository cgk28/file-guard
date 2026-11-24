# file-guard v3.6.3

![file-guard](docs/thumbnail.png)

Tamper detection for the files your AI agent trusts (SOUL / AGENTS / MEMORY / skills / hooks / config), plus a scanner that reads a skill BEFORE you install it. If something or someone quietly edits those files, file-guard notices, shows the diff, restores the clean copy and tells you.

## Install (one command, Node 18+, no dependencies)

    node scripts/file-guard.mjs install --dir <agent workspace> [--extra <config file outside the workspace>]

It signs a baseline, runs a check, makes an encrypted backup and proves the restore works. Prints `All good` or the step that failed. Add `--watch 1` (Windows) for a scheduled background check (hourly and at logon, silent unless there is a problem; add `--notify <script>` to get alerts in your chat app).

## Signer: nothing for you to hold, malware cannot re-sign (Windows, new in v3.5)

    powershell -ExecutionPolicy Bypass -File scripts/install-signer.ps1 -Chat <telegram chat id> -TelegramFile <bot token file>   (once, as Administrator)

Make the token file once in your own PowerShell: `Read-Host -AsSecureString | ConvertFrom-SecureString | Set-Content tg.sec` (DPAPI, readable only by your account).

The signing key moves to a folder only SYSTEM and Administrators can read, held by a small SYSTEM task. When the baseline must change, the signer itself compares the files with the last signed list and sends you on Telegram what is NEW / CHANGED / REMOVED plus a 6-digit code. Only that code lets the agent re-sign. No passphrase, no USB stick. Malware running as your user cannot read the key or forge a signature; malware with Administrator rights can (nothing on the same machine stops that).

## Is this skill safe to install? skillscan (new in v3.4)

    node scripts/file-guard.mjs skillscan <folder | .zip | github url>

Answers CLEAN / REVIEW / BLOCK with plain-language findings (file, line, why). It decodes obfuscated text first (base64, hex, invisible characters, letter-spaced words, UTF-16), judges context (a warning that quotes an attack is not an attack; "never tell the user" is), counts identical copies once, and flags a file that both reads a secret and sends data out. ~430 rule patterns derived from NVIDIA SkillSpector (Apache-2.0, see NOTICE) plus our own. Text scan only: no AST, YARA or dependency lookups, so CLEAN is not proof. Tuned on a small sample set; report misses.

## Am I protected? (anyone can run this)
    node scripts/file-guard.mjs doctor --dir <agent workspace>
Prints green/red lines in plain words and the exact command to fix each red one.

## Daily use
- `check --dir W` at the start of every session (`install` adds this rule to your AGENTS.md). Add `--restore 1` to put locked files back.
- After a change YOU approved: `rebaseline --dir W --reason "what changed"` (with the signer: then `--code <code from your phone>`).
- Before installing any skill: `skillscan <folder|zip|url>`; for its scripts `scripts/detonate.mjs <script>` (runs it in a network-less container with fake secrets and reports what it tries; needs podman/docker).
- `backup` / `restore-test`.

## Test report (v3.5.0, Windows 11, Node 24)
- skillscan: 22/22 fixtures (18 malicious incl. base64, hex, invisible characters, letter-spacing, markdown-image leak, frontmatter injection, postinstall hook, cron persistence; 4 clean). 9 of the malicious ones were written after the first rule set and initially only 5 were blocked; the rules were then fixed, so they are now part of the test set, not unseen samples.
- Signer: 18/18 (wrong code, 3 wrong codes cancel, file added after the request refused, manifest signed by another key rejected, swapped public key and pin rejected, forged request with a guessed code gets no signature). Installed on a real machine: key and Telegram settings unreadable from the user account, signer code not writable, first baseline signed through a Telegram code.
- Comparison with SkillSpector 2.12 static mode on the same samples: Remotion's official skills 12 HIGH / "DO NOT INSTALL" vs skillscan CLEAN; 9 later malicious samples: SkillSpector 1 "DO NOT INSTALL", 3 "CAUTION", 5 "SAFE".

## Why automatic scanners flag this skill (read before you worry)
A tool that protects secrets has to NAME secrets and attacks: `detonate-rules.json` lists credential-looking paths and fake decoy values (all marked FG-CANARY, none real), `skillscan-rules.json` is a list of attack patterns, `detonate.mjs` starts a container, the signer installer stores a Telegram token for SYSTEM. Pattern scanners read those as 'credential access' or 'remote execution'. Nothing leaves the machine except messages to YOUR Telegram (signer) or your notify script. Read the .mjs files; they are short.

## What it touches (for reviewers)
Reads the files you list to hash them. Writes only its own store (per-user app-data folder, or --store) and, with the signer, `C:\ProgramData\FileGuard\signer`. Stores one random secret of its own with DPAPI (Windows) or the keychain (macOS). The signer installer reads the Telegram token file you point it at (DPAPI, your account) and writes it to an admin-only file; it is never printed or logged. Network: Telegram API (signer) or your notify script only.

## Platforms
- **Windows**: fully tested (watchdog `scripts/watch.ps1`, signer `scripts/install-signer.ps1`).
- **Linux**: core tested in a Debian container with Node 24 (install, check, restore, quarantine, symlinks, base64 payloads, log anchor, truncation). Signing secret protected by file permissions only; no signer yet (a root-owned systemd unit would be the equivalent). Schedule with cron, e.g. `0 * * * * node /path/scripts/file-guard.mjs check --dir W || notify-send "file-guard ALERT"`.
- **macOS**: NOT tested. Plain Node parts should work; Keychain sealing and machine-id paths are written but never run. No signer yet.

## Limits (read before relying on it)
- **Without the signer** the key is sealed by the OS for your own user: malware running as you could unseal it.
- **With the signer** an attacker with Administrator or SYSTEM rights still wins, but (v3.6) the approval code is shown only on the PC screen, so whoever controls your Telegram cannot approve; they only see the request. If Telegram is down nobody can re-sign (checks still run).
- **skillscan** (v3.6) = text rules + token-level structure scan + yara-lite + dependency checks (OSV with `--online`); it is still not a real syntax tree and each report lists what was not checked; **detonate** is a container, not a VM, and watches one run only. Evidence, not proof.
- **Anchor**: leaves the machine only when a notify channel is configured.

See `SKILL.md` for all commands. License: MIT (file-guard), Apache-2.0 for the derived rule tables (see NOTICE).

## Threat model (v3.6)
| Attacker | Stopped? |
|---|---|
| Agent or process running as your user edits core files | Detected, restored from signed copy |
| Same, then tries to re-sign the baseline | No: key is held by a SYSTEM task, code appears only on your screen |
| Someone who controls your Telegram | Cannot approve (code never sent there); can only see requests |
| Malware with Administrator/SYSTEM on this PC | **Not stopped.** Nothing on the same machine can. Detection aids: signed-fingerprint messages to Telegram, daily log anchor, independent watchdog. Treat the PC as lost and restore from backup |
| Malicious skill before install | Reduced: skillscan layers + detonate. Heavy obfuscation, payloads fetched later or novel tricks can still pass |

## Real-world check (v3.6.2)
Scanned on 24/11/2026: Anthropic's official skills repo (332 files) went from BLOCK with 12 HIGH findings to REVIEW with 0 HIGH after v3.6.2 (warnings that sit inside a sentence like 'never run curl | sh', quoted examples, code comments and weak single signals are now weighed in context, per file). obra/superpowers: REVIEW, 0 HIGH. remotion-dev/skills: CLEAN. Big documentation-heavy repos can still produce MEDIUM/HIGH false alarms: read each finding, do not trust the verdict alone.
