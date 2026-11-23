# file-guard

![file-guard](docs/thumbnail.png)

Tamper detection for the files your AI agent trusts (SOUL / AGENTS / MEMORY / skills / hooks / config). If something or someone quietly edits them, file-guard notices, shows the diff, restores the clean copy and tells you.

## Install (one command, Node 18+, no dependencies)

    node scripts/file-guard.mjs install --dir <agent workspace> [--extra <config file outside the workspace>]

It signs a baseline, runs a check, makes an encrypted backup and proves the restore works. Prints `All good` or the step that failed. Add `--watch 1` (Windows) for a scheduled background check (hourly and at logon, silent unless there is a problem; add `--notify <script>` to get alerts in your chat app).

## Daily use
- `check --dir W` at the start of every session (`install` adds this rule to your AGENTS.md). Add `--restore 1` to put locked files back.
- After a change YOU approved: `rebaseline --dir W --reason "what changed"`.
- `backup` / `restore-test`.

## Features / Tính năng
- **Signed baseline / Mốc chuẩn có chữ ký**: hashes and signs your agent's key files (SOUL, AGENTS, MEMORY, skills, hooks, config). / Băm và ký các file quan trọng của agent.
- **Injection scan / Quét chèn lệnh**: flags prompt-injection and secret-exfiltration phrases in changed files. / Cảnh báo câu lệnh độc hại hoặc đòi gửi bí mật trong file bị sửa.
- **Auto-restore / Tự khôi phục**: puts the clean copy back and keeps the tampered file as evidence. / Trả file sạch về, giữ file bị sửa làm bằng chứng.
- **Encrypted backup / Sao lưu mã hóa**: signed, encrypted copy with a restore test. / Bản sao lưu mã hóa, có kiểm tra khôi phục.
- **Background watch / Giám sát nền** (Windows): scheduled check, silent unless there is a problem. / Kiểm tra định kỳ, chỉ báo khi có vấn đề.
- **Zero dependencies / Không cần cài thêm gì**: just Node 18+. / Chỉ cần Node 18+.

## Giới thiệu (Tiếng Việt)
file-guard là "bức tường chống sửa lén" cho các file mà AI agent của bạn tin tưởng (SOUL / AGENTS / MEMORY / skill / hook / cấu hình). Nếu có ai hoặc thứ gì âm thầm sửa chúng, file-guard phát hiện, cho xem phần khác biệt, khôi phục bản sạch và báo cho bạn.

Cài một lệnh (Node 18+, không phụ thuộc thư viện nào):

    node scripts/file-guard.mjs install --dir <thư mục workspace của agent>

Dùng hằng ngày: chạy `check --dir W` đầu mỗi phiên; sau khi bạn tự duyệt một thay đổi, chạy `rebaseline --dir W --reason "đã đổi gì"`. Giới hạn: chế độ mặc định chặn sửa vô ý hoặc đơn giản, không chống được agent đã bị chiếm quyền hoàn toàn; muốn mạnh hơn dùng `scripts/setup.ps1 -Auto`. Đã thử trên Windows; macOS/Linux viết sẵn nhưng chưa thử.
## Honest limits
Default mode (tier 0) keeps the signing secret sealed by the OS: it stops accidental and naive tampering, not an agent that is fully hijacked and can unseal it. For that, use `scripts/setup.ps1 -Auto` (owner-held passphrase). The content scan is heuristic. It detects, it does not prevent reads. Tested on Windows; macOS/Linux paths are written but untested.

See `SKILL.md` for all commands. License: MIT.

## What it touches (for reviewers)
Reads the files you list to hash them. Writes only its own store (default: per-user app-data folder, or --store). Stores one random secret of its own with DPAPI (Windows) or the keychain (macOS); it never reads other credentials. Network: none, except the optional notifier script YOU provide. Scanners may flag the keychain call: that is it.

## Credits
Made in Vietnam by CGK VIETNAM, together with AI assistant Chu. Copyright (c) 2026 CGK VIETNAM. MIT licensed.

