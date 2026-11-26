# Optional Telegram alert. Copy to notify.ps1 and set TRUSTME_TG_TOKEN and TRUSTME_TG_CHAT in your environment. Never commit a token.
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$b=@{chat_id=$env:TRUSTME_TG_CHAT;text=$env:TM_MSG}|ConvertTo-Json -Compress
Invoke-RestMethod -Uri "https://api.telegram.org/bot$env:TRUSTME_TG_TOKEN/sendMessage" -Method Post -Body ([Text.Encoding]::UTF8.GetBytes($b)) -ContentType "application/json; charset=utf-8" | Out-Null
