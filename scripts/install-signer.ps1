<#
 file-guard signer installer (Windows). Run ELEVATED (Administrator). It:
   1. creates C:\ProgramData\FileGuard\signer with admin-only rights on the key and the Telegram settings,
   2. copies signer.mjs (and, if node lives in a user-writable folder, node.exe) INTO that folder, so nothing the
      agent's own account can edit is ever executed as SYSTEM,
   3. makes the key pair, copies the owner's Telegram settings from the DPAPI file without printing them,
   4. registers the scheduled task FileGuard-Signer (SYSTEM, at startup, restarts itself) and starts it,
   5. only when the signer answers, writes ready.flag (from then on file-guard check/rebaseline use the signer).
 Usage:  powershell -ExecutionPolicy Bypass -File install-signer.ps1 -Chat <your Telegram chat id> -TelegramFile <file with the bot token, DPAPI-encrypted for your account (ConvertFrom-SecureString)>
         powershell -ExecutionPolicy Bypass -File install-signer.ps1 -Uninstall
 Result and errors are written to C:\ProgramData\FileGuard\signer\install.log (readable by everyone, never holds secrets).
#>
param([string]$Chat = $env:FILEGUARD_TG_CHAT, [string]$TelegramFile = $env:FILEGUARD_TG_FILE, [string]$ScriptDir = $PSScriptRoot, [string]$NodePath = '', [switch]$Uninstall, [switch]$NoPause)
$ErrorActionPreference = 'Stop'
$Dir = Join-Path $env:ProgramData 'FileGuard\signer'
$LogFile = Join-Path $Dir 'install.log'
function Log($m) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null; Add-Content -Path $LogFile -Value ("{0} {1}" -f (Get-Date -Format s), $m) }
function Done($code) { if (-not $NoPause) { Write-Host ''; Write-Host 'You can close this window.' ; Start-Sleep 4 }; exit $code }
try {
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { Write-Host 'Run this as Administrator.' -ForegroundColor Red; Done 1 }
  if ($Uninstall) {
    Unregister-ScheduledTask -TaskName 'FileGuard-Signer' -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $Dir 'ready.flag') -Force -ErrorAction SilentlyContinue
    Log 'uninstalled: task removed, ready.flag removed (key kept)'; Write-Host 'Signer task removed. The key stays in' $Dir; Done 0
  }
  Log '--- install start'
  if (-not $Uninstall -and (-not $Chat -or -not $TelegramFile)) { throw 'give -Chat <telegram chat id> and -TelegramFile <DPAPI token file> (or env FILEGUARD_TG_CHAT / FILEGUARD_TG_FILE)' }
  New-Item -ItemType Directory -Force -Path $Dir, "$Dir\inbox", "$Dir\outbox", "$Dir\state" | Out-Null
  # 1. rights: everybody may read, only SYSTEM/Administrators may write; secrets are admin-only
  icacls $Dir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' 'BUILTIN\Users:(OI)(CI)RX' | Out-Null
  icacls "$Dir\state" /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null
  icacls "$Dir\inbox" /grant:r 'BUILTIN\Users:(OI)(CI)M' | Out-Null   # the agent may drop requests and codes here, nothing else
  Log 'folders and rights set'
  # 2. code that runs as SYSTEM lives in the admin-only folder
  $srcSigner = Join-Path $ScriptDir 'signer.mjs'
  if (-not (Test-Path $srcSigner)) { throw "signer.mjs not found next to the installer ($srcSigner)" }
  Copy-Item $srcSigner "$Dir\signer.mjs" -Force
  $node = if ($NodePath) { $NodePath } else { (Get-Command node -ErrorAction Stop).Source }; if (-not (Test-Path $node)) { throw ('node not found: ' + $node + ' (pass -NodePath)') }
  if ($node -notlike "$env:ProgramFiles*" -and $node -notlike "${env:ProgramFiles(x86)}*") { New-Item -ItemType Directory -Force "$Dir\node" | Out-Null; Copy-Item $node "$Dir\node\node.exe" -Force; $node = "$Dir\node\node.exe"; Log 'node was in a user-writable folder: copied to the signer folder' }
  Log ('node = ' + $node)
  # 3. key pair + pin
  if (-not (Test-Path "$Dir\key.pem")) { & $node "$Dir\signer.mjs" keygen --dir $Dir | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'keygen failed' } }
  icacls "$Dir\key.pem" /inheritance:r /grant:r 'SYSTEM:F' 'BUILTIN\Administrators:F' | Out-Null
  Log 'key ready (admin-only)'
  # 4. Telegram settings: read with the owner's DPAPI, write for SYSTEM only. Never echoed.
  if (-not (Test-Path $TelegramFile)) { throw "Telegram token file not found: $TelegramFile" }
  $tok = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((Get-Content $TelegramFile | ConvertTo-SecureString)))
  if (-not $tok -or $tok.Length -lt 20) { throw 'Telegram token could not be read' }
  [IO.File]::WriteAllText("$Dir\notify.json", (@{ token = $tok; chat = $Chat } | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding $false)); $tok = $null
  icacls "$Dir\notify.json" /inheritance:r /grant:r 'SYSTEM:F' 'BUILTIN\Administrators:F' | Out-Null
  Log 'telegram settings stored (admin-only)'
  # 5. the task
  Unregister-ScheduledTask -TaskName 'FileGuard-Signer' -Confirm:$false -ErrorAction SilentlyContinue
  $act = New-ScheduledTaskAction -Execute $node -Argument "`"$Dir\signer.mjs`" serve" -WorkingDirectory $Dir
  $trg = New-ScheduledTaskTrigger -AtStartup
  $set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName 'FileGuard-Signer' -Action $act -Trigger $trg -Settings $set -User 'SYSTEM' -RunLevel Highest -Description 'file-guard signer: signs a new baseline only after a one-time code from the owner' | Out-Null
  Start-ScheduledTask -TaskName 'FileGuard-Signer'
  Log 'task registered and started'
  # 6. wait for the signer to prove it is alive, then switch file-guard over
  $alive = $false
  for ($i = 0; $i -lt 20; $i++) { Start-Sleep -Milliseconds 500; $hb = "$Dir\heartbeat.txt"; if ((Test-Path $hb) -and ((Get-Date) - (Get-Item $hb).LastWriteTime).TotalSeconds -lt 10) { $alive = $true; break } }
  if (-not $alive) { throw 'the signer task did not start (no heartbeat). ready.flag NOT written.' }
  Set-Content -Path "$Dir\ready.flag" -Value (Get-Date -Format s)
  Log ('READY. fingerprint ' + (Get-Content "$Dir\pin.txt"))
  Write-Host 'Signer installed and running. Fingerprint:' (Get-Content "$Dir\pin.txt") -ForegroundColor Green
  Done 0
} catch { Log ('ERROR: ' + $_.Exception.Message); Write-Host ('Installer failed: ' + $_.Exception.Message) -ForegroundColor Red; Done 1 }
