# file-guard watchdog: runs `check` on a schedule OUTSIDE the agent and alerts the owner on a separate channel.
# Install:   powershell -ExecutionPolicy Bypass -File watch.ps1 -Install -Dir <workspace> [-Notify <script taking one text argument>] [-EveryMinutes 60]
# Uninstall: powershell -ExecutionPolicy Bypass -File watch.ps1 -Uninstall -Dir <workspace>
param([string]$Dir, [string]$Notify, [string]$Store, [string]$Node, [int]$EveryMinutes = 60, [switch]$Install, [switch]$Uninstall, [switch]$Run)
$Dir = (Resolve-Path $Dir).Path
$name = 'FileGuard-' + (Split-Path $Dir -Leaf)
$guard = Join-Path $PSScriptRoot 'file-guard.mjs'
$st = if ($Store) { $Store } else { Join-Path $env:LOCALAPPDATA ('FileGuard\' + (Split-Path $Dir -Leaf)) }
if ($Run) {
  $args2 = @('check', '--dir', $Dir); if ($Store) { $args2 += @('--store', $Store) }
  $nodeExe = if ($Node -and (Test-Path $Node)) { $Node } else { (Get-Command node -ErrorAction SilentlyContinue).Source }
  if (-not $nodeExe) { $out = 'node not found for the scheduled task (re-run -Install from a shell where node works)'; $code = 127 } else { $out = (& $nodeExe $guard @args2 2>&1 | Out-String).Trim(); $code = $LASTEXITCODE }
  New-Item -ItemType Directory -Force $st | Out-Null; $flag = Join-Path $st 'ALERT.txt'; $last = Join-Path $st 'last-alert.sha'
  if ($code -eq 0) { Remove-Item $flag, $last -ErrorAction SilentlyContinue; $an = @('anchor', '--dir', $Dir); if ($Notify) { $an += @('--notify', $Notify) }; if ($Store) { $an += @('--store', $Store) }; & $nodeExe $guard @an 2>&1 | Out-Null; exit 0 }
  if ($code -ne 1 -or -not $out) { $out = "WATCHDOG COULD NOT RUN check (exit $code). Output: " + $out + " (Antivirus blocking node/powershell? Reboot or run check by hand.)" }
  Set-Content $flag $out
  $h = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($out)))
  if ((Test-Path $last) -and ((Get-Content $last) -eq $h)) { exit 1 }   # same alert already sent: no spam
  Set-Content $last $h
  $msg = "file-guard ALERT on $env:COMPUTERNAME ($Dir):`n" + $out.Substring(0, [Math]::Min(1200, $out.Length))
  if ($Notify) { & $Notify $msg } else { msg.exe * /TIME:600 $msg 2>$null }
  exit 1
}
if ($Install) {
  $a = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Run -Dir `"$Dir`""; if ($Notify) { $a += " -Notify `"$Notify`"" }; $nodePath = (Get-Command node -ErrorAction Stop).Source; $a += " -Node `"$nodePath`""; if ($Store) { $a += " -Store `"$Store`"" }
  $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $a
  $trg = @((New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $EveryMinutes)), (New-ScheduledTaskTrigger -AtLogOn))
  try { Register-ScheduledTask -TaskName $name -Action $act -Trigger $trg -Description 'file-guard integrity watchdog (independent of the agent)' -Force -ErrorAction Stop | Out-Null }
  catch { # no admin rights: fall back to a per-user task via schtasks (hourly; never report success if it fails)
    New-Item -ItemType Directory -Force $st | Out-Null; $cmd = Join-Path $st "run-watch.cmd"; Set-Content $cmd "@powershell.exe $a" -Encoding ASCII; schtasks /Create /TN $name /TR "`"$cmd`"" /SC MINUTE /MO $EveryMinutes /F | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (schtasks /Query /TN $name 2>$null)) { Write-Host "FAILED to install task '$name' (needs rights?)."; exit 1 }
  }
  Write-Host "Installed task '$name': check every $EveryMinutes min and at logon (silent unless a problem), alerts via $(if ($Notify) { $Notify } else { 'desktop message' })."
} elseif ($Uninstall) { Unregister-ScheduledTask -TaskName $name -Confirm:$false; Write-Host "Removed task '$name'." }
else { Write-Host 'Use -Install, -Uninstall or -Run.' }
