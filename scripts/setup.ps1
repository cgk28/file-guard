# file-guard one-time setup (run by the OWNER, in a normal PowerShell window, not by the agent).
# Creates the signing key (passphrase known only to you) and signs the baseline of the current files.
param([string]$Dir = (Get-Location).Path, [string]$KeyFile = "$HOME\file-guard-owner.key.enc", [string]$Store, [switch]$Auto)
$script = Join-Path $PSScriptRoot 'file-guard.mjs'
if ($Auto -and -not $env:FILEGUARD_SIGNPASS) {
  # random 24-char passphrase (no look-alike characters), shown ONCE to the owner, never written to disk
  $chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'.ToCharArray()
  $bytes = New-Object byte[] 24; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  $env:FILEGUARD_SIGNPASS = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
  Write-Host "`nYOUR SIGNING PASSPHRASE (write it down NOW, it will not be shown again):`n`n    $env:FILEGUARD_SIGNPASS`n"
  if (-not $env:FILEGUARD_NOPAUSE) { Read-Host 'Press Enter once you have written it down' | Out-Null; Clear-Host }
}
if (-not $env:FILEGUARD_SIGNPASS) {
  $p1 = Read-Host 'Choose a signing passphrase (only you must know it)' -AsSecureString
  $p2 = Read-Host 'Repeat it' -AsSecureString
  $a = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1))
  $b = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2))
  if ($a -ne $b -or $a.Length -lt 10) { throw 'Passphrases differ or are shorter than 10 characters.' }
  $env:FILEGUARD_SIGNPASS = $a
}
$extra = @(); if ($Store) { $extra = @('--store', $Store) }
$out = node $script keygen --dir $Dir --keyfile $KeyFile --force 1 @extra; $out
node $script init --dir $Dir --keyfile $KeyFile @extra
$fp = ($out | Select-String 'FINGERPRINT[^:]*:\s*(\w+)').Matches.Groups[1].Value
if ($fp) { [Environment]::SetEnvironmentVariable('FILEGUARD_PUBFP', $fp, 'User'); Write-Host "Pinned fingerprint $fp as user env FILEGUARD_PUBFP (new terminals)." }
Remove-Item Env:FILEGUARD_SIGNPASS -ErrorAction SilentlyContinue
Write-Host "`nDONE. Now MOVE $KeyFile to a USB stick / another machine (keep it away from the agent)."
