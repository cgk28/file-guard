# Opens the TrustMe live window: a normal app window you can drag, resize, snap or put on another screen.
# It remembers the size and position you left it at (%LOCALAPPDATA%\TrustMe\window.json) and reopens there.
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
try { Invoke-WebRequest http://127.0.0.1:7077/feed -UseBasicParsing -TimeoutSec 1 | Out-Null }
catch { Start-Process node -ArgumentList "`"$dir\server.mjs`"" -WindowStyle Hidden; Start-Sleep 1 }
$edge = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
$cfgDir = Join-Path $env:LOCALAPPDATA 'TrustMe'; $cfg = Join-Path $cfgDir 'window.json'
$size = '--window-size=720,360'; $pos = $null
try { $c = Get-Content $cfg -Raw | ConvertFrom-Json
  if ($c.w -ge 300 -and $c.h -ge 200) { $size = "--window-size=$($c.w),$($c.h)"; $pos = "--window-position=$($c.x),$($c.y)" } } catch {}
$a = @('--app=http://127.0.0.1:7077', $size, "--user-data-dir=$env:TEMP\trustme-live"); if ($pos) { $a += $pos }
Start-Process $edge -ArgumentList $a
Add-Type @'
using System;using System.Runtime.InteropServices;
public class W{
 [StructLayout(LayoutKind.Sequential)] public struct R{public int L,T,Rt,B;}
 [DllImport("user32.dll")]public static extern bool SetWindowPos(IntPtr h,IntPtr a,int x,int y,int cx,int cy,uint f);
 [DllImport("user32.dll")]public static extern bool GetWindowRect(IntPtr h,out R r);
 [DllImport("user32.dll")]public static extern bool IsWindow(IntPtr h);
 [DllImport("user32.dll")]public static extern bool IsIconic(IntPtr h);
}
'@
for ($i=0; $i -lt 15; $i++) {
  Start-Sleep -Milliseconds 400
  $p = Get-Process msedge -ErrorAction SilentlyContinue | Where-Object MainWindowTitle -like '*TrustMe*' | Select-Object -First 1
  if ($p) {
    $h = $p.MainWindowHandle
    [W]::SetWindowPos($h, [IntPtr](-1), 0, 0, 0, 0, 0x13) | Out-Null   # keep on top
    # own taskbar identity + shiba icon, so the window and the pinned shortcut are one button
    . "$dir\taskbar.ps1"
    $ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    [TB]::Window($h, 'TrustMe.Live', "`"$ps`" -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$dir\open-live.ps1`"", "$dir\trustme-shiba.ico,0", 'TrustMe Live')
    # remember size/position while the window is open (saves only after it stays still for ~2 s)
    New-Item -ItemType Directory -Force $cfgDir | Out-Null
    $last = ''; $stable = 0
    while ([W]::IsWindow($h)) {
      Start-Sleep -Seconds 1
      if ([W]::IsIconic($h)) { continue }
      $r = New-Object W+R
      if (-not [W]::GetWindowRect($h, [ref]$r)) { continue }
      $now = "$($r.L),$($r.T),$($r.Rt - $r.L),$($r.B - $r.T)"
      if ($now -eq $last) { $stable++ } else { $last = $now; $stable = 0 }
      if ($stable -eq 2 -and $r.Rt - $r.L -ge 300) {
        @{ x = $r.L; y = $r.T; w = $r.Rt - $r.L; h = $r.B - $r.T } | ConvertTo-Json -Compress | Set-Content $cfg
      }
    }
    break
  }
}
