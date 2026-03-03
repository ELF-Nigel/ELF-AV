param(
    [string]$Repo = "ELF-Nigel/ELF-AV",
    [string]$InstallDir = "C:\Program Files\AVResearch",
    [string]$ReleaseTag = "latest"
)

# requires admin
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "run this script as administrator."
    exit 1
}

$ErrorActionPreference = "Stop"

# stop and uninstall old service if present
try { sc.exe stop AVResearch | Out-Null } catch {}
Start-Sleep -Seconds 2
try { & "$InstallDir\av_research.exe" --uninstall } catch {}
try { sc.exe delete AVResearch | Out-Null } catch {}

# remove scheduled task if present
try { schtasks.exe /delete /tn avresearch /f | Out-Null } catch {}

# take ownership and reset acl so we can delete
if (Test-Path $InstallDir) {
    try { takeown /f $InstallDir /r /d y | Out-Null } catch {}
    try { icacls $InstallDir /reset /t /c | Out-Null } catch {}
    try { icacls $InstallDir /grant "Administrators:F" /t /c | Out-Null } catch {}
    Remove-Item -Recurse -Force $InstallDir
}

# download latest release asset
$api = "https://api.github.com/repos/$Repo/releases/$ReleaseTag"
$release = Invoke-RestMethod -Headers @{"User-Agent"="avresearch"} -Uri $api
$asset = $release.assets | Where-Object { $_.name -eq "av_research.exe" } | Select-Object -First 1
if (-not $asset) { throw "release asset av_research.exe not found" }

$tmp = Join-Path $env:TEMP "av_research.exe"
Invoke-WebRequest -Headers @{"User-Agent"="avresearch"} -Uri $asset.browser_download_url -OutFile $tmp

# install
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item $tmp (Join-Path $InstallDir "av_research.exe") -Force

# unblock if needed
try { Unblock-File (Join-Path $InstallDir "av_research.exe") } catch {}

# install and start service
& (Join-Path $InstallDir "av_research.exe") --install
Start-Service AVResearch

Write-Host "install complete"
