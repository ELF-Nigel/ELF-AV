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

# create test cert and trust it (for unsigned override, still useful)
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=ELF-AV Test" -CertStoreLocation "Cert:\CurrentUser\My"
$thumb = $cert.Thumbprint
certutil -user -addstore "TrustedPublisher" $thumb | Out-Null
certutil -user -addstore "Root" $thumb | Out-Null

# sign exe with test cert (local trust)
$ts = "http://timestamp.digicert.com"
Set-AuthenticodeSignature -FilePath (Join-Path $InstallDir "av_research.exe") -Certificate $cert -TimestampServer $ts | Out-Null

# install and start service
& (Join-Path $InstallDir "av_research.exe") --install
Start-Service AVResearch

# run a quick scan of downloads
$dl = Join-Path $env:USERPROFILE "Downloads"
& (Join-Path $InstallDir "av_research.exe") --scan $dl

Write-Host "vm setup complete"
