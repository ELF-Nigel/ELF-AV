param(
  [string]$ExePath = "build\Release\av_research.exe",
  [string]$Subject = "CN=ELF-AV Test"
)

$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject -CertStoreLocation "Cert:\CurrentUser\My"

$ts = "http://timestamp.digicert.com"
$ok = Set-AuthenticodeSignature -FilePath $ExePath -Certificate $cert -TimestampServer $ts

Write-Host "signed: $ExePath"
Write-Host $ok.Status
