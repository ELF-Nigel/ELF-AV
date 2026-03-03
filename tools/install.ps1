param(
    [string]$ExePath = "C:\\Program Files\\AVResearch\\av_research.exe"
)

# Requires admin
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "run this script as administrator."
    exit 1
}

if (-not (Test-Path $ExePath)) {
    Write-Error "executable not found: $ExePath"
    exit 1
}

& $ExePath --install
& auditpol.exe /set /subcategory:"Process Creation" /success:enable /failure:enable
& auditpol.exe /set /subcategory:"Process Termination" /success:enable /failure:enable
& sc.exe start AVResearch
