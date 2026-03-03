param(
    [string]$OutDir = "build_vs2022"
)

# run from repo root
cmake -S . -B $OutDir -G "Visual Studio 17 2022" -A x64
Write-Host "generated sln in $OutDir"
