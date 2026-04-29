<#
.SYNOPSIS
    Downloads the which-distro/os-release repository for local development reference.

.DESCRIPTION
    This script fetches a local copy of the which-distro/os-release collection
    (https://github.com/which-distro/os-release) into third_party/which-distro-os-release/.

    IMPORTANT:
    - which-distro/os-release is licensed under GPL-2.0-or-later.
    - The downloaded files are ONLY for local development use (studying distro data to
      inform the detection maps in DetectionMaps.cs).
    - This directory is .gitignore'd and must NEVER be committed or redistributed.
    - The project (ContainerRuntimeProbe) is licensed under MIT and does not ship
      any GPL code or data.

.EXAMPLE
    .\scripts\fetch-distro-fixtures.ps1
#>

[CmdletBinding()]
param(
    [string]$TargetDir = "$PSScriptRoot\..\third_party\which-distro-os-release"
)

$repoUrl = "https://github.com/which-distro/os-release.git"

$TargetDir = [System.IO.Path]::GetFullPath($TargetDir)

Write-Host "Target directory: $TargetDir"
Write-Host ""
Write-Host "NOTE: which-distro/os-release is GPL-2.0-or-later."
Write-Host "      This data is for LOCAL DEVELOPMENT ONLY. Do not commit or redistribute."
Write-Host ""

if (Test-Path $TargetDir) {
    Write-Host "Directory already exists. Pulling latest changes..."
    Push-Location $TargetDir
    try {
        git pull --ff-only
    } finally {
        Pop-Location
    }
} else {
    Write-Host "Cloning $repoUrl ..."
    git clone --depth 1 $repoUrl $TargetDir
}

Write-Host ""
Write-Host "Done. OS-release fixtures available at: $TargetDir"
Write-Host ""

# Show how many distros were fetched
$distroCount = (Get-ChildItem $TargetDir -Recurse -Filter "os-release" -ErrorAction SilentlyContinue).Count
Write-Host "Found $distroCount os-release files."
