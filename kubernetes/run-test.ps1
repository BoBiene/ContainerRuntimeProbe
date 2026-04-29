<#
.SYNOPSIS
    Applies a Kubernetes test job for Container Runtime Probe, waits for completion, and prints logs.

.DESCRIPTION
    Uses one of the checked-in manifests in this folder and runs a basic
    kubectl apply -> wait -> logs flow for quick manual validation.

.EXAMPLE
    .\kubernetes\run-test.ps1

.EXAMPLE
    .\kubernetes\run-test.ps1 -Mode UrlOnly -Namespace default -Cleanup
#>

[CmdletBinding()]
param(
    [ValidateSet("Report", "UrlOnly")]
    [string]$Mode = "Report",

    [string]$Namespace,

    [string]$Image = "ghcr.io/bobiene/containerruntimeprobe:preview",

    [int]$WaitTimeoutSeconds = 120,

    [switch]$Cleanup
)

$manifestPath = switch ($Mode) {
    "UrlOnly" { Join-Path $PSScriptRoot "job-url.yaml" }
    default { Join-Path $PSScriptRoot "job.yaml" }
}

$jobName = switch ($Mode) {
    "UrlOnly" { "container-runtime-probe-url" }
    default { "container-runtime-probe" }
}

$kubectlArgs = @()
if (-not [string]::IsNullOrWhiteSpace($Namespace)) {
    $kubectlArgs += @("-n", $Namespace)
}

Write-Host "Using manifest: $manifestPath"
Write-Host "Job name: $jobName"
Write-Host "Image: $Image"
Write-Host ""

& kubectl @kubectlArgs delete job $jobName --ignore-not-found | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "kubectl delete job failed."
}

& kubectl @kubectlArgs apply -f $manifestPath
if ($LASTEXITCODE -ne 0) {
    throw "kubectl apply failed."
}

if (-not [string]::Equals($Image, "ghcr.io/bobiene/containerruntimeprobe:preview", [System.StringComparison]::Ordinal)) {
    & kubectl @kubectlArgs set image "job/$jobName" "container-runtime-probe=$Image"
    if ($LASTEXITCODE -ne 0) {
        throw "kubectl set image failed."
    }
}

& kubectl @kubectlArgs wait --for=condition=complete "job/$jobName" "--timeout=$($WaitTimeoutSeconds)s"
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Job did not reach Completed within the timeout. Fetching logs anyway."
}

Write-Host ""
& kubectl @kubectlArgs logs "job/$jobName"

if ($Cleanup) {
    Write-Host ""
    & kubectl @kubectlArgs delete job $jobName --ignore-not-found
}
