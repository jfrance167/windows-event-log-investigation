[CmdletBinding()]
param(
    [Parameter()]
    [string]$Marker = "WINDOWS_EVENT_LOG_LAB"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$timestamp = (Get-Date).ToUniversalTime().ToString("o")
$process = Get-Process -Id $PID
$service = Get-Service | Sort-Object DisplayName | Select-Object -First 1

[pscustomobject]@{
    Marker        = $Marker
    TimestampUtc  = $timestamp
    PowerShellPid = $PID
    ProcessName   = $process.ProcessName
    SampleService = $service.Name
}

Write-Host "Safe activity complete. No accounts, services, or security settings were changed."
Write-Host "If Script Block Logging is enabled, search Event ID 4104 for marker: $Marker"
