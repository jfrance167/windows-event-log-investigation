[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = ".private\windows-events.jsonl",

    [Parameter()]
    [ValidateRange(1, 8760)]
    [int]$Hours = 24,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$LogName = @(
        "Security",
        "Microsoft-Windows-PowerShell/Operational",
        "System"
    ),

    [Parameter()]
    [ValidateCount(1, 256)]
    [int[]]$EventId = @(
        4624, 4625, 4688, 4720, 4726, 4728, 4732, 4756,
        4103, 4104, 7045
    ),

    [Parameter()]
    [switch]$IncludeMessage,

    [Parameter()]
    [switch]$FailOnCollectionError
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Convert-EventData {
    param([Parameter(Mandatory)] [System.Diagnostics.Eventing.Reader.EventRecord]$Event)

    [xml]$xml = $Event.ToXml()
    $data = [ordered]@{}
    $index = 0
    foreach ($node in @($xml.Event.EventData.Data)) {
        if ($node -is [System.Xml.XmlElement]) {
            $name = [string]$node.GetAttribute("Name")
            $value = [string]$node.InnerText
        }
        else {
            $name = ""
            $value = [string]$node
        }
        if ([string]::IsNullOrWhiteSpace($name)) {
            $name = "Data_$index"
        }
        $candidate = $name
        $suffix = 1
        while ($data.Contains($candidate)) {
            $candidate = "${name}_$suffix"
            $suffix++
        }
        $data[$candidate] = $value
        $index++
    }
    return $data
}

$resolvedOutput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
    $OutputPath
)
$outputDirectory = Split-Path -Parent $resolvedOutput
if (-not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

$temporaryPath = Join-Path $outputDirectory (
    ".{0}.{1}.tmp" -f (Split-Path -Leaf $resolvedOutput), [guid]::NewGuid()
)
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$writer = [System.IO.StreamWriter]::new($temporaryPath, $false, $utf8NoBom)
$startTime = (Get-Date).AddHours(-$Hours)
$eventCount = 0
$successfulLogs = 0
$failures = [System.Collections.Generic.List[string]]::new()
$collectionFailure = $null

try {
    foreach ($log in $LogName) {
        try {
            $logInformation = Get-WinEvent -ListLog $log -ErrorAction Stop
            if (-not $logInformation.IsEnabled) {
                throw "Event log is disabled."
            }
            $filter = @{
                LogName   = $log
                Id        = $EventId
                StartTime = $startTime
            }
            $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop)
            $successfulLogs++
        }
        catch {
            if ($_.FullyQualifiedErrorId -like "NoMatchingEventsFound*") {
                $successfulLogs++
                Write-Warning "No matching events found in '$log'."
            }
            else {
                $failure = "${log}: $($_.Exception.Message)"
                $failures.Add($failure)
                Write-Warning $failure
            }
            continue
        }

        foreach ($event in $events) {
            try {
                $document = [ordered]@{
                    timestamp = $event.TimeCreated.ToUniversalTime().ToString("o")
                    event_id  = [int]$event.Id
                    provider  = [string]$event.ProviderName
                    channel   = [string]$event.LogName
                    record_id = [long]$event.RecordId
                    computer  = [string]$event.MachineName
                    data      = Convert-EventData -Event $event
                }
                if ($IncludeMessage) {
                    $document["message"] = [string]$event.Message
                }
                $jsonLine = $document | ConvertTo-Json -Compress -Depth 8
            }
            catch {
                $failure = "${log} record $($event.RecordId): $($_.Exception.Message)"
                $failures.Add($failure)
                Write-Warning $failure
                continue
            }
            $writer.WriteLine($jsonLine)
            $eventCount++
        }
    }
}
catch {
    $collectionFailure = $_
}
finally {
    $writer.Dispose()
}

if ($null -ne $collectionFailure) {
    Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    throw $collectionFailure
}

if ($successfulLogs -eq 0) {
    Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    throw "No requested event log could be queried. Run with appropriate permissions."
}

Move-Item -LiteralPath $temporaryPath -Destination $resolvedOutput -Force

[pscustomobject]@{
    OutputPath     = $resolvedOutput
    StartTime      = $startTime.ToUniversalTime().ToString("o")
    EventsWritten  = $eventCount
    LogsQueried    = $successfulLogs
    LogsFailed     = $failures.Count
    FailedLogNames = @($failures)
}

if ($failures.Count -gt 0) {
    Write-Warning (
        "Collection completed with {0} inaccessible or failed log(s)." -f $failures.Count
    )
    if ($FailOnCollectionError) {
        throw "Collection produced one or more warnings; see failure details above."
    }
}
