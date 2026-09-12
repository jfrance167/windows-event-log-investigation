# Windows Event Log Investigation

A defensive security lab that collects Windows events, normalizes them to
JSONL, detects suspicious activity, and produces an incident-style timeline.
The project uses PowerShell and the Python standard library.

Use it only on systems and event data you own or are authorized to investigate.

## Objective

Practice the complete workflow a junior SOC analyst would follow:

1. Collect relevant host evidence without changing audit policy.
2. Preserve structured event fields for repeatable analysis.
3. Identify authentication attacks and suspicious system changes.
4. Produce a timeline and clearly separate detections from conclusions.
5. Document visibility gaps, false-positive considerations, and next steps.

## What it detects

| Rule | Windows events | Purpose |
|---|---|---|
| `AUTH-BRUTE-FORCE` | 4625 | Repeated failures against one account and source |
| `AUTH-PASSWORD-SPRAY` | 4625 | One source failing across multiple accounts |
| `AUTH-SUCCESS-AFTER-FAILURES` | 4624, 4625 | Successful access after repeated failures |
| `ACCOUNT-CREATED` / `ACCOUNT-DELETED` | 4720, 4726 | Account lifecycle changes |
| `GROUP-MEMBERSHIP-ADDED` | 4728, 4732, 4756 | Addition to security-enabled groups |
| `POWERSHELL-SUSPICIOUS-CONTENT` | 4103, 4104 | Potentially risky PowerShell content |
| `PROCESS-LOLBIN` | 4688 | Execution of commonly abused Windows utilities |
| `SERVICE-INSTALLED` | 7045 | New service installation or persistence lead |

These are triage rules. A match is not proof of malicious activity.

## Project contents

- `collect_windows_events.ps1` — read-only Windows event collector
- `generate_safe_activity.ps1` — harmless activity for validating collection
- `windows_event_analyzer.py` — parser, detections, and report generator
- `samples/lab_events.jsonl` — sanitized deterministic investigation scenario
- `reports/sample_incident_report.md` — report generated from the sample
- `VALIDATION.md` — sanitized record of real local collection and analysis
- `tests/` — parser, detection, reporting, and CLI tests

## Quick demonstration

Run the included sanitized scenario:

```powershell
python windows_event_analyzer.py demo
python windows_event_analyzer.py demo --format json
```

Write a redacted Markdown report:

```powershell
python windows_event_analyzer.py demo `
  --redact `
  --output reports\demo-report.md
```

The scenario contains fictional RFC 5737 documentation IP addresses and a
fictional Windows host. It exercises brute-force, password-spray,
success-after-failures, account creation, privileged-group membership,
suspicious PowerShell, risky utility, and service-installation detections.

## Collect real Windows events

The collector does not enable logging, create accounts, change policy, or
generate failed logons. It only reads requested channels:

```powershell
.\generate_safe_activity.ps1

.\collect_windows_events.ps1 `
  -Hours 24 `
  -OutputPath .private\windows-events.jsonl
```

Then analyze the local evidence:

```powershell
python windows_event_analyzer.py analyze `
  .private\windows-events.jsonl `
  --output reports\live-investigation.md
```

The Security channel normally requires an elevated PowerShell session. The
collector continues with accessible channels, emits a warning for every failed
channel, and refuses to claim success if none can be queried.

For automation, add `-FailOnCollectionError` to return a failure after
preserving the partial evidence file whenever a channel or record could not be
collected.

To collect a narrower set:

```powershell
.\collect_windows_events.ps1 `
  -Hours 72 `
  -LogName Security,System `
  -EventId 4624,4625,4720,4732,7045
```

`-IncludeMessage` adds rendered event messages. It is disabled by default
because messages may duplicate data and increase exposure.

## Privacy and evidence handling

Windows logs may contain usernames, IP addresses, computer names, commands,
paths, and other sensitive evidence. Raw collection output is placed under
`.private/`, which is excluded from Git. Review every artifact before sharing.

Use `--redact` when generating Markdown or JSON for broader sharing. It removes
the input path and pseudonymizes sensitive alert entities consistently while
retaining analytical relationships. Redaction is a sharing aid, not a forensic
anonymization guarantee.

## Analyzer options

```powershell
python windows_event_analyzer.py analyze events.jsonl `
  --failure-threshold 5 `
  --window-minutes 10 `
  --format markdown `
  --fail-on-alert
```

Exit codes:

- `0`: analysis completed
- `1`: alerts were found and `--fail-on-alert` was selected
- `2`: malformed input, invalid arguments, or another analysis error

Input is newline-delimited JSON. Each event requires `timestamp`, `event_id`,
`provider`, `channel`, and a string-to-string `data` object. Timestamps must
include a timezone. Input structure and per-line size are validated before
analysis. The analyzer refuses to use the input evidence file as its output
path.

## Run the tests

```powershell
python -W error -m unittest discover -s tests -v
```

GitHub Actions tests Python 3.10 and 3.13 on both Windows and Ubuntu and parses
both PowerShell scripts for syntax errors.

## Local validation performed

This development machine exposed the Application, System, and PowerShell
Operational channels. Real Event 4104 records were confirmed in the PowerShell
Operational log. The non-elevated session could not access the Security log;
that limitation is reported rather than hidden. No raw host logs are committed.

## Investigation limitations

- Detection coverage depends on enabled Windows audit policy and log retention.
- PowerShell 4104 requires script-block logging or compatible event generation.
- Process command lines in 4688 depend on the relevant audit configuration.
- Security-channel access commonly requires elevation.
- Keyword detections can produce legitimate-administration false positives.
- The tool does not enrich IPs, correlate other hosts, or perform containment.
- This is an offline learning tool, not a replacement for a SIEM or EDR.
