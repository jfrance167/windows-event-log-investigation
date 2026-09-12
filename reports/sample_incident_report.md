# Windows Event Log Investigation Report

- Generated: 2026-09-12T15:05:34+00:00
- Source: `samples/lab_events.jsonl`
- Events analyzed: 17
- Alerts: 8

## Executive summary

The automated triage identified events requiring analyst review. A match is an investigative lead, not proof of compromise.

| Severity | Count |
|---|---:|
| Critical | 1 |
| High | 6 |
| Medium | 1 |
| Low | 0 |

## Event coverage

| Event ID | Count |
|---:|---:|
| 4104 | 1 |
| 4624 | 1 |
| 4625 | 11 |
| 4688 | 1 |
| 4720 | 1 |
| 4732 | 1 |
| 7045 | 1 |

## Alert timeline

### 1. [CRITICAL] Successful logon after repeated failures

- Rule: `AUTH-SUCCESS-AFTER-FAILURES`
- Time: 2026-01-15T15:00:00+00:00
- Related events: 7
- Entities: source=`192.0.2.44`, user=`alice`

Event 4624 followed repeated Event 4625 failures for the same account and source.

### 2. [HIGH] Repeated failed logons

- Rule: `AUTH-BRUTE-FORCE`
- Time: 2026-01-15T15:00:00+00:00
- Related events: 5
- Entities: source=`192.0.2.44`, user=`alice`

At least 5 Event 4625 failures occurred for one account and source within 10 minutes.

### 3. [HIGH] Possible password spray

- Rule: `AUTH-PASSWORD-SPRAY`
- Time: 2026-01-15T15:10:00+00:00
- Related events: 5
- Entities: accounts=`5`, source=`198.51.100.23`

One source failed against at least 5 distinct accounts within 10 minutes.

### 4. [MEDIUM] Local or domain account created

- Rule: `ACCOUNT-CREATED`
- Time: 2026-01-15T15:20:00+00:00
- Related events: 1
- Entities: account=`svc-backup`

Windows recorded Event 4720 for a newly created account.

### 5. [HIGH] Account added to a security-enabled group

- Rule: `GROUP-MEMBERSHIP-ADDED`
- Time: 2026-01-15T15:21:00+00:00
- Related events: 1
- Entities: group=`Administrators`, member=`LAB-WIN11\svc-backup`

Windows recorded group-membership Event 4732.

### 6. [HIGH] Suspicious PowerShell content

- Rule: `POWERSHELL-SUSPICIOUS-CONTENT`
- Time: 2026-01-15T15:30:00+00:00
- Related events: 1
- Entities: indicators=`encoded command`

Matched behavior requires analyst validation; the command or utility can also have legitimate administrative uses.

### 7. [HIGH] New Windows service installed

- Rule: `SERVICE-INSTALLED`
- Time: 2026-01-15T15:31:00+00:00
- Related events: 1
- Entities: service=`LabUpdater`

System Event 7045 can indicate legitimate software or persistence.

### 8. [HIGH] Potentially risky Windows utility execution

- Rule: `PROCESS-LOLBIN`
- Time: 2026-01-15T15:32:00+00:00
- Related events: 1
- Entities: indicators=`DLL execution utility`

Matched behavior requires analyst validation; the command or utility can also have legitimate administrative uses.

## Recommended analyst actions

1. Validate the affected accounts, sources, processes, and services.
2. Correlate with endpoint, identity-provider, firewall, and EDR evidence.
3. Confirm whether activity was authorized before containment.
4. Preserve relevant logs and document conclusions and false positives.

## Limitations

- Detection depends on the Windows audit policies and logs enabled on the host.
- Missing or inaccessible channels reduce visibility and must be reported.
- Keyword matches require context and can represent legitimate administration.
- This lab performs offline triage; it is not a real-time SIEM or EDR.
