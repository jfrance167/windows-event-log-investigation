# Local Validation Record

This record documents a real, read-only validation run performed on September
12, 2026. Raw host logs are deliberately excluded from the repository.

## Collection result

- Requested lookback: 168 hours
- Accessible channels: PowerShell Operational and System
- Inaccessible channel: Security (elevation required)
- Normalized events written: 149
- Evidence size: 1,725,537 bytes
- Evidence SHA-256:
  `58c3f93f9e15695204d01fd600408c25b4a65368f22451efec06c1d9bc7dbc6d`
- Earliest collected event: 2026-09-07 14:23:26 UTC
- Latest collected event: 2026-09-12 14:44:40 UTC

Event coverage:

| Event ID | Channel | Count |
|---:|---|---:|
| 4104 | Microsoft-Windows-PowerShell/Operational | 141 |
| 7045 | System | 8 |

## Analysis result

The analyzer successfully parsed all 149 records. It produced eight
`SERVICE-INSTALLED` investigative leads from Event 7045. Service names and raw
messages are not included here because they are host evidence. These detections
require validation against authorized software activity and are not treated as
proof of compromise.

The harmless activity generator completed without changing accounts, services,
audit policy, or security settings. Its marker was not present in the collected
4104 records, demonstrating that event availability depends on host logging
configuration and PowerShell host behavior.

## Privacy controls verified

- Raw JSONL remained under the gitignored `.private/` directory.
- Redacted Markdown removed the input evidence path.
- Redacted JSON replaced service names with stable pseudonyms.
- The optional rendered-message collection path was tested separately against
  eight real System 7045 records.
- Strict collection mode was exercised with one accessible and one inaccessible
  channel. It returned failure as designed while preserving eight normalized
  records from the accessible channel.
- An all-channels-inaccessible run returned failure and did not publish an
  evidence file.

## Automated verification

- Python compilation passed.
- Both PowerShell scripts passed parser validation.
- All 26 automated tests passed at this stage of development.
- The sanitized 17-event scenario produced the expected eight alerts.
