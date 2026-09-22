#!/usr/bin/env python3
"""Analyze normalized Windows Event Log JSONL for suspicious activity."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Sequence


MAX_JSONL_LINE_BYTES = 2 * 1024 * 1024
DEFAULT_FAILURE_THRESHOLD = 5
DEFAULT_WINDOW_MINUTES = 10
DEFAULT_SUCCESS_WINDOW_MINUTES = 15
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SUSPICIOUS_POWERSHELL_TERMS = {
    "-encodedcommand": "encoded command",
    "frombase64string": "base64 decoding",
    "downloadstring": "remote content download",
    "invoke-webrequest": "web request",
    "invoke-expression": "dynamic expression execution",
    "-windowstyle hidden": "hidden window",
    "-executionpolicy bypass": "execution-policy bypass",
}
SUSPICIOUS_PROCESS_TERMS = {
    "certutil": "certificate utility",
    "mshta": "HTML application host",
    "regsvr32": "DLL registration utility",
    "rundll32": "DLL execution utility",
    "bitsadmin": "BITS administration utility",
}
SENSITIVE_ENTITY_KEYS = {"user", "source", "account", "member", "group", "service"}
PRIVILEGED_GROUP_TERMS = {
    "administrators",
    "backup operators",
    "domain admins",
    "enterprise admins",
    "remote desktop users",
    "schema admins",
}


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    event_id: int
    provider: str
    channel: str
    record_id: int | None
    computer: str | None
    data: dict[str, str]

    def to_dict(self) -> dict[str, object]:
        return {
            "timestamp": format_timestamp(self.timestamp),
            "event_id": self.event_id,
            "provider": self.provider,
            "channel": self.channel,
            "record_id": self.record_id,
            "computer": self.computer,
            "data": self.data,
        }


@dataclass(frozen=True)
class Alert:
    severity: str
    rule_id: str
    title: str
    start_time: datetime
    end_time: datetime
    event_count: int
    entities: dict[str, str]
    description: str

    def to_dict(self, redact: bool = False) -> dict[str, object]:
        document = asdict(self)
        document["start_time"] = format_timestamp(self.start_time)
        document["end_time"] = format_timestamp(self.end_time)
        if redact:
            document["entities"] = redact_entities(self.entities)
        return document


@dataclass(frozen=True)
class Investigation:
    generated_at: datetime
    source: str
    events_analyzed: int
    first_event: datetime | None
    last_event: datetime | None
    event_counts: dict[int, int]
    channel_counts: dict[str, int]
    alerts: list[Alert]

    def to_dict(self, redact: bool = False) -> dict[str, object]:
        return {
            "generated_at": format_timestamp(self.generated_at),
            "source": "[REDACTED]" if redact else self.source,
            "events_analyzed": self.events_analyzed,
            "first_event": (
                format_timestamp(self.first_event) if self.first_event else None
            ),
            "last_event": (
                format_timestamp(self.last_event) if self.last_event else None
            ),
            "event_counts": {
                str(event_id): count
                for event_id, count in sorted(self.event_counts.items())
            },
            "channel_counts": dict(sorted(self.channel_counts.items())),
            "alert_count": len(self.alerts),
            "severity_counts": dict(
                sorted(Counter(alert.severity for alert in self.alerts).items())
            ),
            "alerts": [alert.to_dict(redact=redact) for alert in self.alerts],
        }


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_timestamp(value: object, line_number: int) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"line {line_number}: timestamp must be a string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"line {line_number}: invalid timestamp {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"line {line_number}: timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def parse_optional_nonnegative_int(
    value: object, field: str, line_number: int
) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 0:
        raise ValueError(f"line {line_number}: {field} must be a nonnegative integer")
    return value


def parse_event(document: object, line_number: int) -> Event:
    if not isinstance(document, dict):
        raise ValueError(f"line {line_number}: event must be a JSON object")
    required = {"timestamp", "event_id", "provider", "channel", "data"}
    allowed = required | {"record_id", "computer", "message"}
    if not required.issubset(document) or not set(document).issubset(allowed):
        raise ValueError(f"line {line_number}: invalid event structure")

    event_id = document["event_id"]
    provider = document["provider"]
    channel = document["channel"]
    computer = document.get("computer")
    data = document["data"]
    if type(event_id) is not int or event_id < 0:
        raise ValueError(f"line {line_number}: event_id must be nonnegative")
    if not isinstance(provider, str) or not provider:
        raise ValueError(f"line {line_number}: provider must be a nonempty string")
    if not isinstance(channel, str) or not channel:
        raise ValueError(f"line {line_number}: channel must be a nonempty string")
    if computer is not None and not isinstance(computer, str):
        raise ValueError(f"line {line_number}: computer must be a string or null")
    if not isinstance(data, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in data.items()
    ):
        raise ValueError(f"line {line_number}: data must map strings to strings")
    if "message" in document and not isinstance(document["message"], str):
        raise ValueError(f"line {line_number}: message must be a string")
    normalized_data = dict(data)
    if "message" in document:
        normalized_data.setdefault("Message", document["message"])
    return Event(
        timestamp=parse_timestamp(document["timestamp"], line_number),
        event_id=event_id,
        provider=provider,
        channel=channel,
        record_id=parse_optional_nonnegative_int(
            document.get("record_id"), "record_id", line_number
        ),
        computer=computer,
        data=normalized_data,
    )


def load_events(path: Path) -> list[Event]:
    events: list[Event] = []
    try:
        with path.open("rb") as stream:
            for line_number, raw_line in enumerate(stream, start=1):
                if len(raw_line) > MAX_JSONL_LINE_BYTES:
                    raise ValueError(
                        f"line {line_number}: exceeds {MAX_JSONL_LINE_BYTES} bytes"
                    )
                if not raw_line.strip():
                    continue
                try:
                    document = json.loads(raw_line.decode("utf-8-sig"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ValueError(
                        f"line {line_number}: invalid UTF-8 JSON: {exc}"
                    ) from exc
                events.append(parse_event(document, line_number))
    except OSError as exc:
        raise ValueError(f"could not read event file {path}: {exc}") from exc
    return sorted(events, key=lambda event: (event.timestamp, event.record_id or -1))


def event_field(event: Event, *names: str, default: str = "<unknown>") -> str:
    lowered = {key.casefold(): value for key, value in event.data.items()}
    for name in names:
        value = lowered.get(name.casefold())
        if value and value != "-":
            return value
    return default


def event_text(event: Event) -> str:
    return "\n".join(event.data.values()).casefold()


def pseudonym(value: str) -> str:
    if value == "<unknown>":
        return value
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:10]
    return f"entity-{digest}"


def redact_entities(entities: dict[str, str]) -> dict[str, str]:
    return {
        key: pseudonym(value) if key in SENSITIVE_ENTITY_KEYS else value
        for key, value in entities.items()
    }


def first_threshold_window(
    events: Sequence[Event],
    threshold: int,
    window: timedelta,
    distinct: Callable[[Event], str] | None = None,
) -> list[Event] | None:
    left = 0
    for right, event in enumerate(events):
        while event.timestamp - events[left].timestamp > window:
            left += 1
        candidate = list(events[left : right + 1])
        count = len({distinct(item) for item in candidate}) if distinct else len(candidate)
        if count >= threshold:
            return candidate
    return None


def login_entities(event: Event) -> tuple[str, str]:
    user = event_field(event, "TargetUserName", "AccountName")
    source = event_field(
        event,
        "IpAddress",
        "SourceNetworkAddress",
        "WorkstationName",
        default=event.computer or "<unknown>",
    )
    return user, source


def login_key(event: Event) -> tuple[str, str]:
    user, source = login_entities(event)
    return user.casefold(), source.casefold()


def detect_brute_force(
    events: Sequence[Event], threshold: int, window: timedelta
) -> list[Alert]:
    grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        if event.event_id == 4625:
            grouped[login_key(event)].append(event)
    alerts: list[Alert] = []
    for _, failures in sorted(grouped.items()):
        candidate = first_threshold_window(failures, threshold, window)
        if candidate:
            user, source = login_entities(candidate[0])
            alerts.append(
                Alert(
                    severity="high",
                    rule_id="AUTH-BRUTE-FORCE",
                    title="Repeated failed logons",
                    start_time=candidate[0].timestamp,
                    end_time=candidate[-1].timestamp,
                    event_count=len(candidate),
                    entities={"user": user, "source": source},
                    description=(
                        f"At least {threshold} Event 4625 failures occurred for one "
                        f"account and source within {int(window.total_seconds() // 60)} minutes."
                    ),
                )
            )
    return alerts


def detect_password_spray(
    events: Sequence[Event], threshold: int, window: timedelta
) -> list[Alert]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.event_id == 4625:
            _, source = login_key(event)
            grouped[source].append(event)
    alerts: list[Alert] = []
    for _, failures in sorted(grouped.items()):
        candidate = first_threshold_window(
            failures,
            threshold,
            window,
            distinct=lambda event: login_key(event)[0],
        )
        if candidate:
            _, source = login_entities(candidate[0])
            distinct_users = len({login_key(event)[0] for event in candidate})
            alerts.append(
                Alert(
                    severity="high",
                    rule_id="AUTH-PASSWORD-SPRAY",
                    title="Possible password spray",
                    start_time=candidate[0].timestamp,
                    end_time=candidate[-1].timestamp,
                    event_count=len(candidate),
                    entities={"source": source, "accounts": str(distinct_users)},
                    description=(
                        f"One source failed against at least {threshold} distinct "
                        f"accounts within {int(window.total_seconds() // 60)} minutes."
                    ),
                )
            )
    return alerts


def detect_success_after_failures(
    events: Sequence[Event], threshold: int, window: timedelta
) -> list[Alert]:
    failures: dict[tuple[str, str], list[Event]] = defaultdict(list)
    alerts: list[Alert] = []
    for event in events:
        identity = login_key(event)
        if event.event_id == 4625:
            failures[identity].append(event)
        elif event.event_id == 4624:
            recent = [
                failure
                for failure in failures[identity]
                if timedelta(0) <= event.timestamp - failure.timestamp <= window
            ]
            if len(recent) >= threshold:
                user, source = login_entities(event)
                alerts.append(
                    Alert(
                        severity="critical",
                        rule_id="AUTH-SUCCESS-AFTER-FAILURES",
                        title="Successful logon after repeated failures",
                        start_time=recent[0].timestamp,
                        end_time=event.timestamp,
                        event_count=len(recent) + 1,
                        entities={"user": user, "source": source},
                        description=(
                            "Event 4624 followed repeated Event 4625 failures for "
                            "the same account and source."
                        ),
                    )
                )
    return alerts


def detect_individual_events(events: Sequence[Event]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        entities: dict[str, str]
        if event.event_id == 4720:
            entities = {"account": event_field(event, "TargetUserName")}
            alerts.append(
                Alert(
                    "medium",
                    "ACCOUNT-CREATED",
                    "Local or domain account created",
                    event.timestamp,
                    event.timestamp,
                    1,
                    entities,
                    "Windows recorded Event 4720 for a newly created account.",
                )
            )
        elif event.event_id == 4726:
            entities = {"account": event_field(event, "TargetUserName")}
            alerts.append(
                Alert(
                    "medium",
                    "ACCOUNT-DELETED",
                    "Account deleted",
                    event.timestamp,
                    event.timestamp,
                    1,
                    entities,
                    "Windows recorded Event 4726 for an account deletion.",
                )
            )
        elif event.event_id in {4732, 4728, 4756}:
            group = event_field(event, "TargetUserName", "GroupName")
            entities = {
                "member": event_field(event, "MemberName", "MemberId"),
                "group": group,
            }
            severity = (
                "high"
                if any(term in group.casefold() for term in PRIVILEGED_GROUP_TERMS)
                else "medium"
            )
            alerts.append(
                Alert(
                    severity,
                    "GROUP-MEMBERSHIP-ADDED",
                    "Account added to a security-enabled group",
                    event.timestamp,
                    event.timestamp,
                    1,
                    entities,
                    f"Windows recorded group-membership Event {event.event_id}.",
                )
            )
        elif event.event_id == 7045:
            entities = {"service": event_field(event, "ServiceName", "param1")}
            alerts.append(
                Alert(
                    "high",
                    "SERVICE-INSTALLED",
                    "New Windows service installed",
                    event.timestamp,
                    event.timestamp,
                    1,
                    entities,
                    "System Event 7045 can indicate legitimate software or persistence.",
                )
            )
    return alerts


def detect_suspicious_commands(events: Sequence[Event]) -> list[Alert]:
    alerts: list[Alert] = []
    powershell_groups: dict[str, list[Event]] = defaultdict(list)
    for index, event in enumerate(events):
        if event.event_id == 4104:
            block_id = event_field(
                event,
                "ScriptBlockId",
                default=f"record-{event.record_id if event.record_id is not None else index}",
            )
            powershell_groups[f"4104:{block_id}"].append(event)
        elif event.event_id == 4103:
            powershell_groups[
                f"4103:{event.record_id if event.record_id is not None else index}"
            ].append(event)

    for fragments in powershell_groups.values():
        fragments.sort(
            key=lambda event: numeric_field(event, "MessageNumber", default=1)
        )
        if fragments[0].event_id == 4104:
            text = "".join(
                event_field(
                    event, "ScriptBlockText", "Message", default=""
                )
                for event in fragments
            ).casefold()
        else:
            text = "\n".join(event_text(event) for event in fragments)
        matches = [
            label
            for term, label in SUSPICIOUS_POWERSHELL_TERMS.items()
            if term in text
        ]
        if matches:
            alerts.append(
                Alert(
                    severity="high",
                    rule_id="POWERSHELL-SUSPICIOUS-CONTENT",
                    title="Suspicious PowerShell content",
                    start_time=fragments[0].timestamp,
                    end_time=fragments[-1].timestamp,
                    event_count=len(fragments),
                    entities={"indicators": ", ".join(sorted(set(matches)))},
                    description=(
                        "Matched behavior requires analyst validation; the command "
                        "or utility can also have legitimate administrative uses."
                    ),
                )
            )

    for event in events:
        if event.event_id != 4688:
            continue
        text = event_text(event)
        matches = [
            label for term, label in SUSPICIOUS_PROCESS_TERMS.items() if term in text
        ]
        if matches:
            alerts.append(
                Alert(
                    severity="high",
                    rule_id="PROCESS-LOLBIN",
                    title="Potentially risky Windows utility execution",
                    start_time=event.timestamp,
                    end_time=event.timestamp,
                    event_count=1,
                    entities={"indicators": ", ".join(sorted(set(matches)))},
                    description=(
                        "Matched behavior requires analyst validation; the command "
                        "or utility can also have legitimate administrative uses."
                    ),
                )
            )
    return alerts


def numeric_field(event: Event, name: str, default: int) -> int:
    value = event_field(event, name, default=str(default))
    try:
        return int(value)
    except ValueError:
        return default


def analyze_events(
    events: Sequence[Event],
    source: str,
    failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
) -> Investigation:
    if failure_threshold < 2:
        raise ValueError("failure threshold must be at least 2")
    if window_minutes < 1:
        raise ValueError("window must be at least 1 minute")
    ordered = sorted(events, key=lambda event: (event.timestamp, event.record_id or -1))
    window = timedelta(minutes=window_minutes)
    alerts = [
        *detect_brute_force(ordered, failure_threshold, window),
        *detect_password_spray(ordered, failure_threshold, window),
        *detect_success_after_failures(
            ordered,
            failure_threshold,
            timedelta(minutes=DEFAULT_SUCCESS_WINDOW_MINUTES),
        ),
        *detect_individual_events(ordered),
        *detect_suspicious_commands(ordered),
    ]
    alerts.sort(
        key=lambda alert: (
            alert.start_time,
            SEVERITY_ORDER[alert.severity],
            alert.rule_id,
        )
    )
    return Investigation(
        generated_at=utc_now(),
        source=source,
        events_analyzed=len(ordered),
        first_event=ordered[0].timestamp if ordered else None,
        last_event=ordered[-1].timestamp if ordered else None,
        event_counts=dict(Counter(event.event_id for event in ordered)),
        channel_counts=dict(Counter(event.channel for event in ordered)),
        alerts=alerts,
    )


def markdown_report(investigation: Investigation, redact: bool = False) -> str:
    severity_counts = Counter(alert.severity for alert in investigation.alerts)
    lines = [
        "# Windows Event Log Investigation Report",
        "",
        f"- Generated: {format_timestamp(investigation.generated_at)}",
        "- Source: "
        + markdown_inline_code("[REDACTED]" if redact else investigation.source),
        f"- Events analyzed: {investigation.events_analyzed}",
        f"- Alerts: {len(investigation.alerts)}",
        "",
        "## Executive summary",
        "",
    ]
    if investigation.alerts:
        lines.append(
            "The automated triage identified events requiring analyst review. "
            "A match is an investigative lead, not proof of compromise."
        )
    else:
        lines.append("No configured detection rules matched the supplied events.")
    lines.extend(
        [
            "",
            "| Severity | Count |",
            "|---|---:|",
            *[
                f"| {severity.title()} | {severity_counts.get(severity, 0)} |"
                for severity in SEVERITY_ORDER
            ],
            "",
            "## Event coverage",
            "",
            "| Event ID | Count |",
            "|---:|---:|",
            *[
                f"| {event_id} | {count} |"
                for event_id, count in sorted(investigation.event_counts.items())
            ],
            "",
            "## Alert timeline",
            "",
        ]
    )
    if not investigation.alerts:
        lines.append("No alerts.")
    for number, alert in enumerate(investigation.alerts, start=1):
        entities = redact_entities(alert.entities) if redact else alert.entities
        entity_text = ", ".join(
            f"{key}={markdown_inline_code(value)}"
            for key, value in sorted(entities.items())
        )
        lines.extend(
            [
                f"### {number}. [{alert.severity.upper()}] {alert.title}",
                "",
                f"- Rule: `{alert.rule_id}`",
                f"- Time: {format_timestamp(alert.start_time)}",
                f"- Related events: {alert.event_count}",
                f"- Entities: {entity_text or 'none'}",
                "",
                alert.description,
                "",
            ]
        )
    lines.extend(
        [
            "## Recommended analyst actions",
            "",
            "1. Validate the affected accounts, sources, processes, and services.",
            "2. Correlate with endpoint, identity-provider, firewall, and EDR evidence.",
            "3. Confirm whether activity was authorized before containment.",
            "4. Preserve relevant logs and document conclusions and false positives.",
            "",
            "## Limitations",
            "",
            "- Detection depends on the Windows audit policies and logs enabled on the host.",
            "- Missing or inaccessible channels reduce visibility and must be reported.",
            "- Keyword matches require context and can represent legitimate administration.",
            "- This lab performs offline triage; it is not a real-time SIEM or EDR.",
            "",
        ]
    )
    return "\n".join(lines)


def markdown_inline_code(value: str) -> str:
    normalized = " ".join(value.splitlines()).replace("`", "'")
    return f"`{normalized}`"


def write_output(content: str, output: Path | None) -> None:
    if output is None:
        print(content)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content.rstrip() + "\n", encoding="utf-8", newline="\n")
    print(f"Report written: {output}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze normalized Windows Event Log JSONL."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command, help_text in (
        ("analyze", "analyze a collected JSONL file"),
        ("demo", "analyze the included sanitized lab events"),
    ):
        subparser = subparsers.add_parser(command, help=help_text)
        if command == "analyze":
            subparser.add_argument("input", help="normalized event JSONL file")
        subparser.add_argument("--output", help="write the report to this path")
        subparser.add_argument(
            "--format", choices=("markdown", "json"), default="markdown"
        )
        subparser.add_argument(
            "--redact",
            action="store_true",
            help="pseudonymize sensitive entities and hide the source path",
        )
        subparser.add_argument(
            "--failure-threshold", type=int, default=DEFAULT_FAILURE_THRESHOLD
        )
        subparser.add_argument(
            "--window-minutes", type=int, default=DEFAULT_WINDOW_MINUTES
        )
        subparser.add_argument(
            "--fail-on-alert",
            action="store_true",
            help="return exit code 1 when one or more alerts are produced",
        )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    project_root = Path(__file__).resolve().parent
    if args.command == "analyze":
        input_path = Path(args.input).expanduser().resolve()
        source_label = str(input_path)
    else:
        input_path = project_root / "samples" / "lab_events.jsonl"
        source_label = "samples/lab_events.jsonl"
    output_path = Path(args.output).expanduser().resolve() if args.output else None
    try:
        if output_path is not None and output_path == input_path:
            raise ValueError("output path must not overwrite the input event file")
        events = load_events(input_path)
        investigation = analyze_events(
            events,
            source=source_label,
            failure_threshold=args.failure_threshold,
            window_minutes=args.window_minutes,
        )
        if args.format == "json":
            content = json.dumps(investigation.to_dict(redact=args.redact), indent=2)
        else:
            content = markdown_report(investigation, redact=args.redact)
        write_output(content, output_path)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 1 if investigation.alerts and args.fail_on_alert else 0


if __name__ == "__main__":
    raise SystemExit(main())