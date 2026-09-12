from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import windows_event_analyzer as analyzer  # noqa: E402


SAMPLE_PATH = PROJECT_ROOT / "samples" / "lab_events.jsonl"


def make_event(
    event_id: int,
    minute: int = 0,
    data: dict[str, str] | None = None,
) -> analyzer.Event:
    return analyzer.Event(
        timestamp=datetime(2026, 1, 1, 12, minute, tzinfo=timezone.utc),
        event_id=event_id,
        provider="Test Provider",
        channel="Test",
        record_id=minute,
        computer="LAB",
        data=data or {},
    )


class ParsingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(
            prefix="event-log-test-", dir=PROJECT_ROOT
        )
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write_jsonl(self, lines: list[object]) -> Path:
        path = self.root / "events.jsonl"
        content = "\n".join(json.dumps(line) for line in lines) + "\n"
        path.write_text(content, encoding="utf-8")
        return path

    def test_loads_and_sorts_sample_events(self) -> None:
        events = analyzer.load_events(SAMPLE_PATH)
        self.assertEqual(len(events), 17)
        self.assertLess(events[0].timestamp, events[-1].timestamp)
        self.assertEqual(events[0].event_id, 4625)

    def test_accepts_z_timestamp_and_normalizes_to_utc(self) -> None:
        path = self.write_jsonl(
            [
                {
                    "timestamp": "2026-01-01T12:00:00Z",
                    "event_id": 1,
                    "provider": "Provider",
                    "channel": "System",
                    "data": {},
                }
            ]
        )
        event = analyzer.load_events(path)[0]
        self.assertEqual(event.timestamp.tzinfo, timezone.utc)

    def test_rejects_naive_timestamp(self) -> None:
        path = self.write_jsonl(
            [
                {
                    "timestamp": "2026-01-01T12:00:00",
                    "event_id": 1,
                    "provider": "Provider",
                    "channel": "System",
                    "data": {},
                }
            ]
        )
        with self.assertRaisesRegex(ValueError, "timezone"):
            analyzer.load_events(path)

    def test_rejects_unknown_fields(self) -> None:
        path = self.write_jsonl(
            [
                {
                    "timestamp": "2026-01-01T12:00:00Z",
                    "event_id": 1,
                    "provider": "Provider",
                    "channel": "System",
                    "data": {},
                    "unexpected": True,
                }
            ]
        )
        with self.assertRaisesRegex(ValueError, "invalid event structure"):
            analyzer.load_events(path)

    def test_rejects_invalid_json_with_line_number(self) -> None:
        path = self.root / "events.jsonl"
        path.write_text("not-json\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "line 1"):
            analyzer.load_events(path)

    def test_rejects_boolean_event_id(self) -> None:
        path = self.write_jsonl(
            [
                {
                    "timestamp": "2026-01-01T12:00:00Z",
                    "event_id": True,
                    "provider": "Provider",
                    "channel": "System",
                    "data": {},
                }
            ]
        )
        with self.assertRaisesRegex(ValueError, "event_id"):
            analyzer.load_events(path)


class DetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.events = analyzer.load_events(SAMPLE_PATH)
        cls.investigation = analyzer.analyze_events(
            cls.events, source="sanitized sample"
        )
        cls.alerts_by_rule = {
            alert.rule_id: alert for alert in cls.investigation.alerts
        }

    def test_detects_brute_force(self) -> None:
        alert = self.alerts_by_rule["AUTH-BRUTE-FORCE"]
        self.assertEqual(alert.entities["user"], "alice")
        self.assertGreaterEqual(alert.event_count, 5)

    def test_detects_password_spray(self) -> None:
        alert = self.alerts_by_rule["AUTH-PASSWORD-SPRAY"]
        self.assertEqual(alert.entities["accounts"], "5")
        self.assertEqual(alert.entities["source"], "198.51.100.23")

    def test_detects_success_after_failures(self) -> None:
        alert = self.alerts_by_rule["AUTH-SUCCESS-AFTER-FAILURES"]
        self.assertEqual(alert.severity, "critical")
        self.assertEqual(alert.entities["user"], "alice")

    def test_detects_account_and_group_changes(self) -> None:
        self.assertIn("ACCOUNT-CREATED", self.alerts_by_rule)
        self.assertIn("GROUP-MEMBERSHIP-ADDED", self.alerts_by_rule)

    def test_detects_powershell_process_and_service_activity(self) -> None:
        self.assertIn("POWERSHELL-SUSPICIOUS-CONTENT", self.alerts_by_rule)
        self.assertIn("PROCESS-LOLBIN", self.alerts_by_rule)
        self.assertIn("SERVICE-INSTALLED", self.alerts_by_rule)

    def test_reassembles_fragmented_powershell_script_blocks(self) -> None:
        events = [
            make_event(
                4104,
                minute=0,
                data={
                    "ScriptBlockId": "block-1",
                    "MessageNumber": "1",
                    "MessageTotal": "2",
                    "ScriptBlockText": "powershell.exe -Encoded",
                },
            ),
            make_event(
                4104,
                minute=1,
                data={
                    "ScriptBlockId": "block-1",
                    "MessageNumber": "2",
                    "MessageTotal": "2",
                    "ScriptBlockText": "Command REDACTED_TEST_VALUE",
                },
            ),
        ]
        investigation = analyzer.analyze_events(events, source="fragments")
        alerts = [
            alert
            for alert in investigation.alerts
            if alert.rule_id == "POWERSHELL-SUSPICIOUS-CONTENT"
        ]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].event_count, 2)

    def test_event_counts_are_reported(self) -> None:
        self.assertEqual(self.investigation.events_analyzed, 17)
        self.assertEqual(self.investigation.event_counts[4625], 11)
        self.assertEqual(self.investigation.channel_counts["System"], 1)

    def test_benign_events_do_not_alert(self) -> None:
        events = [
            make_event(4104, data={"ScriptBlockText": "Get-Date | Out-Null"}),
            make_event(
                4688,
                minute=1,
                data={"NewProcessName": "C:\\Windows\\System32\\notepad.exe"},
            ),
        ]
        investigation = analyzer.analyze_events(events, source="benign")
        self.assertEqual(investigation.alerts, [])

    def test_threshold_window_expires_old_failures(self) -> None:
        events = [
            make_event(
                4625,
                minute=minute,
                data={"TargetUserName": "alice", "IpAddress": "192.0.2.1"},
            )
            for minute in (0, 11, 22, 33, 44)
        ]
        investigation = analyzer.analyze_events(events, source="spread out")
        rules = {alert.rule_id for alert in investigation.alerts}
        self.assertNotIn("AUTH-BRUTE-FORCE", rules)

    def test_authentication_grouping_is_case_insensitive(self) -> None:
        events = [
            make_event(
                4625,
                minute=minute,
                data={
                    "TargetUserName": "Alice" if minute % 2 else "ALICE",
                    "IpAddress": "Example.Host" if minute % 2 else "EXAMPLE.HOST",
                },
            )
            for minute in range(5)
        ]
        investigation = analyzer.analyze_events(events, source="case test")
        rules = {alert.rule_id for alert in investigation.alerts}
        self.assertIn("AUTH-BRUTE-FORCE", rules)

    def test_nonprivileged_group_change_is_medium(self) -> None:
        event = make_event(
            4732,
            data={"MemberName": "LAB\\alice", "TargetUserName": "Users"},
        )
        investigation = analyzer.analyze_events([event], source="group test")
        self.assertEqual(investigation.alerts[0].severity, "medium")

    def test_invalid_thresholds_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "threshold"):
            analyzer.analyze_events([], source="empty", failure_threshold=1)
        with self.assertRaisesRegex(ValueError, "window"):
            analyzer.analyze_events([], source="empty", window_minutes=0)


class ReportingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.investigation = analyzer.analyze_events(
            analyzer.load_events(SAMPLE_PATH), source="sanitized sample"
        )

    def test_markdown_contains_timeline_and_limitations(self) -> None:
        report = analyzer.markdown_report(self.investigation)
        self.assertIn("## Alert timeline", report)
        self.assertIn("## Limitations", report)
        self.assertIn("AUTH-BRUTE-FORCE", report)

    def test_redaction_removes_raw_account_and_source(self) -> None:
        report = analyzer.markdown_report(self.investigation, redact=True)
        self.assertNotIn("alice", report)
        self.assertNotIn("192.0.2.44", report)
        self.assertIn("entity-", report)

    def test_json_report_is_serializable(self) -> None:
        document = self.investigation.to_dict()
        encoded = json.dumps(document)
        self.assertIn('"alert_count"', encoded)
        self.assertEqual(document["events_analyzed"], 17)

    def test_json_redaction_hides_source_and_sensitive_entities(self) -> None:
        document = self.investigation.to_dict(redact=True)
        encoded = json.dumps(document)
        self.assertEqual(document["source"], "[REDACTED]")
        self.assertNotIn("alice", encoded)
        self.assertNotIn("192.0.2.44", encoded)
        self.assertIn("encoded command", encoded)

    def test_demo_cli_outputs_json(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            exit_code = analyzer.main(["demo", "--format", "json"])
        document = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(document["events_analyzed"], 17)
        self.assertEqual(document["source"], "samples/lab_events.jsonl")
        self.assertGreater(document["alert_count"], 0)

    def test_fail_on_alert_returns_one(self) -> None:
        with redirect_stdout(StringIO()):
            exit_code = analyzer.main(["demo", "--fail-on-alert"])
        self.assertEqual(exit_code, 1)

    def test_missing_input_returns_two(self) -> None:
        with redirect_stderr(StringIO()):
            exit_code = analyzer.main(
                ["analyze", "definitely-missing-events.jsonl"]
            )
        self.assertEqual(exit_code, 2)

    def test_output_cannot_overwrite_input_evidence(self) -> None:
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT) as directory:
            evidence = Path(directory) / "events.jsonl"
            original = '{"not":"valid enough to analyze"}\n'
            evidence.write_text(original, encoding="utf-8")

            with redirect_stderr(StringIO()):
                result = analyzer.main(
                    ["analyze", str(evidence), "--output", str(evidence)]
                )

            self.assertEqual(result, 2)
            self.assertEqual(evidence.read_text(encoding="utf-8"), original)


if __name__ == "__main__":
    unittest.main()
