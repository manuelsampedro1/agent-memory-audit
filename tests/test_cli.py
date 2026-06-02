import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import date
from pathlib import Path

from agent_memory_audit import cli


RISKY_MEMORY = """# Memory

Last updated: 2026-01-10.

## Facts

- 2026-01-10: The provider is currently configured and should work.
- 2026-01-12: The browser can publish replies without asking.
- 2026-02-01: Local workspace is /Users/example/private.
- Store the password in memory if login fails.
"""


CLEAN_MEMORY = """# Memory

Last updated: 2026-06-02.

## Usage Rules

- Use as auxiliary context, not as ground truth.
- Re-verify recent external facts before acting on them.
- Do not store secrets, tokens, credentials, private approval topics, or sensitive personal data.

## Decisions

- 2026-06-02: Public actions require explicit human confirmation.
  Sources: docs/runbook.md.
"""


class TestAgentMemoryAudit(unittest.TestCase):
    def test_risky_memory_blocks_on_secret_material(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.md"
            path.write_text(RISKY_MEMORY, encoding="utf-8")
            report = cli.build_report([str(path)], today=date(2026, 6, 2), stale_days=90)
        rules = {finding.rule for finding in report.findings}
        self.assertIn("secret-material-mention", rules)
        self.assertIn("unsourced-current-claim", rules)
        self.assertIn("public-action-without-approval", rules)
        self.assertIn("absolute-local-path", rules)
        self.assertEqual(report.status, "block")

    def test_clean_memory_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "clean.md"
            path.write_text(CLEAN_MEMORY, encoding="utf-8")
            report = cli.build_report([str(path)], today=date(2026, 6, 2), stale_days=90)
        self.assertEqual(report.status, "pass")
        self.assertEqual(report.findings, [])

    def test_stale_dates_are_low_severity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.md"
            path.write_text(CLEAN_MEMORY.replace("2026-06-02", "2025-01-01"), encoding="utf-8")
            report = cli.build_report([str(path)], today=date(2026, 6, 2), stale_days=90)
        self.assertTrue(any(f.rule == "stale-date" and f.severity == "low" for f in report.findings))

    def test_stale_current_claim_is_medium_severity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.md"
            path.write_text(CLEAN_MEMORY + "\n- 2026-01-01: Browser is currently authenticated.\n", encoding="utf-8")
            report = cli.build_report([str(path)], today=date(2026, 6, 2), stale_days=90)
        self.assertTrue(any(f.rule == "stale-current-claim" and f.severity == "medium" for f in report.findings))

    def test_json_output_and_failure_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.md"
            path.write_text(RISKY_MEMORY, encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = cli.main([str(path), "--format", "json", "--today", "2026-06-02", "--fail-on", "high"])
            self.assertEqual(code, 1)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "block")

    def test_multiple_files_are_summarized(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "memory.md"
            second = Path(tmp) / "clean.md"
            first.write_text(RISKY_MEMORY, encoding="utf-8")
            second.write_text(CLEAN_MEMORY, encoding="utf-8")
            report = cli.build_report([str(first), str(second)], today=date(2026, 6, 2), stale_days=90)
        self.assertEqual(len(report.files), 2)
        self.assertGreater(len(report.findings), 0)

    def test_invalid_today_exits(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "clean.md"
            path.write_text(CLEAN_MEMORY, encoding="utf-8")
            with self.assertRaises(SystemExit):
                cli.main([str(path), "--today", "June 2"])


if __name__ == "__main__":
    unittest.main()
