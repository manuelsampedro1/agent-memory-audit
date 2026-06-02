from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from datetime import date, datetime
from typing import Iterable, Optional, Sequence


SEVERITY_WEIGHT = {"low": 5, "medium": 15, "high": 30, "critical": 45}
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

DATE_RE = re.compile(r"\b(20\d{2})-(\d{2})-(\d{2})\b")
SECRET_RE = re.compile(
    r"(BEGIN [A-Z ]*PRIVATE KEY|API[_ -]?KEY|ACCESS[_ -]?TOKEN|AUTH[_ -]?TOKEN|PASSWORD|SECRET|CREDENTIAL)",
    re.IGNORECASE,
)
EXTERNAL_CLAIM_RE = re.compile(
    r"\b(current|currently|latest|today|now|authenticated|configured|logged in|available|enabled|pricing|policy|CEO|president)\b",
    re.IGNORECASE,
)
PUBLIC_ACTION_RE = re.compile(
    r"\b(publish|post|reply|send|email|deploy|delete|charge|refund|schedule|like|follow|dm)\b",
    re.IGNORECASE,
)
APPROVAL_RE = re.compile(r"\b(explicit|human|approval|confirmation|attended|manual)\b", re.IGNORECASE)
UNATTENDED_RE = re.compile(
    r"\b(without asking|without confirmation|no approval|unattended|automatic|auto-?publish|auto-?send)\b",
    re.IGNORECASE,
)
PROTECTIVE_SECRET_POLICY_RE = re.compile(
    r"\b(do not|don't|never|avoid|redact|remove|rotate|treat .*leaked)\b",
    re.IGNORECASE,
)
SOURCE_RE = re.compile(r"\b(source|sources|verified|evidence|from|see):", re.IGNORECASE)
ABSOLUTE_PATH_RE = re.compile(r"(/Users/[^ \n]+|/home/[^ \n]+|/private/[^ \n]+)")


@dataclass(frozen=True)
class Finding:
    severity: str
    rule: str
    path: str
    line: int
    reason: str
    evidence: str


@dataclass(frozen=True)
class FileSummary:
    path: str
    lines: int
    dated_entries: int
    stale_dates: int
    has_usage_rules: bool
    has_source_mentions: bool


@dataclass(frozen=True)
class AuditReport:
    score: int
    status: str
    files: list[FileSummary]
    findings: list[Finding]
    summary: dict[str, int]
    follow_up_checks: list[str]


def parse_date(value: str) -> Optional[date]:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def redact(text: str, limit: int = 180) -> str:
    redacted = SECRET_RE.sub("[sensitive-marker]", text)
    redacted = re.sub(r"(?i)(password|secret|token|key|credential)\s*[:=]\s*[^,\s]+", r"\1=[redacted]", redacted)
    if len(redacted) > limit:
        redacted = redacted[: limit - 3] + "..."
    return redacted


def nearby_source(lines: Sequence[str], index: int) -> bool:
    window = lines[max(0, index - 2) : min(len(lines), index + 3)]
    return any(SOURCE_RE.search(line) for line in window)


def is_protective_secret_policy(line: str) -> bool:
    return bool(SECRET_RE.search(line) and PROTECTIVE_SECRET_POLICY_RE.search(line))


def audit_file(path: str, today: date, stale_days: int) -> tuple[FileSummary, list[Finding]]:
    with open(path, "r", encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    text = "\n".join(lines)
    findings: list[Finding] = []
    dated_entries = 0
    stale_dates = 0
    has_usage_rules = bool(re.search(r"^##?\s+Usage Rules\b", text, re.IGNORECASE | re.MULTILINE))
    has_source_mentions = bool(SOURCE_RE.search(text))

    if not has_usage_rules:
        findings.append(
            Finding(
                severity="medium",
                rule="missing-usage-rules",
                path=path,
                line=1,
                reason="Memory file does not declare usage rules.",
                evidence="missing usage rules",
            )
        )
    if not re.search(r"do not store (secrets|tokens|credentials)|re-verify|not as ground truth", text, re.IGNORECASE):
        findings.append(
            Finding(
                severity="medium",
                rule="weak-memory-policy",
                path=path,
                line=1,
                reason="Memory policy does not clearly warn against secrets, stale facts, or treating memory as ground truth.",
                evidence="missing memory hygiene policy",
            )
        )

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        for match in DATE_RE.finditer(stripped):
            dated_entries += 1
            found = parse_date(match.group(0))
            if found and (today - found).days > stale_days:
                stale_dates += 1
                if EXTERNAL_CLAIM_RE.search(stripped):
                    findings.append(
                        Finding(
                            severity="medium",
                            rule="stale-current-claim",
                            path=path,
                            line=idx,
                            reason=f"Current-state memory is older than {stale_days} days.",
                            evidence=redact(stripped),
                        )
                    )
                    continue
                findings.append(
                    Finding(
                        severity="low",
                        rule="stale-date",
                        path=path,
                        line=idx,
                        reason=f"Dated memory is older than {stale_days} days.",
                        evidence=redact(stripped),
                    )
                )
        if SECRET_RE.search(stripped) and not is_protective_secret_policy(stripped):
            findings.append(
                Finding(
                    severity="high",
                    rule="secret-material-mention",
                    path=path,
                    line=idx,
                    reason="Memory references secrets, credentials, tokens, or passwords.",
                    evidence=redact(stripped),
                )
            )
        if EXTERNAL_CLAIM_RE.search(stripped) and not nearby_source(lines, idx - 1):
            findings.append(
                Finding(
                    severity="medium",
                    rule="unsourced-current-claim",
                    path=path,
                    line=idx,
                    reason="Current-state or external claim lacks nearby source evidence.",
                    evidence=redact(stripped),
                )
            )
        if PUBLIC_ACTION_RE.search(stripped) and not APPROVAL_RE.search(stripped):
            severity = "high" if UNATTENDED_RE.search(stripped) else "medium"
            findings.append(
                Finding(
                    severity=severity,
                    rule="public-action-without-approval",
                    path=path,
                    line=idx,
                    reason="Public or sensitive action is mentioned without explicit human approval language.",
                    evidence=redact(stripped),
                )
            )
        if ABSOLUTE_PATH_RE.search(stripped):
            findings.append(
                Finding(
                    severity="low",
                    rule="absolute-local-path",
                    path=path,
                    line=idx,
                    reason="Absolute local path should be reviewed before public reuse.",
                    evidence=redact(stripped),
                )
            )
    return (
        FileSummary(
            path=path,
            lines=len(lines),
            dated_entries=dated_entries,
            stale_dates=stale_dates,
            has_usage_rules=has_usage_rules,
            has_source_mentions=has_source_mentions,
        ),
        findings,
    )


def build_report(paths: Sequence[str], today: date, stale_days: int) -> AuditReport:
    summaries: list[FileSummary] = []
    findings: list[Finding] = []
    for path in paths:
        summary, file_findings = audit_file(path, today, stale_days)
        summaries.append(summary)
        findings.extend(file_findings)

    summary_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        summary_counts[finding.severity] += 1
    score = max(0, 100 - sum(SEVERITY_WEIGHT[f.severity] for f in findings))
    status = "pass"
    if summary_counts["critical"] or summary_counts["high"]:
        status = "block"
    elif summary_counts["medium"] or summary_counts["low"]:
        status = "warn"
    return AuditReport(
        score=score,
        status=status,
        files=summaries,
        findings=findings,
        summary=summary_counts,
        follow_up_checks=[
            "Remove or redact secret-material references before memory reuse.",
            "Re-verify stale current-state facts before acting on them.",
            "Attach sources to external claims that future agents may treat as durable.",
            "Keep public actions attended unless explicit approval is recorded outside public memory.",
        ],
    )


def render_markdown(report: AuditReport) -> str:
    lines = [
        "# Agent Memory Audit",
        "",
        f"Status: {report.status}",
        f"Score: {report.score}/100",
        f"Files: {len(report.files)}",
        "",
        "## Summary",
        "",
        f"- Critical findings: {report.summary['critical']}",
        f"- High findings: {report.summary['high']}",
        f"- Medium findings: {report.summary['medium']}",
        f"- Low findings: {report.summary['low']}",
        "",
        "## Files",
        "",
    ]
    for item in report.files:
        lines.append(
            f"- {item.path}: {item.lines} lines, {item.dated_entries} dated entries, "
            f"{item.stale_dates} stale dates"
        )
    lines.append("")
    if report.findings:
        lines.extend(["## Findings", ""])
        for finding in report.findings:
            lines.append(f"### {finding.severity}: {finding.rule}")
            lines.append("")
            lines.append(f"- File: {finding.path}")
            lines.append(f"- Line: {finding.line}")
            lines.append(f"- Reason: {finding.reason}")
            lines.append(f"- Evidence: `{finding.evidence}`")
            lines.append("")
    else:
        lines.extend(["## Findings", "", "No configured memory hygiene issues detected.", ""])

    lines.extend(["## Follow-Up Checks", ""])
    lines.extend(f"- {check}" for check in report.follow_up_checks)
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def severity_at_or_above(findings: Iterable[Finding], threshold: str) -> bool:
    target = SEVERITY_ORDER[threshold]
    return any(SEVERITY_ORDER[finding.severity] >= target for finding in findings)


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit local agent memory files.")
    parser.add_argument("paths", nargs="+", help="Markdown or text memory files to audit.")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--today", help="Audit date in YYYY-MM-DD format. Defaults to today.")
    parser.add_argument("--stale-days", type=int, default=90, help="Age threshold for stale dated memory.")
    parser.add_argument("--min-score", type=int, default=0, help="Fail when score is below this value.")
    parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        help="Fail when any finding is at or above this severity.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    for path in args.paths:
        if not os.path.exists(path):
            parser.error(f"memory file not found: {path}")
    today = date.today()
    if args.today:
        parsed = parse_date(args.today)
        if not parsed:
            parser.error("--today must use YYYY-MM-DD")
        today = parsed
    report = build_report(args.paths, today=today, stale_days=args.stale_days)
    if args.format == "json":
        print(json.dumps(asdict(report), indent=2, sort_keys=True))
    else:
        sys.stdout.write(render_markdown(report))
    failed = report.score < args.min_score
    if args.fail_on:
        failed = failed or severity_at_or_above(report.findings, args.fail_on)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
