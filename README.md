# agent-memory-audit

Audit agent memory files for stale facts, missing sources, secret-material
markers, and public-action policy drift before memory is reused.

The tool is intentionally narrow. It does not upload memory, call a model, or
decide what is true. It reads local Markdown or text memory files and reports
review findings a human can act on.

## Why

Agent memory compounds. That is useful when it preserves durable decisions, but
dangerous when it stores old external facts, credential hints, private approval
details, or unsourced claims that future agents treat as ground truth.

Use this before:

- reusing a long-lived agent memory in a new run,
- publishing docs derived from private automation notes,
- importing memory into a run ledger or proof packet,
- trusting stored tool, auth, pricing, policy, or account-state claims.

## Install

```sh
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pip install -e .
```

## Usage

Audit one memory file:

```sh
agent-memory-audit examples/memory.md --today 2026-06-02 --fail-on high
```

Audit several files:

```sh
agent-memory-audit examples/memory.md examples/clean-memory.md --min-score 80
```

JSON output for automation:

```sh
agent-memory-audit examples/memory.md --format json --today 2026-06-02
```

## What It Detects

- Secret-material markers and credential-handling phrases.
- Dates older than a configurable stale-day threshold, with stronger warnings
  when old entries still claim "current", "authenticated", or "latest" state.
- External or current-state claims that mention live systems without nearby
  source evidence.
- Public-action notes around posting, sending, deploying, publishing, deleting,
  billing, or credentials without explicit human approval language.
- Absolute local paths that should be reviewed before public reuse.
- Missing memory usage rules such as "verify recent facts" or "do not store
  secrets".

## Output

Markdown output includes:

- overall status and score,
- finding severity, rule, file path, line number, reason, and redacted evidence,
- memory hygiene summary,
- follow-up checks.

JSON output exposes the same data for CI gates, proof packets, or automation
maintenance runs.

## Limits

- This is not a truth verifier.
- This is not a full secret scanner.
- Stale dates are review prompts, not automatic deletion requests.
- A clean report means no configured memory hygiene issue was detected, not that
  every stored fact is current.

## Verify

```sh
make test
make lint
make build
make smoke
```
