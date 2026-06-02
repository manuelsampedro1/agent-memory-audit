# AGENTS.md

## Scope

This repository contains `agent-memory-audit`, a dependency-free Python CLI for
auditing local agent memory files.

## Rules

- Keep the project standard-library only.
- Do not upload, transmit, or execute memory content.
- Do not add model calls, telemetry, credentials, or hosted services.
- Redact secret-looking evidence in rendered output.
- Preserve Markdown and JSON output for humans and automation.
- Add tests whenever a new memory hygiene rule, severity, or parser behavior
  changes.

## Verification

Run these before closing relevant changes:

```sh
make test
make lint
make build
make smoke
```

For packaging changes, also verify editable install in a temporary virtual
environment before public promotion.

## Closeout

Report changed behavior, exact verification commands, residual risks, and any
rule limits that remain. Do not claim this tool proves memory facts are true.
