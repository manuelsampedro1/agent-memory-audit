.PHONY: test lint build smoke

test:
	PYTHONPATH=src python3 -m unittest discover -s tests

lint:
	python3 -m py_compile src/agent_memory_audit/*.py tests/*.py

build:
	python3 -m compileall -q src tests

smoke:
	PYTHONPATH=src python3 -m agent_memory_audit examples/memory.md --today 2026-06-02 --min-score 0
	PYTHONPATH=src python3 -m agent_memory_audit examples/memory.md --format json --today 2026-06-02 --fail-on high >/tmp/agent-memory-audit-smoke.json || test $$? -eq 1
