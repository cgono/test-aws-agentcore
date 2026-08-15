# AgentCore Identity POC

Experiment with AWS AgentCore Identity.

## Setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
```

## Verify

```bash
.venv/bin/python -m pytest
.venv/bin/ruff check .
.venv/bin/mypy src
```
