.PHONY: setup dev test lint typecheck build check bench bench-events release

VENV := .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

setup:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements-dev.txt
	$(PIP) install -e .

dev:
	@$(PY) -m pcap_inspector --help

test:
	$(PY) -m pytest

lint:
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

typecheck:
	$(PY) -m mypy src tests

build:
	$(PY) -m compileall -q src

check: lint typecheck test build

bench:
	$(PY) scripts/bench_inspect.py --packets 50000 --flows 500 --repeat 3 --no-events

bench-events:
	$(PY) scripts/bench_inspect.py --packets 20000 --flows 500 --repeat 3 --top-events 5000

release:
	@echo "Use PROJECT.md for release commands."
