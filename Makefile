PYTHON ?= .venv/bin/python
NPM ?= npm

.PHONY: help install test smoke lint format dev daemon build package clean

help:
	@echo "install   install the python and node dependencies"
	@echo "test      run the python test suite"
	@echo "smoke     run the end to end smoke test against a live daemon"
	@echo "lint      run ruff and the typescript type checker"
	@echo "daemon    run the daemon on its own"
	@echo "dev       run the desktop shell with hot reload"
	@echo "build     build the desktop shell"
	@echo "package   freeze the daemon and build the distributable desktop app"
	@echo "clean     remove build output and caches"

install:
	$(PYTHON) -m pip install -e ".[dev]"
	cd apps/desktop && $(NPM) install

test:
	$(PYTHON) -m pytest

smoke:
	$(PYTHON) scripts/smoke.py

lint:
	$(PYTHON) -m ruff check src tests plugins scripts
	cd apps/desktop && npx tsc -p renderer/tsconfig.json --noEmit
	cd apps/desktop && npx tsc -p electron/tsconfig.json --noEmit

format:
	$(PYTHON) -m ruff check --fix src tests plugins scripts
	$(PYTHON) -m ruff format src tests plugins scripts

daemon:
	$(PYTHON) -m intercept serve

dev:
	cd apps/desktop && $(NPM) run dev

build:
	cd apps/desktop && $(NPM) run build

package:
	bash scripts/build_daemon.sh
	cd apps/desktop && $(NPM) run dist

clean:
	rm -rf apps/desktop/dist dist build .pytest_cache .ruff_cache htmlcov .coverage
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
