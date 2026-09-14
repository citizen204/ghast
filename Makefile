PYTHON ?= python3

# Prefer the installed console script; fall back to running from the source
# tree so `make demo` and `make test` work straight from a clone.
GHAST := $(shell command -v ghast 2>/dev/null || echo "$(PYTHON) -m ghast")

.PHONY: help install test lint scan demo hunt clean

help:
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install:  ## install ghast and its test dependencies
	$(PYTHON) -m pip install -e '.[dev]'

test:  ## run the test suite
	$(PYTHON) -m pytest -q

scan:  ## scan this repository (fixtures excluded)
	$(GHAST) scan . --exclude examples

demo:  ## show the tool finding, and not finding, things
	@echo "=== examples/vulnerable — should report criticals ==="
	@# A non-zero exit is the point here, so it is not a make failure.
	@$(GHAST) scan examples/vulnerable --min-severity high || true
	@echo
	@echo "=== examples/safe — the same patterns, hardened — should report nothing ==="
	@$(GHAST) scan examples/safe --min-severity info

hunt:  ## scan the 25 most-starred public repositories (read-only)
	$(GHAST) hunt --top 25 --min-severity high --fail-on never

clean:  ## remove build and cache artifacts
	rm -rf build dist *.egg-info .pytest_cache .coverage
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
