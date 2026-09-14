.PHONY: help install test lint scan demo hunt clean

help:
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install:  ## install ghast and its test dependencies
	pip install -e '.[dev]'

test:  ## run the test suite
	pytest -q

scan:  ## scan this repository (fixtures excluded)
	ghast scan . --exclude examples

demo:  ## show the tool finding, and not finding, things
	@echo "=== examples/vulnerable — should report criticals ==="
	-@ghast scan examples/vulnerable --min-severity high
	@echo
	@echo "=== examples/safe — should report nothing ==="
	@ghast scan examples/safe --min-severity info

hunt:  ## scan the 25 most-starred public repositories (read-only)
	ghast hunt --top 25 --min-severity high --fail-on never

clean:  ## remove build and cache artifacts
	rm -rf build dist *.egg-info .pytest_cache .coverage
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
