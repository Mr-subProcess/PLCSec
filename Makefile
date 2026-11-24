.PHONY: install test lint typecheck check clean

install:
	python -m pip install -e '.[all,dev]'

test:
	PYTHONPATH=src python -m pytest

lint:
	ruff check src tests

typecheck:
	mypy src/plcsec

check:
	PYTHONPATH=src python -m compileall -q src tests plcsec_util.py
	PYTHONPATH=src python -m pytest

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
