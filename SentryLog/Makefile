.PHONY: install dev test lint clean demo

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest --cov=sentrylog --cov-report=term-missing

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

format:
	ruff format src/ tests/
	ruff check --fix src/ tests/

clean:
	rm -rf build/ dist/ *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +

demo:
	sentrylog demo
