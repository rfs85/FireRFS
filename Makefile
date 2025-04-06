.PHONY: install test lint clean docs build

# Variables
PYTHON = python
PIP = pip
PYTEST = pytest
BLACK = black
FLAKE8 = flake8
SPHINX = sphinx-build

# Installation
install:
	$(PIP) install -e .

install-dev:
	$(PIP) install -r requirements-dev.txt
	$(PIP) install -e .

# Testing
test:
	$(PYTEST) tests/ -v

test-coverage:
	$(PYTEST) tests/ --cov=firebase_rfs --cov-report=html

# Code Quality
lint:
	$(BLACK) .
	$(FLAKE8) firebase_rfs/ tests/ setup.py

format:
	$(BLACK) .

# Documentation
docs:
	$(SPHINX) -b html docs/source docs/build/html

# Cleaning
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf docs/build/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete

# Running Examples
example-basic:
	$(PYTHON) main.py --example basic

example-rules:
	$(PYTHON) main.py --example rules

example-discovery:
	$(PYTHON) main.py --example discovery

example-monitoring:
	$(PYTHON) main.py --example monitoring

# Development
dev-setup: clean install-dev
	pre-commit install

# Building
build:
	$(PYTHON) setup.py sdist bdist_wheel

# Help
help:
	@echo "Available commands:"
	@echo "  make install         - Install package"
	@echo "  make install-dev     - Install development dependencies"
	@echo "  make test           - Run tests"
	@echo "  make test-coverage  - Run tests with coverage report"
	@echo "  make lint           - Run linters"
	@echo "  make format         - Format code with Black"
	@echo "  make docs           - Build documentation"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make example-basic  - Run basic example"
	@echo "  make example-rules  - Run rules example"
	@echo "  make dev-setup      - Setup development environment"
	@echo "  make build          - Build package" 