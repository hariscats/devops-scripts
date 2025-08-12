.PHONY: help install install-dev test lint format clean build

help:  ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

install:  ## Install the package
	pip install -e .

install-dev:  ## Install the package in development mode with dev dependencies
	pip install -e ".[dev]"
	pre-commit install

test:  ## Run tests
	pytest tests/ -v --cov=src --cov-report=term-missing

test-watch:  ## Run tests in watch mode
	pytest-watch tests/ -- -v

lint:  ## Run linting tools
	flake8 src tests
	mypy src
	black --check src tests

format:  ## Format code
	black src tests
	isort src tests

clean:  ## Clean build artifacts
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build:  ## Build the package
	python -m build

docker-build:  ## Build Docker containers for testing
	docker build -t devops-tools:latest .

docker-test:  ## Run tests in Docker
	docker run --rm devops-tools:latest pytest

pre-commit:  ## Run pre-commit hooks on all files
	pre-commit run --all-files

security-scan:  ## Run security scanning
	bandit -r src/
	safety check
