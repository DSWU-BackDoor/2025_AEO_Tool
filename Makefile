.PHONY: help install clean test format run

.DEFAULT_GOAL := help

PYTHON := python3
PIP := pip

help: ## Show this help message
	@echo "AEO Security Tool - Available commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

install: ## Install the package
	$(PIP) install -e .

install-dev: ## Install with development dependencies
	$(PIP) install -e .
	$(PIP) install pytest pytest-cov black isort

clean: ## Remove build artifacts and cache
	rm -rf build/ dist/ *.egg-info
	rm -rf .pytest_cache .coverage htmlcov/
	rm -rf reports/ output/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

test: ## Run tests
	pytest

test-cov: ## Run tests with coverage
	pytest --cov=aeo_tool --cov-report=html --cov-report=term

format: ## Format code with black and isort
	black aeo_tool tests
	isort aeo_tool tests

run: ## Run example scan (usage: make run TARGET=./path)
	$(PYTHON) -m aeo_tool.cli scan --target $(TARGET)

run-demo: ## Run demo scan on current directory
	$(PYTHON) -m aeo_tool.cli scan --target . --output ./reports