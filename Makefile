.PHONY: install test lint build docker run clean help

PYTHON ?= python
PIP ?= pip
DOCKER ?= docker
IMAGE_NAME ?= aegisagent
IMAGE_TAG ?= latest

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install package with all dependencies (editable mode)
	$(PIP) install -e ".[all,dev]"

test:  ## Run test suite with coverage
	$(PYTHON) -m pytest tests/ -v --tb=short --cov=aegis --cov-report=term-missing

lint:  ## Run linters (ruff, black, mypy)
	ruff check aegis/
	black --check aegis/
	mypy aegis/

format:  ## Auto-format code with black and ruff
	ruff check --fix aegis/
	black aegis/

build:  ## Build distribution packages
	$(PYTHON) -m build
	@echo "Built packages in dist/"

docker:  ## Build Docker image
	$(DOCKER) build -t $(IMAGE_NAME):$(IMAGE_TAG) .

docker-run:  ## Run Docker container
	$(DOCKER) run --rm -p 8901:8901 -p 8902:8902 $(IMAGE_NAME):$(IMAGE_TAG)

run:  ## Start the AegisAgent server locally
	$(PYTHON) -m aegis.cli serve --host 0.0.0.0 --port 8901

clean:  ## Remove build artifacts and caches
	rm -rf dist/ build/ *.egg-info/
	rm -rf __pycache__ aegis/__pycache__
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	rm -rf .venv/
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete
	@echo "Cleaned."
