.PHONY: help test test-verbose test-coverage test-race lint build clean install-tools

# Variables
GO := go
GOLANGCI_LINT := golangci-lint
COVERAGE_FILE := coverage.out
COVERAGE_HTML := coverage.html

# Default target
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test: ## Run tests
	$(GO) test -race ./...

test-verbose: ## Run tests with verbose output
	$(GO) test -v -race ./...

test-coverage: ## Run tests with coverage report
	$(GO) test -coverprofile=$(COVERAGE_FILE) ./...
	$(GO) tool cover -func=$(COVERAGE_FILE)
	@echo ""
	@echo "Coverage report generated: $(COVERAGE_FILE)"
	@echo "To view HTML report, run: make coverage-html"

test-coverage-html: test-coverage ## Generate HTML coverage report
	$(GO) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@echo "HTML coverage report generated: $(COVERAGE_HTML)"

test-all: test-race test-coverage ## Run all tests (race detector + coverage)

lint: ## Run linter
	$(GOLANGCI_LINT) run

lint-fix: ## Run linter and fix issues
	$(GOLANGCI_LINT) run --fix

build: ## Build the project
	$(GO) build ./...

clean: ## Clean generated files
	rm -f $(COVERAGE_FILE) $(COVERAGE_HTML)
	$(GO) clean ./...

ci-test: ## Run CI test suite (with gotestfmt)
	@which gotestfmt > /dev/null || go install github.com/gotesttools/gotestfmt/v2/cmd/gotestfmt@latest
	$(GO) test -v -json -race -coverprofile=$(COVERAGE_FILE) ./... | gotestfmt

