.PHONY: help build test coverage coverage-summary lint fmt clean bench race staticcheck docs release install

# Variables
VERSION := v1.0.7
MAIN_PACKAGE := github.com/gourdian25/gourdiantoken
MODULE := github.com/gourdian25/gourdiantoken
GO := go
COVERAGE_MIN := 70
BUILD_DIR := ./bin

# Help command - displays all available targets
help:
	@echo "Makefile targets for gourdiantoken:"
	@echo ""
	@echo "Core Commands:"
	@echo "  make build            Build the package"
	@echo "  make test             Run all tests"
	@echo "  make race             Run tests with race detector"
	@echo "  make coverage         Generate HTML coverage report"
	@echo "  make coverage-summary Show coverage summary by function"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint             Run linters (requires golangci-lint)"
	@echo "  make fmt              Format code"
	@echo "  make staticcheck      Run staticcheck analysis"
	@echo "  make vet              Run go vet"
	@echo ""
	@echo "Performance & Documentation:"
	@echo "  make bench            Run benchmarks"
	@echo "  make docs             Start local documentation server"
	@echo ""
	@echo "Development & Release:"
	@echo "  make install          Install package locally"
	@echo "  make release          Tag and release new version"
	@echo "  make clean            Clean build artifacts"
	@echo ""

# Build the package
build:
	@echo "Building gourdiantoken $(VERSION)..."
	$(GO) build -ldflags="-X $(MAIN_PACKAGE).Version=$(VERSION)" -o $(BUILD_DIR)/gourdiantoken ./...
	@echo "✓ Build complete"

# Run all tests with verbose output
test:
	@echo "Running tests..."
	$(GO)  test -count=1 -timeout=5m -cover ./... -bench=. -benchmem
	@echo "✓ Tests passed"

# Run tests with race detector enabled
race:
	@echo "Running tests with race detector..."
	$(GO) test -race -timeout 5m ./...
	@echo "✓ Race detector tests passed"

# Generate HTML coverage report
coverage:
	@echo "Generating coverage report..."
	$(GO) test -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "✓ HTML coverage report saved as coverage.html"
	@$(GO) tool cover -func=coverage.out | tail -1 | awk '{print "Total coverage: " $$3}'

# Display coverage summary by function
coverage-summary:
	@echo "Coverage summary by function:"
	@$(GO) test -coverprofile=coverage.out ./...
	@$(GO) tool cover -func=coverage.out
	@echo ""
	@$(GO) tool cover -func=coverage.out | grep total | awk '{print "Total coverage: " $$3}'

# Check coverage meets minimum threshold
coverage-check:
	@echo "Checking coverage meets $(COVERAGE_MIN)% threshold..."
	@$(GO) test -coverprofile=coverage.out .
	@COVERAGE=$$($(GO) tool cover -func=coverage.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	if [ "$${COVERAGE%.*}" -lt $(COVERAGE_MIN) ]; then \
		echo "✗ Coverage $${COVERAGE} is below $(COVERAGE_MIN)% threshold"; \
		exit 1; \
	fi; \
	echo "✓ Coverage $${COVERAGE} meets $(COVERAGE_MIN)% threshold"

# Run benchmarks with memory stats
bench:
	@echo "Running benchmarks..."
	@echo ""
	$(GO) test -bench=. -benchmem -benchtime=10s ./...
	@echo ""
	@echo "✓ Benchmarks complete"

# Run specific benchmark
bench-%:
	@echo "Running benchmark: $*"
	$(GO) test -bench=$* -benchmem -benchtime=10s -run ^$$ ./...

# Run linters (requires: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
lint:
	@echo "Running linters..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest" && exit 1)
	golangci-lint run ./...
	@echo "✓ Linting passed"

# Run go vet
vet:
	@echo "Running go vet..."
	$(GO) vet ./...
	@echo "✓ Vet analysis complete"

# Run staticcheck (requires: go install honnef.co/go/tools/cmd/staticcheck@latest)
staticcheck:
	@echo "Running staticcheck..."
	@which staticcheck > /dev/null || (echo "staticcheck not found. Install with: go install honnef.co/go/tools/cmd/staticcheck@latest" && exit 1)
	staticcheck ./...
	@echo "✓ Staticcheck complete"

# Format code with goimports
fmt:
	@echo "Formatting code..."
	@which goimports > /dev/null || (echo "goimports not found. Install with: go install golang.org/x/tools/cmd/goimports@latest" && exit 1)
	goimports -w .
	$(GO) fmt ./...
	@echo "✓ Code formatted"

# Run all quality checks
quality: vet lint staticcheck fmt
	@echo "✓ All quality checks passed"

# View documentation locally (requires: go install golang.org/x/tools/cmd/godoc@latest)
docs:
	@echo "Starting documentation server at http://localhost:6060"
	@echo "Press Ctrl+C to stop"
	@which godoc > /dev/null || (echo "godoc not found. Install with: go install golang.org/x/tools/cmd/godoc@latest" && exit 1)
	godoc -http=:6060

# Quick documentation lookup
doc-%:
	@$(GO) doc $(MODULE).$*

# Install package locally
install:
	@echo "Installing gourdiantoken..."
	$(GO) install -ldflags="-X $(MAIN_PACKAGE).Version=$(VERSION)" ./...
	@echo "✓ Installation complete"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f coverage.out coverage.html
	rm -rf $(BUILD_DIR)
	$(GO) clean ./...
	@echo "✓ Clean complete"

# Verify dependencies
deps:
	@echo "Verifying dependencies..."
	$(GO) mod verify
	@echo "Tidying dependencies..."
	$(GO) mod tidy
	@echo "✓ Dependency verification complete"

# Update dependencies to latest versions
deps-update:
	@echo "Checking for dependency updates..."
	$(GO) get -u ./...
	$(GO) mod tidy
	@echo "✓ Dependencies updated"

# Show available updates without applying them
deps-check:
	@echo "Available dependency updates:"
	$(GO) list -u -m all

# Generate mocks and code if needed
generate:
	@echo "Running go generate..."
	$(GO) generate ./...
	@echo "✓ Code generation complete"

# Pre-commit checks (run before committing)
precommit: clean fmt vet lint coverage-check
	@echo ""
	@echo "✓ All pre-commit checks passed"
	@echo "Ready to commit!"

# Pre-release checks (comprehensive testing)
prerelease: clean fmt vet lint coverage-check race
	@echo ""
	@echo "✓ All pre-release checks passed"
	@echo "Ready to release version $(VERSION)"

# Tag and push for release (creates git tag)
release: prerelease
	@echo "Releasing version $(VERSION)..."
	@if [ -z "$$(git status --porcelain)" ]; then \
		git tag -a $(VERSION) -m "Release $(VERSION)"; \
		git push origin $(VERSION); \
		echo "✓ Version $(VERSION) tagged and pushed"; \
	else \
		echo "✗ Working directory is dirty. Commit changes before releasing."; \
		exit 1; \
	fi

# Create a release using goreleaser (requires: go install github.com/goreleaser/goreleaser@latest)
goreleaser-release:
	@echo "Building release with goreleaser..."
	@which goreleaser > /dev/null || (echo "goreleaser not found. Install with: go install github.com/goreleaser/goreleaser@latest" && exit 1)
	goreleaser release --clean

# Development build (faster, with debugging info)
dev-build:
	@echo "Building development version..."
	$(GO) build -o $(BUILD_DIR)/gourdiantoken-dev ./...
	@echo "✓ Development build complete"

# Watch for changes and rebuild (requires: entr or similar)
watch:
	@echo "Watching for changes... (Press Ctrl+C to stop)"
	@which ls > /dev/null || (echo "ls not found"; exit 1)
	ls -d *.go **/*.go 2>/dev/null | entr -r make build test

# Generate test report
test-report:
	@echo "Running tests with verbose output..."
	$(GO) test -v -race -coverprofile=coverage.out ./... -json | tee test-report.json
	@echo "✓ Test report saved as test-report.json"

# Full build and test pipeline (CI/CD simulation)
ci: clean deps vet lint test coverage-check race
	@echo ""
	@echo "✓ CI pipeline completed successfully"

.DEFAULT_GOAL := help