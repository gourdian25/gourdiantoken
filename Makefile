# File: Makefile

.PHONY: help build test coverage coverage-summary lint fmt clean bench race staticcheck docs release install goreleaser-release goreleaser-check docker-up docker-down

# Variables
VERSION := v2.5.0
MAIN_PACKAGE := github.com/gourdian25/gourdiantoken/v2
MODULE := github.com/gourdian25/gourdiantoken/v2
GO := go
COVERAGE_MIN := 95
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
	@echo "Test Infrastructure:"
	@echo "  make docker-up        Start the shared Postgres/Redis/Mongo test containers (idempotent)"
	@echo "  make docker-down      Stop those containers (state preserved for a fast restart)"
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

# docker-up is idempotent: safe to run repeatedly, and safe to run
# alongside grnoti/grcache/graudit's own `make docker-up` since every
# gourdian25 repo shares these same container names/ports — each just
# gets its own database/keyspace/DB-index inside them (see CLAUDE.md).
# gourdiantoken doesn't need Kafka or Memcached, unlike grnoti/grcache.
docker-up:
	@echo "Starting shared test containers..."
	@docker inspect gourdian-postgres >/dev/null 2>&1 || docker run -d --name gourdian-postgres -p 5432:5432 \
		-e POSTGRES_USER=postgres_user -e POSTGRES_PASSWORD=postgres_password -e POSTGRES_DB=gourdiantoken_test postgres:16
	@docker start gourdian-postgres >/dev/null 2>&1 || true
	@docker inspect gourdian-redis >/dev/null 2>&1 || docker run -d --name gourdian-redis -p 6379:6379 redis:7 --requirepass redis_password
	@docker start gourdian-redis >/dev/null 2>&1 || true
	@docker volume create gourdian-mongo-keyfile >/dev/null
	@docker inspect gourdian-mongo-auth >/dev/null 2>&1 || (docker run --rm -v gourdian-mongo-keyfile:/keyfile-dir mongo:7 bash -c "openssl rand -base64 756 > /keyfile-dir/mongo-keyfile && chmod 400 /keyfile-dir/mongo-keyfile && chown 999:999 /keyfile-dir/mongo-keyfile" && docker run -d --name gourdian-mongo-auth -p 27018:27017 -e MONGO_INITDB_ROOT_USERNAME=root -e MONGO_INITDB_ROOT_PASSWORD=mongo_password -v gourdian-mongo-keyfile:/etc/mongo-keyfile-dir mongo:7 --replSet rs0 --keyFile /etc/mongo-keyfile-dir/mongo-keyfile)
	@docker start gourdian-mongo-auth >/dev/null 2>&1 || true
	@echo "Waiting for Postgres..."
	@until docker exec gourdian-postgres pg_isready -U postgres_user >/dev/null 2>&1; do sleep 1; done
	@docker exec gourdian-postgres psql -U postgres_user -d postgres -tc "SELECT 1 FROM pg_database WHERE datname = 'gourdiantoken_test'" | grep -q 1 || \
		docker exec gourdian-postgres psql -U postgres_user -d postgres -c "CREATE DATABASE gourdiantoken_test"
	@echo "Waiting for Redis..."
	@until docker exec gourdian-redis redis-cli -a redis_password ping 2>/dev/null | grep -q PONG; do sleep 1; done
	@echo "Waiting for Mongo (auth + replica set)..."
	@until docker exec gourdian-mongo-auth mongosh --quiet -u root -p mongo_password --authenticationDatabase admin --eval 'db.runCommand({ping:1})' >/dev/null 2>&1; do sleep 1; done
	@docker exec gourdian-mongo-auth mongosh --quiet -u root -p mongo_password --authenticationDatabase admin --eval 'rs.initiate()' >/dev/null 2>&1 || true
	@echo "Docker test infrastructure ready (postgres/redis/mongo-auth)"

docker-down:
	@docker stop gourdian-postgres gourdian-redis gourdian-mongo-auth 2>/dev/null || true
	@echo "Stopped (containers preserved for a fast restart via 'make docker-up')"

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
# Depends on `release` so the VERSION tag exists and is pushed *before* goreleaser runs —
# goreleaser determines its own release version from the actual git tag at HEAD (via `git
# describe`), not from this Makefile's VERSION variable, so running this target without
# tagging first would build/publish under the wrong (previous) version.
goreleaser-release: release
	@echo "Building release with goreleaser..."
	@which goreleaser > /dev/null || (echo "goreleaser not found. Install with: go install github.com/goreleaser/goreleaser/v2@latest" && exit 1)
	goreleaser release --clean

# Validate .goreleaser.yml and do a full local dry-run (no publish) without needing a real tag
goreleaser-check:
	@which goreleaser > /dev/null || (echo "goreleaser not found. Install with: go install github.com/goreleaser/goreleaser/v2@latest" && exit 1)
	goreleaser check
	goreleaser release --snapshot --clean

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