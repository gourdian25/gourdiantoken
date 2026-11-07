# File: Makefile

.PHONY: help build test coverage coverage-summary lint fmt clean bench race staticcheck docs guard-version tag release install goreleaser-release goreleaser-check docker-up docker-create docker-down

# Variables
VERSION ?=

# The shared Postgres/Redis/Mongo containers every gourdian25 repo tests
# against. grsentry's docker-compose.yml is the source of truth for how
# they're built (images, ports, credentials, volumes); this path is where
# it sits in the usual side-by-side checkout. gourdiantoken needs no Kafka.
GRSENTRY_COMPOSE ?= ../grsentry/docker-compose.yml
SHARED_CONTAINERS := gourdian-postgres gourdian-redis gourdian-mongo-auth

# wait_for runs the command $(2) once a second until it succeeds, giving up
# after 60 tries with an error naming container $(1), never looping forever.
wait_for = for i in $$(seq 60); do { $(2); } >/dev/null 2>&1 && exit 0; sleep 1; done; \
	echo "FAIL: $(1) is not ready after 60s; see 'docker logs $(1)'"; exit 1

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
	@echo "  make docker-up        Start the shared Postgres/Redis/Mongo test containers (from grsentry's docker-compose.yml) (idempotent)"
	@echo "  make docker-create    Create any missing container with docker run (fallback when grsentry isn't checked out beside this repo)"
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

# docker-up is idempotent and shares its Postgres/Redis/Mongo containers
# with every other gourdian25 repo (gourdiantoken's are the
# gourdiantoken_test database, its Redis keyspace and Mongo database).
# Containers that already exist, whoever made them, are just started.
# Missing ones are created from grsentry's docker-compose.yml when that
# checkout sits beside this one, so they're exactly what grsentry runs;
# otherwise docker-create builds them by hand. Every wait assumes the
# compose layout (mongod on 27018 inside its container) and gives up after
# 60s rather than hanging.
docker-up:
	@missing=""; for c in $(SHARED_CONTAINERS); do docker inspect $$c >/dev/null 2>&1 || missing="$$missing $$c"; done; \
	if [ -z "$$missing" ]; then \
		echo "Starting the shared test containers..."; docker start $(SHARED_CONTAINERS) >/dev/null; \
	elif [ -f "$(GRSENTRY_COMPOSE)" ]; then \
		echo "Creating$$missing from $(GRSENTRY_COMPOSE)..."; docker compose -f "$(GRSENTRY_COMPOSE)" up -d postgres redis mongo mongo-init; \
	else \
		echo "$(GRSENTRY_COMPOSE) not found; creating$$missing with docker run..."; $(MAKE) --no-print-directory docker-create; \
	fi
	@echo "Waiting for Postgres..."; $(call wait_for,gourdian-postgres,docker exec gourdian-postgres pg_isready -U postgres_user -d postgres)
	@docker exec gourdian-postgres psql -U postgres_user -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname = 'gourdiantoken_test'" | grep -q 1 || \
		docker exec gourdian-postgres createdb -U postgres_user gourdiantoken_test
	@echo "Waiting for Redis..."; $(call wait_for,gourdian-redis,docker exec gourdian-redis redis-cli -a redis_password ping | grep -q PONG)
	@echo "Waiting for Mongo..."; $(call wait_for,gourdian-mongo-auth,docker exec gourdian-mongo-auth mongosh --port 27018 --quiet --eval 'db.runCommand({ping:1})')
	@docker exec gourdian-mongo-auth mongosh --port 27018 --quiet -u root -p mongo_password --authenticationDatabase admin --eval \
		'try { rs.status() } catch (e) { try { rs.initiate({_id: "rs0", members: [{_id: 0, host: "127.0.0.1:27018"}]}) } catch (e2) {} }' >/dev/null
	@echo "Waiting for the Mongo replica set..."; $(call wait_for,gourdian-mongo-auth,docker exec gourdian-mongo-auth mongosh --port 27018 --quiet -u root -p mongo_password --authenticationDatabase admin --eval 'rs.status().members[0].stateStr' | grep -q PRIMARY)
	@echo "Docker test infrastructure ready (postgres/redis/mongo-auth, database gourdiantoken_test)"

# docker-create builds whichever shared container is missing with plain
# docker run, for a checkout without grsentry beside it. Every image, port,
# credential and volume mirrors $(GRSENTRY_COMPOSE): keep the two in sync.
# The Mongo replica set is initiated by docker-up, as compose's one-shot
# mongo-init service does there.
docker-create:
	@docker inspect gourdian-postgres >/dev/null 2>&1 || docker run -d --name gourdian-postgres --restart unless-stopped -p 5432:5432 \
		-e POSTGRES_USER=postgres_user -e POSTGRES_PASSWORD=postgres_password -e POSTGRES_DB=gourdiantoken_test \
		-v gourdian-postgres-data:/var/lib/postgresql postgres:18-alpine
	@docker inspect gourdian-redis >/dev/null 2>&1 || docker run -d --name gourdian-redis --restart unless-stopped -p 6379:6379 \
		-v gourdian-redis-data:/data redis:8-alpine redis-server --requirepass redis_password
	@docker inspect gourdian-mongo-auth >/dev/null 2>&1 || { \
		docker run --rm -v gourdian-mongo-keyfile:/keyfile-dir --entrypoint bash mongo:8.3 -c \
			'[ -f /keyfile-dir/mongo-keyfile ] || { openssl rand -base64 756 > /keyfile-dir/mongo-keyfile && chmod 400 /keyfile-dir/mongo-keyfile && chown 999:999 /keyfile-dir/mongo-keyfile; }' && \
		docker run -d --name gourdian-mongo-auth --restart unless-stopped -p 27018:27018 \
			-e MONGO_INITDB_ROOT_USERNAME=root -e MONGO_INITDB_ROOT_PASSWORD=mongo_password \
			-v gourdian-mongo-keyfile:/etc/mongo-keyfile-dir -v gourdian-mongo-data:/data/db \
			mongo:8.3 --port 27018 --replSet rs0 --keyFile /etc/mongo-keyfile-dir/mongo-keyfile; }

docker-down:
	@docker stop $(SHARED_CONTAINERS) 2>/dev/null || true
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

# Ensure VERSION is set before any tagging/release action, matching the
# convention used by grpop/graudit/grcache/grnoti. A stale hardcoded
# default here previously caused a bare `make goreleaser-release` (no
# VERSION= override) to silently re-target an already-released version
# instead of failing loudly.
guard-version:
	@if [ -z "$(VERSION)" ]; then \
		echo "VERSION is required (example: make release VERSION=v2.5.0)"; \
		exit 1; \
	fi

# Tag and push for release (creates git tag)
tag: guard-version
	@echo "Tagging $(VERSION)..."
	@if [ -n "$$(git status --porcelain)" ]; then \
		echo "✗ Working directory is dirty. Commit changes before releasing."; \
		exit 1; \
	fi
	git tag $(VERSION)
	git push origin $(VERSION)
	@echo "✓ Tagged and pushed $(VERSION)"

# Pre-release checks (comprehensive testing)
prerelease: clean fmt vet lint coverage-check race
	@echo ""
	@echo "✓ All pre-release checks passed"
	@echo "Ready to release version $(VERSION)"

# Full release: guard VERSION, run the pre-release check suite, tag, then
# publish with goreleaser — matching the tag/release/goreleaser-check shape
# every other gourdian25 repo uses, with gourdiantoken's own stricter
# pre-flight pipeline layered in ahead of tagging.
release: guard-version prerelease tag
	@echo "Releasing $(VERSION) with goreleaser..."
	@which goreleaser > /dev/null || (echo "goreleaser not found. Install with: go install github.com/goreleaser/goreleaser/v2@latest" && exit 1)
	goreleaser release --clean
	@echo "✓ Released $(VERSION)"

# Back-compat alias: release now does the full tag+goreleaser publish
# itself, so this is just an alias for anyone still typing the old name.
goreleaser-release: release

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