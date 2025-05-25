VERSION := v1.0.3

.PHONY: build
build:
	go build -ldflags="-X github.com/gourdian25/gourdiantoken.Version=$(VERSION)" ./...

.PHONY: test
test:
	go test -v .

.PHONY: coverage
coverage:
	go test -coverprofile=coverage.out .
	go tool cover -html=coverage.out -o coverage.html
	@echo "HTML coverage report saved as coverage.html"

.PHONY: coverage-summary
coverage-summary:
	go test -coverprofile=coverage.out .
	go tool cover -func=coverage.out

.PHONY: bench
bench:
	go test -bench=. -benchmem .


.PHONY: release
release:
	git tag $(VERSION)
	git push origin $(VERSION)
	goreleaser release --clean
