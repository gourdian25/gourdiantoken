# Makefile
VERSION := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.1-dev")

.PHONY: build
build:
	go build -ldflags="-X github.com/yourusername/gourdiantoken.Version=$(VERSION)" ./...

.PHONY: test
test:
	go test -v ./...

.PHONY: release
release:
	git tag $(VERSION)
	git push origin $(VERSION)