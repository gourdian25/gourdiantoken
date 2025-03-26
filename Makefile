VERSION := v0.0.5

.PHONY: build
build:
	go build -ldflags="-X github.com/gourdian25/gourdiantoken.Version=$(VERSION)" ./...

.PHONY: test
test:
	go test -v ./...

.PHONY: release
release:
	git tag $(VERSION)
	git push origin $(VERSION)
	goreleaser release --clean