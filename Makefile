
GO := go


.PHONY: build
build: fmt test vuln-check lint vet
	$(GO) build ./...


.PHONY: fmt
fmt:
	$(GO) fmt ./...
	$(GO) mod tidy

.PHONY: test
test:
	$(GO) test -v ./...

.PHONY: vuln-check
vuln-check:
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

.PHONY: lint
lint:
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run --timeout 5m

.PHONY: vet
vet:
	$(GO) vet ./...


example_vexhub:
	$(GO) run ./example/vexhub/main.go
