GO ?= go

.PHONY: all build fabric vault test test-race fmt fmt-check vet check deploy clean help

all: build

build: fabric vault

fabric:
	$(GO) build -o fabric ./cmd/fabric

vault:
	mkdir -p build
	$(GO) build -o build/vault ./cmd/vault

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

fmt:
	$(GO) fmt ./...

fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "The following files need formatting:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

vet:
	$(GO) vet ./...

check: vet test

deploy:
	@test -n "$(strip $(HOSTS))" || { \
		echo 'Usage: make deploy HOSTS="host1 [host2 ...]"'; \
		exit 2; \
	}
	./scripts/deploy.sh $(HOSTS)

clean:
	rm -f fabric build/vault

help:
	@echo "Available targets:"
	@echo "  build      Build both fabric and vault (default)"
	@echo "  fabric     Build the fabric binary"
	@echo "  vault      Build the standalone vault binary at build/vault"
	@echo "  test       Run all tests"
	@echo "  test-race  Run all tests with the race detector"
	@echo "  fmt        Format all Go packages"
	@echo "  fmt-check  Check formatting without changing files"
	@echo "  vet        Run go vet"
	@echo "  check      Run vet and test checks"
	@echo '  deploy     Deploy with HOSTS="host1 [host2 ...]"'
	@echo "  clean      Remove built binaries"
