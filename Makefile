GO ?= go
PREFIX ?= $(HOME)/.local
FABRIC_BIN ?= $(PREFIX)/bin/fabric

.PHONY: all build fabric install install-user restart-user status-user logs-user test test-race fmt fmt-check vet check deploy clean help

all: build

build: fabric

fabric:
	$(GO) build -o fabric ./cmd/fabric

# Install locally without touching identity/state.  This is also the path used
# by `fabric deploy` on remote hosts.
install: fabric
	install -d $(dir $(FABRIC_BIN))
	install -m 0755 fabric $(FABRIC_BIN).new
	mv $(FABRIC_BIN).new $(FABRIC_BIN)

# Set up (or refresh) the unprivileged per-user service and start it.  Use the
# system-service installer directly when this is a dedicated machine with TUN.
install-user: install
	./scripts/install-systemd.sh -U -b $(FABRIC_BIN)

restart-user: install
	systemctl --user restart fabric.service

status-user:
	systemctl --user --no-pager --full status fabric.service

logs-user:
	journalctl --user -u fabric.service -f

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

deploy: fabric
	@test -n "$(strip $(HOSTS))" || { \
		echo 'Usage: make deploy HOSTS="host1 [host2 ...]"'; \
		exit 2; \
	}
	./fabric deploy $(HOSTS)

clean:
	rm -f fabric

help:
	@echo "Available targets:"
	@echo "  build      Build fabric (default)"
	@echo "  fabric     Build the fabric binary"
	@echo "  install    Build and install to $(FABRIC_BIN)"
	@echo "  install-user  Install and start/refresh the user service"
	@echo "  restart-user  Install the new binary and restart the user service"
	@echo "  status-user   Show user-service status"
	@echo "  logs-user     Follow user-service logs"
	@echo "  test       Run all tests"
	@echo "  test-race  Run all tests with the race detector"
	@echo "  fmt        Format all Go packages"
	@echo "  fmt-check  Check formatting without changing files"
	@echo "  vet        Run go vet"
	@echo "  check      Run vet and test checks"
	@echo '  deploy     Run fabric deploy with HOSTS="host1 [host2 ...]"'
	@echo "  clean      Remove built binaries"
