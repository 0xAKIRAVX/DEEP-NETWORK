# DEEP NETWORK — developer workflow targets.
#
# The panel is a single static Go binary; these targets wrap the commands the
# maintainers actually run so they are discoverable and typo-proof:
#
#   make build     compile the panel binary to ./out
#   make test      run the full unit test suite
#   make race      run the suite under the race detector
#   make vet       static analysis (go vet)
#   make fmt       gofmt every Go file in place
#   make check      fmt + vet + test — the pre-push gate
#   make probe     build the Rust prober (rust-probe/)
#   make family    compile the C /16 family tool (tools/c/)
#   make docker    build the container image locally
#   make clean     remove build artifacts

GO      ?= go
BINARY  ?= out
IMAGE   ?= ghcr.io/0xakiravx/deep-network:dev

.PHONY: build test race vet fmt check probe family docker clean help

build:
	$(GO) build -trimpath -ldflags="-s -w" -o $(BINARY) .

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w *.go

check: fmt vet test
	@echo "all checks passed"

probe:
	cargo build --release --manifest-path rust-probe/Cargo.toml

family:
	cc -O2 -Wall -Wextra -o /tmp/familycheck tools/c/familycheck.c
	/tmp/familycheck --test

docker:
	docker build -t $(IMAGE) .

clean:
	rm -f $(BINARY)
	rm -rf rust-probe/target
	rm -f /tmp/familycheck

help:
	@sed -n '2,20p' Makefile | sed 's/^# \{0,1\}//'
