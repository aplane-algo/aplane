.PHONY: all clean apshell apsigner apadmin apconsole apapprover apstore appolicy appass aplocalnet appass-file appass-systemd-creds approbe applugin-checksum applugin-checksums help compile-teal compile-docassets test check formal-test race-test unit-test contract-test integration-test integration-test-testnet integration-test-localnet integration-test-reuse integration-test-cleanup soak-test-localnet apshell-command-coverage-localnet bundled-plugins bundled-plugins-linux bundled-plugins-darwin example-plugins examples-plugins install-example-plugins check-example-plugins build-bundled-plugins build-example-plugins docker-systemd-test docker-local-test apshell-arm64 apsigner-arm64 apadmin-arm64 apconsole-arm64 apstore-arm64 appolicy-arm64 apapprover-arm64 appass-arm64 aplocalnet-arm64 appass-file-arm64 appass-systemd-creds-arm64 approbe-arm64 applugin-checksum-arm64 bin-arm64 bin-amd64 bin-darwin-amd64 bin-darwin-arm64 security-analysis analyze-keyzero analyze-keylog analyze-seedphrase config-docs release-local fmt-check vet mod-tidy-check deadcode-check smoke-test integrity-check lint

# Default target when running just "make"
.DEFAULT_GOAL := all

# Version information (injected into binaries at build time)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Version ldflags (injected into all binaries)
VERSION_PKG = github.com/aplane-algo/aplane/internal/version
VERSION_LDFLAGS = -X $(VERSION_PKG).Version=$(VERSION) -X $(VERSION_PKG).GitCommit=$(GIT_COMMIT) -X $(VERSION_PKG).BuildTime=$(BUILD_TIME)
TLA_SPECS = sign_boundary policy_precedence composition lifecycle

# OS-specific build configuration
# Linux: use musl-gcc for static linking (secure, portable)
# macOS: dynamic linking only (Apple doesn't support static binaries)
ifeq ($(shell uname),Darwin)
    CC_CMD =
    LD_FLAGS = -ldflags '$(VERSION_LDFLAGS)'
    STATIC_NOTE = (dynamically linked - macOS limitation)
else
    CC_CMD = CC=musl-gcc
    LD_FLAGS = -ldflags '$(VERSION_LDFLAGS) -linkmode external -extldflags "-static"'
    STATIC_NOTE = (statically linked with musl)
endif

# Compile TEAL programs and copy to embedded locations
# Only compiles if source is newer than target or if goal is available
compile-teal: resources/dummy.teal.tok internal/signing/dummy.teal.tok internal/lsig/dummy.teal.tok

GENERATED_JSAPI = internal/docassets/generated/USER_JSAPI.md

compile-docassets: $(GENERATED_JSAPI)

$(GENERATED_JSAPI): docs/USER_JSAPI.md
	@echo "Updating $(GENERATED_JSAPI)..."
	@mkdir -p $(dir $(GENERATED_JSAPI))
	@cp docs/USER_JSAPI.md $(GENERATED_JSAPI)
	@echo "✓ Updated $(GENERATED_JSAPI)"

resources/dummy.teal.tok: resources/dummy.teal
	@echo "Compiling resources/dummy.teal..."
	@if ! command -v goal >/dev/null 2>&1; then \
		echo "Error: 'goal' command not found. Please install Algorand node tools."; \
		echo "Note: Pre-compiled .tok files are in git - run 'git restore resources/dummy.teal.tok'"; \
		exit 1; \
	fi
	@goal clerk compile resources/dummy.teal -o resources/dummy.teal.tok
	@echo "✓ Compiled resources/dummy.teal"

internal/signing/dummy.teal.tok: resources/dummy.teal.tok
	@echo "Updating internal/signing/dummy.teal.tok..."
	@cp resources/dummy.teal.tok internal/signing/dummy.teal.tok
	@echo "✓ Updated internal/signing/dummy.teal.tok"

internal/lsig/dummy.teal.tok: resources/dummy.teal.tok
	@echo "Updating internal/lsig/dummy.teal.tok..."
	@cp resources/dummy.teal.tok internal/lsig/dummy.teal.tok
	@echo "✓ Updated internal/lsig/dummy.teal.tok"

# Default: Build all first-party binaries and official bundled plugins.
all: compile-teal apshell apsigner apadmin apconsole apapprover apstore appolicy appass aplocalnet appass-file appass-systemd-creds approbe bundled-plugins

# Build apshell
apshell: compile-teal compile-docassets
	CGO_ENABLED=1 $(CC_CMD) go build $(LD_FLAGS) -o bin/apshell ./cmd/apshell

apsigner: compile-teal
	CGO_ENABLED=1 $(CC_CMD) go build $(LD_FLAGS) -o bin/apsigner ./cmd/apsigner

apadmin: compile-teal
	CGO_ENABLED=1 $(CC_CMD) go build $(LD_FLAGS) -o bin/apadmin ./cmd/apadmin

apconsole: compile-teal compile-docassets
	CGO_ENABLED=1 $(CC_CMD) go build $(LD_FLAGS) -o bin/apconsole ./cmd/apconsole

apapprover:
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/apapprover ./cmd/apapprover

apstore: compile-teal
	CGO_ENABLED=1 $(CC_CMD) go build $(LD_FLAGS) -o bin/apstore ./cmd/apstore

appolicy:
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/appolicy ./cmd/appolicy

# appass-file is a dev-only plaintext file passphrase helper (pure Go)
appass-file:
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/appass-file ./cmd/appass-file
	@chmod 700 bin/appass-file

# appass-systemd-creds encrypts passphrase via systemd-creds (TPM2/host key, Linux only, pure Go)
appass-systemd-creds:
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/appass-systemd-creds ./cmd/appass-systemd-creds
	@chmod 700 bin/appass-systemd-creds

# appass manages passphrase auto-unlock configuration (pure Go)
appass:
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/appass ./cmd/appass

# aplocalnet configures local AlgoKit LocalNet support (pure Go)
aplocalnet:
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/aplocalnet ./cmd/aplocalnet

# approbe is an installer-facing liveness probe (pure Go)
approbe:
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/approbe ./cmd/approbe

# applugin-checksum doesn't need CGO (pure Go crypto)
applugin-checksum:
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/applugin-checksum ./cmd/applugin-checksum

# ARM64 cross-compilation targets
# Uses Zig for musl-based static linking (install: https://ziglang.org/download/)
# Override with: make bin-arm64 ARM64_CC=aarch64-linux-musl-gcc
ARM64_CC ?= zig cc -target aarch64-linux-musl
ARM64_LD_FLAGS = -ldflags '$(VERSION_LDFLAGS) -linkmode external -extldflags "-static"'

apshell-arm64: compile-teal compile-docassets
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC="$(ARM64_CC)" go build $(ARM64_LD_FLAGS) -o apshell-arm64 ./cmd/apshell

apsigner-arm64: compile-teal
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC="$(ARM64_CC)" go build $(ARM64_LD_FLAGS) -o apsigner-arm64 ./cmd/apsigner

apadmin-arm64: compile-teal
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC="$(ARM64_CC)" go build $(ARM64_LD_FLAGS) -o apadmin-arm64 ./cmd/apadmin

apconsole-arm64: compile-teal compile-docassets
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC="$(ARM64_CC)" go build $(ARM64_LD_FLAGS) -o apconsole-arm64 ./cmd/apconsole

apstore-arm64: compile-teal
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC="$(ARM64_CC)" go build $(ARM64_LD_FLAGS) -o apstore-arm64 ./cmd/apstore

# apapprover, aplocalnet, approbe, and applugin-checksum are pure Go, so cross-compilation is simple
appolicy-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '$(VERSION_LDFLAGS)' -o appolicy-arm64 ./cmd/appolicy

apapprover-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '$(VERSION_LDFLAGS)' -o apapprover-arm64 ./cmd/apapprover

appass-file-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '$(VERSION_LDFLAGS)' -o appass-file-arm64 ./cmd/appass-file
	@chmod 700 appass-file-arm64

appass-systemd-creds-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '$(VERSION_LDFLAGS)' -o appass-systemd-creds-arm64 ./cmd/appass-systemd-creds
	@chmod 700 appass-systemd-creds-arm64

appass-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '$(VERSION_LDFLAGS)' -o appass-arm64 ./cmd/appass

aplocalnet-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '$(VERSION_LDFLAGS)' -o aplocalnet-arm64 ./cmd/aplocalnet

approbe-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '$(VERSION_LDFLAGS)' -o approbe-arm64 ./cmd/approbe

applugin-checksum-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '$(VERSION_LDFLAGS)' -o applugin-checksum-arm64 ./cmd/applugin-checksum

# Build all binaries for arm64 into bin/arm64/
bin-arm64: apshell-arm64 apsigner-arm64 apadmin-arm64 apconsole-arm64 apstore-arm64 appolicy-arm64 apapprover-arm64 appass-arm64 aplocalnet-arm64 appass-file-arm64 appass-systemd-creds-arm64 approbe-arm64 applugin-checksum-arm64
	@mkdir -p bin/arm64
	@mv apshell-arm64 bin/arm64/apshell
	@mv apsigner-arm64 bin/arm64/apsigner
	@mv apadmin-arm64 bin/arm64/apadmin
	@mv apconsole-arm64 bin/arm64/apconsole
	@mv apstore-arm64 bin/arm64/apstore
	@mv appolicy-arm64 bin/arm64/appolicy
	@mv apapprover-arm64 bin/arm64/apapprover
	@mv appass-arm64 bin/arm64/appass
	@mv aplocalnet-arm64 bin/arm64/aplocalnet
	@mv appass-file-arm64 bin/arm64/appass-file
	@chmod 700 bin/arm64/appass-file
	@mv appass-systemd-creds-arm64 bin/arm64/appass-systemd-creds
	@chmod 700 bin/arm64/appass-systemd-creds
	@mv approbe-arm64 bin/arm64/approbe
	@mv applugin-checksum-arm64 bin/arm64/applugin-checksum
	@echo "✓ Built arm64 binaries in bin/arm64/"

# Build all binaries for amd64 into bin/amd64/
bin-amd64: compile-teal compile-docassets
	@mkdir -p bin/amd64
	CGO_ENABLED=1 $(CC_CMD) go build $(LD_FLAGS) -o bin/amd64/apshell ./cmd/apshell
	CGO_ENABLED=1 $(CC_CMD) go build $(LD_FLAGS) -o bin/amd64/apsigner ./cmd/apsigner
	CGO_ENABLED=1 $(CC_CMD) go build $(LD_FLAGS) -o bin/amd64/apadmin ./cmd/apadmin
	CGO_ENABLED=1 $(CC_CMD) go build $(LD_FLAGS) -o bin/amd64/apconsole ./cmd/apconsole
	CGO_ENABLED=1 $(CC_CMD) go build $(LD_FLAGS) -o bin/amd64/apstore ./cmd/apstore
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/amd64/appolicy ./cmd/appolicy
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/amd64/apapprover ./cmd/apapprover
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/amd64/appass-file ./cmd/appass-file
	@chmod 700 bin/amd64/appass-file
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/amd64/appass-systemd-creds ./cmd/appass-systemd-creds
	@chmod 700 bin/amd64/appass-systemd-creds
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/amd64/appass ./cmd/appass
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/amd64/aplocalnet ./cmd/aplocalnet
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/amd64/approbe ./cmd/approbe
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/amd64/applugin-checksum ./cmd/applugin-checksum
	@echo "✓ Built amd64 binaries in bin/amd64/"

# macOS build targets (dynamically linked — Apple doesn't support static binaries)
DARWIN_LD_FLAGS = -ldflags '$(VERSION_LDFLAGS)'

# Build all binaries for darwin/arm64 (Apple Silicon) into bin/darwin-arm64/
bin-darwin-arm64: compile-teal compile-docassets
	@mkdir -p bin/darwin-arm64
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-arm64/apshell ./cmd/apshell
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-arm64/apsigner ./cmd/apsigner
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-arm64/apadmin ./cmd/apadmin
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-arm64/apconsole ./cmd/apconsole
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-arm64/apstore ./cmd/apstore
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-arm64/appolicy ./cmd/appolicy
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-arm64/apapprover ./cmd/apapprover
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-arm64/appass-file ./cmd/appass-file
	@chmod 700 bin/darwin-arm64/appass-file
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-arm64/appass ./cmd/appass
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-arm64/aplocalnet ./cmd/aplocalnet
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-arm64/approbe ./cmd/approbe
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-arm64/applugin-checksum ./cmd/applugin-checksum
	@if command -v codesign >/dev/null 2>&1; then \
		for bin in bin/darwin-arm64/*; do \
			codesign --force --sign - "$$bin" >/dev/null; \
		done; \
	fi
	@echo "✓ Built darwin/arm64 binaries in bin/darwin-arm64/"

# Build all binaries for darwin/amd64 (Intel Mac) into bin/darwin-amd64/
bin-darwin-amd64: compile-teal compile-docassets
	@mkdir -p bin/darwin-amd64
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-amd64/apshell ./cmd/apshell
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-amd64/apsigner ./cmd/apsigner
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-amd64/apadmin ./cmd/apadmin
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-amd64/apconsole ./cmd/apconsole
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-amd64/apstore ./cmd/apstore
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-amd64/appolicy ./cmd/appolicy
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-amd64/apapprover ./cmd/apapprover
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-amd64/appass-file ./cmd/appass-file
	@chmod 700 bin/darwin-amd64/appass-file
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-amd64/appass ./cmd/appass
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-amd64/aplocalnet ./cmd/aplocalnet
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-amd64/approbe ./cmd/approbe
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-amd64/applugin-checksum ./cmd/applugin-checksum
	@if command -v codesign >/dev/null 2>&1; then \
		for bin in bin/darwin-amd64/*; do \
			codesign --force --sign - "$$bin" >/dev/null; \
		done; \
	fi
	@echo "✓ Built darwin/amd64 binaries in bin/darwin-amd64/"

clean:
	find bin -mindepth 1 ! -name '.gitkeep' -delete 2>/dev/null || true
	rm -rf internal/docassets/generated
	rm -f apshell apsigner apadmin apconsole apapprover apstore appolicy appass aplocalnet appass-file appass-systemd-creds approbe migrate-config-v1 applugin-checksum
	rm -f apshell-arm64 apsigner-arm64 apadmin-arm64 apconsole-arm64 apapprover-arm64 apstore-arm64 appolicy-arm64 appass-arm64 aplocalnet-arm64 appass-file-arm64 appass-systemd-creds-arm64 approbe-arm64 migrate-config-v1-arm64 applugin-checksum-arm64

# Local release dry-run (builds archives without publishing)
# On macOS: also builds darwin archives. On Linux: linux only.
# Linux tarballs include installer/, installer/scripts/, install.sh, and uninstall.sh.
release-local: bin-amd64 bin-arm64 bundled-plugins-linux
	@mkdir -p dist
	@RAW_VERSION=$$(git describe --tags --always --dirty 2>/dev/null || echo dev); \
	VERSION=$$(printf '%s' "$$RAW_VERSION" | sed 's/^v//'); \
	GIT_COMMIT=$$(git rev-parse --short HEAD 2>/dev/null || echo unknown); \
	BUILT_AT=$$(date -u '+%Y-%m-%dT%H:%M:%SZ'); \
	write_release_metadata() { \
		root="$$1"; \
		printf '{\n  "schema_version": 1,\n  "version": "%s",\n  "commit": "%s",\n  "built_at": "%s"\n}\n' "$$RAW_VERSION" "$$GIT_COMMIT" "$$BUILT_AT" > "$$root/release.json"; \
	}; \
	for arch in amd64 arm64; do \
		archive="aplane_$${VERSION}_linux_$${arch}.tar.gz"; \
		rm -rf dist/staging; \
		mkdir -p dist/staging/aplane/bin dist/staging/aplane/installer/scripts dist/staging/aplane/library/templates dist/staging/aplane/plugins.available; \
		cp bin/$${arch}/apshell bin/$${arch}/apsigner bin/$${arch}/apadmin \
		   bin/$${arch}/apconsole \
		   bin/$${arch}/apapprover bin/$${arch}/apstore bin/$${arch}/appolicy bin/$${arch}/appass \
		   bin/$${arch}/aplocalnet \
		   bin/$${arch}/appass-file \
		   bin/$${arch}/appass-systemd-creds \
		   bin/$${arch}/approbe \
		   bin/$${arch}/applugin-checksum dist/staging/aplane/bin/; \
		cp installer/apsigner.service installer/apsigner.service.template \
		   installer/sudoers.template \
		   dist/staging/aplane/installer/; \
		cp installer/scripts/systemd-setup.sh installer/scripts/aplane-env-audit.sh installer/scripts/config-mcp.sh dist/staging/aplane/installer/scripts/; \
		cp library/templates/README.md library/templates/*.yaml dist/staging/aplane/library/templates/; \
		scripts/stage-bundled-plugins.sh --os linux --arch $${arch} dist/staging/aplane/plugins.available; \
		cp install.sh uninstall.sh dist/staging/aplane/; \
		write_release_metadata dist/staging/aplane; \
		tar -czf "dist/$${archive}" -C dist/staging aplane; \
		echo "✓ Created dist/$${archive}"; \
	done; \
	rm -rf dist/staging; \
	for darwindir in bin/darwin-*/; do \
		[ -d "$$darwindir" ] || continue; \
		darwinarch=$$(basename "$$darwindir" | sed 's/darwin-//'); \
		archive="aplane_$${VERSION}_darwin_$${darwinarch}.tar.gz"; \
		rm -rf dist/staging; \
		mkdir -p dist/staging/aplane/bin dist/staging/aplane/installer/scripts dist/staging/aplane/library/templates dist/staging/aplane/plugins.available; \
		cp $${darwindir}apshell $${darwindir}apsigner $${darwindir}apadmin \
		   $${darwindir}apconsole \
		   $${darwindir}apapprover $${darwindir}apstore $${darwindir}appolicy $${darwindir}appass \
		   $${darwindir}aplocalnet \
		   $${darwindir}appass-file \
		   $${darwindir}approbe \
		   $${darwindir}applugin-checksum dist/staging/aplane/bin/; \
		cp installer/scripts/aplane-env-audit.sh installer/scripts/config-mcp.sh dist/staging/aplane/installer/scripts/; \
		cp library/templates/README.md library/templates/*.yaml dist/staging/aplane/library/templates/; \
		scripts/stage-bundled-plugins.sh --os darwin --arch $${darwinarch} dist/staging/aplane/plugins.available; \
		cp install.sh uninstall.sh dist/staging/aplane/; \
		write_release_metadata dist/staging/aplane; \
		tar -czf "dist/$${archive}" -C dist/staging aplane; \
		echo "✓ Created dist/$${archive}"; \
	done; \
	rm -rf dist/staging; \
	cd dist && sha256sum *.tar.gz > checksums.txt && cd ..; \
	echo "✓ Generated dist/checksums.txt"; \
	cat dist/checksums.txt

test: compile-docassets
	go test $$(go list ./... | grep -v '/test/integration' | grep -v '/node_modules/' | grep -v '^github.com/aplane-algo/aplane/temp/')

check: test contract-test

formal-test:
	@set -e; \
	jar="$(TLA2TOOLS_JAR)"; \
	if [ -z "$$jar" ]; then \
		for candidate in .tools/tla2tools.jar tla2tools.jar "$$HOME/tla/tla2tools.jar"; do \
			if [ -f "$$candidate" ]; then jar="$$candidate"; break; fi; \
		done; \
	fi; \
	if [ -z "$$jar" ] || [ ! -f "$$jar" ]; then \
		echo "Error: tla2tools.jar not found. Set TLA2TOOLS_JAR=/path/to/tla2tools.jar."; \
		exit 1; \
	fi; \
	for spec in $(TLA_SPECS); do \
		echo "Running TLC for $$spec"; \
		java -cp "$$jar" tlc2.TLC \
			-cleanup \
			-config "docs/formal/$$spec.cfg" \
			"docs/formal/$$spec.tla"; \
	done

# ---- Integrity check building blocks ----

# Fail if any Go file is not gofmt-clean.
fmt-check:
	@echo "Checking gofmt..."
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "✗ Unformatted files:"; \
		echo "$$unformatted"; \
		echo ""; \
		echo "Run 'gofmt -s -w .' to fix"; \
		exit 1; \
	fi
	@echo "✓ gofmt clean"

# Run go vet across the module.
vet: compile-docassets
	@echo "Running go vet..."
	@go vet ./...
	@echo "✓ go vet clean"

# Fail if go.mod / go.sum are not tidy.
mod-tidy-check:
	@echo "Checking go.mod / go.sum are tidy..."
	@diff=$$(go mod tidy -diff 2>&1); \
	if [ -n "$$diff" ]; then \
		echo "✗ go mod tidy would change files:"; \
		echo "$$diff"; \
		exit 1; \
	fi
	@echo "✓ go.mod / go.sum are tidy"

# Whole-program dead code analysis. The SSH admin client under internal/transport/ssh.go
# is live only under the testmode build tag, so the check uses -tags=testmode to avoid
# false positives. Fails on any non-empty output.
#
# We install deadcode to a temp GOBIN rather than 'go run' so its module cache
# side-effects don't pollute this module's go.mod/go.sum and so download noise
# doesn't get captured as analysis output.
deadcode-check: compile-docassets
	@echo "Running deadcode analysis..."
	@tmpbin=$$(mktemp -d); \
	GOBIN=$$tmpbin go install golang.org/x/tools/cmd/deadcode@latest >/dev/null 2>&1 || { \
		echo "✗ failed to install deadcode tool"; rm -rf $$tmpbin; exit 1; \
	}; \
	out=$$($$tmpbin/deadcode -test -tags=testmode ./... 2>&1); \
	rc=$$?; \
	rm -rf $$tmpbin; \
	if [ $$rc -ne 0 ]; then \
		echo "✗ deadcode tool failed:"; echo "$$out"; exit 1; \
	fi; \
	if [ -n "$$out" ]; then \
		echo "✗ Dead code detected:"; \
		echo "$$out"; \
		exit 1; \
	fi
	@echo "✓ no dead code"

# End-to-end Systemd install test. Builds a release tarball, boots a
# fresh Ubuntu 24.04 systemd container, runs install.sh --systemd, verifies
# the systemd layout and appass systemd-mode detection, runs the bundled
# uninstaller, and verifies signer data is preserved. Requires docker.
# Pass extra flags to the underlying script via ARGS, e.g.
#   make docker-systemd-test ARGS="--keep-container --skip-build"
docker-systemd-test:
	@./scripts/docker-systemd-smoke.sh $(ARGS)

# End-to-end local install test. Builds a release tarball, boots signer, sentry,
# client/admin, and LocalNet algod containers on one Docker network, then
# verifies SSH token provisioning, shared LocalNet reachability, and client
# signer reachability across the Docker network.
# Requires docker. Pass extra flags via ARGS.
docker-local-test:
	@./scripts/docker-local-four-node-smoke.sh $(ARGS)

# Smoke test: exercise init paths of each built binary. Binaries that support
# --version get it; the rest get invoked in a way that prints a usage error
# after init (we just care they start without a panic / link failure).
# Requires bin-amd64 to have been built first.
smoke-test:
	@echo "Smoke-testing built binaries..."
	@for b in apshell apsigner apadmin apconsole apstore appolicy appass aplocalnet approbe; do \
		if [ ! -x bin/amd64/$$b ]; then \
			echo "✗ bin/amd64/$$b missing (run 'make bin-amd64' first)"; exit 1; \
		fi; \
		out=$$(./bin/amd64/$$b --version 2>&1) || { \
			echo "✗ $$b --version failed: $$out"; exit 1; \
		}; \
		echo "  $$out"; \
	done
	@for b in apapprover appass-file appass-systemd-creds applugin-checksum; do \
		if [ ! -x bin/amd64/$$b ]; then \
			echo "✗ bin/amd64/$$b missing (run 'make bin-amd64' first)"; exit 1; \
		fi; \
		./bin/amd64/$$b >/dev/null 2>&1; \
		rc=$$?; \
		if [ $$rc -ge 128 ]; then \
			echo "✗ $$b crashed on startup (exit=$$rc)"; exit 1; \
		fi; \
		echo "  $$b starts (exit=$$rc on bare invocation)"; \
	done
	@echo "✓ all binaries start cleanly"

# Full system integrity check. Runs every static, dynamic, and build-time
# gate. Stops at the first failure. Expect ~30 minutes on a fresh tree.
#
# Order is chosen so cheap/fast checks fail before slow ones:
#   1. static       : gofmt, vet, mod tidy, lint, deadcode
#   2. security     : keyzero, keylog, insecurerand, seedphrase analyzers
#   3. correctness  : race-enabled unit tests
#   4. cross-build  : Linux amd64 + arm64
#   5. smoke        : --version on every built binary
#   6. signer API   : contract tests
#   7. end-to-end   : integration tests (requires .env.test fixture)
#   8. tree clean   : no generated files drifted during the run
integrity-check:
	@echo "==> [1/8] Static analysis"
	@$(MAKE) fmt-check
	@$(MAKE) vet
	@$(MAKE) mod-tidy-check
	@$(MAKE) lint
	@$(MAKE) deadcode-check
	@echo ""
	@echo "==> [2/8] Security analyzers"
	@$(MAKE) security-analysis
	@echo ""
	@echo "==> [3/8] Race-enabled unit tests"
	@$(MAKE) race-test
	@echo ""
	@echo "==> [4/8] Cross-compile (linux/amd64, linux/arm64)"
	@$(MAKE) bin-amd64
	@$(MAKE) bin-arm64
	@echo ""
	@echo "==> [5/8] Binary smoke test"
	@$(MAKE) smoke-test
	@echo ""
	@echo "==> [6/8] Signer API contract tests"
	@$(MAKE) contract-test
	@echo ""
	@echo "==> [7/8] Integration tests"
	@$(MAKE) integration-test
	@echo ""
	@echo "==> [8/8] Working tree clean?"
	@if ! git diff --quiet HEAD --; then \
		echo "✗ Working tree changed during integrity-check:"; \
		git diff --stat HEAD --; \
		exit 1; \
	fi
	@echo "✓ working tree unchanged"
	@echo ""
	@echo "==================================================="
	@echo "✓ integrity-check PASSED"
	@echo "==================================================="

# Run linter
lint: compile-docassets
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Error: golangci-lint not found. Install from: https://golangci-lint.run/usage/install/"; \
		exit 1; \
	fi
	@echo "Running golangci-lint..."
	golangci-lint run

# Run tests with race detector (slower but catches data races)
race-test: compile-docassets
	@echo "Running tests with race detector..."
	CGO_ENABLED=1 go test -race ./...

# Run unit tests (all tests except those in test/integration/ and root package)
unit-test: compile-docassets
	@echo "Running unit tests..."
	@go test $$(go list ./... | grep -v '/test/integration' | grep -v '/node_modules/' | grep -v '^github.com/aplane-algo/aplane/temp/' | grep -v '^apshell$$')

contract-test:
	@echo "Running signer API contract tests..."
	@echo "== Go signer API =="
	go test -v -run 'TestSignerAPIContract(FixturesRoundTrip|FixtureManifest)' ./pkg/signerapi

# Integration test package and go test flags. Override for focused runs, e.g.:
#   APLANE_INTEGRATION_NETWORK=localnet make integration-test INTEGRATION_GO_ARGS='-count=1 -timeout 25m -v -run TestName'
INTEGRATION_TEST_PKG ?= ./test/integration
INTEGRATION_GO_ARGS ?= -count=1 -timeout 25m
SOAK_TEST_PKG ?= ./test/soak
SOAK_GO_ARGS ?= -count=1 -timeout 2h
COMMAND_COVERAGE_GO_ARGS ?= -count=1 -timeout 15m
APLANE_SOAK_DURATION ?= 30m
APLANE_SOAK_MAX_ITERATIONS ?= 0
APLANE_SOAK_RESTART_EVERY ?= 0
APLANE_SOAK_FALCON_EVERY ?= 5

# Run integration tests (tests in test/integration/)
# Always regenerates the shared fixture and .env.test first to avoid stale
# /tmp/aplane-test-env state or mismatched passphrases.
# Requires APLANE_INTEGRATION_NETWORK=testnet or localnet.
integration-test:
	@echo "Running integration tests..."
	@./test/setup-test-env.sh
	@echo "Loading environment from regenerated .env.test"
	@set -a && . ./.env.test && set +a && INTEGRATION=1 go test $(INTEGRATION_GO_ARGS) $(INTEGRATION_TEST_PKG)
	@./test/run-sdk-integration.sh

integration-test-testnet:
	@APLANE_INTEGRATION_NETWORK=testnet $(MAKE) integration-test

integration-test-localnet:
	@APLANE_INTEGRATION_NETWORK=localnet $(MAKE) integration-test

soak-test-localnet:
	@echo "Running LocalNet soak test..."
	@APLANE_INTEGRATION_NETWORK=localnet ./test/setup-test-env.sh
	@echo "Loading environment from regenerated .env.test"
	@set -a && . ./.env.test && set +a && APLANE_INTEGRATION_NETWORK=localnet APLANE_SOAK=1 APLANE_SOAK_DURATION=$(APLANE_SOAK_DURATION) APLANE_SOAK_MAX_ITERATIONS=$(APLANE_SOAK_MAX_ITERATIONS) APLANE_SOAK_RESTART_EVERY=$(APLANE_SOAK_RESTART_EVERY) APLANE_SOAK_FALCON_EVERY=$(APLANE_SOAK_FALCON_EVERY) INTEGRATION=1 go test $(SOAK_GO_ARGS) $(SOAK_TEST_PKG)

apshell-command-coverage-localnet:
	@echo "Running LocalNet apshell command coverage..."
	@APLANE_INTEGRATION_NETWORK=localnet ./test/setup-test-env.sh
	@echo "Loading environment from regenerated .env.test"
	@set -a && . ./.env.test && set +a && APLANE_INTEGRATION_NETWORK=localnet APLANE_COMMAND_COVERAGE=1 INTEGRATION=1 go test $(COMMAND_COVERAGE_GO_ARGS) $(SOAK_TEST_PKG)

# Run integration tests using the existing .env.test and /tmp fixture as-is.
# This is faster, but can fail if the shared test environment is stale.
integration-test-reuse:
	@echo "Running integration tests with existing fixture..."
	@if [ -f .env.test ]; then \
		echo "Loading environment from .env.test"; \
		set -a && . ./.env.test && set +a && INTEGRATION=1 go test $(INTEGRATION_GO_ARGS) $(INTEGRATION_TEST_PKG); \
		./test/run-sdk-integration.sh; \
	else \
		echo "Note: Create .env.test with TEST_FUNDING_MNEMONIC, TEST_PASSPHRASE, DISABLE_MEMORY_LOCK"; \
		echo "Example: echo 'TEST_FUNDING_MNEMONIC=\"your 25 words\"' > .env.test"; \
		INTEGRATION=1 go test $(INTEGRATION_GO_ARGS) $(INTEGRATION_TEST_PKG); \
	fi

# Delete leaked test apps from previous integration runs that failed cleanup.
# Targets apps matching the test fixture schema (2 global uint, 2 global bytes,
# 2 local uint, 0 local bytes) and skips everything else.
integration-test-cleanup:
	@echo "Cleaning up leaked test apps..."
	@if [ -f .env.test ]; then \
		set -a && . ./.env.test && set +a && CLEANUP=1 go test -count=1 -run TestCleanupLeakedApps -timeout 10m ./test/integration; \
	else \
		echo "Error: .env.test not found (need TEST_FUNDING_MNEMONIC)"; \
		exit 1; \
	fi

# Official Bundled Plugins (plugins/)
bundled-plugins: build-bundled-plugins

# Build target-specific bundled plugin payloads for Linux release archives.
bundled-plugins-linux:
	@mkdir -p dist/bundled-plugins
	@scripts/build-algokit-localnet-plugin-target.sh --os linux --arch amd64 --out-dir dist/bundled-plugins/linux-amd64/algokit-localnet
	@scripts/build-algokit-localnet-plugin-target.sh --os linux --arch arm64 --out-dir dist/bundled-plugins/linux-arm64/algokit-localnet

# Build target-specific bundled plugin payloads for macOS release archives.
bundled-plugins-darwin:
	@mkdir -p dist/bundled-plugins
	@scripts/build-algokit-localnet-plugin-target.sh --os darwin --arch amd64 --out-dir dist/bundled-plugins/darwin-amd64/algokit-localnet
	@scripts/build-algokit-localnet-plugin-target.sh --os darwin --arch arm64 --out-dir dist/bundled-plugins/darwin-arm64/algokit-localnet

# Example External Plugins (examples/external_plugins/)
# These are examples, not required for the standard build, but should stay in sync

# Dev workflow: build every example plugin and install it into
# $APCLIENT_DATA/plugins.available/, enabling all of them in plugins.yaml.
# Destructive on plugins.available/ and plugins.yaml — intended for dev client
# data directories only. APCLIENT_DATA defaults to $HOME/aplane/apclient.
example-plugins:
	@scripts/install-example-plugins.sh

# Alias for the common plural spelling.
examples-plugins: example-plugins

# Check if any TypeScript example plugins have stale dist files or standalone binaries.
check-example-plugins:
	@stale=0; \
	for plugin_dir in examples/external_plugins/*/; do \
		if [ -f "$$plugin_dir/tsconfig.json" ]; then \
			plugin_name=$$(basename $$plugin_dir); \
			src_ts=$$(find "$$plugin_dir/src" -maxdepth 1 -name '*-plugin.ts' | head -n 1); \
			dist_js=$$(find "$$plugin_dir/dist" -maxdepth 1 -name '*-plugin.js' | head -n 1); \
			if [ -f "$$src_ts" ] && [ -f "$$dist_js" ]; then \
				if [ "$$src_ts" -nt "$$dist_js" ]; then \
					echo "⚠ Stale: $$plugin_name (src newer than dist)"; \
					stale=1; \
				fi; \
			elif [ -f "$$src_ts" ] && [ ! -f "$$dist_js" ]; then \
				echo "⚠ Missing: $$plugin_name dist not built"; \
				stale=1; \
			fi; \
			if grep -q '"build:standalone"' "$$plugin_dir/package.json"; then \
				plugin_bin="$$plugin_dir$$plugin_name"; \
				if [ ! -f "$$plugin_bin" ]; then \
					echo "⚠ Missing: $$plugin_name standalone binary"; \
					stale=1; \
				else \
					newer=$$(find "$$plugin_dir/src" "$$plugin_dir/scripts" "$$plugin_dir/package.json" "$$plugin_dir/package-lock.json" -type f -newer "$$plugin_bin" -print -quit 2>/dev/null); \
					if [ -n "$$newer" ]; then \
						echo "⚠ Stale: $$plugin_name standalone binary"; \
						stale=1; \
					fi; \
				fi; \
			fi; \
		fi; \
	done; \
	if [ $$stale -eq 0 ]; then \
		echo "✓ All example plugins up to date"; \
	else \
		echo ""; \
		echo "Run 'make build-example-plugins' to rebuild stale plugins"; \
		exit 1; \
	fi

# Build bundled plugin payloads and refresh their checksums.
build-bundled-plugins: applugin-checksum
	@for plugin_dir in plugins/*/; do \
		[ -d "$$plugin_dir" ] || continue; \
		plugin_name=$$(basename "$$plugin_dir"); \
		echo "Building bundled $$plugin_name..."; \
		if [ -f "$$plugin_dir/Makefile" ]; then \
			$(MAKE) -C "$$plugin_dir" build || exit 1; \
		elif [ -f "$$plugin_dir/go.mod" ]; then \
			(cd "$$plugin_dir" && CGO_ENABLED=0 go build -o "$$plugin_name" .) || exit 1; \
		else \
			echo "Error: no build recipe found for bundled plugin $$plugin_name"; \
			exit 1; \
		fi; \
		echo "✓ Built bundled $$plugin_name"; \
	done
	@echo "Refreshing bundled plugin checksums..."
	@for plugin_dir in plugins/*/; do \
		if [ -f "$$plugin_dir/manifest.json" ]; then \
			bin/applugin-checksum "$$plugin_dir" || exit 1; \
		fi; \
	done

# Build all example plugins and refresh their checksums.
build-example-plugins:
	@for plugin_dir in examples/external_plugins/*/; do \
		if [ -f "$$plugin_dir/tsconfig.json" ]; then \
			plugin_name=$$(basename $$plugin_dir); \
			if ! command -v npm >/dev/null 2>&1; then \
				echo "Skipping $$plugin_name: npm is not installed. Install Node.js/npm to build this npm-based example plugin."; \
				continue; \
			fi; \
			if [ ! -d "$$plugin_dir/node_modules" ]; then \
				echo "$$plugin_name needs npm packages installed into $$plugin_dir/node_modules before it can be built."; \
				printf "Install them locally now? [y/N] "; \
				read -r answer || answer=; \
				case "$$answer" in \
					[Yy]|[Yy][Ee][Ss]) ;; \
					*) echo "Skipping $$plugin_name build."; continue ;; \
				esac; \
				install_cmd="npm install"; \
				if [ -f "$$plugin_dir/package-lock.json" ]; then install_cmd="npm ci"; fi; \
				echo "Installing $$plugin_name dependencies into $$plugin_dir/node_modules..."; \
				(cd "$$plugin_dir" && $$install_cmd) || exit 1; \
				echo "✓ Installed $$plugin_name"; \
			fi; \
			echo "Building $$plugin_name..."; \
			(cd "$$plugin_dir" && npm run build) || exit 1; \
			echo "✓ Built $$plugin_name"; \
		elif [ -f "$$plugin_dir/Makefile" ]; then \
			plugin_name=$$(basename $$plugin_dir); \
			echo "Building $$plugin_name..."; \
			$(MAKE) -C "$$plugin_dir" build || exit 1; \
			echo "✓ Built $$plugin_name"; \
		elif [ -f "$$plugin_dir/go.mod" ]; then \
			plugin_name=$$(basename $$plugin_dir); \
			echo "Building $$plugin_name..."; \
			(cd "$$plugin_dir" && CGO_ENABLED=0 go build -o "$$plugin_name" .) || exit 1; \
			echo "✓ Built $$plugin_name"; \
		fi; \
	done
	@echo "Refreshing example plugin checksums..."
	@$(MAKE) applugin-checksums

# Install dependencies for all example plugins
install-example-plugins:
	@for plugin_dir in examples/external_plugins/*/; do \
		if [ -f "$$plugin_dir/package.json" ]; then \
			plugin_name=$$(basename $$plugin_dir); \
			if ! command -v npm >/dev/null 2>&1; then \
				echo "Skipping $$plugin_name: npm is not installed. Install Node.js/npm to build this npm-based example plugin."; \
				continue; \
			fi; \
			if [ -d "$$plugin_dir/node_modules" ]; then \
				continue; \
			fi; \
			echo "$$plugin_name needs npm packages installed into $$plugin_dir/node_modules."; \
			printf "Install them now? [y/N] "; \
			read -r answer || answer=; \
			case "$$answer" in \
				[Yy]|[Yy][Ee][Ss]) ;; \
				*) echo "Skipping $$plugin_name dependency install."; continue ;; \
			esac; \
			install_cmd="npm install"; \
			if [ -f "$$plugin_dir/package-lock.json" ]; then install_cmd="npm ci"; fi; \
			echo "Installing $$plugin_name dependencies into $$plugin_dir/node_modules..."; \
			(cd "$$plugin_dir" && $$install_cmd) || exit 1; \
			echo "✓ Installed $$plugin_name"; \
		fi; \
	done

# Generate checksums.sha256 for all example plugins
applugin-checksums: applugin-checksum
	@for plugin_dir in examples/external_plugins/*/; do \
		if [ -f "$$plugin_dir/manifest.json" ]; then \
			plugin_name=$$(basename $$plugin_dir); \
			if [ -f "$$plugin_dir/package.json" ] && [ ! -x "$$plugin_dir/$$plugin_name" ]; then \
				echo "Skipping $$plugin_name checksum: executable is not built."; \
				continue; \
			fi; \
			bin/applugin-checksum "$$plugin_dir"; \
		fi; \
	done

# Security Static Analysis
# These analyzers check for common security issues in the codebase

analyze-keyzero:
	@echo "Running key zeroing analysis..."
	@go run ./analysis/keyzero .

analyze-keylog:
	@echo "Running key logging analysis..."
	@go run ./analysis/keylog .

analyze-insecurerand:
	@echo "Running insecure random analysis..."
	@go run ./analysis/insecurerand .

analyze-seedphrase:
	@echo "Running seed phrase detection analysis..."
	@go run ./analysis/seedphrase -git .

security-analysis: analyze-keyzero analyze-keylog analyze-insecurerand analyze-seedphrase
	@echo "All security analyses complete."

# Documentation Generation
config-docs:
	@echo "Generating configuration reference..."
	@go run ./cmd/configdoc > docs/USER_CONFIG_REFERENCE.md
	@echo "✓ Generated docs/USER_CONFIG_REFERENCE.md"

help:
	@echo "Available targets:"
	@echo "  make apshell            - Build apshell"
	@echo "  make apsigner        - Build apsigner (signing server)"
	@echo "  make apadmin     - Build apadmin"
	@echo "  make apconsole    - Build apconsole"
	@echo "  make apapprover  - Build apapprover"
	@echo "  make apstore     - Build apstore (init, backup, restore, changepass)"
	@echo "  make appolicy    - Build appolicy (offline policy editor/checker)"
	@echo "  make aplocalnet  - Build aplocalnet (LocalNet setup TUI)"
	@echo "  make approbe     - Build approbe (installer liveness probe)"
	@echo "  make applugin-checksum - Build applugin-checksum (generate checksums.sha256)"
	@echo "  make all             - Build all first-party binaries and bundled plugins"
	@echo "  make clean           - Remove built binaries"
	@echo "  make compile-teal    - Compile TEAL programs and update embedded copies"
	@echo "  make compile-docassets - Copy docs/USER_JSAPI.md into the generated embed location"
	@echo ""
	@echo "Cross-compilation:"
	@echo "  make bin-arm64         - Build all binaries for ARM64 into bin/arm64/"
	@echo "  make bin-amd64         - Build all binaries for AMD64 into bin/amd64/"
	@echo "  make apshell-arm64        - Cross-compile apshell for ARM64"
	@echo "  make apsigner-arm64    - Cross-compile apsigner for ARM64"
	@echo "  make apadmin-arm64 - Cross-compile apadmin for ARM64"
	@echo "  make apconsole-arm64 - Cross-compile apconsole for ARM64"
	@echo "  make apstore-arm64 - Cross-compile apstore for ARM64"
	@echo "  make appolicy-arm64 - Cross-compile appolicy for ARM64"
	@echo ""
	@echo "Testing:"
	@echo "  make test            - Run unit tests (excludes integration tests)"
	@echo "  make check           - Run Go unit tests plus signer API contract tests"
	@echo "  make formal-test     - Run TLC over docs/formal/*.tla specs"
	@echo "  make race-test       - Run tests with race detector (slower, catches data races)"
	@echo "  make unit-test       - Run unit tests only (excludes integration tests)"
	@echo "  make contract-test   - Run signer API golden fixture tests"
	@echo "  APLANE_INTEGRATION_NETWORK=testnet make integration-test - Regenerate fixture and run integration tests"
	@echo "  APLANE_INTEGRATION_NETWORK=localnet make integration-test - Run integration tests against LocalNet"
	@echo "  make integration-test-testnet - Regenerate fixture and run integration tests against testnet"
	@echo "  make integration-test-localnet - Regenerate fixture and run integration tests against LocalNet"
	@echo "  make integration-test-reuse - Run integration tests with existing fixture"
	@echo "  make soak-test-localnet - Run opt-in LocalNet transaction soak test"
	@echo "  make apshell-command-coverage-localnet - Run broad LocalNet apshell command coverage"
	@echo "  make docker-systemd-test - End-to-end systemd install+uninstall in a fresh Ubuntu systemd container (requires docker)"
	@echo "  make docker-local-test - End-to-end local Docker install smoke test with shared LocalNet (requires docker)"
	@echo ""
	@echo "External Plugins:"
	@echo "  make install-example-plugins - Install npm dependencies for all example plugins"
	@echo "  make bundled-plugins         - Build and checksum bundled plugin payloads"
	@echo "  make bundled-plugins-linux   - Build Linux amd64/arm64 bundled plugin payloads"
	@echo "  make bundled-plugins-darwin  - Build macOS amd64/arm64 bundled plugin payloads"
	@echo "  make build-bundled-plugins   - Build host bundled plugin payloads"
	@echo "  make example-plugins         - Dev install: build all example plugins, copy them into APCLIENT_DATA, and enable them in plugins.yaml"
	@echo "  make build-example-plugins   - Build every example plugin without installing (no APCLIENT_DATA changes)"
	@echo "  make check-example-plugins   - Check if TypeScript example plugins need rebuilding"
	@echo "  make applugin-checksums        - Generate checksums.sha256 for all example plugins"
	@echo ""
	@echo "Security Analysis:"
	@echo "  make security-analysis     - Run all security analyzers"
	@echo "  make analyze-keyzero       - Check key material is properly zeroed"
	@echo "  make analyze-keylog        - Check for key material in logs/errors"
	@echo "  make analyze-insecurerand  - Check for math/rand in crypto code"
	@echo "  make analyze-seedphrase    - Check for BIP-39 seed phrases in files"
	@echo ""
	@echo "Documentation:"
	@echo "  make config-docs           - Generate config reference from struct tags"
	@echo ""
	@echo "Note: Binaries $(STATIC_NOTE)"
