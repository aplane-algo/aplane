.PHONY: all clean apshell apshell-core apshell-all apsignerd apadmin apapprover apstore plugin-checksum plugin-checksums help generate-plugin-imports list-plugins disable-all compile-teal test race-test unit-test integration-test check-example-plugins build-example-plugins docker-playground apshell-arm64 apsignerd-arm64 apadmin-arm64 apstore-arm64 apapprover-arm64 pass-file-arm64 pass-systemd-creds-arm64 plugin-checksum-arm64 bin-arm64 bin-amd64 bin-darwin-amd64 bin-darwin-arm64 security-analysis analyze-keyzero analyze-keylog analyze-insecurerand analyze-seedphrase config-docs client-package python-sdk python-sdk-test python-sdk-clean typescript-sdk typescript-sdk-clean typescript-sdk-test release-local

# Default target when running just "make"
.DEFAULT_GOAL := all

# Version information (injected into binaries at build time)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Version ldflags (injected into all binaries)
VERSION_PKG = github.com/aplane-algo/aplane/internal/version
VERSION_LDFLAGS = -X $(VERSION_PKG).Version=$(VERSION) -X $(VERSION_PKG).GitCommit=$(GIT_COMMIT) -X $(VERSION_PKG).BuildTime=$(BUILD_TIME)

# OS-specific build configuration
# Linux: use musl-gcc for static linking (secure, portable)
# macOS: dynamic linking only (Apple doesn't support static binaries)
ifeq ($(shell uname),Darwin)
    CC_CMD =
    LD_FLAGS = -ldflags '$(VERSION_LDFLAGS)'
    STATIC_NOTE = (dynamically linked - macOS limitation)
else
    CC_CMD = CC=musl-gcc
    LD_FLAGS = -ldflags '$(VERSION_LDFLAGS) -extldflags "-static"'
    STATIC_NOTE = (statically linked with musl)
endif

# Auto-detect all available core plugins by scanning coreplugins/ directory (directories and symlinks)
AVAILABLE_PLUGINS := $(notdir $(shell find coreplugins -maxdepth 1 \( -type d -o -type l \) -not -name coreplugins 2>/dev/null | sort))

# Generate plugin import files in cmd/apshell/ based on available plugins
generate-plugin-imports:
	@echo "Generating plugin import files..."
	@for plugin in $(AVAILABLE_PLUGINS); do \
		echo "//go:build $$plugin" > cmd/apshell/plugin_$$plugin.go; \
		echo "// +build $$plugin" >> cmd/apshell/plugin_$$plugin.go; \
		echo "" >> cmd/apshell/plugin_$$plugin.go; \
		echo "package main" >> cmd/apshell/plugin_$$plugin.go; \
		echo "" >> cmd/apshell/plugin_$$plugin.go; \
		echo "import _ \"github.com/aplane-algo/aplane/coreplugins/$$plugin\"" >> cmd/apshell/plugin_$$plugin.go; \
		echo "Generated: cmd/apshell/plugin_$$plugin.go"; \
	done

# Compile TEAL programs and copy to embedded locations
# Only compiles if source is newer than target or if goal is available
compile-teal: resources/dummy.teal.tok internal/signing/dummy.teal.tok internal/lsig/dummy.teal.tok

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

# Default: Build all components
all: compile-teal apshell apsignerd apadmin apapprover apstore pass-file pass-systemd-creds plugin-checksums client-package

# Build apshell with enabled plugins (default)
apshell: apshell-all

# Build apshell with NO plugins (minimal binary)
apshell-core: compile-teal
	CGO_ENABLED=1 $(CC_CMD) go build $(LD_FLAGS) -o bin/apshell ./cmd/apshell

# Build apshell with all enabled core plugins (auto-detected from symlinks)
apshell-all: compile-teal generate-plugin-imports
	@if [ -z "$(AVAILABLE_PLUGINS)" ]; then \
		echo "No core plugins available in coreplugins/ directory"; \
		CGO_ENABLED=1 $(CC_CMD) go build $(LD_FLAGS) -o bin/apshell ./cmd/apshell; \
	else \
		echo "Building with all available plugins: $(AVAILABLE_PLUGINS)"; \
		CGO_ENABLED=1 $(CC_CMD) go build $(LD_FLAGS) -tags "$(AVAILABLE_PLUGINS)" -o bin/apshell ./cmd/apshell; \
	fi

apsignerd: compile-teal
	CGO_ENABLED=1 $(CC_CMD) go build $(LD_FLAGS) -o bin/apsignerd ./cmd/apsignerd

apadmin: compile-teal
	CGO_ENABLED=1 $(CC_CMD) go build $(LD_FLAGS) -o bin/apadmin ./cmd/apadmin

apapprover:
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/apapprover ./cmd/apapprover

apstore: compile-teal
	CGO_ENABLED=1 $(CC_CMD) go build $(LD_FLAGS) -o bin/apstore ./cmd/apstore

# pass-file is a dev-only plaintext file passphrase helper (pure Go)
pass-file:
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/pass-file ./cmd/pass-file
	@chmod 700 bin/pass-file

# pass-systemd-creds encrypts passphrase via systemd-creds (TPM2/host key, Linux only, pure Go)
pass-systemd-creds:
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/pass-systemd-creds ./cmd/pass-systemd-creds
	@chmod 700 bin/pass-systemd-creds

# plugin-checksum doesn't need CGO (pure Go crypto)
plugin-checksum:
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/plugin-checksum ./cmd/plugin-checksum

# ARM64 cross-compilation targets
# Uses Zig for musl-based static linking (install: https://ziglang.org/download/)
# Override with: make bin-arm64 ARM64_CC=aarch64-linux-musl-gcc
ARM64_CC ?= zig cc -target aarch64-linux-musl
ARM64_LD_FLAGS = -ldflags '$(VERSION_LDFLAGS) -extldflags "-static"'

apshell-arm64: compile-teal generate-plugin-imports
	@if [ -z "$(AVAILABLE_PLUGINS)" ]; then \
		echo "Building apshell-arm64 with no plugins"; \
		CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC="$(ARM64_CC)" go build $(ARM64_LD_FLAGS) -o apshell-arm64 ./cmd/apshell; \
	else \
		echo "Building apshell-arm64 with plugins: $(AVAILABLE_PLUGINS)"; \
		CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC="$(ARM64_CC)" go build $(ARM64_LD_FLAGS) -tags "$(AVAILABLE_PLUGINS)" -o apshell-arm64 ./cmd/apshell; \
	fi

apsignerd-arm64: compile-teal
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC="$(ARM64_CC)" go build $(ARM64_LD_FLAGS) -o apsignerd-arm64 ./cmd/apsignerd

apadmin-arm64: compile-teal
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC="$(ARM64_CC)" go build $(ARM64_LD_FLAGS) -o apadmin-arm64 ./cmd/apadmin

apstore-arm64: compile-teal
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC="$(ARM64_CC)" go build $(ARM64_LD_FLAGS) -o apstore-arm64 ./cmd/apstore

# apapprover and plugin-checksum are pure Go (no CGO), so cross-compilation is simple
apapprover-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '$(VERSION_LDFLAGS)' -o apapprover-arm64 ./cmd/apapprover

pass-file-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '$(VERSION_LDFLAGS)' -o pass-file-arm64 ./cmd/pass-file
	@chmod 700 pass-file-arm64

pass-systemd-creds-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '$(VERSION_LDFLAGS)' -o pass-systemd-creds-arm64 ./cmd/pass-systemd-creds
	@chmod 700 pass-systemd-creds-arm64

plugin-checksum-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '$(VERSION_LDFLAGS)' -o plugin-checksum-arm64 ./cmd/plugin-checksum

# Build all binaries for arm64 into bin/arm64/
bin-arm64: apshell-arm64 apsignerd-arm64 apadmin-arm64 apstore-arm64 apapprover-arm64 pass-file-arm64 pass-systemd-creds-arm64 plugin-checksum-arm64
	@mkdir -p bin/arm64
	@mv apshell-arm64 bin/arm64/apshell
	@mv apsignerd-arm64 bin/arm64/apsignerd
	@mv apadmin-arm64 bin/arm64/apadmin
	@mv apstore-arm64 bin/arm64/apstore
	@mv apapprover-arm64 bin/arm64/apapprover
	@mv pass-file-arm64 bin/arm64/pass-file
	@chmod 700 bin/arm64/pass-file
	@mv pass-systemd-creds-arm64 bin/arm64/pass-systemd-creds
	@chmod 700 bin/arm64/pass-systemd-creds
	@mv plugin-checksum-arm64 bin/arm64/plugin-checksum
	@echo "✓ Built arm64 binaries in bin/arm64/"

# Build all binaries for amd64 into bin/amd64/
bin-amd64: compile-teal generate-plugin-imports
	@mkdir -p bin/amd64
	@if [ -z "$(AVAILABLE_PLUGINS)" ]; then \
		CGO_ENABLED=1 $(CC_CMD) go build $(LD_FLAGS) -o bin/amd64/apshell ./cmd/apshell; \
	else \
		CGO_ENABLED=1 $(CC_CMD) go build $(LD_FLAGS) -tags "$(AVAILABLE_PLUGINS)" -o bin/amd64/apshell ./cmd/apshell; \
	fi
	CGO_ENABLED=1 $(CC_CMD) go build $(LD_FLAGS) -o bin/amd64/apsignerd ./cmd/apsignerd
	CGO_ENABLED=1 $(CC_CMD) go build $(LD_FLAGS) -o bin/amd64/apadmin ./cmd/apadmin
	CGO_ENABLED=1 $(CC_CMD) go build $(LD_FLAGS) -o bin/amd64/apstore ./cmd/apstore
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/amd64/apapprover ./cmd/apapprover
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/amd64/pass-file ./cmd/pass-file
	@chmod 700 bin/amd64/pass-file
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/amd64/pass-systemd-creds ./cmd/pass-systemd-creds
	@chmod 700 bin/amd64/pass-systemd-creds
	CGO_ENABLED=0 go build -ldflags '$(VERSION_LDFLAGS)' -o bin/amd64/plugin-checksum ./cmd/plugin-checksum
	@echo "✓ Built amd64 binaries in bin/amd64/"

# macOS build targets (dynamically linked — Apple doesn't support static binaries)
DARWIN_LD_FLAGS = -ldflags '$(VERSION_LDFLAGS)'

# Build all binaries for darwin/arm64 (Apple Silicon) into bin/darwin-arm64/
bin-darwin-arm64: compile-teal generate-plugin-imports
	@mkdir -p bin/darwin-arm64
	@if [ -z "$(AVAILABLE_PLUGINS)" ]; then \
		CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-arm64/apshell ./cmd/apshell; \
	else \
		CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build $(DARWIN_LD_FLAGS) -tags "$(AVAILABLE_PLUGINS)" -o bin/darwin-arm64/apshell ./cmd/apshell; \
	fi
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-arm64/apsignerd ./cmd/apsignerd
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-arm64/apadmin ./cmd/apadmin
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-arm64/apstore ./cmd/apstore
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-arm64/apapprover ./cmd/apapprover
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-arm64/pass-file ./cmd/pass-file
	@chmod 700 bin/darwin-arm64/pass-file
	@echo "✓ Built darwin/arm64 binaries in bin/darwin-arm64/"

# Build all binaries for darwin/amd64 (Intel Mac) into bin/darwin-amd64/
bin-darwin-amd64: compile-teal generate-plugin-imports
	@mkdir -p bin/darwin-amd64
	@if [ -z "$(AVAILABLE_PLUGINS)" ]; then \
		CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-amd64/apshell ./cmd/apshell; \
	else \
		CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build $(DARWIN_LD_FLAGS) -tags "$(AVAILABLE_PLUGINS)" -o bin/darwin-amd64/apshell ./cmd/apshell; \
	fi
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-amd64/apsignerd ./cmd/apsignerd
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-amd64/apadmin ./cmd/apadmin
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-amd64/apstore ./cmd/apstore
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-amd64/apapprover ./cmd/apapprover
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(DARWIN_LD_FLAGS) -o bin/darwin-amd64/pass-file ./cmd/pass-file
	@chmod 700 bin/darwin-amd64/pass-file
	@echo "✓ Built darwin/amd64 binaries in bin/darwin-amd64/"

clean: python-sdk-clean typescript-sdk-clean
	find bin -mindepth 1 ! -name '.gitkeep' -delete 2>/dev/null || true
	rm -rf temp/apshell temp/apshell-client.tar.gz
	rm -f cmd/apshell/plugin_*.go

# Client package for remote SSH access
# Creates temp/apshell-client.tar.gz with apshell binary and config for SSH tunnel
CLIENT_PKG_DIR = temp/apshell

client-package: apshell
	@echo "Building client package..."
	@rm -rf $(CLIENT_PKG_DIR)
	@mkdir -p $(CLIENT_PKG_DIR)/.ssh
	@cp bin/apshell $(CLIENT_PKG_DIR)/
	@sed 's/signer\.example\.com/REPLACE_WITH_SIGNER_HOST/' \
		examples/config/apshell/config.yaml.example.remote > $(CLIENT_PKG_DIR)/config.yaml
	@echo "apshell - SSH Client for aPlane Signer" > $(CLIENT_PKG_DIR)/README.txt
	@echo "==========================================" >> $(CLIENT_PKG_DIR)/README.txt
	@echo "" >> $(CLIENT_PKG_DIR)/README.txt
	@echo "Setup:" >> $(CLIENT_PKG_DIR)/README.txt
	@echo "1. Edit config.yaml and set signer_host to your apsignerd IP/hostname" >> $(CLIENT_PKG_DIR)/README.txt
	@echo "2. Run: ./apshell -d ." >> $(CLIENT_PKG_DIR)/README.txt
	@echo "" >> $(CLIENT_PKG_DIR)/README.txt
	@echo "First connection:" >> $(CLIENT_PKG_DIR)/README.txt
	@echo "- SSH identity key will be auto-generated in .ssh/id_ed25519" >> $(CLIENT_PKG_DIR)/README.txt
	@echo "- You'll be prompted to trust the server's host key (TOFU)" >> $(CLIENT_PKG_DIR)/README.txt
	@echo "- API token will be requested from the server automatically" >> $(CLIENT_PKG_DIR)/README.txt
	@echo "- The server operator will be prompted to approve your client" >> $(CLIENT_PKG_DIR)/README.txt
	@echo "" >> $(CLIENT_PKG_DIR)/README.txt
	@echo "Files:" >> $(CLIENT_PKG_DIR)/README.txt
	@echo "  apshell          - The binary" >> $(CLIENT_PKG_DIR)/README.txt
	@echo "  config.yaml      - Configuration (edit signer_host)" >> $(CLIENT_PKG_DIR)/README.txt
	@echo "  .ssh/            - SSH keys (auto-created on first connect)" >> $(CLIENT_PKG_DIR)/README.txt
	@echo "  aplane.token     - API token (auto-created on first connect)" >> $(CLIENT_PKG_DIR)/README.txt
	@tar -czf temp/apshell-client.tar.gz -C temp apshell
	@echo "✓ Created temp/apshell-client.tar.gz"

# Python SDK distribution
# Requires: pip install build
PYTHON_SDK_DIR = sdk/python

python-sdk:
	@echo "Building Python SDK distribution..."
	@if ! command -v python3 -m build --help >/dev/null 2>&1; then \
		echo "Error: 'build' package not found. Install with: pip install build"; \
		exit 1; \
	fi
	@cd $(PYTHON_SDK_DIR) && python3 -m build
	@echo "✓ Built Python SDK:"
	@ls -la $(PYTHON_SDK_DIR)/dist/

python-sdk-test:
	@echo "Testing Python SDK..."
	@if ! command -v pytest >/dev/null 2>&1; then \
		echo "Error: 'pytest' not found. Install with: pip install pytest"; \
		exit 1; \
	fi
	@cd $(PYTHON_SDK_DIR) && pytest -v
	@echo "✓ Python SDK tests passed"

python-sdk-clean:
	@echo "Cleaning Python SDK build artifacts..."
	@rm -rf $(PYTHON_SDK_DIR)/dist $(PYTHON_SDK_DIR)/build $(PYTHON_SDK_DIR)/*.egg-info
	@find $(PYTHON_SDK_DIR) -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "✓ Cleaned Python SDK build artifacts"

# TypeScript SDK
TYPESCRIPT_SDK_DIR = sdk/typescript/aplane

typescript-sdk:
	@echo "Building TypeScript SDK..."
	@if ! command -v npm >/dev/null 2>&1; then \
		echo "Error: 'npm' not found. Please install Node.js"; \
		exit 1; \
	fi
	@cd $(TYPESCRIPT_SDK_DIR) && npm install --silent && npm run build --silent && npm pack --silent
	@echo "✓ Built TypeScript SDK:"
	@ls -la $(TYPESCRIPT_SDK_DIR)/*.tgz

typescript-sdk-test:
	@echo "Testing TypeScript SDK..."
	@cd $(TYPESCRIPT_SDK_DIR) && npm test
	@echo "✓ TypeScript SDK tests passed"

typescript-sdk-clean:
	@echo "Cleaning TypeScript SDK build artifacts..."
	@rm -rf $(TYPESCRIPT_SDK_DIR)/dist $(TYPESCRIPT_SDK_DIR)/node_modules $(TYPESCRIPT_SDK_DIR)/*.tgz
	@echo "✓ Cleaned TypeScript SDK build artifacts"

# Docker playground image
# Requires: docker buildx plugin, aarch64-linux-musl-gcc for arm64 cross-compilation
DOCKER_PLAYGROUND_IMAGE := makman568/ap-play

# Build and push multi-arch Docker image (amd64 + arm64)
docker-playground: bin-arm64 bin-amd64
	docker buildx build --platform linux/amd64,linux/arm64 -t $(DOCKER_PLAYGROUND_IMAGE):latest --push -f docker/Dockerfile .
	@echo "✓ Pushed $(DOCKER_PLAYGROUND_IMAGE):latest (amd64 + arm64)"

# Local release dry-run (builds archives without publishing)
# On macOS: also builds darwin archives. On Linux: linux only.
release-local: bin-amd64 bin-arm64
	@mkdir -p dist
	@VERSION=$$(git describe --tags --always --dirty 2>/dev/null | sed 's/^v//'); \
	for arch in amd64 arm64; do \
		archive="aplane_$${VERSION}_linux_$${arch}.tar.gz"; \
		tar -czf "dist/$${archive}" -C "bin/$${arch}" \
			apshell apsignerd apadmin apapprover apstore pass-file pass-systemd-creds; \
		echo "✓ Created dist/$${archive}"; \
	done; \
	cd dist && sha256sum *.tar.gz > checksums.txt && cd ..; \
	echo "✓ Generated dist/checksums.txt"; \
	cat dist/checksums.txt

test:
	go test ./...

# Run linter
lint:
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Error: golangci-lint not found. Install from: https://golangci-lint.run/usage/install/"; \
		exit 1; \
	fi
	@echo "Running golangci-lint..."
	golangci-lint run

# Run tests with race detector (slower but catches data races)
race-test:
	@echo "Running tests with race detector..."
	CGO_ENABLED=1 go test -race ./...

# Run unit tests (all tests except those in test/integration/ and root package)
unit-test:
	@echo "Running unit tests..."
	@go test $$(go list ./... | grep -v '/test/integration' | grep -v '^apshell$$')

# Run integration tests (tests in test/integration/)
# Loads environment from .env.test if it exists (gitignored for security)
integration-test:
	@echo "Running integration tests..."
	@if [ -f .env.test ]; then \
		echo "Loading environment from .env.test"; \
		set -a && . ./.env.test && set +a && go test -v ./test/integration/...; \
	else \
		echo "Note: Create .env.test with TEST_FUNDING_MNEMONIC, TEST_PASSPHRASE, DISABLE_MEMORY_LOCK"; \
		echo "Example: echo 'TEST_FUNDING_MNEMONIC=\"your 25 words\"' > .env.test"; \
		go test -v ./test/integration/...; \
	fi

# Plugin Management Targets

list-plugins:
	@echo "Available core plugins (in coreplugins_repository/):"
	@find coreplugins_repository -maxdepth 1 -type d -not -name coreplugins_repository 2>/dev/null | sed 's|coreplugins_repository/||' | sed 's/^/  /' || echo "  (none)"
	@echo ""
	@echo "Active core plugins (symlinked in coreplugins/):"
	@find coreplugins -maxdepth 1 -type l 2>/dev/null | sed 's|coreplugins/||' | sed 's/^/  /' || echo "  (none)"

enable-%:
	@if [ -d coreplugins_repository/$* ]; then \
		if [ -e coreplugins/$* ]; then \
			echo "✗ Core plugin '$*' is already enabled"; \
			exit 1; \
		fi; \
		ln -s ../coreplugins_repository/$* coreplugins/$*; \
		echo "✓ Enabled core plugin: $*"; \
		echo "  Run 'make apshell-all' to build with this plugin"; \
	else \
		echo "✗ Core plugin '$*' not found in coreplugins_repository/"; \
		echo "  Available core plugins:"; \
		find coreplugins_repository -maxdepth 1 -type d -not -name coreplugins_repository 2>/dev/null | sed 's|coreplugins_repository/||' | sed 's/^/    /' || echo "    (none)"; \
		exit 1; \
	fi

disable-%:
	@if [ -L coreplugins/$* ]; then \
		rm coreplugins/$*; \
		echo "✓ Disabled core plugin: $*"; \
	else \
		echo "✗ Core plugin '$*' not found or not a symlink in coreplugins/"; \
		echo "  Active core plugins:"; \
		find coreplugins -maxdepth 1 -type l 2>/dev/null | sed 's|coreplugins/||' | sed 's/^/    /' || echo "    (none)"; \
		exit 1; \
	fi

disable-all:
	@active=$$(find coreplugins -maxdepth 1 -type l 2>/dev/null); \
	if [ -z "$$active" ]; then \
		echo "No active core plugins to disable"; \
	else \
		for plugin in $$active; do \
			plugin_name=$$(basename $$plugin); \
			rm $$plugin; \
			echo "✓ Disabled: $$plugin_name"; \
		done; \
	fi

# Example External Plugins (TypeScript plugins in examples/external_plugins/)
# These are examples, not required for algosh build, but should stay in sync

# Check if any example plugins have stale dist files
check-example-plugins:
	@stale=0; \
	for plugin_dir in examples/external_plugins/*/; do \
		if [ -f "$$plugin_dir/tsconfig.json" ]; then \
			plugin_name=$$(basename $$plugin_dir); \
			src_ts="$$plugin_dir/src/$${plugin_name}-plugin.ts"; \
			dist_js="$$plugin_dir/dist/$${plugin_name}-plugin.js"; \
			if [ -f "$$src_ts" ] && [ -f "$$dist_js" ]; then \
				if [ "$$src_ts" -nt "$$dist_js" ]; then \
					echo "⚠ Stale: $$plugin_name (src newer than dist)"; \
					stale=1; \
				fi; \
			elif [ -f "$$src_ts" ] && [ ! -f "$$dist_js" ]; then \
				echo "⚠ Missing: $$plugin_name dist not built"; \
				stale=1; \
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

# Build all TypeScript example plugins
build-example-plugins:
	@for plugin_dir in examples/external_plugins/*/; do \
		if [ -f "$$plugin_dir/tsconfig.json" ]; then \
			plugin_name=$$(basename $$plugin_dir); \
			echo "Building $$plugin_name..."; \
			(cd "$$plugin_dir" && npm run build) || exit 1; \
			echo "✓ Built $$plugin_name"; \
		fi; \
	done

# Generate checksums.sha256 for all example plugins
plugin-checksums: plugin-checksum
	@for plugin_dir in examples/external_plugins/*/; do \
		if [ -f "$$plugin_dir/manifest.json" ]; then \
			plugin_name=$$(basename $$plugin_dir); \
			bin/plugin-checksum "$$plugin_dir"; \
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
	@go run ./analysis/seedphrase .

security-analysis: analyze-keyzero analyze-keylog analyze-insecurerand analyze-seedphrase
	@echo "All security analyses complete."

# Documentation Generation
config-docs:
	@echo "Generating configuration reference..."
	@go run ./cmd/configdoc > doc/USER_CONFIG_REFERENCE.md
	@echo "✓ Generated doc/USER_CONFIG_REFERENCE.md"

help:
	@echo "Available targets:"
	@echo "  make apshell            - Build with enabled plugins (auto-detected: $(AVAILABLE_PLUGINS))"
	@echo "  make apshell-all        - Alias for 'make apshell'"
	@echo "  make apshell-core       - Build with NO plugins (minimal binary)"
	@echo "  make apsignerd        - Build apsignerd (signing server)"
	@echo "  make apadmin     - Build apadmin"
	@echo "  make apapprover  - Build apapprover"
	@echo "  make apstore     - Build apstore (init, backup, restore, changepass)"
	@echo "  make plugin-checksum - Build plugin-checksum (generate checksums.sha256)"
	@echo "  make all             - Build everything"
	@echo "  make clean           - Remove built binaries"
	@echo "  make compile-teal    - Compile TEAL programs and update embedded copies"
	@echo "  make client-package  - Create SSH client package (temp/apshell-client.tar.gz)"
	@echo "  make docker-playground - Build and push Docker image (amd64 + arm64)"
	@echo ""
	@echo "Cross-compilation:"
	@echo "  make bin-arm64         - Build all binaries for ARM64 into bin/arm64/"
	@echo "  make bin-amd64         - Build all binaries for AMD64 into bin/amd64/"
	@echo "  make apshell-arm64        - Cross-compile apshell for ARM64"
	@echo "  make apsignerd-arm64    - Cross-compile apsignerd for ARM64"
	@echo "  make apadmin-arm64 - Cross-compile apadmin for ARM64"
	@echo "  make apstore-arm64 - Cross-compile apstore for ARM64"
	@echo ""
	@echo "Testing:"
	@echo "  make test            - Run all tests"
	@echo "  make race-test       - Run tests with race detector (slower, catches data races)"
	@echo "  make unit-test       - Run unit tests only (excludes integration tests)"
	@echo "  make integration-test - Run integration tests (uses .env.test if present)"
	@echo ""
	@echo "Plugin Management:"
	@echo "  make list-plugins         - List active and inactive plugins"
	@echo "  make enable-<plugin>      - Enable a plugin (e.g., make enable-selfping)"
	@echo "  make disable-<plugin>     - Disable a plugin (e.g., make disable-selfping)"
	@echo "  make disable-all          - Disable all active plugins"
	@echo "  make generate-plugin-imports - Auto-generate plugin import files (automatic on build)"
	@echo ""
	@echo "Example Plugins (TypeScript):"
	@echo "  make check-example-plugins - Check if example plugins need rebuilding"
	@echo "  make build-example-plugins - Rebuild all TypeScript example plugins"
	@echo "  make plugin-checksums      - Generate checksums.sha256 for all example plugins"
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
	@echo "Python SDK:"
	@echo "  make python-sdk            - Build Python SDK wheel and sdist (requires: pip install build)"
	@echo "  make python-sdk-test       - Run Python SDK tests (requires: pip install pytest)"
	@echo "  make python-sdk-clean      - Clean Python SDK build artifacts"
	@echo ""
	@echo "TypeScript SDK:"
	@echo "  make typescript-sdk        - Build TypeScript SDK (requires: npm)"
	@echo "  make typescript-sdk-test   - Run TypeScript SDK tests"
	@echo "  make typescript-sdk-clean  - Clean TypeScript SDK build artifacts"
	@echo ""
	@echo "Current Status:"
	@echo "  Enabled plugins: $(if $(AVAILABLE_PLUGINS),$(AVAILABLE_PLUGINS),none)"
	@echo ""
	@echo "Note: Plugin import files (cmd/apshell/plugin_*.go) are auto-generated."
	@echo "Note: Binaries $(STATIC_NOTE)"
