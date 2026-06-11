#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

mkdir -p .githooks

cat > .githooks/pre-commit <<'HOOK'
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

gopath_bin="$(go env GOPATH)/bin"
export PATH="$gopath_bin:$PATH"

echo "pre-commit: running format, lint, and test checks"

make fmt-check
make vet
make testmode-check

if ! command -v staticcheck >/dev/null 2>&1; then
	echo "pre-commit: staticcheck not found in PATH"
	echo "Install with: go install honnef.co/go/tools/cmd/staticcheck@2025.1.1"
	exit 1
fi
echo "Running staticcheck..."
staticcheck ./...

make analyze-seedphrase
make lint
make test

echo "pre-commit: checks passed"
HOOK

chmod +x .githooks/pre-commit
git config core.hooksPath .githooks

echo "Configured git hooks for $(basename "$repo_root")"
echo "core.hooksPath=$(git config --get core.hooksPath)"
