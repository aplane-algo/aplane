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

make staticcheck

make analyze-seedphrase
make lint
make test

echo "pre-commit: checks passed"
HOOK

chmod +x .githooks/pre-commit
git config core.hooksPath .githooks

echo "Configured git hooks for $(basename "$repo_root")"
echo "core.hooksPath=$(git config --get core.hooksPath)"
