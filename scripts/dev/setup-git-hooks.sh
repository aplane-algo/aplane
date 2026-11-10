#!/usr/bin/env bash
set -euo pipefail

# Writes this checkout's git hooks and points git at them. .githooks/ is not
# tracked, so rerun this after it changes.
#
#   pre-commit  format, vet, the testmode build, staticcheck, the seed-phrase
#               scan and lint. It takes seconds.
#   pre-push    the unit suite (make test). It takes minutes, so it runs once
#               per push and not on every commit. CI runs it again on the PR.

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

# The unit suite runs in pre-push, not here: it takes several minutes, and a
# commit should take seconds. CI runs it again on the pull request.
echo "pre-commit: running format and lint checks"

make fmt-check
make vet
make testmode-check

make staticcheck

make analyze-seedphrase
make lint

echo "pre-commit: checks passed"
HOOK

cat > .githooks/pre-push <<'HOOK'
#!/usr/bin/env bash
set -euo pipefail

# Runs the unit suite before a push. It tests the working tree, so push the
# branch that is checked out.
#
# It runs on every push that sends commits, a doc-only one included: some tests
# read the docs (the golden vectors in docs/ARCH_BOUNDED_DSA.md, the
# architecture tests). A push that only deletes refs is skipped.
#
# Skip once with: git push --no-verify

zero="0000000000000000000000000000000000000000"
sends_commits=false
while read -r _local_ref local_sha _remote_ref _remote_sha; do
	if [ "$local_sha" != "$zero" ]; then
		sends_commits=true
	fi
done
if [ "$sends_commits" = false ]; then
	exit 0
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

gopath_bin="$(go env GOPATH)/bin"
export PATH="$gopath_bin:$PATH"

echo "pre-push: running the unit suite"

make test

echo "pre-push: tests passed"
HOOK

chmod +x .githooks/pre-commit .githooks/pre-push
git config core.hooksPath .githooks

echo "Configured git hooks for $(basename "$repo_root")"
echo "core.hooksPath=$(git config --get core.hooksPath)"
