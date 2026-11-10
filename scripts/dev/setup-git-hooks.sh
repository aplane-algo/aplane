#!/usr/bin/env bash
set -euo pipefail

# Writes the repository's git hooks and points git at them. .githooks/ is not
# tracked, so rerun this after it changes.
#
# The hooks live in the main checkout and git is given their absolute path, so a
# linked worktree runs them too. A relative path would point each worktree at a
# .githooks directory it doesn't have, and it would run no hooks without saying so.
#
#   pre-commit  format, vet, the testmode build, staticcheck, the seed-phrase
#               scan and lint. It takes seconds.
#   pre-push    the unit suite (make test). It takes minutes, so it runs once
#               per push and not on every commit. CI runs it again on the PR.

# The main checkout, whichever worktree this runs from.
repo_root="$(cd "$(git rev-parse --path-format=absolute --git-common-dir)/.." && pwd)"
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
# It runs on every push that sends a branch, a doc-only one included: some tests
# read the docs (the golden vectors in docs/ARCH_BOUNDED_DSA.md, the
# architecture tests). Two kinds of push are skipped: one that only deletes
# refs, and one that only sends tags, whose commits are already on a branch.
#
# Skip once with: git push --no-verify

sends_branch=false
while read -r local_ref local_sha _remote_ref _remote_sha; do
	case "$local_sha" in
	*[!0]*) ;;
	*) continue ;; # all zeros: a deletion, in a SHA-1 or SHA-256 repository
	esac
	case "$local_ref" in
	refs/tags/*) continue ;;
	esac
	sends_branch=true
done
if [ "$sends_branch" = false ]; then
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
git config core.hooksPath "$repo_root/.githooks"

echo "Configured git hooks for $(basename "$repo_root")"
echo "core.hooksPath=$(git config --get core.hooksPath)"
