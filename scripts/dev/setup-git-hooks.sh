#!/usr/bin/env bash
set -euo pipefail

# Writes the repository's git hooks and points git at them. .githooks/ is not
# tracked, so rerun this after it changes.
#
# The hooks live in the main checkout and git is given their absolute path, so a
# linked worktree runs them too. A relative path would point each worktree at a
# .githooks directory it doesn't have, and it would run no hooks without saying so.
#
# Two things follow from that, and git has no setting that avoids both:
#   - Rerun this after moving or renaming the checkout. The path would then name
#     a directory that is gone, and git runs no hooks without saying so.
#   - The hooks are one copy, shared by every worktree. Running an older copy of
#     this script from a worktree on an old branch replaces them for all.
#
#   pre-commit  format, vet, the testmode build, staticcheck, the seed-phrase
#               scan and lint. It takes seconds.
#   pre-push    the unit suite (make test). It takes minutes, so it runs once
#               per push and not on every commit. CI runs it again on the PR.

# The main checkout, whichever worktree this runs from: git lists it first.
repo_root="$(git worktree list --porcelain | sed -n '1s/^worktree //p')"
if [ -z "$repo_root" ] || [ ! -d "$repo_root" ]; then
	echo "setup-git-hooks: could not find the main checkout" >&2
	exit 1
fi
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

# Runs the unit suite before a push.
#
# It runs when the push sends a commit the remote doesn't have yet, a doc-only
# one included: some tests read the docs (the golden vectors in
# docs/ARCH_BOUNDED_DSA.md, the architecture tests). A push that sends nothing
# new is skipped: a deletion, a tag on a commit already pushed, a pushed commit
# under another branch name. A tag on a commit that was never pushed is tested,
# since a tag can start a release.
#
# It tests the checked-out tree, not the commits being pushed, and says so when
# the two differ.
#
# git opens the connection to the remote before it runs this hook. If the suite
# outlasts the remote's idle timeout the push fails after the tests pass; push
# again, which is quick because test results are cached, or set an SSH
# keep-alive (ServerAliveInterval).
#
# Skip once with: git push --no-verify

head_sha="$(git rev-parse HEAD)"
sends_new=false
other_commit=false
while read -r _local_ref local_sha _remote_ref _remote_sha; do
	case "$local_sha" in
	*[!0]*) ;;
	*) continue ;; # all zeros: a deletion, in a SHA-1 or SHA-256 repository
	esac
	# Commits this ref would send that no remote-tracking ref has yet.
	if [ -z "$(git rev-list --max-count=1 "$local_sha" --not --remotes 2>/dev/null)" ]; then
		continue
	fi
	sends_new=true
	if [ "$(git rev-parse "$local_sha^{commit}" 2>/dev/null)" != "$head_sha" ]; then
		other_commit=true
	fi
done
if [ "$sends_new" = false ]; then
	exit 0
fi

if [ "$other_commit" = true ]; then
	echo "pre-push: WARNING: the push sends a commit that is not the one checked out."
	echo "pre-push: the tests below run on the checked-out tree, not on that commit."
fi
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
	echo "pre-push: WARNING: the tree has uncommitted changes, which the tests below include."
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
echo "Rerun this script if the checkout is moved or renamed."
