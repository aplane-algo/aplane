# Updating an existing aplane clone

For agents and developers working in a clone made before 2026-11-04.

On that date the project moved to Go 1.27.3, new linter versions, and a
stricter release setup. The GitHub side is already done, so nothing needs to
change there. Each **clone** needs a pull, and each **machine** needs its
tools updated once.

If a version here differs from `.github/workflows/ci.yml` or `go.mod`, those
files win.

## Update the clone

Check for uncommitted work first, and do not discard or stash it without
asking the user.

```bash
git status --short
git switch main
git pull --tags
```

Repeat for each clone. Worktrees of the same clone share its history but need
their own branch updated.

## Update the machine

Do this once per machine, from an up-to-date clone. The pre-commit hook puts
`$(go env GOPATH)/bin` first on `PATH`, so `~/go/bin` must hold these versions.
A different `PATH` will not override it.

```bash
GOTOOLCHAIN=go1.27.3 go install honnef.co/go/tools/cmd/staticcheck@2026.2.2
GOTOOLCHAIN=go1.27.3 go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
```

Without this, `make staticcheck`, `make lint`, and every commit through the
hook fail with `export data version 5 is greater than maximum supported
version 2` or `Staticcheck was built with go1.25.7`.

`go` downloads Go 1.27.3 by itself on first use in the repo. That needs network
access, and it does not work with `GOTOOLCHAIN=local`. In either case, install
Go 1.27 or later.

Also install Go 1.27 or later as the system Go. Ask the user before changing it.
`go` switches toolchain from `go.mod`, but a `gofmt` on `PATH` does not, so an
older `gofmt -w` can undo Go 1.27 formatting and fail CI. Until then, format
with:

```bash
"$(go env GOROOT)/bin/gofmt" -s -w <files>
```

`make fmt-check` already uses the active toolchain's `gofmt`.

## Verify

Run these from the repo root:

```bash
go version                     # go1.27.3
~/go/bin/staticcheck -version  # 2026.2.2
~/go/bin/golangci-lint version # 2.15.0, built with go1.27.3
git config core.hooksPath      # .githooks
make fmt-check
make staticcheck
make lint
```

If `core.hooksPath` is empty, the clone never had the hook. Run
`scripts/dev/setup-git-hooks.sh`.

Do not use `git commit --no-verify` to get past a tool failure. Fix the tool.

## Old branches

Merge `main` into a branch before opening a PR, and resolve any conflicts. A PR
that conflicts with `main` gets no CI run, and every action must now be pinned
to a commit, so a branch must not bring back `@v7`-style references.

## What changed

| Action | Now |
|---|---|
| Push to `main` | Needs a PR with passing CI. Admins can bypass this, and git prints `Bypassed rule violations`, which is expected. |
| Merge a PR | All 7 CI checks in `aplane`, or `test` in `aplanesdk`, must pass unless an admin bypasses them. |
| Create a tag | Admins only. |
| Move or delete a tag | Not possible, for anyone. Fix a bad release with a new version. |
| Start an `aplane` release | Push a `v*` tag. Other tags do nothing. The signing job then waits for the user's approval in GitHub Actions. |
| Rerun a release by hand | Start `release.yml` from the tag, not from `main`. |
| Publish the SDK | Start `publish-sdks.yml` from `main` with the tag as input. It waits for the user's approval in GitHub Actions. PyPI then publishes, and npm only stages the package. |
| Finish an npm release | The user reviews the staged package and approves it on npm with 2FA. |
| Add or update a workflow action | Use the full 40-character commit SHA with the version in a comment. Tags and short SHAs fail the run. |

```yaml
uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
```

Resolve annotated tags to the commit they point at, not the tag object.

Go 1.27 raises some minimums. Building `aplane` from source needs Go 1.27, and
macOS binaries need macOS 13. The Go SDK needs Go 1.26.

## Rules for agents

- Do not approve a release or publish. Those approvals are the user's human
  check, even when your login could approve them through the API.
- Do not move, delete, or re-create a tag.
- The user pushes release tags. Give them the exact command and commit.
- Do not change GitHub, PyPI, or npm settings without asking.
- Keep worktrees on a short path. Tests in `internal/storeperm` create Unix
  sockets inside the repo and fail with `bind: invalid argument` on a long path.
