# Vendored tools

## tla2tools.jar

The TLA+ tools (TLC model checker), used by `make formal-test` /
`formal-test-deep` and the Formal Models CI job.

Vendored because the upstream download URL
(`https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar`)
is a **rolling artifact**: the tlaplus project re-publishes the asset under
the same v1.8.0 tag on every build, so neither the URL nor a pinned checksum
of it is stable. Committing the jar makes the verification tool immutable,
removes the network step from CI, and puts updates under review like any
other change.

Current jar:
- Source: the URL above, fetched 2026-07-06
- TLC version string: `2026.07.03.221739 (rev: 227f61b)`
- sha256: `9e27b5e19a69ae1f56aabf8403a6ed5598dbfa6e638908e5278ac39736c1543d`

To update: download a new jar, run `make formal-test TLA2TOOLS_JAR=<new>` and
`make formal-test-deep TLA2TOOLS_JAR=<new>` (all recorded outcomes and metrics
must match), then replace this file's provenance block and the jar in one
commit.
