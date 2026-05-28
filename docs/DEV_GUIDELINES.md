# Development Guidelines

## Prerequisites

- Go 1.25 or later
- Make
- Git
- `golangci-lint` for `make lint` and `make integrity-check`

Before architectural, protocol, storage, or refactor-sensitive work, read
[ARCH_SPEC.md](ARCH_SPEC.md) and
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md). Before key type or
LogicSig template work, also read [DEV_KEYTYPES.md](DEV_KEYTYPES.md) and the
`docs/AGENTS_KEYTYPES.md` checklist, plus
[USER_LOGICSIG_GUIDELINES.md](USER_LOGICSIG_GUIDELINES.md) for LogicSig safety
review.

## Pre-Commit Checks

For ordinary changes, run the narrowest checks that cover the touched surface:

```bash
gofmt -s -w <changed-go-files>
go test ./path/to/touched/package
make contract-test        # when signer API wire shapes change
make integration-test     # when signer, shell, SSH, app, or network flows change
```

For release-quality or broad cross-cutting changes, run:

```bash
make integrity-check
```

`make integrity-check` chains formatting, vet, module tidy, lint, dead-code
analysis, security analyzers, race tests, cross-builds, smoke tests, signer API
contract tests, integration tests, and a clean-tree check.

## Pull Request Checklist

- [ ] Code is formatted: `gofmt -s -w <changed-go-files>` or `make fmt-check`
- [ ] Unit tests for touched packages pass
- [ ] `make contract-test` passes for signer API changes
- [ ] `make integration-test` passes for end-to-end signer/shell/network changes
- [ ] `make security-analysis` passes for security-sensitive changes
- [ ] Documentation is updated for behavior, protocol, config, or operator-facing changes
- [ ] Compatibility-sensitive fixture updates under `test/contracts/signerapi/` are intentional

## Package Boundaries

- `cmd/apshell` is adapter-only: flags, provider registration, bootstrap, and mode selection.
- Shell command parsing, REPL/session mechanics, MCP mode, plugin argument normalization, and rendering belong in `internal/apshellcli`.
- Shell command behavior belongs in `internal/apshellapp` with typed request/result APIs and behavior tests.
- Reusable client mechanics belong in `internal/engine`, `internal/clientstate`, and `internal/engine/connect`.
- Signer runtime, approval, identity, key management, and template lifecycle belong under `internal/signerapp`.
- Compatibility-bearing signer API DTOs live in `pkg/signerapi`; internal aliases live under `internal/signerapi`.
- Avoid catch-all helpers; keep helpers in the owning package or an existing focused package.

## Error Handling

```go
// Wrap errors with context.
if err != nil {
    return fmt.Errorf("failed to load key %s: %w", keyID, err)
}

// Use sentinel errors for expected conditions.
var ErrKeyNotFound = errors.New("key not found")

// Avoid panics in library code except for unrecoverable system failures,
// such as crypto/rand failure.
```

## Testing

### Unit Tests

- Place tests in `*_test.go` alongside the code.
- Use `t.TempDir()` for filesystem state.
- Prefer explicit dependency injection over process-global state.
- Use table-driven tests where it improves coverage and readability.
- Keep focused tests fast; broaden coverage when shared contracts or user-facing flows change.

```go
func TestFeature(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    string
        wantErr bool
    }{
        {"valid", "abc", "ABC", false},
        {"empty", "", "", true},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := Feature(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("wantErr %v, got %v", tt.wantErr, err)
            }
            if got != tt.want {
                t.Errorf("got %q, want %q", got, tt.want)
            }
        })
    }
}
```

### Contract Tests

Signer API contract fixtures live under `test/contracts/signerapi/`.
These JSON fixtures are compatibility source material, not throwaway generated
output. When a wire shape intentionally changes, update the fixture in this repo
and the SDK contract coverage in `aplane-algo/aplanesdk` together:

```bash
make contract-test
```

### Integration Tests

Integration tests live in `test/integration/`. The canonical target regenerates
the shared fixture and `.env.test` before running the suite:

```bash
export TEST_FUNDING_MNEMONIC="your twenty five word mnemonic..."
make integration-test
```

The generated test signer fixture lives under `/tmp/aplane-test-env`.
`TEST_PASSPHRASE` is derived from that fixture rather than inherited from the
shell. When `APLANE_SDKS_REPO` points at a local `aplanesdk` checkout,
`make integration-test` also runs that repo's live signer integration suites
against the regenerated fixture. CI runs unit, race, contract, build, and
security jobs; integration tests remain a local or release-gate responsibility
because they require funded testnet access.

## Security Analyzers

```bash
make security-analysis              # Run all analyzers

# Individual analyzers
go run ./analysis/keyzero .         # Check key material zeroing
go run ./analysis/keylog .          # Check for keys in logs
go run ./analysis/insecurerand .    # Check for insecure random
go run ./analysis/seedphrase -git . # Check for committed seed phrases
```

## Commit Messages

- Use imperative mood: "Add feature" not "Added feature".
- Keep subject lines concise and focused.
- Do not include AI attribution.

```text
Add KeyStore interface for pluggable key storage

- Define KeyStore interface in internal/keystore
- Implement FileKeyStore as default
- Add compile-time interface check
```
