# Development Guidelines

## Prerequisites

- Go 1.25 or later
- Make
- Git

## Pre-Commit Check

```bash
go build ./... && go test ./... && go vet ./... && gofmt -d . | head
```

## Pull Request Checklist

- [ ] Code compiles: `go build ./...`
- [ ] Tests pass: `go test ./...`
- [ ] No race conditions: `go test -race ./...`
- [ ] Code is formatted: `gofmt -s -w .`
- [ ] Linters pass: `go vet ./...` and `staticcheck ./...`
- [ ] Security analyzers pass: `make security-analysis`

## Error Handling

```go
// Wrap errors with context
if err != nil {
    return fmt.Errorf("failed to load key %s: %w", keyID, err)
}

// Use sentinel errors for expected conditions
var ErrKeyNotFound = errors.New("key not found")

// Avoid panics in library code (except for crypto/rand failures)
```

## Testing

### Unit Tests

- Place tests in `*_test.go` alongside the code
- Use `t.TempDir()` for file operations
- Use table-driven tests for multiple scenarios
- Keep tests fast (<100ms each)

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

### Integration Tests

Integration tests live in `test/integration/` and require:
- `TEST_FUNDING_MNEMONIC` environment variable
- Network access to Algorand testnet

These tests are excluded from CI because they require funded accounts and network access.

```bash
export TEST_FUNDING_MNEMONIC="your twenty five word mnemonic..."
make integration-test
```

## Security Analyzers

```bash
make security-analysis              # Run all analyzers

# Individual analyzers
go run ./analysis/keyzero .         # Check key material zeroing
go run ./analysis/keylog .          # Check for keys in logs
go run ./analysis/insecurerand .    # Check for insecure random
```

## Commit Messages

- Use imperative mood: "Add feature" not "Added feature"
- Keep subject line under 72 characters

```
Add KeyStore interface for pluggable key storage

- Define KeyStore interface in internal/keystore
- Implement FileKeyStore as default
- Add compile-time interface check
```
