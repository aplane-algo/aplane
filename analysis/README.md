# Security Static Analysis

Custom static analyzers for detecting security issues in the aPlane codebase.

## Usage

```bash
# Run all security analyzers
make security-analysis

# Run individual analyzers
make analyze-keyzero       # Key material zeroing
make analyze-keylog        # Key material in logs
make analyze-insecurerand  # Insecure random usage
```

## Analyzers

### analyze-keyzero

Detects functions that handle private key material but may not properly zero it after use.

**Scans:** `internal/signing`, `internal/crypto`, `lsig/`

**What it checks:**
- Functions referencing `PrivateKey`, `SecretKey`, etc.
- Whether `ZeroBytes()` or `ZeroKey()` is called before return

**Handling findings:**
- If the function returns key material to caller → caller is responsible for zeroing (may be acceptable)
- If the function uses key material internally → should zero before returning
- Add `// lint:ignore keyzero` comment to suppress if intentional

### analyze-keylog

Detects potential key material being printed to logs or error messages.

**Scans:** All `.go` files

**What it checks:**
- `fmt.Print*`, `log.*`, `fmt.Errorf` with key-related variables
- Format specifiers (`%x`, `%v`) with private key variables

**Known acceptable patterns:**
- `fmt.Println(mnemonic)` in batch export (intentional output)
- `PrivateKeyHex: fmt.Sprintf("%x", ...)` for struct creation (not logging)

### analyze-insecurerand

Ensures `crypto/rand` is used instead of `math/rand` in security-critical paths.

**Scans:** `internal/signing`, `internal/crypto`, `internal/keygen`, `internal/mnemonic`, `lsig/`

**What it checks:**
- `math/rand` imports in critical directories
- `rand.Seed`, `rand.Intn`, etc. without `crypto/rand` import

## Exit Codes

- `0` - No issues found
- `1` - Issues found (review required)
- `2` - Analyzer error

## Adding New Analyzers

Create a new directory under `analysis/` with a `main.go`:

```go
package main

func main() {
    // Scan files, report findings
    // Exit 0 for pass, 1 for findings
}
```

Add to Makefile:
```makefile
analyze-mycheck:
	@go run ./analysis/mycheck .
```

## False Positive Suppression

Future: Add support for inline comments like:
```go
// lint:ignore keyzero - key returned to caller
return privateKey
```
