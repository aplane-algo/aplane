# Security Static Analysis

Custom static analyzers for detecting security issues in the APlane codebase.

## Usage

```bash
# Run all security analyzers
make security-analysis

# Run individual analyzers
make analyze-keyzero       # Key material zeroing
make analyze-keylog        # Key material in logs
make analyze-insecurerand  # Insecure random usage
make analyze-seedphrase    # Seed phrases committed to files
```

## Analyzers

### analyze-keyzero

Detects functions that handle private key material but may not properly zero it after use.

**Scans:** `internal/signing`, `internal/crypto`, `lsig/`

**What it checks:**
- Functions referencing `PrivateKey`, `SecretKey`, etc.
- Whether `ZeroBytes()` or `ZeroKey()` is called before return

**Handling findings:**
- If the function returns key material to caller, the finding may be acceptable but should be reviewed
- If the function uses key material internally, it should zero before returning
- Inline suppression comments are not implemented; adjust analyzer exemptions in code if needed

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

### analyze-seedphrase

Checks tracked files for likely seed phrases or mnemonics that should not be committed.

**Scans:** Text files in the repository, excluding common generated/binary paths

**What it checks:**
- likely 25-word Algorand mnemonics
- likely 12/24-word BIP-39-style seed phrases
- obvious seed-phrase labels in committed files

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

## False Positives

These analyzers are intentionally simple. Treat findings as review prompts, not
proof of a bug. If a recurring false positive is legitimate, update the
analyzer's allowlist or heuristic rather than assuming inline suppression is available.
