# SLH-DSA evaluation reference

This package restores the October 21, 2026 stateless rotating-stage experiment:
a Go reference for SLH-DSA-SHA2-128s, ACVP vectors, verification hash counts, and
key generation, signing, and verification benchmarks. It is an experimental
package with no registered APlane key type or production signing integration.

The source and tests were recovered from the original session's file writes,
including its `Len1` correction and `SigningKey` renaming. The restored tests
also report the parameter description and erase generated key seeds, making
those existing helpers reachable by the repository's dead-code check.
Unchecked randomness reads in the original tests and benchmarks now check
errors to satisfy the repository linter.

Run the reference tests and benchmarks with:

```sh
go test -count=1 -v ./internal/crypto/slhdsa
go test -run '^$' -bench . -benchtime=3x ./internal/crypto/slhdsa
```

## Test vector provenance

`testdata/acvp_sha2_128s.json` was regenerated on October 26, 2026 using the
selection procedure from the original experiment. Its source is NIST's
[ACVP-Server vector collection](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files).
The vectors are public test data, including the test signing keys.

The three source files are `internalProjection.json` under these directories
in `gen-val/json-files/`. SHA-256 identifies the downloaded source bytes:

| Directory | SHA-256 |
| --- | --- |
| `SLH-DSA-keyGen-FIPS205` | `d7c53a1b6450087047b57aae83a5a51a0ac89ecdb23ebe071e83fbb69ae9d920` |
| `SLH-DSA-sigGen-FIPS205` | `62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba` |
| `SLH-DSA-sigVer-FIPS205` | `a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792` |

Selection keeps only `SLH-DSA-SHA2-128s`: all 10 key generation cases, the first
three cases from each pure/internal signing group (12 total), and all 28
pure/internal verification cases. Signing cases cover deterministic and
randomized operation; verification cases include rejection vectors.

## Remaining experiment

The prior work stopped before implementing a TEAL verifier or measuring its
cost on LocalNet. `VerifyStats` counts hash calls in the Go reference; it is
not a measured AVM opcode cost. The next feasibility step is a TEAL verifier
and an exact group-size, fee, and execution-cost measurement with Falcon and
Ed25519 alongside SLH-DSA. No smaller draft parameter set is implemented here.
