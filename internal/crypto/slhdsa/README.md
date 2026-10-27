# SLH-DSA reference

This package is a Go implementation of the SLH-DSA construction of FIPS 205
with SHA-256, n = 16, WOTS+ with w = 16 and the FORS of SLH-DSA-SHA2-128s,
parametric in the hypertree shape. Two shapes are defined:

| Value | Hypertree | Signature | Standing |
| --- | --- | ---: | --- |
| `SHA2128s` | 7 layers of height 9 (h = 63) | 7,856 bytes | SLH-DSA-SHA2-128s of FIPS 205; pinned to the NIST ACVP vectors |
| `Rescaled128` | 2 layers of height 11 (h = 22) | 4,400 bytes | not a FIPS 205 parameter set; sized for rotating stage keys that each sign a few messages |

Both shapes run the same code. The ACVP vectors therefore exercise the
construction the rescaled shape uses; the rescaled shape is pinned by golden
vectors generated from fixed seeds. It supplies the primitive for the opt-in
`aplane.rotating-triple-slhdsa.v1` key type; see `docs/SLHDSA_EVALUATION.md`
for the per-stage signing bound that justifies the shorter hypertree.

The package began as the October 21, 2026 stateless rotating-stage
experiment: a reference for SLH-DSA-SHA2-128s, ACVP vectors, verification
hash counts, and key generation, signing and verification benchmarks. The
hypertree shape became a parameter on October 27, 2026.

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

## Rotating integration

`lsig/rotatingtripleslhdsa` contains frozen TEAL verifiers and signer hooks
for both shapes, selected at build time by `rotatingkey.RotatingSlhdsaHeight` (default 22). At
height 22 the declared ceiling is 68645 AVM opcodes, which fits four
transactions, and the 5,887 bytes of LogicSig arguments decide the group,
six transactions; at height 63 the ceiling is 187258 and the 9,343 argument
bytes need ten. See `docs/ARCH_CRYPTO.md` for the design record and cost
proof. `VerifyStats` counts hash calls and WOTS verification steps; LocalNet
tests compare those steps to the verifier's exact cost model.
