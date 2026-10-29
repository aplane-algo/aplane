# Proposal: Rotating Family Unification

One shared skeleton for the three rotating key types, so that each scheme
package holds only what is particular to it: its stage template, its key
layouts and the hash-based half of its stage.

Status: approved for implementation, 2026-10-29, after two design reviews
the same day (section 9). A refactor in five pull requests. It changes no stage
address, key file, wire shape or signing flow. Its only behaviour changes
refuse inputs no caller sends (section 4, steps 2 and 3).

## 1. Problem

The layer above the scheme packages is already unified. The `rotating1`
flow, the stage tables and the release record reach each key type through
`signing.RotatingStageOps`, read its differences from `rotatingkey.Profile`
(`OneTimeStage`, `StatelessHash`, `LeavesPerStage`, `StagesPerTree`,
`Preparation`), and use the optional `signing.RotatingTreeOps` for XMSS's
shared trees. Nothing above the scheme packages switches on the key type.

Below that layer, `lsig/rotatingtriplewots`, `lsig/rotatingtriplexmss` and
`lsig/rotatingtripleslhdsa` each have `stage`, `signerops` and `signerreg`
packages, and the second and third were built by copying the first:

| Piece | Where, in each scheme | Copies |
|---|---|---|
| Generator: `GenerateRandom` and the two refusals | `signerreg/generator.go` | 3, differing only in key type and family |
| `Register`, `accountAddress`, `NewKeyPayload` | `signerreg/register.go` | 3; the WOTS and SLH-DSA `validateSeed` are identical |
| Opening a deriver from a stored seed and genesis hash | `signerops/stageops.go` (`deriveFromMaterial`, XMSS `deriverFor`) and `signerreg/register.go` (`validateSeed`) | 6 |
| The stage's Ed25519 and Falcon-1024 half: derive, sign, verify with the Falcon size cap, zero | `signerops/keys.go`, plus XMSS `validateSeed` and `verifyOpenTest` | 4 |
| `Program`, `Address`, the salt search and the strict `Parse` | `stage/program.go` | 3 |
| Stage-ops scaffolding: the open-test message, `StageAddress`, `zeroArgs`, wiping signatures on a failed check | `signerops/stageops.go` | 3 |
| Constants: TEAL version, validity window, Falcon key and signature sizes, Ed25519 signature size, salt limit | `stage/program.go` | 3 |
| Registration and key tests | `signerreg/register_test.go`, `signerops/keys_test.go` | 3: the same five registration tests and three key tests |

This has three costs:

- **Duplicated secret handling.** Code that zeroes secrets, and code that
  verifies signatures before they are released, is maintained in three or
  four places.
- **A dependency on WOTS.** The XMSS and SLH-DSA generators import
  `GenesisHashParameter` from `lsig/rotatingtriplewots/signerreg`. Retiring
  WOTS, which the fourth reopening trigger of
  [PROPOSAL_ROTATING_INTEGRATION.md](PROPOSAL_ROTATING_INTEGRATION.md)
  contemplates, would break the other two.
- **Drift between the copies.**
  - WOTS `stage.Build` dereferences nil keys; SLH-DSA's refuses them.
  - Only SLH-DSA checks, in its stage keys, that the message is a 32-byte
    transaction ID.
  - SLH-DSA carries WOTS-era text: the error "rotating triple deriver is
    nil", and a package comment calling it "the triple hybrid rotating key
    type".
  - In `rotatingkey`, the WOTS constants keep generic names
    (`RotatingTripleMaxProgramBytes`, `RotatingTripleDisplayName`) beside
    `RotatingXmss*` and `RotatingSlhdsa*`.
  - Several package lists in the docs omit the SLH-DSA package (step 5).

## 2. Constraints

What must not move:

- **Stage addresses.** Derivation labels, HKDF info tags, frozen templates,
  constant offsets and the salt rule all stay per scheme. Shared code takes
  each of them as a parameter.
- **Key files.** Each scheme's stage 0 record keeps its order and size, and
  a key file written before the series still loads after it.
- **Wire and flow.** Nothing in `pkg/signerapi`, the `rotating1` flow or
  the SDKs changes.
- **`rotatingkey` stays free of scheme code.** Its profile constants mirror
  the stage packages on purpose and stay pinned by tests.

Guards already in place:

- `TestGoldenVectors` in each `signerops` package pins stage addresses and
  public keys for stages 0 and 1, and for XMSS also stages 1023 and 1024,
  across the first tree boundary.
- `TestBuildMatchesStockAssembler` and `TestParseRejectsNonCanonicalPrograms`
  in each `stage` package. The assembler test skips when algod is
  unreachable, so a green `make test` does not show it ran (step 3).
- The registration tests and the profile pin tests in each `signerreg`
  package.
- The rotating tests under `test/integration`.

These guards miss one case. Each scheme's stored-payload test generates a
new payload and round-trips it. A change that swapped two same-sized fields
in both `packPublicKeys` and `unpackPublicKeys` would still round-trip and
still match the golden addresses, while every existing key file stopped
loading. Step 1 therefore opens with fixed stored-payload fixtures.

The rule for the series: no pull request edits an expected value in these
tests or in the fixtures that step 1 adds. One that needs to is out of
scope.

## 3. Target shape

Shared code follows the `lsig/dsafamily` split: registration in its own
`signerreg` package, apart from what signing code needs, so no scheme's
`stage` or `signerops` package depends on registration or persistence. The
dependencies run one way:

- each scheme's `stage` imports `stageprog`;
- each scheme's `signerops` imports `stagesign` and `stageprog`;
- each scheme's `signerreg` imports the shared `signerreg`.

**`internal/crypto/rotatinghybrid`** stays focused on derivation. It gains
`OpenDeriver(seed, genesisHash []byte, label string) (*Deriver, error)`:
the length checks, copies and zeroing that the six copies do now.

**`internal/falconparams`** already owns the Falcon-1024 public key size and
the maximum compressed signature size (`PublicKeySize`,
`CompressedSignatureMaxSize`). The three stage packages use those instead of
their own copies.

**`lsig/rotatingfamily/stageprog`** is new and small. It has no signing
dependency, and the three `stage` packages import it:

- `Program` and `Address`.
- `Finish(unsalted []byte) (Program, error)`: the off-curve check, then the
  v13 assembler's `intcblock 1 <salt>` search.
- `ParseStrict`: the length check, then rebuild and compare, with each
  scheme supplying its extract and build functions.
- Shared `ErrNoOffCurveSalt` and `ErrInvalidProgram`, which each stage
  package re-exports.

It stays apart from `internal/lsigsalt`, which deliberately does not
reproduce the assembler's salting.

**`lsig/rotatingfamily/stagesign`** is new and signer-side. It holds what
stage signing shares, and depends on `rotatinghybrid`, `falconparams` and
the Falcon signer, but not on `keys`, `keygen` or configuration:

- `ClassicalKeys`, one stage's Ed25519 and Falcon-1024 keys:
  `DeriveClassicalKeys(d, stage, ed25519Tag, falconTag)`, `Sign`,
  `PublicKeys` and `Zero`. `Zero` is nil-safe and safe to call twice.
- `VerifyClassical`, which checks both signatures and the Falcon size cap.
- `OpenTestMessage(label)`, `ZeroArgs` and the 32-byte message check.

Buffer ownership is part of the contract:

- `ClassicalKeys` owns its private keys until `Zero`.
  `DeriveClassicalKeys` zeroes whatever it has derived when a later step
  fails.
- `Sign` returns new signature buffers, which the caller owns. When it
  fails, it first wipes any buffer it had produced.
- A failure during signing wipes what was already signed. When the
  hash-based signature succeeds and Falcon signing then fails, the
  hash-based signature is wiped before the error returns, as each scheme's
  `Sign` does today.
- A `StageOps` method that fails after signing wipes every signature it
  produced before it returns. On success the returned arguments belong to
  the signing flow.

**`lsig/rotatingfamily/signerreg`** is new. Each scheme's `signerreg`
imports it as `rotatingfamilyreg`, as the DSA families import
`dsafamilyreg`:

- `Descriptor`: key type, family, `NewKeyPayload`, `AccountAddress`,
  `ValidateSeed` and the stage ops.
- `Register(Descriptor)`, which installs the codec, the stage ops and the
  generator. Like `dsafamilyreg.RegisterSigner`, it keeps no bookkeeping
  of its own. Each scheme keeps its `sync.Once` around the call, so
  repeated registration stays idempotent, and the registries still panic
  on a duplicate key type.
- The shared generator, with `GenesisHashParameter` moved from the WOTS
  package.

**Registration preserves the stage ops value.** The descriptor holds it
exactly as the scheme supplies it, and `Register` registers that value
without copying or wrapping it. For XMSS that value is the process-wide
`*StageOps`: the same instance whose tree cache key generation and
validation share, and that `StageOps()` returns. The signer's
`RotatingTreeOps` assertion must keep finding `Prepare` and `TreeReady` on
it.

**Each scheme keeps:**

- In `stage`: its template, offsets, `PublicKeys`, fill and extract, and
  `TEALSource`.
- In `signerops`: its hash-based derive, sign and verify, its argument
  layout and its `StageOps`. XMSS keeps its tree cache and its open test,
  which never signs with a leaf.
- In `signerreg`: its stage 0 record layout and its descriptor. XMSS keeps
  its cheaper `ValidateSeed`, which compares tree 0's root only when the
  tree is cached rather than rebuilding it.

**`lsig/rotatingfamily/rotatingtest`** is new test support, like
`internal/keys/keystest`. It runs one contract suite against each scheme:

- A stage's address matches its signing program.
- The open test passes.
- Stages differ, and network binding changes the address.
- Signatures verify against the embedded keys.
- A failed check wipes the signatures.
- The key payload round-trips to the stage 0 address.
- A tampered stage 0 record is refused. XMSS's tree 0 root is the one
  exception: it is refused only while tree 0 is cached. The suite tests
  XMSS with a cold cache and a warm one, and checks that cold validation
  does not build the tree.
- Registration is idempotent, and the registered stage ops are the
  scheme's own value. For XMSS that means the instance `StageOps()`
  returns, still implementing `RotatingTreeOps`.
- The generator binds the network.

## 4. Steps

One pull request per step. Every step runs `make test` and
`make security-analysis`, which includes the key-zeroing check. Steps 1 to 3
also run the rotating integration tests on LocalNet. Copied tests are
replaced only in step 4, after the extracted code has passed every scheme's
existing tests unchanged.

1. **Payload fixtures, then registration and generator.**
   - The first commit, made before any extraction, adds a stored-payload
     fixture per scheme. Each is built from a fixed test seed and network
     by the code as it stands: the packed stage 0 record and the decrypted
     payload as stored, in `testdata`.
   - A test loads each fixture, validates it through the registered
     codec, and checks its address against the golden vector.
   - The fixtures never change in the series.
   - The extraction then adds `rotatinghybrid.OpenDeriver` and
     `lsig/rotatingfamily/signerreg` with `Descriptor`, `Register`, the
     generator and `GenesisHashParameter`. Each scheme's `signerreg`
     becomes a descriptor plus its record layout, and the dependency on
     the WOTS package goes away.
2. **The Ed25519 and Falcon half.** Add `stagesign` with `ClassicalKeys`,
   `VerifyClassical`, `OpenTestMessage`, `ZeroArgs` and the message check.
   Each scheme's `signerops` keeps only its hash-based half, and XMSS's
   `validateSeed` and open test use the shared type. Every `SignStage`
   refuses a message that is not 32 bytes, before deriving anything; every
   caller already sends the raw transaction ID. The step carries its own
   safety tests:
   - **Partial initialization.** In `stagesign`, fail Falcon key
     generation after the Ed25519 key was derived, and fail a seed
     expansion, and check that nothing derived before the failure
     survives. Each scheme's `DeriveStage` zeroes its keys through one
     `Zero` on every later error path. Injecting failures inside each
     scheme would need a test hook around every allocation.
   - **Failure during signing.** For each scheme, make Falcon signing fail
     after the hash-based signature succeeded, and check that the
     hash-based signature is wiped.
   - **Failure-path wiping.** For each scheme, make the program parse and
     then the verification fail after signing, and check that every
     returned buffer is wiped.

   The key-zeroing analyzer is heuristic and cannot prove these
   properties, so these tests are the evidence.
3. **Stage program finishing.** Add `stageprog`, and move the stage
   packages to the `falconparams` sizes. Each `stage.Build` fills its
   template and calls `Finish`, and each `Parse` calls `ParseStrict`.
   WOTS `Build` refuses nil keys, as SLH-DSA's does. The pull request shows
   `TestBuildMatchesStockAssembler` passing, not skipped, for all three
   schemes: run with `-v` against a reachable algod, and include the
   output.
4. **Contract suite.** Add `rotatingtest` and replace the copied tests with
   it. Keep the golden vectors, the step 1 fixtures, the step 2 safety
   tests and the scheme-specific tests: the XMSS tree cache and tree
   boundary, WOTS same-stage reuse, and the SLH-DSA shapes and resource
   ceiling. Add one cross-scheme test that pins the shared rotation guard.
   Its first 28 bytes (TEAL version, rekey required and not to itself, no
   close-out, validity window of at most 100 rounds) are identical in all
   three programs today.
5. **Names and docs**, as a separate final cleanup.
   - Rename the WOTS constants in `rotatingkey` to `RotatingWots*`.
   - Fix the copied SLH-DSA strings and package comments.
   - Update the package lists and the new-scheme recipe in:
     - `lsig/doc.go`;
     - `DEV_KEYTYPES.md` section E;
     - `ARCH_KEYTYPES.md`;
     - `ARCH_OVERVIEW.md`;
     - `ARCH_CRYPTO.md`;
     - the source list of `KEYTYPE_ROTATING_TRIPLE_HYBRID.md`.

     These lists name the shared packages and the SLH-DSA package, and
     restate a new scheme as a descriptor, a stage package and a hash-based
     half.

## 5. Left alone

- **Templates and bytecode.** They are frozen and define addresses. Step 4's
  test pins the shared guard instead.
- **Labels, info tags and record layouts.** These are part of the address
  and the key file.
- **The three hash primitives.** The tweaked WOTS, RFC 8391 XMSS and the
  rescaled SLH-DSA follow different specifications with different
  addressing, and each is checked against its own vectors.
- **The XMSS tree cache.** It is XMSS-only and already behind its own
  optional interface.
- **The profile constants in `rotatingkey`.** They are mirrored on purpose
  (section 2).
- **The package names `rotatingtriple*`.** Renaming them would churn every
  import for no change in behaviour.

## 6. Risks

- **Address or key file drift.** The guards in section 2 and the step 1
  fixtures cover it, and no step edits their expected values.
- **Zeroing regressions.** When a secret moves into a shared type, its
  zeroing moves with it. Step 2's partial-initialization and failure-path
  tests check this directly, and the key-zeroing analyzer runs on every
  step as a second check.
- **Losing XMSS capabilities.** A copied or wrapped stage ops value would
  drop the tree cache from signing, or split it between key generation and
  signing. The descriptor rule in section 3 and the contract test prevent
  this.
- **Over-abstraction.** Shared code works on bytes and small function
  parameters, not on generics over each scheme's `PublicKeys`, so a
  scheme's layout stays readable in its own package. Nothing
  scheme-specific moves into `rotatingfamily`.
- **SLH-DSA is still experimental.** Its shape is a build-time choice
  (h = 22 today), so `stageprog` must not assume a template size or an
  argument count.

## 7. Size

Roughly 400 lines of non-test code leave the scheme packages. Most of the
three copies of the registration and key tests collapse into the contract
suite. Steps 1 and 2 also add tests: the fixtures, and the
partial-initialization and failure-path wiping tests. Steps 1 and 4 are the
largest, steps 2 and 3 are small, and step 5 is mechanical.

## 8. Decisions

- **The shared package is `lsig/rotatingfamily`**, with `stageprog`,
  `stagesign`, `signerreg` and `rotatingtest` under it.
- **`ClassicalKeys` lives in `stagesign`**, not in `rotatinghybrid`. That
  keeps derivation and signing in separate packages, and keeps Falcon
  signing out of stage building.
- **Step 5's renames are a separate final pull request.**

## 9. Revision notes

Design review (2026-10-29):

1. Registration moved into `lsig/rotatingfamily/signerreg`, and the signing
   helpers into `stagesign`, so `signerops` does not depend on registration
   and persistence. The Falcon sizes come from `internal/falconparams`
   (3, 4).
2. Step 1 opens with fixed stored-payload fixtures, because a matched change
   to packing and unpacking would pass every existing guard (2, 4).
3. The descriptor keeps the scheme's own stage ops value, which for XMSS
   preserves the tree cache and `RotatingTreeOps`. The contract suite
   states XMSS's cold-cache root exception and tests both cache states
   (3, 6).
4. Step 2 carries its own partial-initialization and failure-path wiping
   tests, with buffer ownership defined. Step 3 must show the assembler
   tests ran, not skipped. Copied tests are replaced only after the
   extracted code passes the existing tests (3, 4).
5. The open questions are settled (8).

Second review (2026-10-29), which approved the plan with two
clarifications:

6. The cleanup contract covers failures during signing, not only after
   it. A Falcon signing failure after a successful hash-based signature
   wipes the hash-based signature, and step 2 tests it (3, 4).
7. Shared registration keeps no bookkeeping of its own. Each scheme's
   `sync.Once` stays, as with `dsafamilyreg` (3).
