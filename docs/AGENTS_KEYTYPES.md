# Agent Guide: Key Types and LogicSig Templates

This guide is for AI agents generating, reviewing, or modifying APlane key
types and LogicSig templates. Treat `docs/DEV_KEYTYPES.md` as the detailed
developer reference and `docs/USER_LOGICSIG_GUIDELINES.md` as the LogicSig
policy/security review reference; this file is the operational safety
checklist.

For new combinations of capabilities, first use
[Designing a new combination](ARCH_KEYTYPES.md#designing-a-new-combination)
in `docs/ARCH_KEYTYPES.md` and complete its design record.
Do not infer that independently supported capabilities can be composed without
defining their shared authority, transition, and signing-flow contracts.

## Signing Authority

See [DEV_KEYTYPES.md](DEV_KEYTYPES.md) (Signing Authority) for the canonical
statement.

Operational consequence for agents: never edit, replace, or recompile a
template to "fix" signing for an existing key. The key file already carries the
signing authority. Treat template provenance warnings as inventory diagnostics,
not as a license to mutate stored bytecode or metadata.

## Mnemonic Recovery

Follow the [approved native-only mnemonic policy](ARCH_KEYTYPES.md#mnemonic-backup-and-recovery):
user-facing mnemonic import, export, and recovery are for native account types;
LogicSigs use complete encrypted credentials or backups. Do not add LogicSig
mnemonic recovery to new designs. Internal seed derivation is separate and
remains supported.

The plain Falcon and Ed25519 LogicSig providers are plain hosts (`lsig/plainhost`):
the composition base every composed account names, and accounts of their own,
with or without overlays and bounds (`aplane.ed25519.v1` once enabled). Keep their
no-parameter program byte-identical: it is the base and the program of restored
plain keys.
See [plain hosts](ARCH_KEYTYPES.md#plain-hosts).

## Signature Constructions

`base_key_type` names a signature construction: an ordered list of primitive components
that must all verify. Every production base is a construction of one. Do not add a
multi-component base, register a fixture identity, or widen the bounded support policy
without an explicit request: each of those needs a signature encoding, a credential
design, and a contract decision. A key size that fits proves nothing about whether a
workflow is supported. A registered base with no catalog construction is refused at
bounded generation. See "Signature constructions" in `docs/ARCH_KEYTYPES.md`.

## Default Behavior

When a user asks for a custom LogicSig template, default to a **user-loaded YAML
template** unless they explicitly ask to add a built-in provider to the source
tree.

Do not edit shipped library templates or Go providers just to satisfy a user's
custom policy. Shipped templates, compiled providers, and installed template key
types are compatibility boundaries. Changing the behavior of an existing key
type such as `aplane.htlc.v1` or `aplane.falcon1024.v1` can break existing
keys and backups. The plain hosts (`aplane.falcon1024.v1`, `aplane.ed25519.v1`),
with their overlays and bounds, are Go-defined. `aplane.htlc.v1` is the only
bundled YAML template.

Installing a user-loaded template with `apadmin template import` requires the
product-store passphrase through an authenticated daemon admin session. An AI
agent cannot perform this step. Generate the YAML file and let the user run
the install command themselves.

Before writing any template, always ask the user whether the template should
cover ALGO payments only or both ALGO payments and ASA transfers. Do not
assume payment-only unless the user explicitly says so.

## Classify First

Before writing code or YAML, classify the requested key type:

| Request | Category | Normal output |
|---|---|---|
| TEAL-only escrow, allowlist, timelock, hashlock | Generic LogicSig template | YAML for `apadmin template import` |
| Falcon signature plus additional TEAL checks | Composed DSA template | YAML for `apadmin template import` |
| New signing algorithm or key material format | DSA/native provider work | Go implementation and registry changes |

If the user is asking for a template policy and does not mention Falcon,
generate a generic LogicSig YAML template.

A composed template uses schema v2 and a `bounded` block unless there is a stated
reason not to. Prefer a framework policy to author TEAL: `bounded.layer3` with
`fixed_allowlist` or `merkle_allowlist` needs no `teal`. For a custom rule on top of an
allowlist, declare both instead of rewriting the list check in TEAL; the allowlist runs
first and the TEAL can only narrow it. The framework has no time policy: a time check is author TEAL.
The field reference is in
[DEV_KEYTYPES.md](DEV_KEYTYPES.md#bounded-schema-schema_version-2).

For Go provider work, keep the client/signer boundary intact. Client-visible
provider metadata and LogicSig derivation may register through the LogicSig
provider registries, but private-key operations must be passed through explicit
signer/keygen ops in signer-side registration paths. A composed template names
its signature construction through `base_key_type` and registers its own
keygen and signing ops; the shared-ops fallback (described in
DEV_KEYTYPES.md) is acceptable only when the template changes TEAL/params and
shares its `base_key_type` provider's existing keygen/signing semantics. Do
not use that fallback for a new version that changes seed derivation, key
format, signature format, mnemonic behavior, or signing semantics.

Do not use `base_key_type` or a provider's `BaseKeyType()` as a universal route
for account metadata, keygen, mnemonic import, TEAL, address derivation, or
cosigned assembly. It names the signature construction. Account semantics are
owned by the full `key_type` unless a specific operation deliberately delegates
to another key type.

## Valid Rekey Target

Every key type declares `valid_rekey_target`: the key type author's declaration
that an aplane key of this type may be the signing authority an account is
rekeyed to, its own account included, subject to that key's own restrictions
(its bounds, a cosigner, its program). See
[Valid rekey target](ARCH_KEYTYPES.md#valid-rekey-target).

- Every YAML template you write must declare it at the top level; install
  refuses a template without it.
- Set `true` only if you make that declaration for the template. Read the TEAL
  with an account other than the program's own as `Sender`: a program that
  never checks `Sender` authorizes for every account rekeyed to it.
- A template that forbids rekey, or allows only a close-out, a fixed recipient,
  or a hashlock or timelock payment, declares `false`. `aplane.htlc.v1` does.
- A new compiled key type declares it in its `internal/keytypecatalog` entry,
  and `internal/lsigprovider/rekey_target_test.go` must list its decision. Its
  value is fixed in code.
- Each aplane key records the declaration when it is created, and the signer
  reads the key's recorded value. Reinstalling a template with another
  declaration changes only keys created afterwards; existing keys keep theirs.
- The signer refuses a rekey of any account to a held aplane key that recorded
  false, the account's own address included, under every `rekeys` setting and
  whatever the account's rekey-to list says (`rekey_target_not_valid`). That
  target is held, not foreign: "foreign" means only that the signer holds no
  aplane key for the address, and `rekeys` decides only about foreign targets.
- No tool edits a key's recorded value. To correct a wrong declaration, correct
  the template's `valid_rekey_target`, reinstall it, then delete and regenerate
  each affected aplane key. A generic LogicSig key regenerated with the same
  parameters keeps its address; a composed template's key gets a new address,
  so move its funds before deleting it. See
  [Correcting a wrong declaration](ARCH_KEYTYPES.md#correcting-a-wrong-declaration).

## Naming Rules

Every custom template needs a unique versioned key type:

- Set `publisher` to a stable lowercase namespace owner such as `aplane`,
  a project name, or an organization name.
- Set `family` to a new stable lowercase name with no spaces.
- Set `version` to `1` for the first version.
- The resulting key type is `<publisher>.<family>.v<version>`.
- For composed DSA templates, use `base_key_type` to select the signature
  construction and `family` to name the template's own versioned key-type line.
- Never reuse an existing built-in key type or previously installed custom key
  type for changed behavior.
- If behavior changes, create a new version such as `example.myescrow.v2`.

Use unique versioned names for optional template entries and test fixtures.
For user output, choose a name tied to the user's actual policy.

## Fingerprint Rules

The template compatibility fingerprint is provenance only (never signing
authority), behavior-only, and versioned (`<n>:` prefix). When touching key-type
definitions or the fingerprint formula:

- The fingerprint hashes only behavior-bearing fields; identity, routing, and
  display fields (`key_type`, `family`, `version`, `publisher`, display strings)
  are forbidden — never add them to the hash.
- `base_primitive` tokens are a frozen namespace: add rows, never rename a token.
- Bump `CompatibilityFingerprintVersion` only on a fingerprint-formula change
  (field set / hashing rules), never on a rename; update the goldens with it.
- Do not add a new-account restriction to `ValidateTemplateSpec`,
  `validateBoundedConfig`, or the bounded metadata helpers. Installed templates
  reach them on load, and an error changes the fingerprint and fails the store's
  validation. Add it to `checkBoundedGenerationSupport`, which only `GenerateTEAL`
  calls.
- A base-key-type or provider-identifier rename is a separate compatibility
  event: add a retained registry alias so existing keys keep signing — the
  `base_primitive` projection does not make a rename safe for signing.

## Explicit Safety Decisions

For bounded (`bounded2`) work, read
[ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md) and preserve these additional invariants:

- base DSA authentication executes on every accepted path;
- composer-owned fee, type, and danger-field checks execute before author
  Layer 3;
- the program checks the spending signature, then the fee ceiling, then
  dispatches on `RekeyTo`, before any Layer 3 or author code; the rekey branch
  accepts only the frozen pure-rekey normal form (under a rekey-to list, only
  with a valid list proof for `RekeyTo`, or under `plus_cosigned` an empty proof
  slot and the cosigner's signature; a cosigned `spending_key` rekey needs the
  cosigner's signature too) or rejects;
- only admitted pure `pay`/`axfer` spends reach Layer 3; no host rule gates a
  rekey;
- `bounded.rekey` is `refused` (no rekey path), `spending_key` (the spending
  key authorizes a pure rekey: alone, or with the cosigner on a cosigned
  account), `only_these` (`refused` plus a framework-injected rekey-to list: the
  spending key and a signer-built list proof authorize a pure rekey to a listed
  address), or `plus_cosigned` (`spending_key` plus the list, cosigner
  required: a listed target takes the spending key alone, any other the spending
  key and the cosigner);
- a cosigner's `required_on` is `[spend]`, or `[spend, spending_rekey]` with
  `spending_key` or `plus_cosigned`; the cosigner slot is required on exactly
  those paths and forbidden on `listed_rekey`, which never asks the cosigner;
- no framework rule makes a `refused` profile without a list keep a transfer
  (`pay`, and `axfer` beside `asset_opt_in`); a template that drops one can
  strand what the account holds, so review that choice;
- `max_fee` is explicit and compiled; it is required and any value from 0 to
  2^53 - 1 is valid, so review that it covers what the account's paths cost unless another
  account is meant to pay its fees;
- caller runtime args can never supply the cosigner signature or a
  signer-derived argument;
- generated bounded keys persist signing-metadata version 2 with the complete
  runtime-argument, signer-derived-argument, and path-specific slot layout;
  signing, inventory, backup, and restore use that stored snapshot rather than
  the installed YAML;
- a rekey-to list compiles only its hiding root into the program; its entries
  stay in the key's stored parameters and are never projected to `/keys`, and
  its salts derive from the spending key, so only the account's own signer can
  build the `listed_rekey` proof;
- `/keys` and `/keytypes` advertise `signing_flow: bounded1` or
  `cosigned1` from durable metadata; every client must dispatch empty,
  `bounded1`, `cosigned1`, and `rotating1` explicitly
  and reject unknown flows, `bounded-cosigner1` and the retired `cosigner1`
  among them;
- the signer classifies each bounded target through `txeffects.ClassifyFor`
  against the path declaration projected from stored metadata, and every
  decision names a rule;
- the implementation manifest and independent protocol inventory remain
  separate completeness controls; and
- schema v1 rejects `bounded`, while schema v2 rejects unknown and duplicate
  fields at every level.

Every template design must make safety-relevant behavior explicit. Do not
silently choose a permissive policy, and do not silently add restrictions that
the user did not ask for. Explain which behavior is enforced in TEAL and which,
for signer-gated templates, is intentionally left to signer approval and local
signer policy.

Common conservative checks for public or self-contained TEAL policies include:

```teal
txn RekeyTo
global ZeroAddress
==
assert
```

For payment transactions, explicitly decide whether TEAL, signer policy, or the
calling workflow owns:

- allowed `Receiver`
- allowed `Amount` behavior, if constrained
- allowed `CloseRemainderTo`
- whether close-out is forbidden or restricted to an approved address

For ASA transfers, explicitly decide whether TEAL, signer policy, or the
calling workflow owns:

- allowed `XferAsset`
- allowed `AssetReceiver`
- allowed `AssetAmount`
- whether `AssetCloseTo` is forbidden or restricted
- whether clawback sender use through `AssetSender` is forbidden or allowed

For transaction types, prefer explicit `txn TypeEnum` checks when the template
is meant to be a self-contained TEAL spending policy. For signer-gated signing
primitives or partial-condition templates, document when transaction-type
control is intentionally owned by signer policy.

Template TEAL must be relocatable. Do not write raw `bytecblock`/`intcblock`
declarations or numeric `bytec`/`intc` references in user-authored TEAL; use
template variables and symbolic references so the compiler can own generated
constants and any TEAL v13 auto-salt safely. Do not add a custom
salt preamble or expose a YAML salt-style selector. Salt style is a versioned
provider/template derivation contract owned by APlane. Templates with omitted
`derivation_version` are unsalted and compile exactly as written, succeeding
only if the unmodified bytecode already derives an off-curve LogicSig address;
new template-derived key types should use `derivation_version: 3` and TEAL v13
compiler auto-salting. APlane validates the final compiled program and address;
it does not reproduce the compiler's salt search.

After compilation/auto-salting, derive `program_bytes` from the final persisted
bytecode and review every path's maximum `argument_bytes` and
`max_opcode_cost`. Exercise dynamic-cost opcodes at worst permitted input
sizes. Never collapse these values into one size scalar: v42 prices program
bytes but pools arguments and opcode cost independently.

`max_opcode_cost` is optional for installed template YAML. Omission uses the
numeric one-transaction opcode ceiling shared by every consensus version
APlane currently supports: 20,000. An explicit positive value is an absolute
override; an explicit zero is rejected. Do not substitute the full-group
320,000 ceiling as a generic fallback.

APlane-owned templates still require an explicit reviewed declaration, even
when it is 20,000, so repository review and maximum-input simulation evidence
remain visible. The default primarily serves third-party and personal
templates whose authors should not be forced to copy a meaningless number.

For an APlane-owned key type, add a maximum-input accepted integration vector
that calls `harness.ValidateDeclaredOpcodeCeiling` with the final production
bytecode and the provider/template's actual declared profile. Reuse the signer
fixture's `teal_compile_network` algod for simulation. Treat absent/zero cost
reporting, uncovered reachable paths, simulation failure, or an observed
ceiling overrun as release-blocking; never raise a declaration automatically
from test output.

For time locks in LogicSig mode, prefer `txn FirstValid` checks. Do not use
`global Round`.

## Close-Out Policy

A close-out is a drain of the full remaining balance. Treat it separately from a
normal send.

Safe patterns:

- Forbid close-out:
  ```teal
  txn CloseRemainderTo
  global ZeroAddress
  ==
  assert
  ```

- Allow close-out only to a specific address:
  ```teal
  txn CloseRemainderTo
  global ZeroAddress
  ==
  txn CloseRemainderTo
  $recipient
  ==
  ||
  assert
  ```

If a user says "allow sending to X", do not assume that means "allow closing to
X" unless they say so. Ask or choose the stricter no-close policy.

## Runtime Args

Use creation params for values that define the account address, such as:

- recipient addresses
- allowlist entries
- timeout rounds
- stored hashes

Use runtime args only for values supplied at signing/submission time, such as:

- hashlock preimages
- per-transaction proof data

Document how the runtime arg is supplied in `apshell`:

```text
send 1 algo from <lsig> to <addr> arg:preimage=0x...
close <lsig> to <addr> arg:preimage=0x...
```

Keep runtime arg ordering aligned with TEAL `arg N` usage. Generic LogicSig
runtime args start at `arg 0`. Composed DSA templates reserve `arg 0` for the
signature, so additional runtime args start after the signature.

Stay inside the network's LogicSig argument limits:

- no single argument over 4,096 bytes: no `byte_length` or `max_size` above 4,096, and
  no signature slot above it (split a larger signature across arguments)
- at most 255 arguments in all, counting signature, derived, runtime, and cosigner
  slots
- do not plan on dummy transactions to lift either limit; they pool program size and
  opcode budget only

Use `lsigresource.MaxLogicSigArgs` and `lsigresource.MaxLogicSigArgBytes` in Go, not
literals.

Know when each check runs. Install refuses a template past a limit, or one that
does not declare `valid_rekey_target` (admission:
`generictemplate.ValidateSpecAdmission`, `composeddsa.ValidateTemplateAdmission`).
Key generation checks a bounded account's argument layout. Signing refuses a supplied
argument over 4,096 bytes. Nothing is re-checked at load. When you add a restriction
on templates or keys, put it in an admission check (install or generation). Do not
add it to `ValidateSpec`, `ValidateTemplateSpec`, `ValidateRuntimeArgSpecs`, provider
construction, or durable metadata `Validate`: a store reload runs those and fails
closed, so a stored template or key that predates the restriction would stop the
whole store from loading.

## User-Loaded Template Flow

For a generic LogicSig YAML template:

```bash
apadmin template import <template.yaml>
```

For a composed DSA YAML template, use `template_type: composed` and
`base_key_type` for the signature construction, such as
`aplane.falcon1024.v1` for Falcon-backed templates or `aplane.ed25519.v1` for
Ed25519-backed
templates:

```bash
apadmin template import <template.yaml>
```

After installing:

1. The authenticated install reloads `apsigner` before reporting success.
2. Confirm discovery:
   ```text
   apshell keytypes
   ```
3. Generate the template-backed key:
   ```text
   apshell generate <keytype> param=value
   ```
4. Use the generated address in `send`, `close`, `sign`, or script flows.

Do not tell the user that editing top-level `library/templates/` installs a template.
Files under top-level `library/templates/` are library entries, not active
runtime definitions by presence alone. New stores install no templates; every
template requires an authenticated import or KeyType Library install, and
every creatable LogicSig key type (compiled or template) except the Falcon
plain host `aplane.falcon1024.v1` is opt-in, the Ed25519 plain host
`aplane.ed25519.v1` included. Only the protocol-native `ed25519` and
`falcon1024` and the Falcon plain host `aplane.falcon1024.v1` are enabled by
default.

For the full disable/remove mechanics (state record transitions, archive
locations, in-use guard, and reload behavior), see
[DEV_KEYTYPES.md](DEV_KEYTYPES.md) (Product Filesystem State and YAML Template
Notes).

Agent-facing rules that follow from those mechanics:

- Never describe a disabled installed template as removed; disable is
  reversible state-only, remove archives the encrypted source.
- Do not propose disable or remove while any product-store keys still use the key
  type — the operation is rejected by the in-use guard.
- Do not claim existing keys stop signing after disable or remove; they keep
  signing from their own stored metadata.

## Validation Expectations

For any template you write or modify, verify both positive and negative cases.

Positive cases should show the intended transaction succeeds, for example:

- normal send to an allowed receiver
- close-out to an explicitly allowed close address
- hashlock spend with the correct preimage
- timelock spend after the allowed round
- under `rekey: only_these` or `plus_cosigned`, a pure rekey to a listed
  address, with no cosigner signature on a cosigned account
- under a cosigned `spending_key` or `plus_cosigned`, a pure rekey to another
  address with the cosigner's signature

Negative cases should show forbidden behavior fails, for example:

- rekey attempt fails (under `only_these`, a rekey to an unlisted address;
  under a cosigned `spending_key`, a rekey without the cosigner's signature;
  under `plus_cosigned`, a rekey to an unlisted address without the cosigner's
  signature, or with a non-empty list proof that does not verify)
- send to an unapproved receiver fails
- close-out to an unapproved address fails
- ASA close/clawback fails when not explicitly allowed
- hashlock spend with missing/wrong preimage fails
- timelock spend before the allowed round fails

For integration tests, prefer the normal end-to-end harness path:

```bash
make integration-test-localnet INTEGRATION_GO_ARGS='-count=1 -timeout 25m -v -run <TestName>'
```

## When To Ask

Ask the user before writing a template if any of these are unclear:

- whether close-out should be allowed
- whether ASA transfers are in scope
- whether an allowlist applies to receiver, close address, or both
- whether the template should be generic or Falcon-signed
- whether runtime proof data is required
- whether changing an existing key type is intended

If in doubt, choose the safer policy: no rekey, no close-out, explicit
transaction type restrictions, and narrow recipient checks.
