# Agent Guide: Key Types and LogicSig Templates

This guide is for AI agents generating, reviewing, or modifying APlane key
types and LogicSig templates. Treat `docs/DEV_KEYTYPES.md` as the detailed
developer reference and `docs/USER_LOGICSIG_GUIDELINES.md` as the LogicSig
policy/security review reference; this file is the operational safety
checklist.

## Signing Authority

See [DEV_KEYTYPES.md](DEV_KEYTYPES.md) (Signing Authority) for the canonical
statement.

Operational consequence for agents: never edit, replace, or recompile a
template to "fix" signing for an existing key. The key file already carries the
signing authority. Treat template provenance warnings as inventory diagnostics,
not as a license to mutate stored bytecode or metadata.

## Default Behavior

When a user asks for a custom LogicSig template, default to a **user-loaded YAML
template** unless they explicitly ask to add a built-in provider to the source
tree.

Do not edit shipped library templates or Go providers just to satisfy a user's
custom policy. Shipped templates, compiled providers, and installed template key
types are compatibility boundaries. Changing the behavior of an existing key
type such as `aplane.whitelist.v1`, `aplane.falcon1024-whitelist.v1`, or
`aplane.htlc.v1` can break existing keys and backups.

Installing a user-loaded template with `apstore template import` requires the
identity master passphrase through the local daemon IPC session. An AI
agent cannot perform this step. Generate the YAML file and let the user run
the install command themselves.

Before writing any template, always ask the user whether the template should
cover ALGO payments only or both ALGO payments and ASA transfers. Do not
assume payment-only unless the user explicitly says so.

## Classify First

Before writing code or YAML, classify the requested key type:

| Request | Category | Normal output |
|---|---|---|
| TEAL-only escrow, whitelist, timelock, hashlock | Generic LogicSig template | YAML for `apstore template import` |
| Falcon signature plus additional TEAL checks | Composed DSA template | YAML for `apstore template import` |
| New signing algorithm or key material format | DSA/native provider work | Go implementation and registry changes |

If the user is asking for a template policy and does not mention Falcon,
generate a generic LogicSig YAML template.

For Go provider work, keep the client/signer boundary intact. Client-visible
provider metadata and LogicSig derivation may register through the LogicSig
provider registries, but private-key operations must be passed through explicit
signer/keygen ops in signer-side registration paths. A composed template names
its signing provider through `base_key_type` and registers its own keygen and
signing ops; the shared-ops fallback (described in DEV_KEYTYPES.md) is
acceptable only when the template changes TEAL/params and shares its
`base_key_type` provider's existing keygen/signing semantics. Do not use that
fallback for a new version that changes seed derivation, key format, signature
format, mnemonic behavior, or signing semantics.

## Naming Rules

Every custom template needs a unique versioned key type:

- Set `publisher` to a stable lowercase namespace owner such as `aplane`,
  a project name, or an organization name.
- Set `family` to a new stable lowercase name with no spaces.
- Set `version` to `1` for the first version.
- The resulting key type is `<publisher>.<family>.v<version>`.
- For composed DSA templates, use `base_key_type` to select the DSA provider
  and `family` to name the template's own versioned key-type line.
- Never reuse an existing built-in key type or previously installed custom key
  type for changed behavior.
- If behavior changes, create a new version such as `example.myescrow.v2`.

Use unique versioned names for optional template entries and test fixtures.
For user output, choose a name tied to the user's actual policy.

## Explicit Safety Decisions

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
template variables and symbolic references so APlane can own generated
constants and any derivation-version salt anchor safely. Do not add a custom
salt preamble or expose a YAML salt-style selector. Salt style is a versioned
provider/template derivation contract owned by APlane. Templates with omitted
`derivation_version` are unsalted and compile exactly as written, succeeding
only if the unmodified bytecode already derives an off-curve LogicSig address;
new template-derived key types should use `derivation_version: 2` for the
trailing dead-code `bytecblock` salt anchor.

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
- whitelist entries
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

## User-Loaded Template Flow

For a generic LogicSig YAML template:

```bash
apstore template import <template.yaml>
```

For a Falcon-backed composed DSA YAML template, use `template_type: composed`
and `base_key_type: aplane.falcon1024.v1`:

```bash
apstore template import <template.yaml>
```

After installing:

1. Unlock or reload `apsigner`.
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
Files under top-level `library/templates/` are optional library entries. They become
installed only after `apstore template import`.

For the full disable/remove mechanics (state record transitions, archive
locations, in-use guard, and reload behavior), see
[DEV_KEYTYPES.md](DEV_KEYTYPES.md) (Identity Filesystem State and YAML Template
Notes).

Agent-facing rules that follow from those mechanics:

- Never describe a disabled installed template as removed; disable is
  reversible state-only, remove archives the encrypted source.
- Do not propose disable or remove while any identity keys still use the key
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

Negative cases should show forbidden behavior fails, for example:

- rekey attempt fails
- send to an unapproved receiver fails
- close-out to an unapproved address fails
- ASA close/clawback fails when not explicitly allowed
- hashlock spend with missing/wrong preimage fails
- timelock spend before the allowed round fails

For integration tests, prefer the normal end-to-end harness path:

```bash
make integration-test INTEGRATION_GO_ARGS='-count=1 -timeout 25m -v -run <TestName>'
```

## When To Ask

Ask the user before writing a template if any of these are unclear:

- whether close-out should be allowed
- whether ASA transfers are in scope
- whether a whitelist applies to receiver, close address, or both
- whether the template should be generic or Falcon-signed
- whether runtime proof data is required
- whether changing an existing key type is intended

If in doubt, choose the safer policy: no rekey, no close-out, explicit
transaction type restrictions, and narrow recipient checks.
