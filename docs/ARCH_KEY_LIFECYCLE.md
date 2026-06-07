# Key And Key Type Lifecycle

> State model for signer key files, key type definitions, key type state
> records, template provenance, and backup/restore behavior.

## Contents

- [Purpose](#purpose)
- [Core Rule](#core-rule)
- [Objects](#objects)
- [Identity Mode Gate](#identity-mode-gate)
- [Key Type Lifecycle](#key-type-lifecycle)
- [Key File Lifecycle](#key-file-lifecycle)
- [Backup And Restore Matrix](#backup-and-restore-matrix)
- [Runtime Reload Behavior](#runtime-reload-behavior)
- [Transition Catalog](#transition-catalog)
- [Invariants](#invariants)
- [Source Of Truth](#source-of-truth)

## Purpose

This document describes durable key and key type states that affect:

- whether an identity can discover or generate a key type,
- whether an existing key can sign,
- what restore preview/apply may write,
- how disabled or conflicting key type records behave,
- which warnings are provenance-only.

It is the key/keytype companion to transaction lifecycle documentation. It does
not define transaction planning, policy verdicts, endpoint routing, token
provisioning, or approval prompts.

## Core Rule

**Key type state controls discovery and generation. Key files control restore
and signing.**

Templates and key type state records are generation/catalog data. They are not
signing authority for an already-created key. A current-format LogicSig key file
stores its bytecode, salt counter, signing metadata, creation parameters, and
base signing provider reference where needed. The signer must never reconstruct
missing signing authority from a current template or library entry.

This separation is deliberate:

- disabling a key type can hide it from new-key generation without breaking
  existing keys,
- restoring a key can work even when the creation template is absent, disabled,
  or locally conflicting,
- provenance warnings can tell operators that the current local definition no
  longer matches the key's original creation definition without changing
  signability.

## Objects

| Object | Durable location | Authority |
|---|---|---|
| Native key file | `identities/<identity>/keys/<address>.key` | Native signing authority. |
| LogicSig key file | `identities/<identity>/keys/<address>.key` | LogicSig bytecode, salt, signing metadata, and any private DSA key material. |
| Attestor component key file | `identities/<identity>/keys/<a_selector>.key` | Component-signing authority for `/sign/component`; not an Algorand spending account. |
| Attestor public sidecar | `identities/<identity>/keys/<a_selector>.public.json` | Public export metadata for component keys. |
| Identity mode | `identities/<identity>/config.yaml` `mode` | Key-class inventory and service-dispatch gate. |
| Key type state record | `identities/<identity>/keytypes/<key_type>.json` | Identity-local discovery/generation state. |
| Installed YAML template | `identities/<identity>/keytypes/<key_type>.template` | Encrypted generation source for that identity after reload. |
| Deleted key archive | `identities/<identity>/deleted/keys/` | Removed key files; outside active scans. |
| Deleted template archive | `identities/<identity>/deleted/keytypes/` | Removed template files; outside active scans. |
| Signer library template | `library/templates/<key_type>.yaml` | Install source only; not active by itself. |
| Compiled provider | Go provider registry and key type catalog | Binary capability; identity visibility may be default-enabled or opt-in. |
| Backup payload | `.apb` inside managed backup archive | Encrypted backup unit containing a key and optional bundled template provenance. |

Component public sidecars are derived public metadata, not independent signing
authority. They exist so `apstore attestor export-public` can work without
decrypting private key material. Backup payloads do not need to carry the
sidecar as a separate authority; restore flows that write attestor component
keys must regenerate the sidecar from the restored component key payload.
Missing sidecars do not make a component key unable to sign, but they do block
offline public export until regenerated or backfilled.

## Identity Mode Gate

Identity mode is an orthogonal key-class gate. It applies before ordinary key
type state can make a key type usable for generation, and reload rejects a
scanned key inventory that conflicts with the identity mode.

| Mode | Stored value | Allowed active key classes | Disallowed active key classes |
|---|---|---|---|
| Signing | `mode: signing`, or omitted | Native signing keys, ordinary LogicSig keys, attested account keys. | Attestor component keys. |
| Attestation | `mode: attestation` | Attestor component keys. | Native signing keys, ordinary LogicSig keys, attested account keys. |
| Dual | `mode: dual` | Both account-signing and attestor component key classes. | None by class. |

Mode is not a trust proof and does not replace transaction policy or attestor
policy. It is a local least-privilege and drift-protection gate:

- key generation and mnemonic import reject key types forbidden by the identity
  mode,
- unlock/reload rejects scanned active keys forbidden by the identity mode,
- account-signing endpoints reject `attestation` mode identities,
- attestor-role component signing rejects `signing` mode identities,
- user-role component signing and attested assembly reject `attestation` mode
  identities.

`dual` means both key classes are allowed by mode. It does not mean every
composition of those keys is acceptable. The same-account self-attestation guard
still forbids one identity from holding both an attested account key and the
attestor component key embedded in that same account, outside explicitly marked
local-development flows.

Mode changes are guarded transitions:

| Transition | Preconditions | Result |
|---|---|---|
| `signing` -> `dual` | Existing inventory is already valid in `signing` mode. | Attestor component keys may be added after the change. |
| `attestation` -> `dual` | Existing inventory is already valid in `attestation` mode. | Account-signing keys may be added after the change. |
| `dual` -> `signing` | No active attestor component keys exist. | Account-signing identity; attestor component keys remain forbidden. |
| `dual` -> `attestation` | No active signing-class keys exist. | Attestor identity; account-signing keys remain forbidden. |
| `signing` -> `attestation` | No active signing-class keys exist. | Equivalent to tightening to an attestor-only identity; the signer must not delete keys to make this true. |
| `attestation` -> `signing` | No active attestor component keys exist. | Equivalent to tightening to a signer-only identity; the signer must not delete keys to make this true. |

The signer must refuse a tightening mode change while contradictory active key
files exist. It must not silently delete keys, and it must not silently ignore
contradictory keys while claiming the tighter mode.

## Key Type Lifecycle

Key type state answers this question:

```text
Can this identity discover this key type and generate new keys of this type?
```

It does not answer whether an existing key file can sign, and it is still
subject to the identity mode gate above.

### Key Type State Matrix

| State | Durable representation | Discovery/generation | Existing-key signing | Normal transition |
|---|---|---|---|---|
| Unsupported by binary | No provider is registered in the current process. | No. | No, if signing needs that provider; native/DSA key types need registered support. | Install/run a binary that supports the key type. |
| Mode-forbidden key type | The identity mode does not allow this key class. | No, even if the provider is default-enabled or activated. | No for active inventory; reload rejects mode-conflicting active keys. | Change mode only after active key inventory already matches the target mode, or remove conflicting keys first. |
| Default-enabled account-signing provider | Provider/generator is registered and cataloged as default-enabled; no identity record required. Examples include `ed25519` and `aplane.falcon1024.v1`. | Yes when allowed by identity mode. | Yes, if the key file is valid and allowed by identity mode. | None. |
| Default-enabled attestor component key type | Raw component key generator/signing support is registered and cataloged as default-enabled. Examples are `aplane.attestor-ed25519.v1` and `aplane.attestor-falcon1024.v1`. | Yes in `attestation` or `dual`; no in `signing`. | Component-signing only, if the key file is valid and allowed by identity mode; never normal spending `/sign`. | None. |
| Library-visible compiled provider, inactive | Provider is registered and cataloged as library-visible; no identity `keytypes/<key_type>.json` record exists. | No. | Existing key may sign if the provider is registered, the key file is valid, and identity mode allows it. | Enable from KeyType Library or `apstore keytype enable`. |
| Library-visible compiled provider, enabled and fingerprint consistent | `keytypes/<key_type>.json` has `source:"compiled"`, `state:"enabled"`, and matching fingerprint. | Yes when allowed by identity mode. | Yes, if the key file is valid and allowed by identity mode. | Disable, if no stored key uses it. |
| Library-visible compiled provider, enabled but fingerprint inconsistent | State record exists, but the stored fingerprint does not match the provider fingerprint in the current binary. | No; reload ignores the conflicting activation record. | Existing key may sign if the provider is registered, the key file is valid, and identity mode allows it. | Refresh with `apstore keytype enable <key_type>`. |
| Signer library YAML only | Plaintext YAML exists under `library/templates/`; no identity install exists. | No. | No effect on existing keys. | Install/import template into identity. |
| YAML installed and enabled | Encrypted `.template` exists and state record has `source:"yaml_generic"` or `source:"yaml_composed"` plus `state:"enabled"`. | Yes after successful reload, when allowed by identity mode. | Existing keys sign from stored key metadata, not the template, when allowed by identity mode. | Disable or remove, if no stored key uses it. |
| YAML installed and disabled | Encrypted `.template` exists and state record has `state:"disabled"`. | No. | Existing keys sign from stored key metadata, not the template, when allowed by identity mode. | Enable, remove, or explicit template restore may re-enable. |
| YAML integrity or fingerprint mismatch | Encrypted `.template` does not match the state record fingerprint, cannot decrypt, or parses to incompatible metadata. | No; reload rejects that template. | Existing keys may still sign from stored key metadata if otherwise valid and allowed by identity mode. | Reinstall through supported template import/install path. |
| YAML removed | State record is deleted and encrypted `.template` is moved to `deleted/keytypes/`. | No. | Existing keys may still sign from stored key metadata if otherwise valid and allowed by identity mode. | Reinstall/import template. |

### Key Type Transitions

| Transition | Preconditions | Write or runtime action | Result |
|---|---|---|---|
| Enable compiled provider | Provider is registered and library-visible. | Write enabled `source:"compiled"` state record with current fingerprint. | Identity can discover/generate that key type after reload. |
| Disable compiled provider | No active key file in the identity uses that key type. | Delete the compiled state record. | Provider remains in the binary, but the identity can no longer generate it. |
| Install YAML template | Candidate YAML parses, key type is valid, and install is authorized. | Encrypt YAML into `.template`, write enabled state record, reload identity. | Identity can discover/generate the template key type. |
| Disable YAML template | No active key file in the identity uses that key type. | Set state record to `disabled`, keep encrypted `.template`. | Template remains installed but hidden from generation. |
| Enable YAML template | Encrypted `.template` and state record are valid. | Set state record to `enabled`, reload identity. | Template is visible for generation. |
| Remove YAML template | No active key file in the identity uses that key type. | Delete state record and move `.template` to `deleted/keytypes/`. | Template leaves active scans. |
| Binary upgrade with changed compiled fingerprint | Existing state record fingerprint no longer matches provider. | Reload ignores the conflicting activation. | Generation is hidden until re-activated; valid existing keys are not rewritten. |
| Manual file edit or copy | Operator changes state/template files outside supported paths. | Reload validates and fails closed for invalid records/templates. | Repair through supported install/activate paths. |

The unused-key guard on disable/remove/deactivate protects operators from
accidentally hiding the normal generation source for a key type still in use.
It is not a sign-time dependency rule; a valid existing key file remains the
signing authority.

## Key File Lifecycle

Key file state answers this question:

```text
Can this stored key be loaded and used for the signing path it belongs to?
```

Key files must also be allowed by the identity mode gate. A mode-conflicting
active key is rejected during reload rather than published as a signable key.

### Key File State Matrix

| State | Durable representation | Signability | Backup/restore behavior |
|---|---|---|---|
| Absent | No active key file under `keys/`. | No. | May be restored from a backup payload. |
| Archived/deleted | Key file moved to `deleted/keys/`. | No; outside active scans. | Restore can write a new active canonical key file if selected. |
| Present but signer locked | Encrypted `.key` exists but identity has no active key session. | No until unlock. | Backup can include active encrypted key files; restore requires authenticated/unlocked flow. |
| Present, decrypts, canonical filename matches derived address/selector | Active `.key` basename matches derived address or component selector. | Candidate for signing after category-specific validation. | Backup and restore use canonical filenames. |
| Misnamed key file | `.key` basename does not match the derived address/selector. | No; scanner rejects/skips it. | Restore writes the canonical filename when it elects to restore. |
| Mode-forbidden key file | Key type is valid, but the active identity mode does not allow that key class. | No; reload rejects the inventory conflict. | Restore/generation should refuse until the identity mode allows that key class. |
| Unknown key type | Payload names a key type unsupported by the current binary. | No. | Restore fails for that key unless support exists. |
| Native key valid | Native key payload has valid key material and canonical key type. | Yes on native signing paths. | Restores directly. |
| DSA LogicSig key valid | Payload has private DSA material, stored LogicSig bytecode, `salt_counter`, `signing_metadata_version`, `base_key_type`, and valid signing metadata. | Yes when the base signing provider is registered. | Restores from stored metadata; composed template is not required. |
| Generic LogicSig key valid | Payload has stored LogicSig bytecode, `salt_counter`, `signing_metadata_version`, and stored signing args. | Yes. | Restores from stored metadata; template is not required. |
| Attestor component key valid | Payload category/type is an attestor component key and selector is canonical. | Only through component-signing role; normal `/sign` and spending paths reject it. | Restores as a component key, regenerating the public sidecar; never as a spending account. |
| Attested account key valid | DSA LogicSig key whose bytecode embeds the attestor public key. | Only through attested orchestration: user component signature, attestor component signature, local assembly. | Restores from stored bytecode and metadata. |
| LogicSig missing `salt_counter` | Payload has LogicSig bytecode but no salt counter. | No; scan/verify/restore reject. | Restore rejects. |
| LogicSig on-curve address | Stored LogicSig bytecode derives an on-curve address. | No; scan/verify/restore reject. | Restore rejects. |
| LogicSig missing v1 signing metadata | Payload has bytecode but lacks `signing_metadata_version` where signing/restore would need durable metadata. | No. | Restore rejects instead of reconstructing from template. |
| DSA key missing supported base provider | DSA LogicSig names a `base_key_type` not registered in the current binary. | No. | Restore fails for that key unless the base provider is supported. |
| Template provenance unavailable | Key has no matching current template/provider fingerprint for comparison. | Yes, if key metadata is valid. | Warning/inventory note only. |
| Template provenance conflict | Key's optional `template_fingerprint` differs from current local definition. | Yes, if key metadata is valid. | Warning/inventory note only. |

### Key File Transitions

| Transition | Preconditions | Write or runtime action | Result |
|---|---|---|---|
| Generate key | Key type is discoverable/generatable and required parameters are valid. | Create encrypted canonical `.key`; LogicSig generation stores bytecode, salt, signing metadata, creation params, and optional template fingerprint. | Key becomes active after reload/scan. |
| Import mnemonic | Provider explicitly supports mnemonic import. | Derive key material and write encrypted canonical `.key`. | Key becomes active after reload/scan. |
| Delete key | Authenticated admin request selects active key. | Move `.key` to `deleted/keys/`. | Key leaves active scans. |
| Backup create | Active key files are selected. | Write encrypted `.apb` payloads in managed backup archive. | Source key files remain unchanged. |
| Restore preview | Managed archive and passphrase are valid. | Decrypt/inspect payloads without mutation. | Reports addresses, key types, conflicts, errors, and template requirements. |
| Restore apply | Selected payload passes validation and no unhandled existing-key conflict remains. | Write canonical encrypted `.key`, optionally install/enable needed template or compiled state, then reload identity. | Key becomes active; per-key rollback undoes restore side effects if final key write fails. |
| Unlock/reload | Master key is available. | Register enabled templates, scan key files, publish runtime indexes. | Valid active keys become signable; rejected files are diagnostics. |
| Repair template provenance | Template/provider state is reinstalled or reactivated. | No key-file rewrite required unless explicitly restoring missing provenance. | Inventory warnings may clear; signing behavior is unchanged. |

## Backup And Restore Matrix

This matrix describes restoring a key whose backup refers to a template-backed
or library-visible key type. Native default-enabled keys follow the direct key
restore path.

| Destination key type state | Key restore | Template/provider restore | Generation after restore |
|---|---|---|---|
| Identity mode forbids key class | Fails or is rejected before publishing active inventory. | No template/provider state should be installed for the forbidden class. | No until mode changes and inventory is reconciled. |
| Key type unsupported by binary | Fails if the key needs that provider or base provider. | Cannot install a runtime provider not supported by the binary. | No. |
| Key type missing locally | Succeeds when the key payload has complete current-format signing metadata and any needed base provider is supported. | Bundled template may be installed only when no authoritative local source exists; library-visible compiled provider activation is created as needed. | Yes only if restore installs/enables a template or activates a compiled provider. |
| Key type imported/installed but disabled | Key restore does not require enabling the template to sign. | Explicit template restore or matching bundled template restore may re-enable it; key restore alone does not need to. | No unless explicitly enabled/re-enabled. |
| Key type enabled and fingerprint consistent | Normal path. | Restore uses the local authoritative definition; identical bundled definitions are provenance only. | Yes. |
| Key type enabled but fingerprint inconsistent | Key restore may still succeed from stored signing metadata; reload may ignore the bad activation/template. | Conflicting bundled template is skipped for key restore and surfaced as a warning; explicit template restore rejects conflicts. | No until repaired. |
| Local template conflicts with bundled template | Key restore writes the key from stored metadata and skips the bundled template with a warning. | Local definition is not overwritten. | Existing local generation state remains as it was. |
| Backup lacks bundled template | Current-format key restore can still succeed from stored key metadata. | No template installed from the backup. | No change unless compiled provider activation is needed and supported. |
| Key already exists | Skipped unless overwrite is explicitly requested. | Restore side effects are avoided or rolled back per key. | Existing destination state remains authoritative. |

Restore precedence for same-`key_type` template definitions is:

1. signer-data library template,
2. existing identity-local installed template, whether enabled or disabled,
3. bundled template from the backup, only when no local source exists.

The restore path never silently changes what a local `key_type` means.

## Runtime Reload Behavior

Unlock/reload publishes a new runtime snapshot only after validation succeeds.
The relevant order is:

1. derive or reuse the identity master key,
2. load and validate identity config, policy, and attestor policy,
3. apply identity mode to key type discovery and service dispatch,
4. register enabled compiled/YAML key type state,
5. register enabled installed templates,
6. scan active key files and validate the scanned inventory against mode,
7. publish runtime key indexes and key type discovery data.

Reload failures fail closed. For policy/config failures, the previous in-memory
snapshot remains active when one exists. Ordinary malformed, misnamed, or
unsupported key/template artifacts may be excluded from new runtime indexes and
surfaced as diagnostics rather than treated as signable authority.

Mode-conflicting key inventory is not ordinary per-item invalidity. It is a
store-level contradiction for that identity: reload must fail closed without
publishing a new active key snapshot for the contradictory inventory. This is a
deliberate safety/availability tradeoff. A hand-placed conflicting `.key` can
brick the identity until the operator removes it, while supported restore/import
paths should preflight mode before writing so this fail-closed path remains a
backstop.

Disabled key type state affects discovery and generation. It does not remove
already-valid key files from active key scans.

Identity mode is stronger than disabled/enabled state: a mode-forbidden active
key is not published as valid runtime inventory.

## Transition Catalog

| Operation | Key type state effect | Key file effect | Notes |
|---|---|---|---|
| Change identity mode | None directly; changes which key classes may be discovered/generated. | None; mode change is refused unless existing active key inventory already matches the target mode. | Never silently deletes or ignores conflicting keys. |
| `apstore keytype enable` | Writes/refreshes compiled enabled state, or enables an installed YAML template. | None. | Does not rewrite existing keys. |
| `apstore keytype disable` | Deletes compiled state or disables an installed YAML template after the unused-key guard. | None. | Provider code and installed template files remain available to the store. |
| `apstore template import` | Installs encrypted template and enabled state. | None. | Active after reload. |
| `apstore template remove` | Deletes state and archives `.template` after unused-key guard. | None. | Removed template leaves active scans. |
| Key generation | Requires discoverable/generatable key type allowed by identity mode. | Writes new encrypted key. | LogicSig key stores signing authority at creation time. |
| Key deletion | None. | Archives active key file. | Archived keys are not signable. |
| Backup create | None. | Reads selected active key files into encrypted backup payloads. | Source store unchanged. |
| Backup import | None in active identity. | None in active identity. | Validates archive before publishing to managed backup locker. |
| Restore preview | None. | None. | Decrypts and reports only. |
| Restore apply | May install/enable required template or activate compiled provider when identity mode allows it. | Writes selected keys. | Per-key rollback on final write failure. |
| Store passphrase change | Re-encrypts installed templates and keys. | Re-encrypts keys. | Authority and state are unchanged. |
| Binary upgrade | May change compiled provider availability/fingerprints. | Existing keys unchanged. | Bad activations require explicit refresh. |
| Sign request | None. | Reads already-loaded key metadata. | Key type discovery state is not a sign-time authorization gate. |

## Invariants

1. Key files are the signing authority for existing keys.
2. Key type state records are discovery/generation state, not signing authority.
3. Templates are generation/provenance definitions, not reconstruction sources
   for missing signing metadata.
4. Identity mode gates allowed key classes for generation, reload, and signing
   endpoint dispatch.
5. Disabled key types block new-key discovery/generation, not valid existing-key
   signing.
6. LogicSig keys must carry durable v1 signing metadata when signing/restore
   would need it.
7. LogicSig key bytecode must derive an off-curve LogicSig address.
8. DSA LogicSig keys require their stored `base_key_type` provider to be
   supported at sign time.
9. Attestor component keys are component-signing keys, not spending accounts.
10. Attestor component public sidecars are derived public metadata and must not
    be treated as independent signing authority.
11. Attested account keys use the attested orchestration flow; normal `/sign`
   rejects them.
12. `dual` mode permits both key classes, but it does not waive the
    same-account self-attestation guard.
13. Backup restore is per-key and must not silently redefine an existing local
    `key_type`.
14. Template/provider fingerprint conflicts are generation/provenance problems,
    not automatic invalidation of otherwise valid key files.

## Source Of Truth

Primary implementation owners:

- key payload parsing/scanning: `internal/keys`
- component public sidecars: `internal/keys/component_public_metadata.go`
- encrypted key and template storage: `internal/keystore`,
  `internal/templatestore`
- identity mode and key-class gates: `internal/signerapp/identity`,
  `internal/signerapp/rest`
- key type state records: `internal/keytypestate`
- key type catalog: `internal/keytypecatalog`
- LogicSig provider registry and template loading: `internal/lsigprovider`,
  `internal/signerapp/templates`
- key generation: `internal/keygen`, `internal/signerapp/keyadmin`
- key type/template admin: `internal/signerapp/templateadmin`
- backup/restore: `internal/backup`, `internal/signerapp/backupadmin`
- signing execution: `internal/signerapp/signing`

Related documents:

- [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md): compatibility-bearing file and
  restore contracts
- [ARCH_DATA_MODEL.md](ARCH_DATA_MODEL.md): durable/runtime/wire data model
- [DEV_KEYTYPES.md](DEV_KEYTYPES.md): developer guide for adding key types
- [USER_KEYTYPES.md](USER_KEYTYPES.md): operator key type management
- [USER_STORE_MGMT.md](USER_STORE_MGMT.md): backup and restore guide
