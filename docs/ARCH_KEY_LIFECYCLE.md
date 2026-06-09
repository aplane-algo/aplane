# Key And Key Type Lifecycle

> State model for signer key files, key type definitions, key type state
> records, template provenance, node role, and backup/restore behavior.

## Contents

- [Purpose](#purpose)
- [Core Rule](#core-rule)
- [Objects](#objects)
- [Node Role Gate](#node-role-gate)
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
| Sentry component key file | `identities/<identity>/keys/<component_selector>.key` | Component-signing authority for sentry-role `/sign/component`; not an Algorand spending account. |
| Sentry public sidecar | `identities/<identity>/keys/<component_selector>.public.json` | Public export metadata for local component keys. |
| Node role | `<APSIGNER_DATA>/node.yaml` | Single-purpose role for the signer data root. |
| Node role integrity sidecar | `identities/<identity>/node.yaml.hmac` | Per-identity HMAC over the exact root `node.yaml` bytes. |
| Identity config | `identities/<identity>/config.yaml` | Identity-local runtime settings such as approval/lock timeouts and decommission state; it does not carry key-class role. |
| Key type state record | `identities/<identity>/keytypes/<key_type>.json` | Identity-local discovery/generation state. |
| Installed YAML template | `identities/<identity>/keytypes/<key_type>.template` | Encrypted generation source for that identity after reload. |
| Deleted key archive | `identities/<identity>/deleted/keys/` | Removed key files; outside active scans. |
| Deleted template archive | `identities/<identity>/deleted/keytypes/` | Removed template files; outside active scans. |
| Signer library template | `library/templates/<key_type>.yaml` | Install source only; not active by itself. |
| Compiled provider | Go provider registry and key type catalog | Binary capability; identity visibility may be default-enabled or opt-in. |
| Backup payload | `.apb` inside managed backup archive | Encrypted backup unit containing a key and optional bundled template provenance. |

Component public sidecars are derived public metadata, not independent signing
authority. They exist so `apstore sentry export` can work without
decrypting private key material. Backup payloads do not need to carry the
sidecar as a separate authority; restore flows that write sentry component
keys must regenerate the sidecar from the restored component key payload.
Missing sidecars do not make a component key unable to sign, but they do block
offline public export until regenerated or backfilled.

The durable and wire contracts use `component_key`, `component_selector`, and
component signing terminology. Human-facing UI may label the same selector as a
Sentry Key or Sentry Key ID; that label does not change the storage or HTTP
field names.

`node.yaml` is plaintext so the process can report its role during early
startup. That plaintext is only a hint until each initialized identity verifies
its HMAC sidecar after unlock. The sidecar key is derived from that identity's
master key, following the same tamper-detection model used by policy sidecars.

## Node Role Gate

Node role is the single-purpose key-class gate for an apsigner data directory.
It applies before ordinary key type state can make a key type usable for
generation, and reload rejects active key inventory that conflicts with the
node role.

`<APSIGNER_DATA>/node.yaml` has this schema:

```yaml
schema_version: 1
role: signer
created_at: "2026-06-07T00:00:00Z"
```

Valid roles are exactly `signer` and `sentry`.

| Node role | Allowed active key classes | Disallowed active key classes | Served signing paths |
|---|---|---|---|
| `signer` | Native signing keys, ordinary LogicSig keys, guarded account keys, and public sentry references used for generation. | Sentry component private keys. | Normal `/sign`, user-role `/sign/component`, `/sign/assemble`. |
| `sentry` | Sentry component private keys and their public sidecars. | Native signing keys, ordinary LogicSig account keys, and guarded account keys. | Sentry-role `/sign/component`. |

Rules:

- every initialized signer data root has one root `node.yaml`,
- new installs default to `role: signer` unless the initializer explicitly
  creates a sentry node,
- there is no `dual` role,
- there is no supported role-change command,
- identity-level `mode` is an unsupported pre-release shape and startup rejects
  it rather than migrating it,
- key generation, mnemonic import, restore, and out-of-band key scans must
  reject key classes forbidden by the node role,
- service endpoints reject role/use mismatches even if a forbidden key file is
  present on disk.

A node may host multiple identities, but all identities inherit the same root
node role. Role-conflicting key inventory anywhere in the data directory is a
node-level store contradiction: startup/reload fails closed for the node rather
than silently quarantining only one identity. This is a deliberate
safety/availability tradeoff. A hand-placed conflicting `.key` can make the
node unavailable until the operator removes it, while supported restore/import
paths should preflight role before writing so this fail-closed path remains a
backstop. After a reload detects a role inventory conflict, the process marks
the identity registry closed so HTTP and admin identity resolution refuse all
identities until operator cleanup and restart.

Local development that needs both roles uses two complete data roots and two
apsigner processes, for example `~/aplane-signer/` and `~/aplane-sentry/`.
Running those two nodes on one host is useful for development and operations,
but it is not independent sentry. Independence remains a deployment-domain
property.

## Key Type Lifecycle

Key type state answers this question:

```text
Can this identity discover this key type and generate new keys of this type?
```

It does not answer whether an existing key file can sign, and it is still
subject to the node role gate above.

### Key Type State Matrix

| State | Durable representation | Discovery/generation | Existing-key signing | Normal transition |
|---|---|---|---|---|
| Unsupported by binary | No provider is registered in the current process. | No. | No, if signing needs that provider; native/DSA key types need registered support. | Install/run a binary that supports the key type. |
| Role-forbidden key type | The node role does not allow this key class. | No, even if the provider is default-enabled or enabled. | No for active inventory; reload rejects role-conflicting active keys. | Use a data root initialized for the correct node role. |
| Default-enabled account-signing provider | Provider/generator is registered and cataloged as default-enabled; no identity record required. Examples include `ed25519` and `aplane.falcon1024.v1`. | Yes on signer nodes. | Yes on signer nodes, if the key file is valid. | None. |
| Default-enabled sentry component key type | Raw component key generator/signing support is registered and cataloged as default-enabled. Examples are `aplane.sentry-ed25519.v1` and `aplane.sentry-falcon1024.v1`. | Yes on sentry nodes. | Component-signing only on sentry nodes; never normal spending `/sign`. | None. |
| Library-visible compiled provider, inactive | Provider is registered and cataloged as library-visible; no identity `keytypes/<key_type>.json` record exists. | No. | Existing key may sign if the provider is registered, the key file is valid, and the node role allows it. | Enable from KeyType Library or `apstore keytype enable`. |
| Library-visible compiled provider, enabled and fingerprint consistent | `keytypes/<key_type>.json` has `source:"compiled"`, `state:"enabled"`, and matching fingerprint. | Yes when allowed by node role. | Yes, if the key file is valid and allowed by node role. | Disable, if no stored key uses it. |
| Library-visible compiled provider, enabled but fingerprint inconsistent | State record exists, but the stored fingerprint does not match the provider fingerprint in the current binary. | No; reload ignores the conflicting activation record. | Existing key may sign if the provider is registered, the key file is valid, and node role allows it. | Refresh with `apstore keytype enable <key_type>`. |
| Signer library YAML only | Plaintext YAML exists under `library/templates/`; no identity install exists. | No. | No effect on existing keys. | Install/import template into identity. |
| YAML installed and enabled | Encrypted `.template` exists and state record has `source:"yaml_generic"` or `source:"yaml_composed"` plus `state:"enabled"`. | Yes after successful reload, when allowed by node role. | Existing keys sign from stored key metadata, not the template, when allowed by node role. | Disable or remove, if no stored key uses it. |
| YAML installed and disabled | Encrypted `.template` exists and state record has `state:"disabled"`. | No. | Existing keys sign from stored key metadata, not the template, when allowed by node role. | Enable, remove, or explicit template restore may re-enable. |
| YAML integrity or fingerprint mismatch | Encrypted `.template` does not match the state record fingerprint, cannot decrypt, or parses to incompatible metadata. | No; reload rejects that template. | Existing keys may still sign from stored key metadata if otherwise valid and allowed by node role. | Reinstall through supported template import/install path. |
| YAML removed | State record is deleted and encrypted `.template` is moved to `deleted/keytypes/`. | No. | Existing keys may still sign from stored key metadata if otherwise valid and allowed by node role. | Reinstall/import template. |

### Key Type Transitions

| Transition | Preconditions | Write or runtime action | Result |
|---|---|---|---|
| Enable compiled provider | Provider is registered and library-visible. | Write enabled `source:"compiled"` state record with current fingerprint. | Identity can discover/generate that key type after reload. |
| Disable compiled provider | No active key file in the identity uses that key type. | Delete the compiled state record. | Provider remains in the binary, but the identity can no longer generate it. |
| Install YAML template | Candidate YAML parses, key type is valid, and install is authorized. | Encrypt YAML into `.template`, write enabled state record, reload identity. | Identity can discover/generate the template key type. |
| Disable YAML template | No active key file in the identity uses that key type. | Set state record to `disabled`, keep encrypted `.template`. | Template remains installed but hidden from generation. |
| Enable YAML template | Encrypted `.template` and state record are valid. | Set state record to `enabled`, reload identity. | Template is visible for generation. |
| Remove YAML template | No active key file in the identity uses that key type. | Delete state record and move `.template` to `deleted/keytypes/`. | Template leaves active scans. |
| Binary upgrade with changed compiled fingerprint | Existing state record fingerprint no longer matches provider. | Reload ignores the conflicting activation. | Generation is hidden until re-enabled; valid existing keys are not rewritten. |
| Manual file edit or copy | Operator changes state/template files outside supported paths. | Reload validates and fails closed for invalid records/templates. | Repair through supported install/enable paths. |

The unused-key guard on disable/remove protects operators from accidentally
hiding the normal generation source for a key type still in use. It is not a
sign-time dependency rule; a valid existing key file remains the signing
authority.

## Key File Lifecycle

Key file state answers this question:

```text
Can this stored key be loaded and used for the signing path it belongs to?
```

Key files must also be allowed by the node role gate. A role-conflicting active
key is rejected during reload rather than published as a signable key.

### Key File State Matrix

| State | Durable representation | Signability | Backup/restore behavior |
|---|---|---|---|
| Absent | No active key file under `keys/`. | No. | May be restored from a backup payload. |
| Archived/deleted | Key file moved to `deleted/keys/`. | No; outside active scans. | Restore can write a new active canonical key file if selected. |
| Present but signer locked | Encrypted `.key` exists but identity has no active key session. | No until unlock. | Backup can include active encrypted key files; restore requires authenticated/unlocked flow. |
| Present, decrypts, canonical filename matches derived address/selector | Active `.key` basename matches derived address or component selector. | Candidate for signing after category-specific validation. | Backup and restore use canonical filenames. |
| Misnamed key file | `.key` basename does not match the derived address/selector. | No; scanner rejects/skips it. | Restore writes the canonical filename when it elects to restore. |
| Role-forbidden key file | Key type is valid, but the node role does not allow that key class. | No; reload rejects the inventory conflict. | Restore/generation should refuse unless the destination node role allows that key class. |
| Unknown key type | Payload names a key type unsupported by the current binary. | No. | Restore fails for that key unless support exists. |
| Native key valid | Native key payload has valid key material and canonical key type. | Yes on signer nodes. | Restores directly onto signer nodes. |
| DSA LogicSig key valid | Payload has private DSA material, stored LogicSig bytecode, `salt_counter`, `signing_metadata_version`, `base_key_type`, and valid signing metadata. | Yes on signer nodes when the base signing provider is registered. | Restores from stored metadata; composed template is not required. |
| Generic LogicSig key valid | Payload has stored LogicSig bytecode, `salt_counter`, `signing_metadata_version`, and stored signing args. | Yes on signer nodes. | Restores from stored metadata; template is not required. |
| Sentry component key valid | Payload category/type is a sentry component key and selector is canonical. | Only through sentry-role component signing on sentry nodes; normal `/sign` and spending paths reject it. | Restores as a component key on sentry nodes, regenerating the public sidecar; never as a spending account. |
| Guarded account key valid | DSA LogicSig key whose bytecode embeds the sentry public key. | Only on signer nodes through guarded orchestration: user component signature, sentry component signature, local assembly. | Restores from stored bytecode and metadata. |
| LogicSig missing `salt_counter` | Payload has LogicSig bytecode but no salt counter. | No; scan/verify/restore reject. | Restore rejects. |
| LogicSig on-curve address | Stored LogicSig bytecode derives an on-curve address. | No; scan/verify/restore reject. | Restore rejects. |
| LogicSig missing v1 signing metadata | Payload has bytecode but lacks `signing_metadata_version` where signing/restore would need durable metadata. | No. | Restore rejects instead of reconstructing from template. |
| DSA key missing supported base provider | DSA LogicSig names a `base_key_type` not registered in the current binary. | No. | Restore fails for that key unless the base provider is supported. |
| Template provenance unavailable | Key has no matching current template/provider fingerprint for comparison. | Yes, if key metadata is valid and node role allows it. | Warning/inventory note only. |
| Template provenance conflict | Key's optional `template_fingerprint` differs from current local definition. | Yes, if key metadata is valid and node role allows it. | Warning/inventory note only. |

### Key File Transitions

| Transition | Preconditions | Write or runtime action | Result |
|---|---|---|---|
| Generate key | Key type is discoverable/generatable, node role allows the key class, and required parameters are valid. | Create encrypted canonical `.key`; LogicSig generation stores bytecode, salt, signing metadata, creation params, and optional template fingerprint. | Key becomes active after reload/scan. |
| Import mnemonic | Provider explicitly supports mnemonic import and node role allows the key class. | Derive key material and write encrypted canonical `.key`. | Key becomes active after reload/scan. |
| Delete key | Authenticated admin request selects active key. | Move `.key` to `deleted/keys/`. | Key leaves active scans. |
| Backup create | Active key files are selected. | Write encrypted `.apb` payloads in managed backup archive and include source node role metadata in the archive manifest. | Source key files remain unchanged. |
| Restore preview | Managed archive and passphrase are valid. | Decrypt/inspect payloads without mutation and compare payload key classes to destination node role. | Reports addresses, key types, conflicts, errors, role mismatches, and template requirements. |
| Restore apply | Selected payload passes validation, destination node role allows the key class, and no unhandled existing-key conflict remains. | Write canonical encrypted `.key`, optionally install/enable needed template or compiled state, then reload identity. | Key becomes active; per-key rollback undoes restore side effects if final key write fails. |
| Unlock/reload | Master key is available. | Verify node role integrity, register enabled templates, scan key files, validate node inventory against role, publish runtime indexes. | Valid active keys become signable; rejected files are diagnostics except role conflicts, which fail closed for the node. |
| Repair template provenance | Template/provider state is reinstalled or re-enabled. | No key-file rewrite required unless explicitly restoring missing provenance. | Inventory warnings may clear; signing behavior is unchanged. |

## Backup And Restore Matrix

This matrix describes restoring a key whose backup refers to a template-backed
or library-visible key type. Native default-enabled keys follow the direct key
restore path.

Backup manifests carry the source node role going forward. Restore validates
payload key classes against the destination node's role; it does not change the
destination role. Rebuild treats source role metadata as a default and
diagnostic, not authority: `apstore rebuild --role signer|sentry` sets the
destination role explicitly, while omitted `--role` uses manifest metadata when
present and otherwise defaults to `signer`.

| Destination key type state | Key restore | Template/provider restore | Generation after restore |
|---|---|---|---|
| Destination node role forbids key class | Fails or is rejected before publishing active inventory. | No template/provider state should be installed for the forbidden class. | No on this node. |
| Key type unsupported by binary | Fails if the key needs that provider or base provider. | Cannot install a runtime provider not supported by the binary. | No. |
| Key type missing locally | Succeeds when the key payload has complete current-format signing metadata, any needed base provider is supported, and node role allows it. | Bundled template may be installed only when no authoritative local source exists; library-visible compiled provider activation is created as needed. | Yes only if restore installs/enables a template or activates a compiled provider. |
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
2. load root `node.yaml` and verify the identity's `node.yaml.hmac`,
3. load and validate identity config and the node-role policy domain from
   `policy.yaml`,
4. apply node role to key type discovery and service dispatch,
5. register enabled compiled/YAML key type state,
6. register enabled installed templates,
7. scan active key files and validate the scanned inventory against node role,
8. publish runtime key indexes and key type discovery data.

Reload failures fail closed. For policy/config failures, the previous in-memory
snapshot remains active when one exists. Ordinary malformed, misnamed, or
unsupported key/template artifacts may be excluded from new runtime indexes and
surfaced as diagnostics rather than treated as signable authority.

Role-conflicting key inventory is not ordinary per-item invalidity. It is a
node-level contradiction: reload must fail closed without publishing a new
active key snapshot for the contradictory inventory.

Disabled key type state affects discovery and generation. It does not remove
already-valid key files from active key scans.

Node role is stronger than disabled/enabled state: a role-forbidden active key
is not published as valid runtime inventory.

## Transition Catalog

| Operation | Key type state effect | Key file effect | Notes |
|---|---|---|---|
| Initialize node role | Writes root `node.yaml`; each initialized identity writes a matching HMAC sidecar when its master key is available. | None. | Default role is `signer`; sentry role is explicit at initialization. |
| Verify node role integrity | None. | None. | Required before unlock-dependent key scan, signing, generation, key/store/template/mnemonic import, restore, or sentry component signing. Client endpoint import is routing state and is outside this key lifecycle. |
| `apstore keytype enable` | Writes/refreshes compiled enabled state, or enables an installed YAML template. | None. | Does not rewrite existing keys. |
| `apstore keytype disable` | Deletes compiled state or disables an installed YAML template after the unused-key guard. | None. | Provider code and installed template files remain available to the store. |
| `apstore template import` | Installs encrypted template and enabled state. | None. | Active after reload. |
| `apstore template remove` | Deletes state and archives `.template` after unused-key guard. | None. | Removed template leaves active scans. |
| Key generation | Requires discoverable/generatable key type allowed by node role. | Writes new encrypted key. | LogicSig key stores signing authority at creation time. |
| Key deletion | None. | Archives active key file. | Archived keys are not signable. |
| Backup create | Records source node role metadata in the managed archive manifest. | Reads selected active key files into encrypted backup payloads. | Source store unchanged. |
| Backup import | None in active identity. | None in active identity. | Validates archive before publishing to managed backup locker. |
| Restore preview | None. | None. | Decrypts and reports only, including node-role mismatch diagnostics. |
| Restore apply | May install/enable required template or activate compiled provider when node role allows it. | Writes selected keys. | Per-key rollback on final write failure. |
| Rebuild absent store | Writes root `node.yaml` from explicit `--role`, manifest source role metadata, or `signer` fallback. | Restores selected keys into a new identity store. | Manifest role is diagnostic/default only; destination key-class gates remain authoritative. |
| Store passphrase change | Re-encrypts installed templates and keys and rewrites role HMAC sidecars. | Re-encrypts keys. | Authority and state are unchanged. |
| Binary upgrade | May change compiled provider availability/fingerprints. | Existing keys unchanged. | Bad activations require explicit refresh. |
| Sign request | None. | Reads already-loaded key metadata. | Key type discovery state is not a sign-time authorization gate. |

## Invariants

1. Key files are the signing authority for existing keys.
2. Key type state records are discovery/generation state, not signing authority.
3. Templates are generation/provenance definitions, not reconstruction sources
   for missing signing metadata.
4. Node role gates allowed key classes for generation, reload, restore, and
   signing endpoint dispatch.
5. Node role is immutable in supported tools and tamper-resistant through
   per-identity HMAC sidecars over root `node.yaml`.
6. Role-conflicting active inventory anywhere in a signer data root fails the
   whole node closed.
7. Disabled key types block new-key discovery/generation, not valid
   existing-key signing.
8. LogicSig keys must carry durable v1 signing metadata when signing/restore
   would need it.
9. LogicSig key bytecode must derive an off-curve LogicSig address.
10. DSA LogicSig keys require their stored `base_key_type` provider to be
    supported at sign time.
11. Sentry component keys are component-signing keys, not spending accounts.
12. Sentry component public sidecars are derived public metadata and must not
    be treated as independent signing authority.
13. Guarded account keys use the guarded orchestration flow; normal `/sign`
    rejects them.
14. Backup restore is per-key and must not silently redefine an existing local
    `key_type`.
15. Template/provider fingerprint conflicts are generation/provenance
    problems, not automatic invalidation of otherwise valid key files.

## Source Of Truth

Primary implementation owners:

- key payload parsing/scanning: `internal/keys`
- component public sidecars: `internal/keys/component_public_metadata.go`
- encrypted key and template storage: `internal/keystore`,
  `internal/templatestore`
- node role and key-class gates: signer startup/identity load, keyadmin,
  restore, and signing dispatch paths
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
