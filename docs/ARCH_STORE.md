# Signer Store

> The signer product store under `APSIGNER_DATA`: its layout, which processes
> may read or change it, how generations commit and recover, and how keys and
> key types move between states.

Each signer or cosigner data root contains one product store at
`identities/default/` and managed backups at `backups/default/`. Store-owning
APIs accept no identity locator, and live mutation and inspection use one
process-wide product-store lock. Compatibility-bearing on-disk formats are in
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md); the closed product-principal and action
model is in [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md).

This document does not define transaction planning, policy verdicts, endpoint
routing, client enrollment, or approval prompts.

## Contents

- [Layout](#layout)
- [Ownership and access](#ownership-and-access)
- [Generations](#generations)
- [Keys and key types](#keys-and-key-types)
- [Source of truth](#source-of-truth)

## Layout

```text
<data-root>/
  config.yaml
  node.yaml
  audit.log
  backups/default/
  library/templates/
  identities/default/
    .keystore
    store-root.enc
    config.yaml
    unlock.yaml
    .ssh/authorized_keys
    passphrase | passphrase.cred
    cosigners/<name>.json
    quarantine/generations/<gen-id>/
    generations/<gen-id>/
      manifest.json
      seal.json
      keys/*.key|*.cos|*.wit.json
      keytypes/*.json|*.template
      deleted/keys/*.key|*.cos
      deleted/keytypes/*.template
      deleted/policies/<selector>.json|.json.hmac
      default.json                                      (node default policy)
      default.json.hmac
      policies/<selector>.json|.json.hmac               (per-key policy; address on
                                                         signer nodes, Witness Key ID
                                                         on cosigner nodes)
      node.yaml.hmac
```

The generation boundary includes all mutable state whose confidentiality or
integrity depends on a keyring term. Process and product configuration,
unlock helpers, SSH state including the enrolled-client registry, cosigner
references, backups, the plaintext template library, and the root node-role
document are not generational.

`quarantine/` is non-authoritative. Normal resolution, signing, historical
reads, successor construction, and rollback never search it.

## Ownership and access

This section is the source of truth for which process may access or mutate
`APSIGNER_DATA`.

### Trust statement

Membership in the operator-facing `aplane` Unix group grants connectivity to
the local administrative IPC socket. It does not grant signer-store authority,
an authenticated admin session, product authorization, or direct access to
encrypted custody material.

The systemd deployment has two distinct filesystem roots:

- `/var/lib/apsigner` is service-user-owned private state (`0700` directories,
  `0600` files). `apsigner` is its sole normal-runtime writer.
- `/run/apsigner` is a service-user-owned runtime directory (`0750`) whose
  `aplane.sock` socket is group-connectable (`0660`). The group can traverse
  the runtime directory and connect to the socket, but cannot create, unlink,
  rename, or replace entries there.

Root-run bootstrap and rescue remain supported while the daemon is stopped.
They are explicit maintenance writers protected by the store lock, not an
ordinary group-mediated administration path. Same-UID local development is a
separate deployment model and may keep its socket below its private data root.
Store ancestors must be owned by the store user or the filesystem-root owner
and must not be group/other writable. Canonical root-owned sticky `/tmp` and
`/var/tmp` are the only shared-ancestor exceptions, allowing a same-UID store
beneath an owned private child without permitting a general writable-ancestor
exception.
An explicit custom socket for a systemd-managed signer must remain outside the
store and its parent runtime directory must be service-user-owned and
non-writable by group and other users. Valid legacy configurations that placed
a custom socket inside the store can be migrated while stopped; the daemon
then refuses that configuration until the socket is moved.

All IPC bind paths use the same directory-chain trust rule. Directory aliases
are resolved before validation and the daemon binds the canonical result. The
canonical immediate socket parent must be owned by the daemon UID and must not
be writable by group or other users. Every canonical ancestor must be a real
directory owned by either the daemon UID or the filesystem-root owner and must
not be group/other writable. A lexical symlink is accepted only when owned by
the daemon or filesystem-root owner and its containing chain independently
meets the same write and ownership rules. Root-owner sticky `/tmp` and
`/var/tmp`, including their canonical platform targets, are the only shared
directory exceptions. This supports macOS temporary paths and compatibility
aliases such as `/var/run` without binding through an unchecked alias or
allowing an unrelated-owner or writable intermediate directory.

### Access inventory

The following classification is compatibility-bearing. A new direct
`APSIGNER_DATA` consumer must be added here with an explicit execution mode or
moved behind an existing owner.

#### Daemon-owned normal runtime

| Owner | Store access |
|---|---|
| `internal/signerapp/productruntime`, `storemut`, `keyadmin`, `templateadmin`, `templates` | Product settings, store mutation locking, keys and templates |
| `internal/signerapp/backupadmin` and `internal/backup` when invoked by it | Managed backup, restore, rollback, reconciliation |
| `internal/keystore`, `internal/keys`, `internal/keymgmt` | Active credential state |
| `internal/genstore`, `internal/storepass` | Atomic store-root publication, reconciliation/quarantine, archive bounds, and fresh-term passphrase rotation |
| `internal/stagetable` when invoked by the daemon | Rotating accounts' stage address tables (`identities/default/stages/`): plaintext caches, removed on key delete, rebuilt from the seed when missing or damaged |
| `internal/policy`, `internal/signerapp/policyapply`, `internal/noderole` when invoked by the daemon | Authenticated policy documents, policy-apply generation commits, and node-role state |
| `internal/cosigner/cosignerrefs` when invoked by the daemon | Public cosigner-reference inventory |
| `internal/signerapp/clientregistry` when invoked by the daemon | Enrolled client key registry (`identities/default/.ssh/authorized_keys`) |
| `internal/signerapp/enrollqueue` when invoked by the daemon | Pending enrollment queue (`identities/default/.ssh/pending_enrollments.json`) |

Normal operators reach these owners through authenticated HTTP or the admin protocol over local IPC;
they do not call the storage packages directly.

`internal/signerapp/productruntime` owns the product runtime aggregate; the
aggregate has no identity ID or selectable runtime registry.

#### Offline bootstrap and rescue

| Command | Classification |
|---|---|
| `apstore initialize` | Offline mutation; root on systemd or data-root owner in same-UID mode |
| `apstore rebuild` | Offline mutation into an absent product store |
| `apstore verify` and offline policy check/verify | Offline read-only recovery inspection |
| `apstore policy sign` | Offline re-signing of sidecars for hand-placed policy documents |
| `apadmin policy rescue` reads | Offline read-only policy inspection under the shared store lock |
| `apadmin policy rescue apply`/`remove` | Offline policy repair for a stopped daemon |
| `apstore generations prune` | Offline pruning of retained authoritative generations; non-authoritative quarantine deletion is a separate authenticated live operation |
| `apstore permissions` | Offline bootstrap, audit, and ownership migration |
| `apstore keys list` | Offline credential inventory for recovery diagnostics |
| `appass` | Offline root/service-owner mutation of startup credentials and `unlock.yaml` |

Offline mutations require a stopped daemon, exclusive store lock, no-follow
inventory validation, and the installation-mode owner check. They preserve the
narrow root-owned `identities/default/passphrase.cred` exception and the
installer-owned `install/` metadata artifacts.

Root-run `apadmin policy rescue apply` and `remove` hold one exclusive lock
across the policy generation commit and managed-store ownership normalization,
so a daemon cannot start between publication and repair. They commit through
the same `internal/signerapp/policyapply` rules as the daemon. Rescue reads
(`status`, `export`, `check`) hold the shared store lock.

#### External-file-only operations

Backup inspection and validation of explicitly supplied external artifacts do
not require signer-store access. Output selected by an operator is created as
operator-owned state outside `APSIGNER_DATA`.

#### Operator clients

The multi-UID clients `apadmin`, `apapprover`, `approbe`, and systemd-attach
`apconsole` resolve the public runtime socket without reading signer
configuration. `apadmin` owns every general running-daemon administration
workflow: policy check/apply, template and key-type administration, cosigner-reference
administration, endpoint export, generation listing, managed backup transfer,
restore, and passphrase rotation. Those workflows use typed admin operations;
operator-selected exports are written to operator-owned locations. `apstore`
does not open the admin transport or construct live admin requests. Same-UID
child `apconsole` retains direct config and node-role access as an explicit
local-mode exception.

Config-free fallback from an unreadable data root to the singleton
`/run/apsigner/aplane.sock` is restricted to the conventional
`/var/lib/apsigner` store. A custom private managed store must supply an
explicit `APSIGNER_IPC_PATH` or `--ipc-path`; permission failure on any other
selected data root is an error and never retargets the client to the singleton
system signer.
Explicit client selection follows the same rule: `--ipc-path` wins first, then
an explicit `-d`, then `APSIGNER_IPC_PATH` paired with an environment/profile
data root. This prevents a stale inherited socket override from redirecting an
operation aimed at a CLI-selected store. The systemd installer pairs its
generated `APSIGNER_DATA` with the daemon's configured external `ipc_path`, or
`/run/apsigner/aplane.sock` when unset. A command that supplies `-d` must also
supply `--ipc-path` when that private root cannot be inspected.

### Filesystem primitives

`internal/fsutil` owns low-level durable publication. Store callers select a
closed artifact profile rather than arbitrary mode/UID/GID combinations. A
store directory uses `MkdirAllPrivate`, which rejects a final symlink and
clamps the caller-owned directory to `0700`. The separate generic `MkdirAll`
creates owner-private client state but does not rechmod an existing directory
that the client may not own. A durable replacement uses a random exclusive
temporary regular file, applies
ownership and its permission ceiling to the unpublished file descriptor,
syncs it, renames it in the destination directory, and syncs that directory.
File-set publication stages and syncs every member before the first rename, so
preparation failure exposes none of the new members. Because multiple paths
cannot be renamed atomically, interruption between publication renames remains
a documented fail-closed mixed-generation state.
Symlink and non-regular destinations are rejected. The legacy profile remains
internal to pre-migration validation; normal writers use private profiles.

`internal/storeperm` owns read-only audit, stopped-service migration, and the
startup permission contract. It inventories without following symlinks and
reports unsafe ancestors, ownership, modes, hardlinks, and unexpected file
types. Its public policies are opaque operation-specific values: production
audit rejects every in-store socket, same-UID audit recognizes one exact live
socket without relaxing ancestor checks, and migration alone receives a
removable legacy socket. Migration validates the complete legacy inventory before mutation,
removes the recognized stale legacy `<data-root>/aplane.sock`, removes group
access at the root first, repairs recognized objects through opened
descriptors, syncs directories, and independently audits the private result. A
clean audit is authority to proceed; an incomplete audit is not.
Stopped migration and post-root-mutation normalization resolve the same exact
configured legacy in-store socket; neither hardcodes the historical default.

The installer bootstrap first uses `apstore permissions prepare-managed-root`
to create and close the real data-directory root through opened directory
descriptors. That operation rejects symlinked, unrelated-owner, and
group/other-writable ancestors before any privileged pathname mutation beneath
them. It retains the final parent descriptor and, after changing ownership,
reopens the leaf without following symlinks to prove the pathname still names
the secured inode; this closes the allowed sticky-temporary-root replacement
window. The narrower read-only `permissions preflight` then runs before `.prod`,
service-principal metadata, or the store lock exists. Preflight rejects
symlinks, hardlinked regular files, and unexpected object types without opening
file contents or changing the tree. Unix sockets are left inert for the
subsequent configured-socket migration policy to classify. The command
deliberately does not infer an owner from untrusted store metadata and does not
create `.apstore.lock`.

`apstore permissions convert-managed` then acquires the exclusive store lock,
migrates and audits the legacy tree, and publishes root-controlled
`install/service-principal.json` followed by `.prod`. A busy store therefore
fails before either managed marker appears. The marker is published last so a
failed migration remains an unmarked local store.

`apstore permissions preflight` and `permissions audit` are read-only. Same-UID audit recognizes the local
installer's non-writable executable `bin/` subtree without treating those
files as signer data. It retains the real-directory requirement for the store
leaf but canonicalizes trusted platform aliases in its ancestor chain and
socket parent before applying the ancestor policy. `apstore permissions migrate` is restricted to
systemd-managed stores, requires the normal offline execution mode and
exclusive store lock, and rejects any store-local `bin/` subtree rather than
stripping binary execute bits or file capabilities. The standalone systemd
setup closes only the real store root before preflight, then rejects a local
`bin/` before writing `.prod` or changing any descendant ownership or mode; its
service `bindir` must be outside the data root. A
root-controlled `install/service-principal.json` records the numeric service
uid/gid and is refreshed by systemd setup before migration. Audit, migration,
and post-mutation normalization use this record instead of trusting the store
root's possibly damaged owner; a missing or unsafe record fails closed. A
systemd-managed daemon reads the same record, verifies that its effective
uid/gid match the recorded principal, and checks the private profile against
that principal before loading configuration or opening the store lock. A
principal mismatch directs the operator to rerun systemd setup; unsafe store
state directs the operator to the permission migration command.

Installer-owned management scripts, release metadata, operator metadata, and
the template library are installed only after migration succeeds. In
particular, recursive template ownership repair never runs against a legacy
tree. The shell installer does not repair `.apstore.lock`; the descriptor-based
Go migrator owns that operation.

### Implemented rollout

The migration order is fixed:

1. harden writers and ownership traversal;
2. establish config-free runtime-socket discovery and move normal clients;
3. add missing authenticated policy, cosigner-reference, and generation reads;
4. move the socket to the protected runtime directory;
5. audit and migrate a stopped legacy store;
6. enable strict startup enforcement and private creation defaults;
7. remove legacy group-shared behavior from normal writers, retaining only the
   read-only legacy profile needed to validate supported upgrades.

The systemd installer performs this ordering while the service is stopped and
runs both migration and post-migration audit before starting the daemon.
The standalone `installer/scripts/systemd-setup.sh` enforces the same stopped
service precondition before changing the unit or store.
Fresh systemd stores are created private. Supported upgrades clamp existing
stores before restart. The systemd smoke test proves that an operator-group
user cannot traverse `/var/lib/apsigner` while the same user can reach
`/run/apsigner/aplane.sock`.

## Generations

This section is the storage contract for the product store. The only
supported layout uses one authenticated commit record for both cryptographic
authority and active-generation selection. There is no compatibility path for
the retired `CURRENT` plus `keyring.enc` layout.

### Store root

`store-root.enc` has strict schema `aplane.store-root.v1`. It contains:

- the passphrase-wrapped `aplane.keyring.v3` subobject;
- `current_generation_id`;
- the current selection term;
- a domain-separated HMAC over the selector and exact wrapped-keyring digest.

The wrapped keyring is AEAD-authenticated under the Argon2id-derived KEK. After
unwrap, the selection term must equal the keyring's current term and the
selection MAC must verify. Unknown fields, trailing content, noncanonical
encoding, unsafe KDF parameters, and oversized input fail closed.

The selector is outside the KEK-sealed payload so an unlocked runtime can mint
an ordinary successor without retaining the passphrase. Such commits reread
the exact root under the mutation lock, authenticate it, preserve the wrapped
keyring subobject byte-for-byte, and change only the selector and selection
MAC. Passphrase change replaces the wrapped keyring and selector together.

The store root authenticates state but is not an external freshness oracle.
An adversary able to restore an older authentic root can roll authority back.
Detecting such replay needs a monotonic hardware or remote authority outside
this store.

### Active-path capability

Passphrase unlock authenticates `store-root.enc`, validates the selected
generation, and binds its ID into a `storepaths.Paths` capability or returns a
`storepaths.GenPaths`. Lower-level packages cannot derive active selection from
public filesystem state. `genstore.Resolve` accepts only an already-bound
capability; an unbound path fails.

Root-changing operations repeat a fresh exact root read under the store
mutation lock. A cached runtime generation or serialized root is never commit
authority.

Reload binds whatever the authenticated root selects as its first step,
before any validation or scan can fail, so a failed reload after a commit
never leaves the runtime bound to the superseded, sealed generation. A root that no
longer authenticates clears the binding. Deleted-archive list and prune, which
run in recovery, read and authenticate the root themselves rather than trust
the cached binding. Every post-commit failure enters recovery before the
store mutation lock is released, and every in-place writer (key generate,
import, and delete; template and key-type changes) rechecks under the lock
that the runtime is still unlocked, so a request queued behind a failed
commit cannot resume into the superseded generation.

### Generation manifest and seal

Every generation has a strict, complete `manifest.json` recording its ID,
parent, operation identity, creation time, at-mint inventory, and optional
restore rollback capability. Self-parent lineage and incomplete manifests are
invalid.

The selected generation is mutable through ordinary durable key, template,
policy, and sidecar operations. A `seal.json` beside it is stale precommit
residue and has no authority.

Immediately before selection moves, the outgoing generation receives an
authenticated seal. The seal binds the exact manifest bytes and complete final
inventory:

- active credentials and installed templates;
- deleted credentials and templates;
- policy documents and integrity sidecars (`default.json` when present,
  `policies/` and `deleted/policies/`), on both node roles;
- node-role integrity sidecar;
- term numbers, sizes, and exact digests.

A retained generation must have a valid seal. Old-term retained generations
also require an exact historical seal anchor in the active keyring. A term key
alone never grants historical authority.

Generations are copied as independent files, never hardlinks. Once non-current,
they are immutable except for explicit generation pruning.

### Ordinary generation commit

Credential restore, restore rollback reconstruction, initialization, rebuild,
passphrase change, and policy apply mint generations. Every policy apply or
removal, online or rescue, mints one generation with operation `policy-apply`
(`internal/signerapp/policyapply`), so each committed apply leaves a retained
generation until explicit generation pruning. Ordinary key mutations do not
mint.

The commit order is:

1. acquire the store mutation lock and any maintenance fence;
2. freshly authenticate the root and selected generation;
3. create a private `.staging-<gen-id>` directory;
4. independently copy the parent, or construct an authorized empty successor;
5. apply the transaction and validate the complete namespace;
6. write the complete manifest and sync the staging tree bottom-up;
7. rename staging to `generations/<gen-id>` and sync `generations/`;
8. write and sync the outgoing generation seal;
9. durably replace `store-root.enc` once;
10. reload and validate the selected generation.

Step 5 includes the caller's complete semantic validation of the candidate
(`storevalidate.Candidate`: deleted archive, node role, policy, templates, and
every credential). Every commit runs it, including initialization and
`apstore rebuild`; `genstore.Mint` refuses a request without it. Rebuild
matters most: once any generation exists a second rebuild is refused, so an
invalid first generation could otherwise only be repaired by hand.

A failure before root replacement leaves the old root authoritative. A visible
candidate after a replacement or directory-sync error is commit-uncertain and
enters recovery; callers do not blindly retry. Once the one root rename is
visible and directory-durable, there is no second witness or publication step.

### Passphrase and term rotation

Changing the passphrase also replaces the current data-encryption term:

1. authenticate and seal the outgoing generation;
2. retain its exact seal and manifest buffers;
3. create a fresh random term and successor keyring;
4. preserve historical keys and exact anchors, adding the outgoing anchor;
5. stage an empty successor;
6. read every source member once and verify it against the retained seal;
7. re-encrypt term envelopes and re-sign integrity sidecars under the new term;
8. validate and publish the complete successor;
9. replace `store-root.enc` with the new wrapped keyring and selector in one
   durable operation;
10. update the configured passphrase helper and reload.

Helper update failure is a post-commit warning. It never rolls the store back.
There is no pending rotation, resumable rewrap, rotation snapshot, rotation
baseline, or unlock-time completion pass.

Retained generations are not rewritten during rotation. Exact historical
anchors and anchor-gated reads preserve historical least authority.

### Restore rollback

Credential restore may add a strict `rollback_capability` to its manifest. The
capability binds the originating operation, archive digest, authenticated
source generation, clean-cutover decision, and exact inventory authority.

Passphrase change carries it only when the outgoing live inventory still
matches its effective authenticated authority. Routine mutations cause that
comparison to fail. Rollback reconstructs authorized source content into a new
current-term successor; it never repoints the root at historical ciphertext.
Rollback restores `keys/`, `keytypes/`, and the per-key `policies/`, because
restore installs a key's archived policy with the key on both node roles. Each
restored policy document is checked against the source seal and written with a
sidecar signed under the current term. The node default `default.json`, the
deleted archives, and node role authority are kept from the outgoing
generation.

### Reconciliation and quarantine

Reconciliation first authenticates the root and validates its selected
generation. Until that succeeds, it deletes nothing.

- Incomplete `.staging-*` directories and durable-write temporary files have
  never carried authority and are removed.
- Sealed, referenced, and declared-parent generations are retained.
- A complete, non-current, unsealed, unreferenced final directory is ambiguous:
  it may be crashed-mint residue or newer state orphaned by restoration of an
  older authentic root. It is classified and quarantined, never adopted or
  deleted.

Quarantine eligibility requires a valid ID, strict complete manifest, closed
regular-file-only layout, bounded enumeration, and live inventory digests.
At-mint mismatch is recorded but is not a veto because a formerly selected
generation may have legitimate post-mint mutations.

Available term validation is classification, not authority. Known-term checks
are recorded as `verified` or `failed`; a member whose term is absent from the
current keyring is `term_unavailable`. All remain relocatable when structural
and bounded checks pass. This is essential when an old root restored across a
passphrase change lacks the orphan's newer term.

A candidate that cannot be safely parsed, enumerated, or bounded remains in
place. Reconciliation and further mints fail closed until authenticated
operator remediation. Quarantine capacity overflow behaves the same way.
Explicit removal of an in-place unvalidatable final directory uses the
separate `identity.generation.abandoned.discard` action, explicit confirmation,
and a durable intent audit. It refuses current, rollback-parent, and sealed
generation state.

Eligible candidates are atomically renamed to
`quarantine/generations/<gen-id>` and both parent directories are synced.
Quarantine is bounded to eight generations and 1 GiB. Live pruning requires
the stable `identity.generation.quarantine.prune` action, explicit
confirmation, and durable intent audit before deletion.

A crashed changepass before root replacement can leave its complete successor
in quarantine. That ciphertext is non-authoritative; a later changepass remains
blocked until an authenticated operator prunes it.

If an orphan crossed a passphrase change, quarantine preserves its ciphertext
but does not imply it is decryptable with the restored root or passphrase. The
newer overwritten root must also be recovered from a coherent snapshot.

### Deleted archive capacity

The selected generation's deleted archive is bounded by release-contract
constants:

- 4,096 entries;
- 256 MiB total encoded bytes;
- warning thresholds reserve one entry and one maximum standalone-envelope
  allocation for an emergency deletion.

If a release ever lowers these layout constants below an existing store's
usage, generation minting and changepass refuse until authenticated archive
prune restores compliance. The health and status surfaces retain a warning
whenever the emergency reserve is consumed.

Deletes preflight the exact append and fail before active-state mutation if the
hard bound would be exceeded. Deleting a key that has a policy of its own
preflights the credential together with its policy document and sidecar, which
move into `deleted/policies/` with it, on both node roles. Mints check the parent before staging and the
successor after apply. An over-limit selected generation blocks ordinary
validation, mint, and passphrase change until pruned.

`apadmin archive list` reports exact usage and the reserve warning.
`apadmin archive prune --confirm <deleted/path>...` accepts only canonical
`deleted/keys/*.key|*.cos`, `deleted/keytypes/*.template`, and
`deleted/policies/*.json|*.json.hmac` selections. An archived policy document
and its sidecar must be selected together. It
requires `identity.archive.prune`, a recovery-capable authenticated runtime,
and durable intent audit before mutation. It changes only the selected
generation; retained copies disappear only with retained-generation pruning.

### Recovery and restoration

Keyring unwrap remains independent of selected-generation health. A valid root
and passphrase with damaged selected state enters authenticated recovery with
signing blocked. Invalid or absent root authority requires `apstore rebuild`;
the implementation never chooses the newest-looking generation.

Credential recovery restore can repair only explicitly selected credential
damage when all destination authority outside those credentials validates.
Damage to policy, node-role integrity, key types/templates, deleted archives,
unselected credentials, or the selected directory itself is not repaired by
inventing authority; restore refuses and directs the operator to rebuild.

Filesystem restoration of `identities/default/` is stopped-signer and
all-or-nothing. Restoring only `store-root.enc`, only generation directories,
or files from independently captured snapshots is unsupported. Quarantine
prevents destructive cleanup after such a mistake but does not make a mixed
restore valid.

### Generation invariants

- One root selects exactly one published generation and one current term.
- The durable root is wholly old or wholly new after a crash.
- A root never selects an unpublished or unsynced generation.
- Every changepass successor term consumer uses the new current term.
- Every old-term input promoted during changepass matches the exact outgoing
  seal buffer and inventory entry.
- Historical terms require exact active-root anchors.
- Non-current generations are immutable.
- Invalid selection authority never triggers automatic adoption or signing.
- Wrapped key authority and generation selection change in one rename.
- Restore rollback eligibility is carried only after an authenticated clean
  decision.
- Credential recovery never fabricates destination authority.
- Deleted-archive count and bytes remain within closed release bounds.
- Ambiguous complete publications are quarantined or preserved, never
  automatically adopted or destroyed.
- Quarantine cannot influence signing, history, rollback, or selection.

The commit and substitution properties are modeled in
[`formal/store_root_commit.tla`](formal/store_root_commit.tla). The normal
configuration checks the invariants; `store_root_commit_negative.cfg` is an
expected-failure control that removes exact outgoing-seal verification.
What the runtime binds, serves, and maintains after a failed post-commit
reload is modeled in [`formal/recovery_binding.tla`](formal/recovery_binding.tla);
its negative control is the pre-fix binding and reproduces the superseded-
generation prune as an invariant violation.

## Keys and key types


This document describes durable key and key type states that affect:

- whether an identity can discover or generate a key type,
- whether an existing key can sign,
- what restore preview/apply/rollback/reconcile may write,
- how disabled or conflicting key type records behave,
- which warnings are provenance-only.

### Core rule

**Key type state controls discovery and generation. Key files control restore
and signing.**

Templates and key type state records are generation/catalog data. They are not
signing authority for an already-created key. A current-format LogicSig key file
stores its final bytecode, derivation contract, signing metadata, creation
parameters, and base signing provider reference where needed. Current
compiler-auto-salted keys omit `salt_counter`; compatible manual-counter keys
retain it. The signer must never reconstruct missing signing authority from a
current template or library entry.

This separation is deliberate:

- disabling a key type can hide it from new-key generation without breaking
  existing keys,
- restoring a key can work even when the creation template is absent, disabled,
  or locally conflicting,
- provenance warnings can tell operators that the current local definition no
  longer matches the key's original creation definition without changing
  signability.

### Objects

| Object | Durable location | Authority |
|---|---|---|
| Native key file | selected generation `keys/<address>.key` | Native signing authority. |
| LogicSig key file | selected generation `keys/<address>.key` | Final LogicSig bytecode, derivation metadata, signing metadata, and any private DSA key material. |
| Cosigner witness credential | selected generation `keys/<witness_key_id>.cos` | Witness key in cosigner custody; component-signing authority for cosigner-role `/sign/component`, never an Algorand spending account. |
| Witness public sidecar | selected generation `keys/<witness_key_id>.wit.json` | Canonical public witness reference for a local cosigner key. |
| External contract-admin witness | Operator-controlled `<witness_key_id>.wit`, outside signer data | The same Falcon witness form in standalone custody; owned only by `aprekey`, never by signer or `apstore`. |
| Contract-admin public reference | Operator-controlled `<witness_key_id>.wit.json` | Disposable canonical public witness reference used during bounded account generation. |
| Node role | `<APSIGNER_DATA>/node.yaml` | Single-purpose role for the signer data root. |
| Node role integrity sidecar | selected generation `node.yaml.hmac` | Product-store HMAC over the exact root `node.yaml` bytes. |
| Product runtime config | `identities/default/config.yaml` | Product runtime settings such as approval and lock timeouts; it does not carry key-class role. Unknown fields are rejected. |
| Key type state record | selected generation `keytypes/<key_type>.json` | Product-store discovery/generation state. |
| Installed YAML template | selected generation `keytypes/<key_type>.template` | Encrypted generation source for the product runtime after reload. |
| Deleted key archive | selected generation `deleted/keys/` | Removed key files; outside active scans. |
| Deleted template archive | selected generation `deleted/keytypes/` | Removed template files; outside active scans. |
| Signer library template | `library/templates/<key_type>.yaml` | Install source only; not active by itself. New signer-role stores install the bundled Falcon allowlist v1 source during initialization; other entries require product-store import/enablement. |
| Compiled provider | Go provider registry and key type catalog | Binary capability; product-store visibility may be default-enabled or opt-in. |
| Backup payload | `.apb` inside managed backup archive | Encrypted credential unit containing key material and durable signing metadata; template YAML is not included. |

Witness public sidecars are derived public metadata, not independent signing
authority. They exist so `apadmin cosigner export` can work without
decrypting private key material. Backup payloads do not need to carry the
sidecar as a separate authority; restore flows that write cosigner keys must
regenerate the sidecar from the restored cosigner key payload.
Missing sidecars do not make a cosigner key unable to sign, but they do block
offline public export until regenerated or backfilled.

The durable and wire contracts use `component_key`, `component_selector`, and
component signing terminology. Human-facing UI may label the same selector as a
Cosigner Key or Witness Key ID; that label does not change the storage or HTTP
field names.

`node.yaml` is plaintext so the process can report its role during early
startup. That plaintext is only a hint until each initialized identity verifies
its HMAC sidecar after unlock. The sidecar key is derived from that identity's
term key, following the same tamper-detection model used by policy sidecars.

### Node role gate

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

Valid roles are exactly `signer` and `cosigner`.

| Node role | Allowed active key classes | Disallowed active key classes | Served signing paths |
|---|---|---|---|
| `signer` | Native signing keys, ordinary and bounded LogicSig account keys, guarded account keys, and public cosigner references used for generation. | Cosigner component private keys and all external contract-admin private artifacts. | Normal `/sign`, bounded-admin spending-partial generation, user-role `/sign/component`, `/sign/assemble`. |
| `cosigner` | Cosigner component private keys and their public sidecars. | Native signing keys, ordinary LogicSig account keys, and guarded account keys. | Cosigner-role `/sign/component`. |

Rules:

- every initialized signer data root has one root `node.yaml`,
- new installs default to `role: signer` unless the initializer explicitly
  creates a cosigner node,
- there is no `dual` role,
- there is no supported role-change command,
- identity-level `mode` is unsupported because node role belongs only in root
  `node.yaml`,
- key generation, mnemonic import, restore, and out-of-band key scans must
  reject key classes forbidden by the node role,
- service endpoints reject role/use mismatches even if a forbidden key file is
  present on disk.

A node hosts one product store. Role-conflicting key inventory anywhere in
the data directory is a node-level store contradiction: startup/reload fails
closed for the node rather than allowing the product runtime to continue.
This is a deliberate
safety/availability tradeoff. A hand-placed role-conflicting `.key` or `.cos` can make the
node unavailable until the operator removes it, while supported restore/import
paths should preflight role before writing so this fail-closed path remains a
backstop. After a reload detects a role inventory conflict, the process records
a sticky node failure so HTTP and admin operations refuse the product runtime
until operator cleanup and restart.

Local development that needs both roles uses two complete data roots and two
apsigner processes, for example `~/aplane-signer/` and `~/aplane-cosigner/`.
Running those two nodes on one host is useful for development and operations,
but it is not independent cosigner. Independence remains a deployment-domain
property.

### Key type lifecycle

Key type state answers this question:

```text
Can this identity discover this key type and generate new keys of this type?
```

It does not answer whether an existing key file can sign, and it is still
subject to the node role gate above.

#### Key type state matrix

| State | Durable representation | Discovery/generation | Existing-key signing | Normal transition |
|---|---|---|---|---|
| Unsupported by binary | No provider is registered in the current process. | No. | No, if signing needs that provider; native/DSA key types need registered support. | Install/run a binary that supports the key type. |
| Role-forbidden key type | The node role does not allow this key class. | No, even if the provider is default-enabled or enabled. | No for active inventory; reload rejects role-conflicting active keys. | Use a data root initialized for the correct node role. |
| Default-enabled account-signing provider | Provider/generator is registered and cataloged as default-enabled; no identity record required. Examples include native `ed25519`, native `falcon1024`, and LogicSig `aplane.falcon1024.v1`. | Yes on signer nodes. | Yes on signer nodes, if the key file is valid and the transaction network supports its authorization kind. | None. |
| Default-enabled cosigner key type | Raw cosigner-key generator/signing support is registered and cataloged as default-enabled. The current type is `aplane.witness-falcon1024.v1`. | Yes on cosigner nodes. | Component-signing only on cosigner nodes; never normal spending `/sign`. | None. |
| Library-visible compiled provider, inactive | Provider is registered and cataloged as library-visible; no identity `keytypes/<key_type>.json` record exists. | No. | Existing key may sign if the provider is registered, the key file is valid, and the node role allows it. | Enable from KeyType Library or `apadmin keytype enable`. |
| Library-visible compiled provider, enabled and fingerprint consistent | `keytypes/<key_type>.json` has `source:"compiled"`, `state:"enabled"`, and matching fingerprint. | Yes when allowed by node role. | Yes, if the key file is valid and allowed by node role. | Disable, if no stored key uses it. |
| Library-visible compiled provider, enabled but fingerprint inconsistent | State record exists, but the stored fingerprint does not match the provider fingerprint in the current binary. | No; reload ignores the conflicting activation record. | Existing key may sign if the provider is registered, the key file is valid, and node role allows it. | Refresh with `apadmin keytype enable <key_type>`. |
| Signer library YAML only | Plaintext YAML exists under `library/templates/`; no identity install exists. | No. | No effect on existing keys. | Install/import template into identity. |
| YAML installed and enabled | Encrypted `.template` exists and state record has `source:"yaml_generic"` or `source:"yaml_composed"` plus `state:"enabled"`. | Yes after successful reload, when allowed by node role. | Existing keys sign from stored key metadata, not the template, when allowed by node role. | Disable or remove, if no stored key uses it. |
| YAML installed and disabled | Encrypted `.template` exists and state record has `state:"disabled"`. | No. | Existing keys sign from stored key metadata, not the template, when allowed by node role. | Enable, remove, or explicit template restore may re-enable. |
| YAML integrity or fingerprint mismatch | Encrypted `.template` does not match the state record fingerprint, cannot decrypt, or parses to incompatible metadata. | No; reload rejects that template. | Existing keys may still sign from stored key metadata if otherwise valid and allowed by node role. | Reinstall through supported template import/install path. |
| YAML removed | State record is deleted and encrypted `.template` is moved to `deleted/keytypes/`. | No. | Existing keys may still sign from stored key metadata if otherwise valid and allowed by node role. | Reinstall/import template. |

#### Key type transitions

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

Fingerprint comparisons are version-aware. The compatibility fingerprint is
behavior-only and identifier-independent (it hashes behavior-bearing fields, not
`key_type`/`family`/display or a renamed base key type) and is stored versioned
(`<n>:` prefix). A real conflict is only a same-version, different-hash pair; a
cross-version or malformed stored fingerprint is "not comparable" and benign —
the activation is re-pinned/registered, not flagged as a conflict. So the
"changed compiled fingerprint" row above triggers only on a genuine same-version
behavior change, not on a formula-version bump.

The unused-key guard on disable/remove protects operators from accidentally
hiding the normal generation source for a key type still in use. It is not a
sign-time dependency rule; a valid existing key file remains the signing
authority.

#### Template mutation ownership and publication

`internal/templatelibrary` is the sole production feature-level coordinator
for writes to encrypted template files and key-type state records.
`internal/templatestore` and `internal/keytypestate` own their formats and
primitive persistence operations; feature packages do not call those writers
directly.

There are two supported mutation contexts:

- live administrative operations are owned by
  `internal/signerapp/templateadmin`, which holds the store mutation lock,
  calls `templatelibrary`, then asks the read-only
  `internal/signerapp/templates` runtime owner to reload;
- initial default installation is owned by `internal/defaultkeytypes`, which
  calls `templatelibrary` while constructing an unpublished generation and
  makes it visible through initial `store-root.enc` publication. No live
  identity or reload exists in that context.

Reload failure does not imply one uniform rollback rule. Install, import, and
installed-YAML enable restore their prior durable state when reload or
acceptance validation fails. Compiled-provider enable, YAML or compiled
disable/deactivation, and installed-template removal leave their completed
durable change in place and report the reload failure; removal still reports
that it occurred. The lifecycle must not be described as fully transactional.

### Key file lifecycle

Key file state answers this question:

```text
Can this stored key be loaded and used for the signing path it belongs to?
```

Key files must also be allowed by the node role gate. A role-conflicting active
key is rejected during reload rather than published as a signable key.

#### Key file state matrix

| State | Durable representation | Signability | Backup/restore behavior |
|---|---|---|---|
| Absent | No active key file under `keys/`. | No. | May be restored from a backup payload. |
| Archived/deleted | Key file moved to `deleted/keys/`. | No; outside active scans. | Restore can write a new active canonical key file if selected. |
| Store recovery-blocked | `store-root.enc` or its selected generation failed reconciliation or validation at unlock, or root durability could not be confirmed. | No; the identity is held in recovery mode with signing blocked. | The operator can reconcile, roll back an eligible restore, or directly restore a validated credential archive when destination authority remains valid. |
| Present but signer locked | Encrypted `.key` or `.cos` exists but identity has no active key session. | No until unlock. | Backup can include active encrypted managed credentials; restore requires authenticated/unlocked flow. |
| Present, decrypts, canonical filename matches derived selector and category | Account `.key` matches its Algorand address, or witness `.cos` matches its Witness Key ID. | Candidate for its category-specific signing path after validation. | Backup and restore use canonical filenames. |
| Misnamed or wrong-class managed credential | Basename selector mismatches the payload, witness payload uses `.key`, or account payload uses `.cos`. | No; scanner rejects/skips it. | Restore derives the canonical filename from validated payload category. |
| Role-forbidden key file | Key type is valid, but the node role does not allow that key class. | No; reload rejects the inventory conflict. | Restore/generation should refuse unless the destination node role allows that key class. |
| Unknown key type | Payload names a key type unsupported by the current binary. | No. | Restore fails for that key unless support exists. |
| Native key valid | Native key payload has valid key material and canonical key type. | Yes on signer nodes. | Restores directly onto signer nodes. |
| DSA LogicSig key valid | Payload has private DSA material, stored LogicSig bytecode, a valid derivation record, `signing_metadata_version`, `base_key_type`, and valid signing metadata. | Yes on signer nodes when the base signing provider is registered. | Restores from stored metadata; composed template is not required. |
| Generic LogicSig key valid | Payload has stored LogicSig bytecode, a valid derivation record, `signing_metadata_version`, and stored signing args. | Yes on signer nodes. | Restores from stored metadata; template is not required. |
| Cosigner key valid | Payload category/type is a cosigner key and Witness Key ID is canonical. | Only through cosigner-role component signing on cosigner nodes; normal `/sign` and spending paths reject it. | Restores as a cosigner key on cosigner nodes, regenerating the public sidecar; never as a spending account. |
| Bounded account key valid | DSA LogicSig key whose bytecode embeds an external contract-admin public key and whose v2 metadata derives the matching Contract Admin Key ID and program binding. | Pure spends use signer-held authority; admin-key operations additionally require external completion through `aprekey`. | Restores from durable bounded metadata. The external `.wit` artifact is never part of signer backup or restore. |
| Guarded account key valid | DSA LogicSig key whose bytecode embeds the cosigner public key. | Only on signer nodes through guarded orchestration: user component signature, cosigner component signature, local assembly. | Restores from stored bytecode and metadata. |
| LogicSig derivation invalid | Payload has bytecode but an unknown or inconsistent derivation record; for example, a manual-counter key omits `salt_counter`, or an `algod_v13_auto_salt` key includes one or stores pre-v13 bytecode. | No; scan/verify/restore reject. | Restore rejects. |
| LogicSig on-curve address | Stored LogicSig bytecode derives an on-curve address. | No; scan/verify/restore reject. | Restore rejects. |
| LogicSig missing v1 signing metadata | Payload has bytecode but lacks `signing_metadata_version` where signing/restore would need durable metadata. | No. | Restore rejects instead of reconstructing from template. |
| DSA key missing supported base provider | DSA LogicSig names a `base_key_type` not registered in the current binary. | No. | Restore fails for that key unless the base provider is supported. |
| Template provenance unavailable | Key has no matching current template/provider fingerprint for comparison. | Yes, if key metadata is valid and node role allows it. | Warning/inventory note only. |
| Template provenance conflict | Key's optional `template_fingerprint` differs from current local definition. | Yes, if key metadata is valid and node role allows it. | Warning/inventory note only. |

#### Key file transitions

| Transition | Preconditions | Write or runtime action | Result |
|---|---|---|---|
| Generate key | Key type is discoverable/generatable, node role allows the key class, and required parameters are valid. | Create canonical account `.key` or cosigner witness `.cos`; LogicSig generation stores final bytecode, derivation metadata, signing metadata, creation params, and optional template fingerprint. | Credential becomes active after reload/scan. |
| Import mnemonic | Provider explicitly supports mnemonic import and node role allows the key class. | Derive key material and write the category-selected canonical managed credential. | Credential becomes active after reload/scan. |
| Delete key | Authenticated admin request selects an active credential. | Preserve its basename while moving `.key` or `.cos` to `deleted/keys/`. | Credential leaves active scans. |
| Backup create | Active key files are selected. | Write encrypted `.apb` payloads in managed backup archive and include source node role metadata in the archive manifest. | Source key files remain unchanged. |
| Restore preview | Managed archive and passphrase are valid. | Authenticate and inspect complete credential payloads without mutation. | Reports addresses, key types, destination presence, errors, and role mismatches. |
| Restore apply | Every selected credential validates and replacement conflicts are explicitly accepted. | Mint one generation containing credential changes only, replace `store-root.enc` once, then reload. | All selected credentials become active together; a definite pre-rename failure leaves the parent active. Visible-but-unconfirmed publication or reload failure enters recovery mode without fabricating rollback authority. |
| Restore rollback | Current generation is exactly a clean, rollback-eligible `credential-restore`. | Reconstruct the sealed parent into a fresh current-term rollback generation. | Restores the pre-restore credential state without repointing at historical ciphertext; rollback generations are not rollback-eligible. |
| Unlock/reload | The store root is open and its selected generation is bound. | Verify node role integrity, register enabled templates, scan key files, validate the scanned inventory against role, publish runtime indexes. | Valid active keys become signable; rejected files are diagnostics except role conflicts, which fail closed for the node. |
| Repair template provenance | Template/provider state is reinstalled or re-enabled. | No key-file rewrite required unless explicitly restoring missing provenance. | Inventory warnings may clear; signing behavior is unchanged. |

### Backup and restore matrix

This matrix describes restoring a template-backed or library-visible key.
Credential backups do not carry template YAML; native default-enabled keys
follow the direct key restore path.

Backup manifests carry the source node role going forward. Restore validates
payload key classes against the destination node's role; it does not change the
destination role. Rebuild treats source role metadata as a default and
diagnostic, not authority: `apstore rebuild --role signer|cosigner` sets the
destination role explicitly, while omitted `--role` uses manifest metadata when
present and otherwise defaults to `signer`.

| Destination key type state | Key restore | Template/provider restore | Generation after restore |
|---|---|---|---|
| Destination node role forbids key class | Fails or is rejected before publishing active inventory. | No template/provider state should be installed for the forbidden class. | No on this node. |
| Key type unsupported by binary | Fails if the key needs that provider or base provider. | Cannot install a runtime provider not supported by the binary. | No. |
| Key type missing locally | Succeeds when the credential has complete current-format signing metadata, any needed base provider is supported, and node role allows it. | Restore does not install templates or create key-type state. | No. |
| Key type imported/installed but disabled | Credential restore does not require enabling the template to sign. | Destination template state remains disabled. | No. |
| Key type enabled and fingerprint consistent | Normal path. | Destination template/provider state remains unchanged. | No. |
| Key type enabled but fingerprint inconsistent | Credential may still restore and sign from stored metadata. | Restore does not reconcile or overwrite destination template state. | No. |
| Backup has no template | Current-format key restore succeeds from stored key metadata when any required base provider is compiled in. | No template is part of a credential backup. | Destination state is unchanged. |
| Key already exists and is canonically identical | Idempotent no-op. | No template/provider effect. | Existing destination state remains authoritative. |
| Key already exists but differs or is unreadable | Conflict unless `replace_existing` is explicit. | No template/provider effect. | Replacement occurs only inside the atomic restore generation. |

A restored rotating account (either rotating key type) needs nothing
beyond its key file: the signer reads the live stage from the chain and
rebuilds the account's stage address table, a cache under
`identities/default/stages/` that backups never carry, in the background.
Until the table reaches the live stage, signing refuses with
`rotating_stage_unproven`.

### Runtime reload behavior

Unlock/reload publishes a new runtime snapshot only after validation succeeds.
The relevant order is:

1. open or reuse the identity keyring,
2. load root `node.yaml` and verify the identity's `node.yaml.hmac`,
3. load and validate product runtime config and the policy documents for the
   node role (`default.json` and every `policies/<selector>.json`),
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

### Transition catalog

| Operation | Key type state effect | Key file effect | Notes |
|---|---|---|---|
| Initialize node role | Writes root `node.yaml`; each initialized identity writes a matching HMAC sidecar when its term key is available. | None. | Default role is `signer`; cosigner role is explicit at initialization. |
| Verify node role integrity | None. | None. | Required before unlock-dependent key scan, signing, generation, key/store/template/mnemonic import, restore, or cosigner component signing. Client endpoint import is routing state and is outside this key lifecycle. |
| `apadmin keytype enable` | Writes/refreshes compiled enabled state, or enables an installed YAML template. | None. | Does not rewrite existing keys. |
| `apadmin keytype disable` | Deletes compiled state or disables an installed YAML template after the unused-key guard. | None. | Provider code and installed template files remain available to the store. |
| `apadmin template import` | Installs encrypted template and enabled state. | None. | Active after reload. |
| `apadmin template remove` | Deletes state and archives `.template` after unused-key guard. | None. | Removed template leaves active scans. |
| Key generation | Requires discoverable/generatable key type allowed by node role. | Writes new encrypted key. | LogicSig key stores signing authority at creation time. |
| Key deletion | None. | Archives active key file. | Archived keys are not signable. |
| Backup create | Records source node role metadata in the managed archive manifest. | Reads selected active key files into encrypted backup payloads. | Source store unchanged. |
| Backup import | None in active identity. | None in active identity. | Validates archive before publishing to managed backup locker. |
| Restore preview | None. | None. | Decrypts and reports only, including node-role mismatch diagnostics. |
| Restore apply | None. | Validates every selected complete credential, classifies canonical-plaintext identity/conflict, then commits all pending entries as one generation behind one `store-root.enc` replacement. | Destination policy/configuration remain authoritative; reload publishes all entries, and uncertain durability enters recovery mode. |
| Restore rollback | None. | Reconstructs the sealed parent of the latest clean rollback-eligible credential restore into a fresh generation. | A rollback generation is not itself eligible for another rollback. |
| Restore reconcile | None. | Validates the visible generation after interrupted or uncertain completion. | Exits recovery mode only after clean validation and reload. |
| Rebuild absent store | Writes root `node.yaml` from explicit `--role`, manifest source role metadata, or `signer` fallback. | Restores selected keys into a new product store. | Manifest role is diagnostic/default only; destination key-class gates remain authoritative. |
| Store passphrase change | Mints a fresh term and generation, re-encrypts every term-encrypted generation member, renews integrity sidecars, and atomically replaces `store-root.enc`. | Re-encrypts keys. | Logical authority and state are unchanged; the old passphrase and term no longer authorize the current generation. |
| Binary upgrade | May change compiled provider availability/fingerprints. | Existing keys unchanged. | Bad activations require explicit refresh. |
| Sign request | None. | Reads already-loaded key metadata. | Key type discovery state is not a sign-time authorization gate. |

### Key invariants

1. Key files are the signing authority for existing keys.
2. Key type state records are discovery/generation state, not signing authority.
3. Templates are generation/provenance definitions, not reconstruction sources
   for missing signing metadata.
4. Node role gates allowed key classes for generation, reload, restore, and
   signing endpoint dispatch.
5. Node role is immutable in supported tools and tamper-resistant through
   a product-store HMAC sidecar over root `node.yaml`.
6. Role-conflicting active inventory anywhere in a signer data root fails the
   whole node closed.
7. Disabled key types block new-key discovery/generation, not valid
   existing-key signing.
8. LogicSig keys must carry durable v1 signing metadata when signing/restore
   would need it.
9. LogicSig key bytecode must derive an off-curve LogicSig address.
10. DSA LogicSig keys require their stored `base_key_type` provider to be
    supported at sign time.
11. Cosigner keys are component-signing keys, not spending accounts.
12. Cosigner public sidecars are derived public metadata and must not
    be treated as independent signing authority.
13. Guarded account keys use the guarded orchestration flow; normal `/sign`
    rejects them.
14. Live backup restore validates the full selected credential set before one
    generation commit. It must not change policy, templates, or key-type state,
    replace a conflicting credential without explicit authorization, or enter
    the signing index before commit and reload complete.
15. Template/provider fingerprint conflicts are generation/provenance
    problems, not automatic invalidation of otherwise valid key files.
    Comparisons are version-aware: the fingerprint is behavior-only and
    identifier-independent, and only a same-version, different-hash pair is a
    conflict — a cross-version or malformed stored fingerprint is "not
    comparable" and benign.

## Source of truth

Primary implementation owners:

- key payload parsing/scanning: `internal/keys`
- witness public sidecars: `internal/keys/witness_public_metadata.go`
- encrypted key and template storage: `internal/keystore`,
  `internal/templatestore`
- node role and key-class gates: signer startup/identity load, keyadmin,
  restore, and signing dispatch paths
- key type state record format and primitives: `internal/keytypestate`
- feature-level template/key-type mutation: `internal/templatelibrary`
- key type catalog: `internal/keytypecatalog`
- LogicSig provider registry and template loading: `internal/lsigprovider`,
  `internal/signerapp/templates`
- key generation: `internal/keygen`, `internal/signerapp/keyadmin`
- live key type/template admin locking and reload: `internal/signerapp/templateadmin`
- staged default-template bootstrap: `internal/defaultkeytypes`
- backup/restore: `internal/backup`, `internal/signerapp/backupadmin`
- signing execution: `internal/signerapp/signing`

Related documents:

- [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md): compatibility-bearing file and
  restore contracts
- [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md): product principals and actions
- [ARCH_DATA_MODEL.md](ARCH_DATA_MODEL.md): durable/runtime/wire data model
- [DEV_KEYTYPES.md](DEV_KEYTYPES.md): developer guide for adding key types
- [USER_KEYTYPES.md](USER_KEYTYPES.md): operator key type management
- [USER_STORE_MGMT.md](USER_STORE_MGMT.md): backup and restore guide
