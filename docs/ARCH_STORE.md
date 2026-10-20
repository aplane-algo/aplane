# Signer Store

> The signer product store under `APSIGNER_DATA`: its layout, which processes
> may read or change it, how generations commit and recover, and how keys and
> key types move between states.

Each signer or cosigner data root contains one product store at
`identities/default/` and managed backups at `backups/default/`. Store-owning
APIs accept no identity locator, and live mutation and inspection use one
process-wide product-store lock. Compatibility-bearing on-disk formats are in
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md); the closed product-principal and action
model is in [ARCH_SECURITY.md](ARCH_SECURITY.md#authorization).

This document does not define transaction planning, policy verdicts, endpoint
routing, client enrollment, or approval prompts.

## Contents

- [Layout](#layout)
- [Ownership and access](#ownership-and-access)
- [Generations](#generations)
- [Keys and key types](#keys-and-key-types)
- [Backup and restore](#backup-and-restore)
- [Source of truth](#source-of-truth)

## Layout

```text
<data_dir>/
  config.yaml
  node.yaml
  audit.log
  .apstore.lock
  cache/
    .cache_key
    <network>_asa_cache.json
  library/
    templates/*.yaml        # plaintext KeyType Library YAML sources
  backups/default/
    *.tar.gz                # restorable managed/imported backup archives
    .import-*.part          # unpublished bounded upload residue
    .import-claimed-*.part  # immutable archive undergoing deep validation
    .import-validation-*/   # private same-filesystem validation residue
  .ssh/ssh_host_key
  identities/default/
    store-root.enc          # sole authenticated key-authority and generation-selection record
    .keystore               # static version 6 + store-root/v1 layout marker
    generations/<gen-id>/
      manifest.json         # immutable at-mint operation record
      seal.json             # final content record, written before flip-away
      keys/*.key            # account authority, selected by Algorand address
      keys/*.cos            # cosigner witness authority, selected by Witness Key ID
      keys/*.wit.json       # derived public witness reference; not private authority
      keytypes/<key_type>.json      # key type state record
      keytypes/<key_type>.template  # encrypted key type template
      deleted/keys/*.{key,cos}
      deleted/keytypes/<key_type>.template
      deleted/policies/<selector>.json[.hmac]  # policy archived with its deleted key
      node.yaml.hmac
      default.json          # node default policy (aplane.policy.v1), both roles
      default.json.hmac
      policies/<selector>.json       # one key's own policy; address or Witness Key ID
      policies/<selector>.json.hmac
    quarantine/generations/<gen-id>/ # non-authoritative abandoned publications
    stages/<selector>.stages        # rotating accounts' stage address tables: plaintext caches, outside generations
    config.yaml
    unlock.yaml
    .ssh/authorized_keys    # enrolled client keys; daemon-written registry
    .ssh/pending_enrollments.json # persisted requests awaiting admin approval
    passphrase              # plaintext appass-file helper artifact, mode 0600
    passphrase.cred         # systemd-creds helper artifact, mode 0600
    cosigners/<name>.json
```

The generation boundary includes all mutable state whose confidentiality or
integrity depends on a keyring term. Process and product configuration,
unlock helpers, SSH state including the enrolled-client registry and pending
enrollment queue, cosigner references, backups, the plaintext template
library, and the root node-role document are not generational.

`quarantine/` is non-authoritative. Normal resolution, signing, historical
reads, successor construction, and rollback never search it.

Layout notes:


- production signer directories are service-owned mode `0700` and ordinary
  signer files are service-owned mode `0600`; the recognized root-owned
  exceptions are `identities/default/passphrase.cred` (`root:root`, `0600`)
  and installer metadata under `install/`. Systemd setup writes
  `install/service-principal.json` as root-owned `0640` metadata containing
  schema version 1 and the numeric service `uid`/`gid`; stopped-store repair
  uses that root-controlled record and never infers its target from the store
  root being repaired
- systemd admin IPC defaults to `/run/apsigner/aplane.sock`; the runtime
  directory is service-owned `0750` and the socket is `0660`. Same-UID local
  mode defaults to `<data_dir>/aplane.sock`. An explicit systemd `ipc_path`
  must be outside the signer store in a service-user-owned directory that is
  not writable by group or other users. Trusted root/current-owned directory
  aliases are resolved and both the alias and canonical directory chains are
  validated before the daemon binds the canonical socket path. A reachable
  existing listener is a hard collision; startup removes only a stable socket
  inode that rejects a connection as stale. The configured alias, which
  clients dial, and the canonical target, which the daemon binds, are each
  rejected before `listen` when they exceed the running platform's pathname
  socket capacity: 107 bytes on Linux and a conservative 103 bytes on
  Darwin/BSD targets. An explicit client `--ipc-path` has highest precedence
  and must be absolute. An explicit client `-d` is resolved next and cannot be
  retargeted by inherited `APSIGNER_IPC_PATH`; the absolute environment socket
  override still takes precedence when the data root came from
  `APSIGNER_DATA`, which supports unreadable custom managed stores, and it may
  be used without a data root when the socket path alone identifies the signer.
  Otherwise normal data-root and runtime discovery apply. Once a selected
  root's `config.yaml` is visible, IPC discovery reads it strictly: read
  failures are errors and must never silently select a default socket for
  another store. The systemd installer derives the paired `apenv.sh` value
  through `approbe signer-ipc-path`, which uses this same resolver rather than
  parsing `ipc_path` independently in shell. The read-only environment audit
  uses the same command with `--honor-ipc-env` when its signer root was not
  explicitly selected, preserving the normal
  `APSIGNER_DATA`/`APSIGNER_IPC_PATH` pairing.
- `.apstore.lock` is the cooperative signer-store lock used by live signer startup and the local `apstore rebuild` rescue path
- signer-managed backup archives are written under
  `<data_dir>/backups/default/`; the archive contains `README.md`,
  `apb/*.apb` encrypted canonical credential payloads, `policies/*.apb`
  encrypted per-key policy documents, and `manifest.sealed` (see
  [Backup and restore](#backup-and-restore))
- imported backup archives are validated by the operator client, streamed to
  the daemon in bounded admin-protocol chunks, and atomically published under
  `<data_dir>/backups/default/`; exports stream bounded chunks in the other
  direction, so operators never need filesystem access to the private locker
- signer `cache/<network>_asa_cache.json` is signer-wide public ASA metadata for policy amount rendering; it is outside the private product store and is not authoritative for policy enforcement
- signer cache files use the same signed JSON/HMAC envelope as client cache files, with `cache/.cache_key` scoped to the signer cache root
- signer ASA cache access is serialized inside `apsigner` by `internal/signerapp/asametadata.Store`; external/manual cache edits are unsupported and tampering is rejected by HMAC validation
- signer ASA metadata is loaded per operation from disk with `internal/asa/registry` built-in metadata as seed data; there is no separate long-lived in-memory signer ASA metadata cache to reconcile
- built-in ASA metadata and convenience aliases live in `internal/asa/registry`; cache-backed current-network metadata is preferred for symbolic resolution, and registry aliases are the fallback used by shell and JavaScript helpers
- the enrolled-client registry is always `identities/default/.ssh/authorized_keys`; there is no server config field for it. The daemon is its only writer. The parser is strict: an option-free public-key line is an enrolled client whose trailing comment is its display label, comment and blank lines are allowed, every option-bearing line is rejected (options under the reserved `aplane-` prefix included), and a malformed line or a duplicate key fails the whole file with its line number. The daemon validates a complete candidate registry, writes it atomically and durably (temp file, fsync, rename, directory fsync, every failure reported), and installs it under one lock, so SSH authentication never observes a partial registry. If the write fails after the rename, the daemon re-reads the file and serves whatever it holds (refusing every key if it cannot be read) rather than keep authority the file no longer grants. A change that took effect this way is treated as made (it is audited as an enrollment or revocation and a revoked key's connections are closed) and the command that caused the write reports the durability failure on top of that, so the audit trail records the authority change separately from its durability outcome. The registry is then remembered as not yet durable, and the next registry operation re-publishes it before doing anything else, so a retried command succeeds only once a sync has succeeded; it is never acknowledged on the strength of the unsynced file
- `passphrase` and `passphrase.cred` are sensitive product-store helper files referenced by `unlock.yaml`

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
| `internal/signerapp/storeadmin`, plus `internal/storeinit` when invoked by it | Live store initialization and passphrase change, including writing the new passphrase through the configured passphrase-command helper |

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
(`status`, `export`, `check`, `diff`, `template`) hold the shared store lock.

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
Symlink and non-regular destinations are rejected. `fsutil` offers only the
private-store and root-credential profiles.

`internal/storeperm` owns read-only audit, stopped-service migration, and the
startup permission contract. It keeps a private legacy group-shared profile
used only to validate and migrate pre-migration trees. It inventories without following symlinks and
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

The format is defined in `internal/crypto/store_root.go` and
`internal/crypto/keyring.go`.

The keyring subobject carries plaintext bounded Argon2id parameters and salt
plus an AES-256-GCM-sealed payload containing the current term, sorted term
set, and exact historical generation anchors. Keyring unwrap is the passphrase
check; there is no separate verifier. The derived KEK is zeroed and never
cached. Ordinary current-state opens authorize only the current term;
historical terms require the separate exact-anchor path.

Strict parsing rejects unknown or trailing fields, oversized/non-regular
files, unsupported KDF parameters, invalid term ordering, a selection term
different from the unwrapped current term, and any selection-MAC mismatch.

The static marker is version 6 with layout `store-root/v1`. No older marker or
layout is readable, translated, or migrated in place. Initialization refuses
retired `CURRENT` and `keyring.enc` artifacts and directs operators to rebuild
from credential backup into a fresh store.

Store initialization stages the first generation with its generation-scoped
node-role sidecar, the role's default policy, and default key types before the
sole commit publishes `store-root.enc`. The generation starts with
`default.json` seeded from the embedded default for the node role
(`policy.WriteEmbeddedDefault`) plus its sidecar, and no per-key documents.
The signer default rejects a foreign rekey, reviews warning-level fields,
routes self-transfers, and leaves everything else to the operator default;
the cosigner default is deny-all, so every cosigner key rejects every request
until it is given a document. Installers and smoke-test setup must not create
or sign a root-level policy file; later policy changes target the
authenticated active generation through the stopped-store or live-admin
policy surfaces.

### Term envelope object context

Every object encrypted under a keyring term records the term in the clear and
binds both the term and the object's logical identity into the AEAD's
additional authenticated data. The identity is a class plus a canonical
selector:

| Class | Selector |
| --- | --- |
| `account-key` | Algorand address |
| `cosigner-credential` | Witness Key ID |
| `keytype-template` | key type |

Behavior:

- the identity is logical, never a path: generations copy ciphertext between
  namespaces and into `deleted/` without re-encrypting it, so a path-based
  binding would break on the first commit
- readers recover the identity from the canonical filename, so a file moved
  under another name fails to open
- a wrong key, an edited term header, and a mismatched object identity are
  indistinguishable failures: all three mean the envelope is not what the
  caller asked for
- passphrase rotation re-encrypts under a new term key with the same context,
  so a rotation cannot relabel a file while it rewrites it
- `crypto.EnvelopeTerm` exposes only the positive term header. Any caller
  using that term as inventory authority must open the same byte buffer with
  its expected logical context; inspecting the header alone is insufficient.

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
passphrase change, and policy apply mint generations. A policy apply or
removal that changes the policy set, online or rescue, mints one generation
with operation `policy-apply` (`internal/signerapp/policyapply`), so each
committed apply leaves a retained generation until explicit generation
pruning; an unchanged policy set mints nothing. Ordinary key mutations do not
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
`apstore rebuild`; `genstore.Mint` refuses a request without it (a test-only
`SkipCandidateValidation` escape exists, and `test/arch` keeps it out of
production). Rebuild
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
7. re-encrypt term envelopes and re-sign integrity sidecars under the new term:
   the node-role sidecar and every policy sidecar, including the documents
   archived under `deleted/policies/`;
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

Product-store deletion archives live inside the selected generation under
`deleted/`. Key deletion moves the encrypted key file from `keys/` to
`deleted/keys/`. Template removal deletes the state record and moves the
encrypted `.template` file from `keytypes/` to `deleted/keytypes/`. Archived
files are outside active signing scans but remain part of the generation seal.

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

- whether the product store can discover or generate a key type,
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
| Backup payload | `.apb` inside managed backup archive | Encrypted credential unit containing key material and durable signing metadata; an archive also carries each key's own per-key policy document as a separate `.apb`. Template YAML is not included. |

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
| YAML integrity or fingerprint mismatch | Encrypted `.template` does not match the state record fingerprint, cannot decrypt, or parses to incompatible metadata. | No. | No for any key; reload fails the selected generation into recovery mode (signing blocked for all keys) until the operator repairs or reinstalls the template. | Reinstall through supported template import/install path. |
| YAML removed | State record is deleted and encrypted `.template` is moved to `deleted/keytypes/`. | No. | Existing keys may still sign from stored key metadata if otherwise valid and allowed by node role. | Reinstall/import template. |

Registration-semantics outcomes are not content defects and do not block other
keys: a compiled, generic, or composed conflict with an already-registered
process-global provider, idempotent re-registration, and disabled records. A
fingerprint pair from different fingerprint versions is not comparable and is
not treated as an external edit.

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

#### Key type records

Product-store key type records under `keytypes/` are plaintext metadata. One
`<key_type>.json` record stores `key_type`, `source`, `state`, optional compatibility
`fingerprint`, and activation time (`activated_at`) for an opt-in key type. A
`source:"compiled", state:"enabled"` record makes a compiled library-visible
provider available to the product runtime for discovery and generation. YAML template
records use `source:"yaml_generic"` or `source:"yaml_composed"` and pair with an
encrypted adjacent `<key_type>.template` file. A disabled YAML record keeps the
encrypted template installed but hides that key type from discovery, reload, and
generation. These records do not gate signing for keys that already exist.

Key type state records are plaintext because they contain no key material. Record writes and
deletes are durable publications (temporary file, file fsync, rename, parent
directory fsync).

The record fingerprint is the behavior-only compatibility digest, stored as
`<n>:<sha256hex>` and described under [Key type transitions](#key-type-transitions). It is provenance
only: never read on the signing path, and not a signing secret or
authorization token.

#### Template library and installation

There are two plaintext library locations with the same relative layout:

- repository and release artifacts carry template YAML sources under top-level `library/templates/`,
- signer installations may carry a copy under `<APSIGNER_DATA>/library/templates/`.

The signer-data path is defined by `internal/storepaths.Paths.TemplateLibraryDir()`. Release installers,
installer re-runs, and test setup flows may refresh this directory from the repository or packaged copy. Files in this
directory are reference material and are not active key types by themselves.
New signer-store initialization installs and enables
`aplane.falcon1024-allowlist.v1` from the bundled library source into the
product-store encrypted template store; cosigner-role initialization skips this
signer account key type. Other bundled templates remain install sources until
explicitly imported/enabled in the product store.

The bundled templates that ship under `library/templates/` are:

| Template | Purpose |
|----------|---------|
| `aplane.falcon1024-timelock.v1` | Falcon-1024 signature gated by round-based timelock |
| `aplane.falcon1024-allowlist.v1` | Falcon-1024 signature restricted to a fixed set of receiver addresses (default-installed) |
| `aplane.falcon1024-allowlist.v2` | Falcon-1024 allowlist using a fixed-depth Merkle root with signer-generated proofs |
| `aplane.htlc.v1` | Hash time-locked contract |
| `aplane.falcon1024-allowlist-alock.v1` | Falcon-1024 bounded allowlist whose pure rekey additionally requires an external Falcon admin signature |
| `aplane.corridor.v1` | Optional bounded Falcon profile with a Merkle recipient allowlist, cosigner-authorized spends, and external-admin pure rekey |

Only `aplane.falcon1024-allowlist.v1` is installed and enabled by default for
new signer stores; the rest are available to install from the library.

`apadmin` presents this mixed source as the KeyType Library. It lists the signer-data library over the
admin protocol and also includes installed product-store templates that no longer have a matching plaintext
library YAML entry. The list result includes parsed metadata (`key_type`, `template_type`, display text,
creation parameters, and runtime arguments) when library source is available, plus install and enabled state.
Invalid files are reported as invalid entries; duplicate or ambiguous library candidates are not activation
events. Compiled providers that are `library` visible in `internal/keytypecatalog` also appear in this list
with `template_type:"compiled_provider"`; their enabled state comes from product-store key type state
records. `compiled_provider` is an admin/library wire projection of
`keytypestate.SourceCompiled`, not a `templatestore.TemplateType`; the encrypted
template store accepts only YAML-backed `generic` and `composed` template types.
YAML template entries use `installed` for encrypted template-file presence and `enabled` for whether
the installed template is exposed to generation. Installed-only entries are derived from
encrypted `.template` filenames and therefore may not include parameter metadata until matching library YAML is
available.

Installing a library template takes `key_type` and `template_type`, re-resolves the candidate from the
signer-data library, parses the YAML, writes it through the encrypted product template store under
the selected generation's `keytypes/<key_type>.template`, writes an enabled state record, then
reloads the product runtime. Installed `.template` files, not the plaintext library files, are the active persisted
runtime source for key generation and key-type discovery; the installed template is not consulted to sign
already-created keys. Template enabled state changes discovery and generation only; it is not a
signing authorization gate for existing key files. The low-level template store
persists encrypted template bytes only; `templatelibrary` coordinates it with
the paired key-type state mutation. Store initialization uses the same encrypted template
store and enabled state-record model for default YAML key types, but runs before
the runtime has a live reload surface. Activating a
`compiled_provider` library entry uses `activate_key_type` and writes only the
product-store state record because the executable provider is already registered in
the binary. Calling `activate_key_type` for an installed YAML template sets its
state record to `enabled` and reloads the runtime. Calling `deactivate_key_type`
for an installed YAML template verifies that no key of that `key_type` exists
in the product store, then sets the record to `disabled`. Calling
`deactivate_key_type` for a compiled provider uses the same unused-key guard,
then deletes the state record.

Install is idempotent for an already-installed matching key type/template
type. Reload-failure rollback follows
[Template mutation ownership and publication](#template-mutation-ownership-and-publication).
Editing or copying files into `<APSIGNER_DATA>/library/templates/` does
not change available key types until an authenticated admin installs one.

Removal helpers distinguish disabling from removal. Disabling a compiled provider removes only the product-store
state record and does not unregister process-global provider code. Disabling a YAML template leaves the
encrypted `.template` installed and sets the product-store state record to disabled. Removing an encrypted YAML template
moves the `.template` source to the product-store deleted key type archive and deletes the state record; this
removal is exposed through authenticated admin transport as `apadmin template remove`.
Disabling or removing an installed YAML template requires that no stored product
key depends on that `key_type`; compiled-provider disable has the same
unused-key guard because it removes the product store's compiled-provider opt-in. The
unused check requires the product store's current term key, scans existing keys, and returns
`key_type_in_use` on the live admin protocol when the guard blocks installed
template disable/removal or compiled-provider disable. Live key type
enable/disable, template install, non-generic key generation, key import, and
key delete operations are serialized by the product store mutation lock so key creation cannot race a
lifecycle decision made from a stale state snapshot. The underlying IPC message
names remain `activate_key_type` and `deactivate_key_type` for compatibility.

#### Template file format

Encrypted YAML in the term envelope, bound to its key type. The parsed template spec
(`generictemplate.TemplateSpec`, which embeds `templatestore.BaseTemplateSpec`)
contains:

- `schema_version`
- `derivation_version` (optional; omitted means no generated salting)
- `max_opcode_cost` (optional absolute reviewed worst-case LogicSig opcode
  cost; omission resolves to the numeric 20,000 one-transaction default shared
  by every currently supported consensus version; explicit zero is rejected)
- `template_type` (`generic` or `composed`)
- `base_key_type` (required for `composed`, rejected for `generic`)
- `publisher`
- `family`
- `version`
- `display_name`
- `description`
- `display_color`
- `template_mode` (`legacy`, `strict`, or `generated`) — carried on
  `TemplateSpec`, not on the embedded `BaseTemplateSpec`

Template capability notes:

- generic template YAML and custom composed DSA template YAML use their
  respective `schema_version: 1` contracts; composed schema v1 rejects a
  top-level `bounded` field
- bounded composed templates use `schema_version: 2`, require a typed `bounded`
  block, and reject unknown and duplicate fields at every nested level
- every APlane-bundled composed template uses schema v2; schema v1 remains a
  fully functional expert mode for imported custom DSA policies
- `bounded.layer3.policy: fixed_allowlist` owns complete pay/axfer Layer-3
  control flow; its typed parameter references are validated against declared
  parameter types and its template must omit `teal`
- schema selection occurs from the raw mapping before version-specific typed
  decoding; merge keys, aliases, multiple documents, and invalid schema
  selectors are rejected
- omitted `derivation_version` compiles the template without a generated salt
  anchor and therefore succeeds only when the unmodified bytecode already
  derives an off-curve LogicSig address
- the effective `max_opcode_cost` is compatibility-bearing for the final
  compiled/autosalted program and must cover the worst permitted runtime
  argument/value sizes; omission materializes and persists as 20,000, while an
  explicit positive declaration is preserved as an absolute override and an
  explicit zero is rejected
- APlane's closed consensus contract tests require every supported profile to
  retain `LogicSigMaxCost == 20,000` and `MaxTxGroupSize == 16`; supporting a
  profile with different values requires revisiting this numeric default
- `derivation_version: 3` uses compiler-owned TEAL v13 auto-salting and is the
  only explicit contract accepted; the retired `derivation_version: 1`
  (generated `pushbytes; pop` marker) and `derivation_version: 2` (trailing
  dead-code `bytecblock` salt anchor) are rejected at template validation
- `template_mode` is required for imported, installed, bundled, and library
  templates; templates without `template_mode` are rejected rather than
  interpreted
- `creation_params` may include scalar params, `select` params with `options[]`,
  plus unordered `address[]` and `uint64[]` list params; public key type
  surfaces preserve optional `input_modes` UI metadata for alternate parameter
  entry forms such as hash/preimage toggles
- strict generic-template YAML and Falcon composed-template YAML use declared `template_variables`
  and symbolic `$name` references that render through generated `intcblock` and `bytecblock`
  constants
- user-authored template TEAL must be relocatable: raw `bytecblock` or
  `intcblock` declarations, numeric `bytec N` or `intc N` references, and
  short forms such as `bytec_0` or `intc_0` are rejected during template
  validation
- generated-mode YAML supports restricted creation-time list expansion
- supported generated-mode list expansion form is `{{range @name}} ... {{.}} ... {{end}}`
- list expansion is creation-time only; it is not a runtime-arg feature
- Falcon/composed suffixes are predicate fragments, not standalone TEAL programs
- Falcon/composed suffixes must not contain `return`; verifier-first composition owns the final `int 1 / return`

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
| Misnamed or wrong-class managed credential | Basename selector mismatches the payload, witness payload uses `.key`, or account payload uses `.cos`. | No; its presence fails reload into recovery. | Restore derives the canonical filename from validated payload category. |
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
| Restore apply | Every selected credential validates and replacement conflicts are explicitly accepted. | Mint one generation containing credential changes and restored keys' archived per-key policies only, replace `store-root.enc` once, then reload. | All selected credentials become active together; a definite pre-rename failure leaves the parent active. Visible-but-unconfirmed publication or reload failure enters recovery mode without fabricating rollback authority. |
| Restore rollback | Current generation is exactly a clean, rollback-eligible `credential-restore`. | Reconstruct the sealed parent into a fresh current-term rollback generation. | Restores the pre-restore credentials, key-type state, and per-key policies while keeping the outgoing `default.json`, without repointing at historical ciphertext; rollback generations are not rollback-eligible. |
| Unlock/reload | The store root is open and its selected generation is bound. | Verify node role integrity, register enabled templates, scan key files, validate the scanned inventory against role, publish runtime indexes. | Valid active keys become signable; rejected files and content defects fail reload into recovery; role conflicts also fail closed. |
| Repair template provenance | Template/provider state is reinstalled or re-enabled. | No key-file rewrite required unless explicitly restoring missing provenance. | Inventory warnings may clear; signing behavior is unchanged. |

### Managed credential files

Managed credential files (`.key` and `.cos`) share one encrypted envelope and
canonical payload schema.

Both managed classes use the same encrypted envelope and canonical payload
schema. Their extension is fixed by payload category:

- `.key`: `ed25519`, `native_pq`, `dsa_lsig`, `generic_lsig`, and
  `rotating_lsig` account authority, selected by a 58-character Algorand
  address;
- `.cos`: `witness` authority assigned to cosigner custody, selected by a
  52-character Witness Key ID.

Managed credential files carry:

- envelope versioning: `envelope_version: 3`, carrying
  `{envelope_version, term, nonce, ciphertext}`,
- the object's own identity in the AEAD's authenticated data, so a credential
  filed under another name does not decrypt (see below),
- payload format versioning,
- enough metadata to recover address and key type after decryption,
- for LogicSig keys, enough signing metadata to assemble LogicSig args without
  trusting the registered template definition.

Categories:

- native signing keys,
- protocol-native post-quantum signing keys (`native_pq`),
- DSA-backed LogicSig keys,
- generic LogicSig template instances,
- rotating LogicSig accounts (`rotating_lsig`), whose authorizing program
  changes on every spend,
- signer-custodied witness keys serving the cosigner role (durable category
  `witness`; used only through cosigner-role `/sign/component`).

Generic LogicSig entries contain final compiler bytecode, derivation metadata,
and parameters rather than a private signing key. Current compiler-auto-salted
entries omit the legacy `salt_counter`.

Bounded account key files retain category `dsa_lsig`, base key type, stored
bytecode, creation parameters, and signing metadata version 2. The injected
`bounded_admin_public_key` is immutable program input. The signer derives the
Contract Admin Key ID and program binding from durable metadata; neither is a
caller-selected creation parameter.

Decrypted key payloads use one canonical v1 JSON schema owned by
`internal/keys.ParsePayload` and `internal/keys.MarshalPayload`. Readers reject
unknown fields, duplicate JSON object members, non-canonical timestamps, and
noncanonical payload aliases. Creation parameters are stored only in `parameters`;
LogicSig bytecode is stored only in `lsig_bytecode`. The durable payload does
not store a separately trusted address, template name, entropy, or
runtime-argument metadata under `runtime_args`.

Rotating LogicSig accounts use `category: "rotating_lsig"`. The key types
are `aplane.rotating-triple-wots.v1` (Falcon-1024 + WOTS-w16 + Ed25519
stages) and `aplane.rotating-triple-xmss.v1` (Falcon-1024 + RFC 8391 XMSS +
Ed25519 stages); each fixes its own derivation and stage program template,
and `internal/rotatingkey` classifies them and carries their frozen sizes
in a per-type profile. The profile also marks the stage as one-time,
because it includes a one-time hash-based signature, names what a reused
stage still rests on, and for the XMSS triple how many leaves a stage holds;
that changes only what the signer reports (`ARCH_SIGNING.md`, rotating
alerts) and which leaf it signs with, never whether it signs.

- `private_key` is the 64-byte BIP-39 seed. Mnemonic entropy is not stored.
- `genesis_hash` (32 bytes, hex) binds stage derivation to one network. No
  other category may carry it.
- `public_key` is stage 0's public record. Triple: the stage tweak (32
  bytes), the Falcon-1024 public key (1793), the WOTS public key (32) and
  the Ed25519 public key (32), 1889 in all. XMSS triple: the public account
  tag (32), the Falcon-1024 public key (1793), tree 0's root (32) and
  public seed (32), and the Ed25519 public key (32), 1921 in all.
- No program is stored: `lsig_bytecode`, `lsig_derivation`, `salt_counter`,
  `lsig_opcode_profile`, `teal_source`, signing metadata, `base_key_type`,
  `parameters` and `signing_args` are all rejected.
- The selector and account address is stage 0's program address, built from
  the stored public key. Validation re-derives stage 0 from the seed and
  genesis hash and rejects a mismatch. For the XMSS triple, whose tree 0
  root takes seconds to recompute, validation checks the tag, the public
  seed and the Ed25519 and Falcon keys on every parse and the root whenever
  tree 0 is cached; a wrong root cannot sign anyway, because the derived
  stage program would not match the account's on-chain authorizer.
- The family registers both checks with `keys.RegisterRotatingCodec`. A
  binary without that registration rejects the file; scanning reports it and
  reload fails into recovery.
- Scanning and inventory never expose the stage public keys. The resource
  profile is the same for every stage: triple 2103 program bytes, 3631
  argument bytes and an opcode ceiling of 59772 (three resource dummies);
  XMSS triple 2683, 4179 and 175562 (eight resource dummies).
- The key file is the whole credential. The signer keeps no durable state
  for the account: which stage is live is read from the chain at every
  request, and the stage address table under `stages/` (below) is a cache
  rebuilt from the seed. The XMSS triple additionally keeps the public
  nodes of its trees in memory, rebuilt from the seed when missing: at most
  three per account (the live tree, the next one built ahead of it, and one
  behind) and sixteen across accounts, the least recently used dropped
  beyond that; no secret is cached. Only accounts created at stage 0 are
  supported.

Native Falcon-1024 uses `category: "native_pq"`, `key_type: "falcon1024"`,
`pq_scheme: "f1"`, and a required numeric `pq_address_salt` in `0..255`.
The public key is exactly 1793 bytes and the private key exactly 2305 bytes.
The salt is the lowest byte whose
`SHA512/256("PQA" || "f1" || salt || public_key)` address is not an
Ed25519 curve point. Its 25-word Algorand mnemonic encodes 32 bytes of
recovery entropy; the Falcon working seed is
`SHA512/256("PQK" || "f1" || entropy)`. Recovery entropy is never persisted.

`aplane.falcon1024.v1` remains a LogicSig DSA with a 24-word BIP-39 mnemonic
and TEAL authorization, but its pre-release derivation moved in place to TEAL
v13 compiler auto-salting. Neither mnemonic nor stored key material is
interchangeable with native `falcon1024`.

This section uses **versioned signing-metadata keys** for key files that carry
`signing_metadata_version >= 1`. Non-bounded LogicSig keys use version 1;
bounded keys require version 2. LogicSig key payloads include:

- `signing_metadata_version` — required; key files lacking it are rejected for
  signing and restore
- `lsig_derivation` — the derivation contract for final stored bytecode;
  current bundled keys use `algod_v13_auto_salt`
- `salt_counter` — present only for legacy APlane-salted derivations; absent
  for compiler-auto-salted bytecode
- `signing_args` — optional; the signing-time arg schema in TEAL argument
  order, represented internally by `internal/signingargs.Info`; absent and
  empty are equivalent and mean the key takes no runtime args
- `base_key_type` — required for composed DSA keys, pointing to the signer-side
  private signing primitive used for key-material signing and signature arg
  packing; v1 signing-metadata DSA keys also persist it when it equals
  `key_type`. This field does not say which provider owns account metadata,
  creation parameters, TEAL, or guarded assembly.
- `template_fingerprint` — optional; the behavior-only, versioned (`<n>:`
  prefix) compatibility fingerprint of the template/provider definition that
  created or was bundled with the key, when known. It depends on no user-facing
  identifier (base key types are projected to a stable `base_primitive` token)
  and is provenance only, never signing authority

Bounded signing-metadata version 2 additionally requires the canonical
`bounded_authorization` object:

- `contract`: `bounded1`
- `base_signature_arg_layout`: exact base arg count and per-position maximums
- `spend_effects`, `max_fee`, and typed `admin_operations`; every operation
  explicitly carries `policy_gate: none|layer3`, and external-admin operations
  require `none`
- `runtime_args` and `derived_args`: canonical declarations, possibly empty
- `argument_layout`: complete ordered slots with source, maximum, and all path masks
- `layer3_policy`: exactly `custom`, `fixed_allowlist`, or `merkle_allowlist`
- optional `cosigner`: contract, witness key type, resolved public key and Witness
  Key ID, maximum signature size, and exact `[spend]` path; its argument slot
  source is `cosigner`
- `admin_public_key`, `admin_key_id`, and `program_binding` when an operation
  uses `authorization: admin_key`; the key ID must derive from that public key,
  and the public key must equal `parameters.bounded_admin_public_key`
- the final stored bytecode plus `argument_layout` and the durable opcode
  profile are the independent sources for program, argument, and opcode budgets

Bounded payloads with metadata version 1, non-bounded payloads with metadata
version 2, unknown nested fields, duplicate object members, invalid or
colliding argument declarations, or inconsistent admin metadata are
rejected. Backup and restore preserve the object unchanged.

Stored LogicSig bytecode and stored signing metadata are authoritative for
signing:

- generic LogicSig signing reads bytecode and orders caller-supplied runtime
  args using stored `signing_args`
- DSA-backed LogicSig signing reads bytecode and stored `signing_args`, signs
  with the stored key material, and uses `base_key_type` to find the signer-side
  private signing primitive that packs the cryptographic signature args
- the generic/composed template registered under `key_type` is not consulted
  to assemble args at sign time

Key address identity is derived from key material, not from signing metadata:

- native signing keys derive their address from stored public/private key
  material, with `key_type` selecting the address derivation implementation
- DSA-backed LogicSig keys derive their account address from stored LogicSig
  bytecode
- generic LogicSig keys derive their account address from stored bytecode;
  the canonical payload has no persisted `address` field. Scanning verifies
  the derived selector against the canonical credential filename

Fields such as `signing_args`, `signing_metadata_version`, `base_key_type`,
and `template_fingerprint` are signing/provenance metadata, not address
derivation inputs. For legacy derivations, `salt_counter` records a value
already embedded in stored LogicSig bytecode; changing metadata alone never
rederives or changes the key address. For compiler-auto-salted keys, the final
stored bytecode itself is the complete address authority.

Signer scanning binds accepted authority to the category-sensitive canonical
filename:

```text
CanonicalName(payload) = Selector(payload) || ExtensionForCategory(payload.category)
```

After decrypting a `.key` or `.cos` candidate, the scanner derives the payload
selector and category. It accepts the file only when the basename equals the
canonical name. A witness payload in `<id>.key`, an account payload in
`<address>.cos`, or any selector mismatch is skipped and reported; `.wit` and
`.wit.json` are never private-credential candidates. Writers and restore derive
the same canonical destination. Restore rejects a contradictory managed class
for the same selector even with `replace_existing`; an exact canonical destination
is replaced only when `replace_existing` is set.

Every persisted LogicSig key file must derive an off-curve LogicSig address.
Signer load, key scanning, backup verify, and restore reject an on-curve
program or a payload whose derivation metadata does not match its bytecode.

LogicSig salting is a generation-time contract:

- Current bundled providers and templates use TEAL v13 compiler auto-salting
  (`derivation_version: 3` / `lsig_derivation: algod_v13_auto_salt`).
- Algod returns the final program and address. APlane verifies that the address
  matches those bytes and is off-curve, but does not reproduce the compiler's
  deterministic salt search.
- Program length and resource profiles are derived after auto-salting from the
  exact final artifact.
- Source-to-address goldens are pinned to the configured compiler toolchain;
  runtime reproducibility comes from persisted final bytecode.
- Manual-counter derivation remains parseable only for stored records that also
  carry a valid reviewed opcode profile. Pre-profile development records are
  rejected with regeneration guidance. New template-derived key types use
  `derivation_version: 3`.
- The stored bytecode, not a live template or regenerated TEAL, is the signing
  authority.

Templates are the source for generation, discovery, and new key creation;
they are not consulted at sign time. `template_fingerprint` is provenance only:
behavior-only, versioned (`<n>:` prefix), and identifier-independent. Key
inventory surfaces may compare it with the registered local definition and
report a template conflict or unavailable template, but those notices do not
invalidate a key. The comparison is version-aware: only a same-version,
different-hash pair is a conflict; a different-version or malformed fingerprint
is "not comparable" and benign.

#### Signing authority

The key file is the signing authority. Templates and live providers are not
consulted to reconstruct missing signing metadata.

- A v1 signing-metadata LogicSig key file persists the TEAL bytecode and the
  signing-time argument contract captured at generation.
- Generic LogicSig keys store final bytecode, derivation metadata, and runtime
  argument schema. Only legacy derivations carry `salt_counter`.
- DSA-backed LogicSig keys additionally store `base_key_type`; that private
  signing primitive must be available because the signer must produce and pack
  the DSA signature. The field is not a claim that the base provider owns the
  account's metadata, creation params, or LogicSig assembly. The composed
  template/provider for that `key_type` is not required to sign an
  already-created key.
- A LogicSig key file that contains bytecode but is not a v1 signing-metadata
  key is rejected for restore and signing.

Templates are used for key creation and LogicSig bytecode derivation, creation
parameter and runtime argument metadata in generation surfaces, key-type
catalog/library/install/enable/disable flows, and live provenance comparison
through `template_fingerprint`. Credential backups do not bundle templates,
and import/restore neither recompiles nor installs them.

#### Offline key inventory

`apstore keys list` is a local, passphrase-gated inventory surface for the
product store's encrypted key files. It decrypts key metadata using
the signer-store passphrase and lists successfully scanned key addresses or
Witness Key IDs with their key type, durable category, creation timestamp, and
key-file name.

The default human output must not emit private key material, mnemonic material,
or raw public-key hex. Cosigner keys are identified by their Witness Key ID, not
by the raw cosigner public key. Recoverable key-scan warnings may be reported
while still listing keys that scanned successfully.

### Stage address tables

A rotating account's stage address table lists the addresses of its first
`k` stages, `A_0 … A_{k-1}`, so that matching the on-chain authorizer to a
stage is a lookup instead of a Falcon-1024 key generation per stage. It
lives at `identities/default/stages/<selector>.stages`, where the selector
is the account address. `internal/stagetable` is the only reader and
writer.

Trust: the table is a cache and nothing more.

- it holds no secrets; stage addresses are program hashes, and only the live
  stage's program can move the account, so the file is plaintext
- it is never trusted. Every address it returns is a hint that the signing
  derivation confirms: the stage the signer signs with must derive, from the
  seed, to the authorizer the chain reports, and the rotation target is
  always derived from the seed, never taken from the table. A tampered,
  stale or corrupt table costs a refusal or a rebuild, never a wrong
  signature
- a missing table is not an error: the signer starts an empty one and fills
  it in the background. Deleting the directory while the signer is stopped
  is always safe

Format (version 1): the magic `APSTAGES`, a big-endian `uint16` format
version, the 32-byte selector, the 32-byte genesis hash, a big-endian
`uint64` count, that many 32-byte addresses in stage order, and a SHA-256 of
everything before it. A table is prefix-complete: its length is the next
stage to derive. A file whose checksum, magic, version, selector or genesis
hash does not match is discarded and rebuilt from the seed, with a warning
in the daemon log.

Placement and lifecycle:

- the directory sits beside `generations/`, not inside one, so mints,
  credential restores and restore rollbacks never copy or rewind it, and
  the key watcher ignores it
- managed backups and exports never include it; a restored or re-imported
  key starts with an empty table and keeps signing while the background
  scan finds its live stage
- deleting a key removes its table; a background fill that loses the race
  with deletion cannot recreate it
- passphrase changes do not touch it: nothing in it is encrypted
- every write is a whole-file durable publication (temp file, fsync,
  rename); files are `0600` in a `0700` directory

Fill: while unlocked, the signer extends each account's table in the
background to `rotating.stage_horizon` stages (default 4,096) past the
account's live stage. An account whose authorizer is not in its table and
is not a key the signer holds is searched for under a bounded recovery
grant: automatically up to `rotating.recovery_max_stages` (default 1,024)
past the table's edge per unlock, or at an operator's request with the
operator's own budget (see `ARCH_SIGNING.md`, "Stage table worker"). The
seed is held only inside the derivation itself, and locking the signer
cancels the pass. The audit log, not the table, is what
rebuilds the signer's memory of released transactions at unlock (see the
`ROTATING_RELEASE` entry in `ARCH_SIGNING.md`).

### Backup and restore matrix

This matrix describes restoring a template-backed or library-visible key.
Credential backups carry each key's own per-key policy when present, but no
`default.json` or template YAML; native default-enabled keys follow the direct
key restore path.

Backup manifests carry the source node role going forward. Restore validates
payload key classes against the destination node's role; it does not change the
destination role. Rebuild uses the authenticated manifest role as the default:
`apstore rebuild --role signer|cosigner` overrides it, while omitted `--role`
uses the authenticated manifest source role, which every valid archive carries.

| Destination key type state | Key restore | Template/provider restore | New-key generation after restore |
|---|---|---|---|
| Destination node role forbids key class | Fails or is rejected before publishing active inventory. | No template/provider state should be installed for the forbidden class. | No on this node. |
| Key type unsupported by binary | Fails if the key needs that provider or base provider. | Cannot install a runtime provider not supported by the binary. | No. |
| Key type missing locally | Succeeds when the credential has complete current-format signing metadata, any needed base provider is supported, and node role allows it. | Restore does not install templates or create key-type state. | No. |
| Key type imported/installed but disabled | Credential restore does not require enabling the template to sign. | Destination template state remains disabled. | No. |
| Key type enabled and fingerprint consistent | Normal path. | Destination template/provider state remains unchanged. | Yes. |
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

1. open or reuse the product store keyring,
2. load root `node.yaml` and verify the product store's `node.yaml.hmac`,
3. load and validate product runtime config and the policy documents for the
   node role (`default.json` and every `policies/<selector>.json`),
4. apply node role to key type discovery and service dispatch,
5. register enabled compiled/YAML key type state,
6. register enabled installed templates,
7. scan active key files and validate the scanned inventory against node role,
8. publish runtime key indexes and key type discovery data,
9. activate the key session,
10. emit audit and IPC notifications.

`productruntime.Runtime.reloadLocked` runs this through the function wired by
`startup.WireReloadFunc`, which is `templates.ReloadService.Reload`.

Reload failures fail closed. For policy/config failures, the previous in-memory
snapshot remains active when one exists. Any malformed, misnamed, wrong-class,
undecryptable, unsupported, or unexpected entry in `keys/`, and any
template/key-type content defect, fails reload with a generation-validation
error: the runtime publishes an empty snapshot and enters recovery with signing
blocked. Entries are not dropped from an otherwise published snapshot.

Role-conflicting key inventory is not ordinary per-item invalidity. It is a
node-level contradiction: reload must fail closed without publishing a new
active key snapshot for the contradictory inventory.

Disabled key type state affects discovery and generation. It does not remove
already-valid key files from active key scans.

Node role is stronger than disabled/enabled state: a role-forbidden active key
is not published as valid runtime inventory.

#### Template activation and key type filtering

Template installation and product-store key-type state are resolved from key
type state records before key scan so generation/discovery state is current. The
key scan classifies generic LogicSig keys and exposes signing args directly from
the v1 signing-metadata key payload. LogicSig key files whose derivation metadata
does not match their bytecode, or whose bytecode derives an on-curve address,
are rejected during scan. LogicSig
key files missing `signing_metadata_version` are rejected when signing or
restoring would otherwise depend on missing durable signing metadata.

New enabled template `key_type` values activate on reload/unlock. Disabled
installed templates remain stored but are skipped. Reload may change what key
types can be generated or displayed as available; it must not change signing
behavior for an existing key file.

Key type immutability:

- a `key_type` is a compatibility boundary and must not be redefined in-place,
- provider registries are process-global within one `apsigner` process,
- private provider namespaces are not part of the product contract,
- custom template/provider authors must use globally unique `key_type` values in one signer process,
- signer-data library templates are authoritative install sources when present,
- keystore templates may add new non-built-in `key_type` values but must not override built-ins,
- reload/unlock may activate new key types or ignore idempotent re-loads of the same definition, but must not replace an existing conflicting definition.

Product key-type filtering:

- a process-global provider can exist without being visible to the product store,
- `/keytypes`, admin `list_key_types`, and key generation filter by the product
  store's default-enabled key types plus enabled product-store state records,
- a globally registered generic/composed template that is not installed or
  enabled for the product store is not generatable by that store,
- existing keys remain owned by the product keystore; provider
  lookup only supplies compatible signing/derivation code for keys already
  owned by the product store.

`internal/signerapp/templates` reports this through a `ReloadReport` with:

- `KeyCount`
- `TemplateNotices`
- `TemplateWarnings`
- `GenericActivatedKeyTypes`
- `ComposedActivatedKeyTypes`
- `GenericIdempotentKeyTypes`
- `ComposedIdempotentKeyTypes`
- `GenericDisabledKeyTypes`
- `ComposedDisabledKeyTypes`
- `GenericConflictingKeyTypes`
- `ComposedConflictingKeyTypes`
- `GenericInvalidKeyTypes`
- `ComposedInvalidKeyTypes`
- `InvalidStateRecordKeyTypes`
- `CompiledInvalidKeyTypes`
- `GenericExternalEditKeyTypes`
- `ComposedExternalEditKeyTypes`
- `GenericOrphanedKeyTypes`
- `ComposedOrphanedKeyTypes`
- `CompiledIdempotentKeyTypes`
- `CompiledConflictingKeyTypes`
- `GenericErr`
- `ComposedErr`
- `NamespaceDefects`

The invalid, invalid-state-record, compiled-invalid, external-edit, orphaned,
and `NamespaceDefects` buckets are content defects that fail reload.

Admin library template install verifies activation from the product-store
`ReloadReport`: the installed key type must appear in the activated or
idempotent bucket for the requested template family. A process-global provider
registry hit alone is not sufficient proof that the product runtime accepted the
template during reload.

#### Key watching

Key/template watching is implemented via `fsnotify` and owned by the one product runtime.

Watched paths:

- the product directory, for `store-root.enc` replacement and late directory
  creation
- the active generation's `keys/` and `keytypes/` directories, resolved from
  the authenticated runtime capability; no product-root namespace fallback is
  active authority

Mechanism:

- reacts to Create, Write, Remove, and Rename on `.key`, `.cos`, and `.template` files
- a `store-root.enc` replacement is a reload candidate; reload authenticates the new
  active generation. Restore, rollback, and reconcile then re-arm the watcher on
  the new generation's directories; after a policy apply or passphrase change the
  key and key type watches stay on the superseded generation until the next
  re-arm or restart, so only store-root replacement triggers a reload for
  out-of-band file edits in that window
- missing key and key type directories are tracked and added later when created
- when unlocked, qualifying changes trigger immediate reload
- when locked, the watcher remains running and marks the product runtime dirty
- watcher-triggered reload obtains the product store mutation lock before scanning keys/templates
- admin mutation paths that already hold the product store mutation lock call direct reload paths and must not call watcher-only reload entrypoints

Debounce:

- 500 ms debounce
- each qualifying event resets the timer

Lifecycle:

- starts when the product runtime is unlocked or initialized
- remains running across lock/unlock transitions
- stops on runtime shutdown

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
| Restore apply | None. | Validates every selected complete credential, classifies canonical-plaintext identity/conflict, then commits all pending entries as one generation behind one `store-root.enc` replacement. | Destination default policy/configuration remain authoritative; reload publishes all entries, and uncertain durability enters recovery mode. |
| Restore rollback | None. | Reconstructs the sealed parent of the latest clean rollback-eligible credential restore into a fresh generation. | A rollback generation is not itself eligible for another rollback. |
| Restore reconcile | None. | Validates the visible generation after interrupted or uncertain completion. | Exits recovery mode only after clean validation and reload. |
| Rebuild absent store | Writes root `node.yaml` from explicit `--role` or the authenticated manifest source role. | Restores selected keys into a new product store. | Manifest role is the default; `--role` overrides it; destination key-class gates remain authoritative. |
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
    generation commit. It must not change the node default policy, templates, key-type state,
    or configuration; it writes only credentials and each restored key's own
    archived policy document (with a current-term sidecar), and a differing
    destination per-key policy is a conflict requiring `replace_existing`. It
    must not replace a conflicting credential without explicit authorization, or enter
    the signing index before commit and reload complete.
15. Template/provider fingerprint conflicts are generation/provenance
    problems, not automatic invalidation of otherwise valid key files.
    Comparisons are version-aware: the fingerprint is behavior-only and
    identifier-independent, and only a same-version, different-hash pair is a
    conflict — a cross-version or malformed stored fingerprint is "not
    comparable" and benign.

## Backup and restore

The key-type side of restore is in the
[Backup and restore matrix](#backup-and-restore-matrix).

Backup and restore are implemented in `internal/backup`; live generation
orchestration is owned by `internal/signerapp/backupadmin`.

The authority boundary is:

> Backup owns credentials and each key's own policy document. The destination
> owns its node default policy and operational configuration.

A backup preserves complete managed credential records, not only raw private
key bytes. This includes durable LogicSig bytecode, signing-argument contracts,
bounded authorization, and other versioned signing metadata carried by
`.key` and `.cos` payloads. A key's own policy document travels with it on both
node roles; restore does not import the node default policy or operational
configuration.

### Export and archive shape

Export:

1. discovers canonical managed credentials from active `.key` and `.cos`
   files; external `.wit`, contract-admin, and deleted artifacts are excluded
2. opens each credential with its object-bound destination term envelope
3. parses and validates the complete credential payload, then canonicalizes it
4. re-encrypts the canonical payload with standalone envelope version 2 under
   the export passphrase
5. writes `apb/<selector>.apb`
6. for each exported credential with a verified policy document of its own,
   encrypts the exact document bytes the same way and writes
   `policies/<selector>.apb`

Standalone envelope version 2 fixes the Argon2id tuple at time 2, memory
65,536 KiB, and parallelism 4. Readers reject omitted, partial, or altered KDF
parameters before decoding the envelope body or invoking Argon2id; changing the
tuple requires a new envelope version. Encoded credential envelopes are limited
to 1 MiB, policy envelopes to 2 MiB, and the sealed manifest to 4 MiB; archive
readers enforce each bound while reading the regular file rather than after an
unbounded allocation. An archive holds at most 16,400 entries and 1 GiB
extracted, enough for a credential and a policy per key at the 8,192-key cosigner
cap; backup creation refuses to package an archive extraction would reject.

An all-credentials backup is fail-hard: if any selected active credential
cannot be read, decrypted, canonicalized, or exported, no archive is
published. It never silently reports a partial archive as a complete backup.

A managed archive contains exactly:

- `README.md`
- one or more `apb/<selector>.apb` files
- zero or more `policies/<selector>.apb` files, each for a credential in the
  archive that has a policy document of its own
- `manifest.sealed`

The sealed manifest plaintext uses schema
`aplane.credential-backup.manifest.v1`, schema version 1. It records the
source node role, packaging time, and the complete member inventory
(`path`, `sha256`, `size`). Backups carry no node default policy, approval defaults,
genesis-hash mappings, templates, endpoints, client enrollment, or other
operator configuration. The manifest is encrypted under the export passphrase.
Knowing that passphrase authenticates the archive as produced or endorsed by a
passphrase holder; it is not independent origin authentication.

Every archive reader authenticates the manifest and verifies exact membership
before trusting payload metadata. Missing, added, duplicated, non-canonical, or
altered members are rejected. Internal pre-release manifests, bundle wrappers,
and legacy envelope versions are unsupported; this is the first supported
backup contract and no migration from earlier internal tags is provided.

### Import and inspection

`apadmin backup import` asks the daemon to validate an external tar archive
deeply before publishing it under `backups/default/`. The commit request
carries the sensitive export passphrase; the daemon authenticates the archive
inventory and validates every credential payload, then zeros the passphrase
without persisting it. Client-side archive inspection is not an authorization
or integrity boundary. Commit is synchronous and can perform one memory-hard
credential verification per archive member, so first-party clients allow up to
30 minutes for that bounded request instead of applying the ordinary 30-second
admin timeout. Import does not compile or install templates because
templates are not archive members. The IPC transfer declares its exact source
size and SHA-256 at commit, is capped at 1 GiB while appending, and permits only
one writable upload for the product store. Commit claims the completed upload under the
store mutation lock, releases that lock for hashing and deep verification,
then reacquires it only for the final publish. A new import supersedes writable
upload residue without deleting an archive already undergoing validation;
daemon startup removes both kinds of residue left by a prior process. Deep
validation extracts into an owner-private reserved directory on the signer
store filesystem rather than the process-global temporary filesystem; normal
completion and daemon startup remove that validation residue. The final rename
is the publication commit point. If the following directory sync fails, the
daemon returns committed success with an operator-visible durability warning;
it must not report an ordinary retryable failure after the destination name is
already live.

`preview_restore` and `apadmin restore preview` authenticate the archive
before revealing addresses or key types. Preview reports credential identity,
destination presence, and validation errors; it performs no store mutation.
Wrong-passphrase and unauthenticated failures share the restore rate limiter.
Authenticated `list_backups`, `read_backup_chunk`, and `preview_restore`
requests are accepted while the identity is either unlocked or
recovery-blocked, allowing an operator to select, export, and inspect repair
material without enabling signing. Locked identities remain rejected.

`apstore verify` is fail-closed: an archive verification error or any invalid
credential returns the stable local `verification_failed` code and a nonzero
process exit.

### Live direct restore

The current admin protocol exposes a direct credential restore:

- `restore_backup`: archive path, optional selectors, export passphrase, and
  optional `replace_existing`
- `restore_backup_result`: operation ID, archive SHA-256, resulting
  generation, restored/identical/conflicting credentials, the keys whose
  archived policy was installed (`policies_restored`), key count, stable code,
  and error
- `rollback_restore`: rolls back only the latest clean, rollback-eligible
  credential restore
- `reconcile_store`: validates/reconciles the visible generation and exits
  recovery mode only when the store is clean

These operations remain authorized by the stable `identity.restore` action.
Restore, rollback, and reconciliation are callable while an authenticated
identity is recovery-blocked so they can repair or resolve store damage.

Restore validates the complete selected set before any write:

- archive/member authentication and format bounds
- payload/envelope versions and strict canonical decoding
- filename, selector, category, and key-type agreement
- public/private-key and address consistency
- LogicSig bytecode/address consistency and off-curve requirements
- complete standalone signing metadata for LogicSig credentials
- bounded-authorization consistency
- source/destination node-role compatibility
- required destination runtime/provider support
- duplicates and contradictory managed credential classes

Destination collision classification compares canonical decrypted plaintext,
not ciphertext. An identical credential is an idempotent no-op. A different
credential is a conflict requiring `replace_existing`. An existing
credential that cannot be decrypted or decoded is also a replaceable conflict,
which permits an explicitly authorized restore to repair damage in recovery
mode.

After validation, restore mints exactly one generation. The parent generation
is copied, selected credentials are applied into staged `keys/`, derived
witness public metadata is updated, the staged generation is validated and
synced, the outgoing generation is sealed, and one durable store-root rename
commits the operation. Archived per-key policy documents are applied in that
same generation, on both node roles. A differing destination document is a
conflict requiring `replace_existing`; a destination document is kept when the
archive carries none. Restore never writes templates, key-type activation
records, the node default policy, config, or network mappings.

The generation manifest operation is exactly `credential-restore`; it records
the archive SHA-256 and whether explicit rollback is eligible. Recovery-mode
repairs are not rollback-eligible because their damaged parent must never be
promoted back into service. A rollback mint uses
`credential-restore-rollback`, so a second rollback is refused.

Reload failure after a committed restore enters recovery mode and blocks
signing. The committed generation stays selected; the operator reconciles or
explicitly rolls back. Uncertain
commit durability, failed rollback after mutation, or failed reconciliation
enters recovery mode and blocks signing. A crash after a complete root replacement loads the committed
generation on restart; uncommitted staging is discarded.

Explicit rollback is allowed only when the current generation:

- was produced by exactly `credential-restore`
- is marked rollback-eligible
- still matches its authenticated effective inventory authority

Divergence refuses rollback rather than discarding later mutations. Rollback
reconstructs the sealed parent content into a fresh current-term generation; it
never repoints the store root at historical ciphertext.

Restored credentials immediately operate under the destination's approval
default, network mappings, endpoints, and installed configuration, and under
their archived per-key policy when the archive carries one (subject to the
destination conflict rule above) or the destination's default policy when it
does not. No source default-policy comparison or unattended-signing
acknowledgement is part of restore. The operator is responsible for the
policy under which restored authority runs.

### Offline rebuild

`apstore rebuild <archive-path> [--role signer|cosigner] [--address ADDRESS ...]` remains the rescue
path for an absent product store. It applies the same credential validation
and credential-only semantics into a newly staged first generation. `--address` limits the rebuild to the
selected credentials; without it every `.apb` payload is restored. The sealed
manifest source role supplies the default role. An explicit `--role` overrides
the manifest role, with a warning when the two differ. Credentials whose key
class the chosen role forbids are rejected.

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
- [ARCH_SECURITY.md](ARCH_SECURITY.md#authorization): product principals and actions
- [ARCH_DATA_MODEL.md](ARCH_DATA_MODEL.md): durable/runtime/wire data model
- [DEV_KEYTYPES.md](DEV_KEYTYPES.md): developer guide for adding key types
- [USER_KEYTYPES.md](USER_KEYTYPES.md): operator key type management
- [USER_STORE_MGMT.md](USER_STORE_MGMT.md): backup and restore guide
