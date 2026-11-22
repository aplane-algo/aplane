# Signer Store

> The signer product store under `APSIGNER_DATA`: its layout, which processes
> may read or change it, how generations commit and recover, and how keys and
> key types move between states.

Each signer or cosigner data root contains one product store at
`identities/default/` and managed backups at `backups/default/`. Store-owning
APIs accept no identity locator, and live mutation and inspection use one
process-wide product-store lock. This document owns the store's
compatibility-bearing on-disk formats, and
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) indexes them with the other contracts; the closed product-principal and action
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
  .prod                     # systemd-managed marker
  install/                  # root-owned installer metadata (release.json, service-principal.json)
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
      keys/*.cos.json       # derived public witness reference; not private authority
      keytypes/<key_type>.json      # key type state record
      keytypes/<key_type>.template  # encrypted key type template
      deleted/keys/*.{key,cos}
      deleted/keytypes/<key_type>.template
      deleted/policies/<selector>.json[.hmac]  # policy archived with its deleted key
      deleted/source_tokens/<witness_key_id>.enc  # source tokens archived with their deleted cosigner key
      node.yaml.hmac
      default.json          # node default policy (aplane.policy.v1), both roles
      asa_set.json[.hmac]   # optional ASA set (aplane.asa-set.v1); absent means built-ins only
      default.json.hmac
      policies/<selector>.json       # one key's own policy; address or Witness Key ID
      policies/<selector>.json.hmac
      source_tokens/<selector>.enc   # cosigner only: one policy selector's source tokens; Witness Key ID or default
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
  encrypted per-key policy documents, `source_tokens/*.apb` encrypted
  per-key source token files, and `manifest.sealed` (see
  [Backup and restore](#backup-and-restore)). A new archive is written and
  synced as `<name>.tar.gz.partial`, which the listing ignores, verified by
  extracting it into a `.create-validation-*` directory beside it and opening
  every payload and the manifest with the export passphrase, checksummed,
  then renamed to its managed name under the store mutation lock (never over
  a file there) and its directory synced. A failure before the rename removes
  it, so a backup that failed is never listed; a directory sync that fails
  after it leaves the archive published with a warning, as an import does.
  The daemon's startup sweep removes partial archives and verification
  directories a crash left behind
- imported backup archives are validated by the operator client, streamed to
  the daemon in bounded admin-protocol chunks, and atomically published under
  `<data_dir>/backups/default/`; exports stream bounded chunks in the other
  direction, so operators never need filesystem access to the private locker
- the signer keeps no ASA cache: its asset metadata is the generation's ASA set (`asa_set.json`) plus the built-in table, published with the policy it was loaded with. A `cache/` directory (`.cache_key`, `<network>_asa_cache.json`) left by an earlier release is neither read nor written and can be deleted
- built-in ASA metadata and convenience aliases live in `internal/asa/registry`; cache-backed current-network metadata is preferred for symbolic resolution, and registry aliases are the fallback used by shell and JavaScript helpers
- the enrolled-client registry is always `identities/default/.ssh/authorized_keys`; there is no server config field for it. The daemon is its only writer. The parser is strict: an option-free public-key line is an enrolled client whose trailing comment is its display label, comment and blank lines are allowed, every option-bearing line is rejected (options under the reserved `aplane-` prefix included), and a malformed line or a duplicate key fails the whole file with its line number. The daemon validates a complete candidate registry, writes it atomically and durably (temp file, fsync, rename, directory fsync, every failure reported), and installs it under one lock, so SSH authentication never observes a partial registry. If the write fails after the rename, the daemon re-reads the file and serves whatever it holds (refusing every key if it cannot be read) rather than keep authority the file no longer grants. A change that took effect this way is treated as made (it is audited as an enrollment or revocation and a revoked key's connections are closed) and the command that caused the write reports the durability failure on top of that, so the audit trail records the authority change separately from its durability outcome. The registry is then remembered as not yet durable, and the next registry operation re-publishes it before doing anything else (when the file could not be read back, the outcome on disk is unknown: the change is reported as applied and not durable, so it is audited and a revoked key's connections are closed; every key is refused meanwhile; and the next registry operation refuses until the file reads again and then publishes the registry the failed write intended, so the empty view that refuses every key is never written over the enrolled keys and what was reported is what the file ends up holding; if that publish fails too, every key stays refused until one succeeds. The commitment is held in memory only: a daemon restarted before it is written serves what the file holds, so a revocation reported in this state should be repeated after a restart. The enrollment queue follows the same rule), so a retried command succeeds only once a sync has succeeded; it is never acknowledged on the strength of the unsynced file
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
non-writable by group and other users. A same-UID store whose `config.yaml`
places a custom socket inside the store can still be converted while stopped;
the managed daemon then refuses that configuration until the socket is moved.

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
| `internal/asasetstore` when invoked by the daemon, candidate validation or passphrase rotation | The authenticated ASA set (`asa_set.json` and its sidecar, under the `asa-set` integrity domain) |
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
| `apstore template repair` | Offline repair of template record defects (re-pin or drop), committed as a `template-repair` generation; its preview takes the same exclusive store lock |
| `apstore source token discard` | Offline deletion, without reading it, of one selector's source token file that keeps reload in recovery |
| `appass` | Offline root/service-owner mutation of startup credentials and `unlock.yaml` |

Offline mutations require a stopped daemon, exclusive store lock, no-follow
inventory validation, and the installation-mode owner check. They preserve the
narrow root-owned `identities/default/passphrase.cred` exception and the
installer-owned `install/` metadata artifacts.

Root-run `apadmin policy rescue apply` and `remove` hold one exclusive lock
across the policy generation commit and managed-store ownership normalization,
so a daemon cannot start between publication and repair, and they normalize on
every outcome, a mint that failed after publication included. Like
`apstore template repair`, they reconcile the generation store first
(`genstore.ReconcileStoreRoot`), since no unlock precedes them. They commit
through the same `internal/signerapp/policyapply` rules as the daemon. Rescue reads
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
startup permission contract. Every audit checks one service-user-only policy
(0700 directories and 0600 files, apart from the named install, binary and
root-credential exceptions); migration treats the owner and mode findings it
reports as the repairs to make. It inventories without following
symlinks and reports unsafe ancestors, ownership, modes, hardlinks, and
unexpected file types. Its public policies are opaque operation-specific values: production
audit rejects every in-store socket, same-UID audit recognizes one exact live
socket without relaxing ancestor checks, and conversion of a same-UID store
alone receives a removable socket: the one exact in-store path its
`config.yaml` names, or the same-UID default `<data-root>/aplane.sock` when
`config.yaml` names a path outside the store, which a daemon run before that
change left behind. Repair of a managed store (`permissions migrate`,
post-root-mutation normalization, and `convert-managed` run again on a store
that is already managed, as the systemd installer does) receives none and
reads no `config.yaml`: a managed daemon never binds inside the store, so a
socket there is refused like any unexpected object. Migration validates
the complete inventory before mutation, removes the recognized socket, removes
group access at the root first, repairs recognized objects through opened
descriptors, syncs directories, and independently audits the private result. A
clean audit is authority to proceed; an incomplete audit is not.

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
migrates and audits the same-UID tree, and publishes root-controlled
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
particular, recursive template ownership repair never runs against a tree
that has not been migrated. The shell installer does not repair `.apstore.lock`; the descriptor-based
Go migrator owns that operation.

### Implemented rollout

The migration order is fixed:

1. harden writers and ownership traversal;
2. establish config-free runtime-socket discovery and move normal clients;
3. add missing authenticated policy, cosigner-reference, and generation reads;
4. move the socket to the protected runtime directory;
5. audit and migrate a stopped shared-group store to the private layout;
6. enable strict startup enforcement and private creation defaults;
7. remove group-shared behavior from normal writers, keeping only the
   read-only structural preflight that conversion and installer upgrades run.

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
authority and active-generation selection.

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
any other marker, and any store with a generation on disk, and directs
operators to restore credentials into a freshly initialized store.

Store initialization stages the first generation with its generation-scoped
node-role sidecar and the role's default policy before the sole commit
publishes `store-root.enc`. It installs no key types or templates:
default-enabled key types need no `keytypes/` record. The generation starts with
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
| `source-tokens` | cosigner policy selector: Witness Key ID or `default` |

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
- `crypto.InspectTermEnvelope` exposes only the positive term header. Any
  caller using that term as inventory authority must open the same byte buffer
  with its expected logical context; inspecting the header alone is
  insufficient.

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
the cached binding, and neither runs during a store mutation: prune takes the
store mutation lock, and list takes it without waiting, answering `store_busy`
while a mutation holds it. Every post-commit failure enters recovery before the
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
- the ASA set and its integrity sidecar, when present;
- node-role integrity sidecar;
- term numbers, sizes, and exact digests.

A retained generation must have a valid seal. Old-term retained generations
also require an exact historical seal anchor in the active keyring. A term key
alone never grants historical authority.

Generations are copied as independent files, never hardlinks. Once non-current,
they are immutable except for explicit generation pruning.

### Ordinary generation commit

Credential restore, restore rollback reconstruction, initialization, rebuild,
passphrase change, policy apply, ASA set updates (operation
`asa-set-update`), and the offline template repair (operation
`template-repair`, `apstore template repair`) mint generations. A policy apply or
removal that changes the policy set, online or rescue, mints one generation
with operation `policy-apply` (`internal/signerapp/policyapply`), so each
committed apply leaves a retained generation until explicit generation
pruning; an unchanged policy set mints nothing. Ordinary key mutations do not
mint.

The commit order is:

1. acquire the store mutation lock and any maintenance fence;
2. freshly authenticate the root and selected generation, and refuse a
   selected generation too large for any successor to fit the quarantine
   candidate limits;
3. create a private `.staging-<gen-id>` directory;
4. independently copy the parent, or construct an authorized empty successor;
5. apply the transaction and validate the complete namespace;
6. write the complete manifest, check the staged tree against the quarantine
   candidate limits, and sync the staging tree bottom-up;
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
enters recovery; callers do not blindly retry. So is a root that cannot be
read back after the error, or that matches neither the old record nor the
candidate (`genstore.RootCommitUncertain`): the candidate may have landed. Once the one root rename is
visible and directory-durable, there is no second witness or publication step.

### Passphrase and term rotation

Changing the passphrase also replaces the current data-encryption term:

1. authenticate and seal the outgoing generation;
2. retain its exact seal and manifest buffers;
3. create a fresh random term and successor keyring;
4. preserve historical keys and the exact anchor of every retained
   generation, adding the outgoing anchor;
5. stage an empty successor;
6. read every source member once and verify it against the retained seal;
7. re-encrypt term envelopes and re-sign integrity sidecars under the new term:
   every key file, template and source token file, including those archived
   under `deleted/`, with the same object context; the node-role sidecar,
   every policy sidecar, including the documents archived under
   `deleted/policies/`, and the ASA set sidecar when present;
8. validate and publish the complete successor;
9. replace `store-root.enc` with the new wrapped keyring and selector in one
   durable operation;
10. update the configured passphrase helper and reload.

Helper update failure is a post-commit warning. It never rolls the store back.
There is no pending rotation, resumable rewrap, rotation snapshot, rotation
baseline, or unlock-time completion pass.

Retained generations are not rewritten during rotation. Exact historical
anchors and anchor-gated reads preserve historical least authority.

Generation pruning does not drop a pruned generation's anchor: prune deletes
generation directories and does not rewrite `store-root.enc`, and an ordinary
root commit keeps the wrapped keyring exactly as it read it. The stale anchor
stays in the root, where it grants nothing, until the next passphrase change
leaves it out of the successor keyring. A successor never changes the anchor of a generation it
retains.

### Restore rollback

Credential restore may add a strict `rollback_capability` to its manifest. The
capability binds the originating operation, archive digest, authenticated
source generation, clean-cutover decision, and exact inventory authority.

Passphrase change carries it only when the outgoing live inventory still
matches its effective authenticated authority. Routine mutations cause that
comparison to fail: the inventory covers every file in the generation's leaf
namespaces, `source_tokens/` among them, so a source token set or removed
after a restore fails it as a key generated or deleted does. Rollback reconstructs authorized source content into a new
current-term successor; it never repoints the root at historical ciphertext.
The rollback generation does not record its source again: its manifest's parent
is the restore generation, whose capability names the source.
Rollback restores `keys/`, `keytypes/`, the per-key `policies/`, and the
per-key token files in `source_tokens/`, because restore installs a key's
archived policy and source tokens with the key. Each
restored policy document is checked against the source seal and written with a
sidecar signed under the current term. Each restored token file is checked
against the source seal, opened under the term that sealed it (through the
source's historical anchor after a passphrase change that carried the
capability), and sealed again under the current term with the same
`source-tokens` object context. The node default `default.json` and its
token file `source_tokens/default.enc`, the
ASA set (`asa_set.json`), the deleted archives, and node role authority are
kept from the outgoing generation. Backup archives carry neither the node
default nor the ASA set: a fresh node restored from a backup has the built-in
assets only until its operator confirms assets again.

**Upgrade boundary.** A generation that carries `asa_set.json` is refused by
binaries older than the ASA set (their structure validation reports an
unsupported entry). Such a generation is minted only after an operator
confirms an asset, so a store without confirmations stays readable by the
previous release; one with them cannot be downgraded across this boundary.

### Reconciliation and quarantine

Reconciliation first authenticates the root and validates its selected
generation. Until that succeeds, it deletes nothing.

- Incomplete `.staging-*` directories and durable-write temporary files have
  never carried authority and are removed.
- Sealed and declared-parent generations are retained.
- Any other complete, non-current, unsealed final directory is ambiguous:
  it may be crashed-mint residue or newer state orphaned by restoration of an
  older authentic root. It is classified and quarantined, never adopted or
  deleted.

Quarantine eligibility requires a valid ID, strict complete manifest, closed
regular-file-only layout, bounded enumeration, and live inventory digests.
At-mint mismatch is recorded but is not a veto because a formerly selected
generation may have legitimate post-mint mutations.

Bounded enumeration is one size rule, the quarantine candidate limits. It
counts every path below the generation directory, files and directories
alike, and every regular file's bytes: at most 65,536 entries, 512 MiB in
all, and 64 MiB for any one file. Classification applies it before reading
anything, quarantine accounting applies the same rule to each quarantined
generation, and every mint applies it to its staged tree before publishing
and refuses a successor that breaks it. A publication that a failed or
crashed mint leaves behind therefore always fits quarantine, and the mint
preflight's reserve of one maximum candidate covers it. The entry limit sits
above the documented count caps (8,192 cosigner credentials with their public
sidecars, 8,192 per-key policy documents with their sidecars, 8,192 source
token files, a full deleted archive), and the byte limit leaves as much again
as a full deleted archive for live state. Ordinary key mutations do not mint,
so a selected generation can grow past the limits in place; its next mint is
refused until keys are deleted and pruned from the deleted archive. If an older root is restored, a
formerly selected generation past the limits stays where it is, and only
abandoned discard (below) removes it.

**Supported store size.** The supported size is 8,192 keys, each with a
policy document of its own, beside a full deleted archive: account keys on a
signer, cosigner credentials on a cosigner (where 8,192 is also a hard cap).
That fits the limits with room for key files of up to about 25 KB (Falcon key
files are 11 to 24 KB) and policy documents of a few KB. On a cosigner each
key may also have a source token file, which is at most 4 KiB, so token files
take at most 32 MiB at 8,192 keys. Signer account keys have no hard cap: key
generation and import add to the selected generation in place and do not
check the limits. A store past them keeps signing, but every
operation that commits a new generation (passphrase change, policy apply, ASA
set changes, restore and its rollback) is refused, because its new generation
would not fit quarantine. On a signer the byte limit binds somewhere between
about 10,000 and 45,000 keys, depending on the key type, per-key policies and
how full the deleted archive is.

The staged-tree check is the authority. Before staging, a mint (and a
passphrase change, before it seals) also measures the selected generation as
a successor would copy it, without its seal and with one manifest
(`genstore.RequireSuccessorFits`), and refuses at once when that already
breaks the rule, naming the remedy; an over-limit store is then not copied,
re-encrypted and validated on every attempt. A mint that would itself shrink
the generation is refused the same way. Deleting keys and then pruning them
from the deleted archive, which do not mint, bring it back under.

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
generation state. Discard applies no size limit and refuses nothing inside its
target, since it exists for the directories that broke the limits or the
layout; it renames and removes, following no link. Such a directory can be
newer state orphaned by restoring an older root, which reconciliation
preserves and never deletes, holding the only copy of keys created after that
root, so the operator copies it out of the store before discarding it. If
it crossed a passphrase change, recovering those keys also needs the newer
store root, as below.

Eligible candidates are atomically renamed to
`quarantine/generations/<gen-id>` and both parent directories are synced.
Quarantine is bounded to eight generations and 1 GiB, twice the candidate
byte limit, so one maximum-sized candidate still leaves the next mint its
reserve. Live pruning requires
the stable `identity.generation.quarantine.prune` action, explicit
confirmation, and durable intent audit before deletion. Like discard, prune
applies no size limit.

A crashed changepass before root replacement can leave its complete successor
in quarantine. That ciphertext is non-authoritative; a later changepass remains
blocked until an authenticated operator prunes it.

If an orphan crossed a passphrase change, quarantine preserves its ciphertext
but does not imply it is decryptable with the restored root or passphrase. The
newer overwritten root must also be recovered from a coherent snapshot.

### Deleted archive capacity

Product-store deletion archives live inside the selected generation under
`deleted/`. Key deletion moves the encrypted key file from `keys/` to
`deleted/keys/`, and a cosigner key's source token file from
`source_tokens/` to `deleted/source_tokens/`. Template removal deletes the
state record and moves the encrypted `.template` file from `keytypes/` to
`deleted/keytypes/`. Archived files are outside active signing scans but
remain part of the generation seal.

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
move into `deleted/policies/` with it, on both node roles. Deleting a cosigner
key that has a source token file preflights that file with them. Key deletion
is the only operation that archives a token file: removing a source's last
token deletes the file. Mints check the parent before staging and the
successor after apply. An over-limit selected generation blocks ordinary
validation, mint, and passphrase change until pruned.

`apadmin archive list` (`list_deleted_archive`) reports exact usage and the
reserve warning; it is read-only and retries while a store mutation answers
`store_busy`. `apadmin archive prune --confirm <deleted/path>...`
(`prune_deleted_archive`) accepts only canonical
`deleted/keys/*.key|*.cos`, `deleted/keytypes/*.template`,
`deleted/policies/*.json|*.json.hmac`, and `deleted/source_tokens/*.enc`
selections. An archived policy document and its sidecar must be selected
together. It
requires `identity.archive.prune`, a recovery-capable authenticated runtime,
and durable intent audit before mutation. It changes only the selected
generation; retained copies disappear only with retained-generation pruning.

### Recovery and restoration

Keyring unwrap remains independent of selected-generation health. A valid root
and passphrase with damaged selected state enters authenticated recovery with
signing blocked. Invalid or absent root authority requires `apstore rebuild`;
the implementation never chooses the newest-looking generation.

Credential recovery restore can repair only explicitly selected credential
damage when all destination authority outside those credentials validates;
the token file of a selected cosigner key whose archived tokens it writes
counts as part of that key. Damage to policy, node-role integrity, key
types/templates, deleted archives, unselected credentials, or the selected
directory itself is not repaired by inventing authority; restore refuses and
directs the operator to rebuild. A damaged source token file a backup cannot
replace is removed with `apstore source token discard` (see
[Source token files](#source-token-files)).
Template record defects alone, an external edit or a record without its
template file, are repaired offline by `apstore template repair`, which
refuses a generation with any other damage in the same way.

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
parameters, and base signing provider reference where needed. A
compiler-auto-salted key records `lsig_derivation: algod_v13_auto_salt`; an
unsalted key has no `lsig_derivation`. The
signer must never reconstruct missing signing authority from a
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
| Native key file | selected generation `keys/<address>.key` | Native signing authority, and the `valid_rekey_target` its key type declared when it was created. |
| LogicSig key file | selected generation `keys/<address>.key` | Final LogicSig bytecode, derivation metadata, signing metadata, the `valid_rekey_target` its key type declared when it was created, and any private DSA key material. |
| Cosigner witness credential | selected generation `keys/<witness_key_id>.cos` | Witness key in cosigner custody; component-signing authority for cosigner-role `/sign/component`, never an Algorand spending account. |
| Witness public sidecar | selected generation `keys/<witness_key_id>.cos.json` | Canonical public witness reference for a local cosigner key. |
| Node role | `<APSIGNER_DATA>/node.yaml` | Single-purpose role for the signer data root. |
| Node role integrity sidecar | selected generation `node.yaml.hmac` | Product-store HMAC over the exact root `node.yaml` bytes. |
| Product runtime config | `identities/default/config.yaml` | Product runtime settings such as approval and lock timeouts; it does not carry key-class role. Unknown fields are rejected, and so is a file with no YAML document; an absent file means no overrides. |
| Key type state record | selected generation `keytypes/<key_type>.json` | Product-store discovery/generation state. |
| Installed YAML template | selected generation `keytypes/<key_type>.template` | Encrypted generation source for the product runtime after reload. |
| Deleted key archive | selected generation `deleted/keys/` | Removed key files; outside active scans. |
| Deleted template archive | selected generation `deleted/keytypes/` | Removed template files; outside active scans. |
| Source token file | selected generation `source_tokens/<selector>.enc`, cosigner nodes only | The tokens a policy selector's external sources authenticate with (see [Source token files](#source-token-files)). Not signing authority, and never in a policy document. |
| Deleted source token archive | selected generation `deleted/source_tokens/` | Token files of deleted cosigner keys; outside the runtime index. |
| Signer library template | `library/templates/<key_type>.yaml` | Install source only; not active by itself. Every entry requires product-store import/enablement; initialization installs none. |
| Compiled provider | Go provider registry and key type catalog | Binary capability; product-store visibility may be default-enabled or opt-in. |
| Backup payload | `.apb` inside managed backup archive | Encrypted credential unit containing key material and durable signing metadata; an archive also carries each key's own per-key policy document and, for a cosigner key, its source token file as separate `.apb` members. Template YAML, the node default policy and the node default's source tokens are not included. |

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
| `signer` | Native signing keys, ordinary, bounded, plain host (cosigned or not) and rotating LogicSig account keys, and public cosigner references used for generation. | Cosigner component private keys. | Normal `/sign`, `/sign/rotating/prepare` and `/sign/rotating/sign`, bounded-base `/sign/component`, `/sign/assemble`. |
| `cosigner` | Cosigner component private keys and their public sidecars. | Every account key class: native signing keys and ordinary, bounded, plain host, cosigned and rotating LogicSig account keys. | Cosigner-role `/sign/component`. |

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
| Default-enabled account-signing provider | Provider/generator is registered and cataloged as default-enabled; no identity record required. These are the protocol-native `ed25519` and `falcon1024` and the Falcon plain host `aplane.falcon1024.v1`; the Ed25519 plain host `aplane.ed25519.v1` and other selectable compiled LogicSig providers are library-visible. | Yes on signer nodes. | Yes on signer nodes, if the key file is valid and the transaction network supports its authorization kind. | None. |
| Default-enabled cosigner key type | Raw cosigner-key generator/signing support is registered and cataloged as default-enabled. The current types are `aplane.witness-falcon1024.v1` and `aplane.witness-ed25519.v1`. | Yes on cosigner nodes. | Component-signing only on cosigner nodes; never normal spending `/sign`. | None. |
| Library-visible compiled provider, inactive | Provider is registered and cataloged as library-visible; no identity `keytypes/<key_type>.json` record exists. | No. | Existing key may sign if the provider is registered, the key file is valid, and the node role allows it. | Enable from KeyType Library or `apadmin keytype enable`. |
| Library-visible compiled provider, enabled and fingerprint consistent | `keytypes/<key_type>.json` has `source:"compiled"`, `state:"enabled"`, and matching fingerprint. | Yes when allowed by node role. | Yes, if the key file is valid and allowed by node role. | Disable, if no stored key uses it. |
| Library-visible compiled provider, enabled but fingerprint inconsistent | State record exists, but the stored fingerprint does not match the provider fingerprint in the current binary. | Yes when allowed by node role: generation follows the enabled record, and reload only warns that the record conflicts. | Existing key may sign if the provider is registered, the key file is valid, and node role allows it. | Refresh with `apadmin keytype enable <key_type>`, which re-pins the record. |
| Signer library YAML only | Plaintext YAML exists under `library/templates/`; no identity install exists. | No. | No effect on existing keys. | Install/import template into identity. |
| YAML installed and enabled | Encrypted `.template` exists and state record has `source:"yaml_generic"` or `source:"yaml_composed"` plus `state:"enabled"`. | Yes after successful reload, when allowed by node role. | Existing keys sign from stored key metadata, not the template, when allowed by node role. | Disable or remove, if no stored key uses it. |
| YAML installed and disabled | Encrypted `.template` exists and state record has `state:"disabled"`. | No. | Existing keys sign from stored key metadata, not the template, when allowed by node role. | Enable, remove, or explicit template restore may re-enable. |
| YAML fingerprint mismatch | Encrypted `.template` decrypts and parses, but the state record pins another fingerprint: an external edit. | No. | No for any key; reload fails the selected generation into recovery mode (signing blocked for all keys) until the operator repairs the record. | With `apsigner` stopped, `apstore template repair` re-pins the record to the stored template or drops it; while the signer is unlocked, `apadmin template import` also re-pins it. See [Repairing a template record](USER_KEYTYPES.md#repairing-a-template-record). |
| YAML record without template file | An enabled or disabled YAML state record has no `.template`: an orphaned record. | No. | No for any key; reload fails the selected generation into recovery mode. | With `apsigner` stopped, `apstore template repair` drops the record. |
| YAML template unreadable or invalid | Encrypted `.template` cannot decrypt, or parses to incompatible metadata. | No. | No for any key; reload fails the selected generation into recovery mode. | Not a record defect, so the template repair refuses the store; rebuild from a backup archive and import the templates again. |
| YAML removed | State record is deleted and encrypted `.template` is moved to `deleted/keytypes/`. | No. | Existing keys may still sign from stored key metadata if otherwise valid and allowed by node role. | Reinstall/import template. |

Registration-semantics outcomes are not content defects and do not block other
keys: a compiled, generic, or composed conflict with an already-registered
process-global provider, idempotent re-registration, and disabled records. A
record's fingerprint is compared with its template's byte for byte, so one from
another fingerprint version is an external edit like any other difference.

#### Key type transitions

| Transition | Preconditions | Write or runtime action | Result |
|---|---|---|---|
| Enable compiled provider | Provider is registered and library-visible. | Write enabled `source:"compiled"` state record with current fingerprint. | Identity can discover/generate that key type after reload. |
| Disable compiled provider | No active key file in the identity uses that key type. | Delete the compiled state record. | Provider remains in the binary, but the identity can no longer generate it. |
| Install YAML template | Candidate YAML parses and passes admission, key type is valid, no registered provider conflicts, the template passes the preparation the reload runs for the key type its record will hold (`PrepareKeystoreTemplateRegistration`), so it cannot be the content defect that reload finds, and install is authorized. | Encrypt YAML into `.template`, write enabled state record, reload identity. A failed reload rolls the two files back. | Identity can discover/generate the template key type. |
| Disable YAML template | No active key file in the identity uses that key type. | Set state record to `disabled`, keep encrypted `.template`. | Template remains installed but hidden from generation. |
| Enable YAML template | Encrypted `.template` and state record are valid. | Set state record to `enabled`, reload identity. | Template is visible for generation. |
| Remove YAML template | No active key file in the identity uses that key type. | Delete state record and move `.template` to `deleted/keytypes/`. | Template leaves active scans. |
| Binary upgrade with changed compiled fingerprint | Existing state record fingerprint no longer matches provider. | Reload warns that the record conflicts. | Generation stays available; valid existing keys are not rewritten; `apadmin keytype enable` re-pins the record. |
| Manual file edit or copy | Operator changes state/template files outside supported paths. | Reload validates and fails closed for invalid records/templates. | Repair a record defect with `apstore template repair`, or through supported install/enable paths while the signer is unlocked; see [Repairing a template record](USER_KEYTYPES.md#repairing-a-template-record). |
| Repair a template record (offline) | `apsigner` stopped (the exclusive store lock), and the generation store reconciled first, as an unlock does (`genstore.ReconcileStoreRoot`); every key type named is a classified record defect (an external edit, or a record with no template file), every defect is named, only an external edit is re-pinned, nothing else unlock refuses is damaged (`storevalidate.TemplateRepairDestination`), and nothing only a commit refuses is (`storevalidate.CommitOnlyDamage`: a deleted-archive member that does not verify, which unlock never opens, is pruned with `apadmin archive prune` in recovery). | Mint a `template-repair` generation over the current one: a re-pin rewrites only the record's `fingerprint`, to the one the stored template computes; a drop deletes the record and moves an existing `.template` to `deleted/keytypes/`, with the archive capacity check. The candidate passes `storevalidate.Candidate` with no exclusions before the root moves. | Unlock succeeds; the damaged generation is kept as the parent. Key files are unchanged: after a re-pin a key whose recorded fingerprint differs reads `conflict`; after a drop its keys read `unavailable`. |

Fingerprint comparisons are exact. The compatibility fingerprint is
identifier-independent (it hashes behavior-bearing fields and a YAML template's
`valid_rekey_target` declaration, not `key_type`/`family`/display or a renamed
base key type) and is stored versioned
(`1:` prefix). A stored fingerprint matches only when it is byte-identical to
the one the current code computes, so one with another version prefix, no
prefix, or a malformed hash is a mismatch: an external edit for a YAML template
record, which fails the reload closed, and a conflict for a compiled provider
record. A provider with no fingerprint, as the plain hosts are, matches only a
record that pins none, so a compiled record that pins any value for it, a
well-formed `1:` one included, is a conflict. A record that pinned no
fingerprint is not compared. A formula-version bump changes every stored
fingerprint, so it is a store format change, not something reload absorbs.

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

There are three supported mutation contexts:

- live administrative operations are owned by
  `internal/signerapp/templateadmin`, which holds the store mutation lock,
  calls `templatelibrary`, then asks the read-only
  `internal/signerapp/templates` runtime owner to reload;
- the offline template repair, `internal/signerapp/templaterepair` under
  `apstore template repair`, holds the exclusive store lock with the signer
  stopped and calls `templatelibrary.RepinTemplateRecordActive` or
  `DropTemplateRecordActive` on the staged generation of a `genstore.Mint`;
- store initialization installs no key types or templates; the first
  generation carries no `keytypes/` records.

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

The record fingerprint is the compatibility digest, stored as
`1:<sha256hex>` and described under [Key type transitions](#key-type-transitions). It is provenance
only: never read on the signing path, and not a signing secret or
authorization token.

#### Template library and installation

There are two plaintext library locations with the same relative layout:

- repository and release artifacts carry template YAML sources under top-level `library/templates/`,
- signer installations may carry a copy under `<APSIGNER_DATA>/library/templates/`.

The signer-data path is defined by `internal/storepaths.Paths.TemplateLibraryDir()`. Release installers,
installer re-runs, and test setup flows may refresh this directory from the repository or packaged copy. Files in this
directory are reference material and are not active key types by themselves.
Store initialization installs none of them; every bundled template remains an
install source until explicitly imported/enabled in the product store.

The bundled templates are:

| Template | Location | Purpose |
|----------|----------|---------|
| `aplane.htlc.v1` | `library/templates/` | Hash time-locked contract |

None is installed by default. Allowlist accounts use the bounds of a plain host,
such as a preset of `aplane.falcon1024.v1`, which needs no template. Installers copy into
`<APSIGNER_DATA>/library/templates/` and never delete from it.

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
the paired key-type state mutation. Activating a
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
- `template_mode` (`strict` or `generated`, required) — carried on
  `TemplateSpec`, not on the embedded `BaseTemplateSpec`

Template capability notes:

- generic template YAML and custom composed DSA template YAML use their
  respective `schema_version: 1` contracts; composed schema v1 rejects a
  top-level `bounded` field
- bounded composed templates use `schema_version: 2`, require a typed `bounded`
  block, and reject unknown and duplicate fields at every nested level
- every APlane-bundled composed template uses schema v2; schema v1 remains a
  fully functional expert mode for imported custom DSA policies
- `bounded.layer3.policy: fixed_allowlist` owns the pay/axfer recipient check;
  its typed parameter references are validated against declared parameter types.
  A template may add `teal`, which runs after the check and can only narrow it
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
  only explicit contract accepted; template validation rejects any other value
  with `derivation_version N is not supported`
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
| Role-forbidden key file | Key type is valid, but the node role does not allow that key class. | No; reload rejects the inventory conflict. | Restore skips that key, and generation refuses it, unless the destination node role allows that key class. |
| Unknown key type | Payload names a key type unsupported by the current binary. | No. | Restore skips that key unless support exists. |
| Native key valid | Native key payload has valid key material and canonical key type. | Yes on signer nodes. | Restores directly onto signer nodes. |
| Native Falcon key in an earlier shape | Payload carries `pq_scheme` or `pq_address_salt`, or has no `recovery_entropy`. | No; scan rejects it, its presence fails reload into recovery, and verify fails. | Restore skips that key; move it by its recovery phrase. |
| DSA LogicSig key valid | Payload has private DSA material, stored LogicSig bytecode, a valid derivation record, `signing_metadata_version`, `base_key_type`, and valid signing metadata. | Yes on signer nodes when the base signing provider is registered. | Restores from stored metadata; composed template is not required. |
| Generic LogicSig key valid | Payload has stored LogicSig bytecode, a valid derivation record, `signing_metadata_version`, and stored signing args. | Yes on signer nodes. | Restores from stored metadata; template is not required. |
| Cosigner key valid | Payload category/type is a cosigner key and Witness Key ID is canonical. | Only through cosigner-role component signing on cosigner nodes; normal `/sign` and spending paths reject it. | Restores as a cosigner key on cosigner nodes, regenerating the public sidecar; never as a spending account. |
| Bounded account key valid | DSA LogicSig key with signing-metadata version 2 and a valid `bounded_authorization`. | Pure spends, spending-key rekeys, and listed rekeys use signer-held authority, with a cosigner signature on spends when the account has one. | Restores from durable bounded metadata. |
| Cosigned account key valid | DSA LogicSig key whose bounded metadata carries the cosigner overlay and whose bytecode embeds the cosigner public key (a plain or bounded host). | Only on signer nodes through the cosigned flow: bounded-base component, cosigner component (none for a listed rekey), local assembly. | Restores from stored bytecode and metadata. |
| LogicSig derivation invalid | Payload has bytecode but an unknown or inconsistent derivation record; for example, an `algod_v13_auto_salt` key stores pre-v13 bytecode. | No; scan rejects it and verify fails. | Restore skips that key. |
| LogicSig on-curve address | Stored LogicSig bytecode derives an on-curve address. | No; scan rejects it and verify fails. | Restore skips that key. |
| LogicSig missing v1 signing metadata | Payload has bytecode but lacks `signing_metadata_version` where signing/restore would need durable metadata. | No. | Restore skips that key instead of reconstructing it from a template. |
| DSA key missing supported base provider | DSA LogicSig names a `base_key_type` not registered in the current binary. | No. | Restore skips that key unless the base provider is supported. |
| Template provenance unavailable | Key has no matching current template/provider fingerprint for comparison. | Yes, if key metadata is valid and node role allows it. | Warning/inventory note only. |
| Template provenance conflict | Key's optional `template_fingerprint` differs from current local definition. | Yes, if key metadata is valid and node role allows it. | Warning/inventory note only. |

#### Key file transitions

| Transition | Preconditions | Write or runtime action | Result |
|---|---|---|---|
| Generate key | Key type is discoverable/generatable, node role allows the key class, and required parameters are valid. | Create canonical account `.key` or cosigner witness `.cos`, recording the key type's `valid_rekey_target` declaration; LogicSig generation stores final bytecode, derivation metadata, signing metadata, creation params, and optional template fingerprint. | Credential becomes active after reload/scan. |
| Import mnemonic | Provider explicitly supports mnemonic import and node role allows the key class. | Derive key material and write the category-selected canonical managed credential, recording the key type's `valid_rekey_target` declaration. | Credential becomes active after reload/scan. |
| Delete key | Authenticated admin request selects an active credential. | Preserve its basename while moving `.key` or `.cos` to `deleted/keys/`. | Credential leaves active scans. |
| Backup create | Active key files are selected. | Write encrypted `.apb` payloads in managed backup archive, with each key's own policy and a cosigner key's source tokens, and include source node role metadata in the archive manifest. | Source key files remain unchanged. |
| Restore preview | Managed archive and passphrase are valid and the source role matches. | Authenticate and admit complete credential payloads, with their policies and source tokens, without mutation. | Reports the keys a restore would admit, with key types, destination presence and the source names each carries a token for (never a token), and the keys it would skip, with the reason. |
| Restore apply | The archive authenticates, no credential the request names is skipped, at least one credential is admitted, and replacement conflicts are explicitly accepted. | Mint one generation containing the admitted credentials' changes and their archived per-key policies and source tokens only, replace `store-root.enc` once, then reload. | All admitted credentials become active together; skipped ones are reported and never written. A definite pre-rename failure leaves the parent active. Visible-but-unconfirmed publication or reload failure enters recovery mode without fabricating rollback authority. |
| Restore rollback | Current generation is exactly a clean, rollback-eligible `credential-restore`. | Reconstruct the sealed parent into a fresh current-term rollback generation. | Restores the pre-restore credentials, key-type state, per-key policies and per-key source tokens while keeping the outgoing `default.json` and `source_tokens/default.enc`, without repointing at historical ciphertext; rollback generations are not rollback-eligible. |
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
and parameters rather than a private signing key. A compiler-auto-salted entry
records `lsig_derivation: algod_v13_auto_salt`; an unsalted entry has no
`lsig_derivation`.

Bounded account key files retain category `dsa_lsig`, base key type, stored
bytecode, creation parameters, and signing metadata version 2. A bounded
account's rekey paths are the ones its `bounded_authorization` declares: a
spending-key rekey (with the cosigner on a cosigned account), a listed rekey to
an address on its rekey-to list, or none at all (`refused`).

Decrypted key payloads use canonical versioned JSON schemas owned by
`internal/keys.ParsePayload` and `internal/keys.MarshalPayload`. Readers reject
unknown fields, duplicate JSON object members, non-canonical timestamps, and
noncanonical payload aliases. Creation parameters are stored only in `parameters`;
LogicSig bytecode is stored only in `lsig_bytecode`. The durable payload does
not store a separately trusted address, template name, legacy `entropy`, or
runtime-argument metadata under `runtime_args`.

Rotating LogicSig accounts use `category: "rotating_lsig"`. The key types
are `aplane.rotating-triple-xmss.v1` (Falcon-1024 + RFC 8391 XMSS +
Ed25519 stages), `aplane.rotating-triple-slhdsa.v1` (Falcon-1024 +
two-layer SLH-DSA-SHA2-128 + Ed25519), and `aplane.rotating-triple-wotsc.v1`
(Falcon-1024 + a tree of WOTS+C keys + Ed25519); each fixes its own derivation and stage program template,
and `internal/rotatingkey` classifies them and carries their frozen sizes
in a per-type profile. SLH-DSA marks `StatelessHash` and keeps no one-time
leaf history. Each hash-based leaf of the XMSS and WOTS+C profiles is one-time,
and each stage has 64 such leaves. The profiles control leaf selection.
Signing waits for release-history restoration, including its
interruption handling; exhausting the leaves is reported but does not itself
refuse a release (see `ARCH_SIGNING.md`, rotating accounts).

- `private_key` is the 64-byte BIP-39 seed. Mnemonic entropy is not stored.
- `genesis_hash` (32 bytes, hex) binds stage derivation to one network. No
  other category may carry it.
- `public_key` is stage 0's public record. XMSS triple: the public account
  tag (32), the Falcon-1024 public key (1793), tree 0's root (32) and
  public seed (32), and the Ed25519 public key (32), 1921 in all. SLH-DSA
  triple and WOTS+C triple: public seed (16), root (16), Falcon public key
  (1793), Ed25519 public key (32), 1857 in all, in that order.
- No program is stored: `lsig_bytecode`, `lsig_derivation`,
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
  profile is the same for every stage: XMSS triple 2675 program bytes, 4179
  argument bytes and an opcode ceiling of 95859 (four resource dummies);
  WOTS+C triple 2497, 2115 and 15723 (two resource dummies); SLH-DSA
  triple 2848, 5887 and 68647.
- The key file holds the signing authority. Which stage is live is read
  from the chain at every request, and the stage address table under
  `stages/` (below) is a cache rebuilt from the seed. XMSS and WOTS+C also
  retain release history in the audit log to rebuild leaf-use memory at
  unlock. The seed cannot reconstruct that history; losing it can cause
  undetected leaf reuse. The XMSS triple additionally keeps the public
  nodes of its trees in memory, rebuilt from the seed when missing: at most
  three per account (the live tree, the next one built ahead of it, and one
  behind) and sixteen across accounts, the least recently used dropped
  beyond that; no secret is cached. Only accounts created at stage 0 are
  supported.

Native Falcon-1024 uses `category: "native_pq"`, `key_type: "falcon1024"`
and `format_version: 1`, the one format every category uses. The public key
is exactly 1793 bytes and the private key exactly 2305 bytes. The key file
stores neither the protocol scheme nor the address salt. The key type fixes
the scheme: `keys.NativePQScheme` maps it, and the payload validator and the
fee planner read it there. The Falcon-only signed envelope (`signerops`) uses
`nativefalcon.Scheme`, the constant that mapping returns for `falcon1024`. The salt
and address follow from the public key: `keys.NativePQAddress` derives them
for validation, `Selector`, generation and signing. For `falcon1024` the
scheme is `f1` and the salt is the lowest byte whose `SHA512/256("PQA" || "f1" || salt || public_key)` address is not an
Ed25519 curve point. `internal/keys/native_pq_test.go` freezes that derivation
with literal vectors: a different scheme or address rule is a new key type,
not a change to `falcon1024`. Its 25-word Algorand mnemonic encodes 32 bytes
of recovery entropy; the Falcon working seed is
`SHA512/256("PQK" || "f1" || entropy)`. Every native Falcon credential keeps
the 32-byte entropy as canonical hex `recovery_entropy` inside the encrypted
payload; no other category may carry it. The full admission parse
(`keys.ParsePayload`, also run by `MarshalPayload` before any write) requires
it to reproduce the exact stored public/private key pair; it is never included
in public metadata or signing projections. Re-deriving the pair is a full
Falcon key generation, so hot reads of credentials already in the
authenticated store (key scans, signing lookups, key list and details) use
`keys.ParseStoredPayload`, which checks the entropy structurally and runs the
cheaper key-pair probe instead. Ingress paths (backup restore, import, copy)
and mnemonic export always use the full parse. Backup/restore and passphrase
changes preserve it, and secret cleanup wipes it.

A native Falcon key file written before key files dropped `pq_scheme` and
`pq_address_salt`, or one from before native Falcon kept recovery entropy, is
refused by both parses. A store that holds such a file cannot be upgraded in
place: the scan reports the file as an incompatible key file, and a reload
fails closed on any scan warning
([Runtime reload behavior](#runtime-reload-behavior)), so the signer publishes
no keys at all and enters recovery with signing blocked. A restore of a backup
that holds such a key admits every other credential and skips that key with
its reason. To move such a store, install fresh, restore its backup, which
brings the LogicSig, rotating, witness and other keys and skips the native
Falcon ones, and then move each native Falcon key by exporting its 25-word
phrase from the old install and importing the phrase into the new one. A native
Falcon key from before v0.48.0 has no recovery entropy and so no phrase; move
its funds to a new account from the old install. Native addresses and signing
are unchanged.

Native Ed25519 recovery phrases are reconstructed from the validated private
key and need no storage change. Both native types may explicitly export their
25-word phrase through authenticated local apadmin with fresh passphrase
verification. Other credential classes continue using encrypted backups.

`aplane.falcon1024.v1` remains a LogicSig DSA with BIP-39 seed derivation and
TEAL authorization, but its pre-release derivation moved in place to TEAL v13
compiler auto-salting. Its seed derivation and stored key material are not
interchangeable with native `falcon1024`.

Plain `aplane.falcon1024.v1` and `aplane.ed25519.v1` are
[plain hosts](ARCH_KEYTYPES.md#plain-hosts) (`aplane.falcon1024.v1`
default-enabled, `aplane.ed25519.v1` opt-in per node), with no mnemonic
import. Their stored credentials, internal derivation, and encrypted
backup/restore contracts are unchanged; a plain host account with overlays also
stores its `plain1` bounded metadata, and one with bounds its `bounded2`
metadata.

This section uses **versioned signing-metadata keys** for key files that carry
`signing_metadata_version >= 1`. Non-bounded LogicSig keys use version 1;
bounded keys require version 2. LogicSig key payloads include:

- `signing_metadata_version` — required; key files lacking it are rejected for
  signing and restore
- `lsig_derivation` — the derivation contract for final stored bytecode;
  current bundled keys use `algod_v13_auto_salt`, and it is absent for unsalted
  bytecode
- `signing_args` — optional; the signing-time arg schema in TEAL argument
  order, represented internally by `internal/signingargs.Info`; absent and
  empty are equivalent and mean the key takes no runtime args
- `base_key_type` — required for composed DSA keys, naming the signature
  construction whose signer-side provider signs with the key material and packs
  signature args; v1 signing-metadata DSA keys also persist it when it equals
  `key_type`. This field does not say which provider owns account metadata,
  creation parameters, TEAL, or cosigned assembly.
- `template_fingerprint` — optional; the versioned (`1:` prefix)
  compatibility fingerprint of the template/provider definition that created
  or was bundled with the key, when known, covering its behavior and a YAML
  template's `valid_rekey_target`. It depends on no user-facing
  identifier (base key types are projected to a stable `base_primitive` token)
  and is provenance only, never signing authority

Bounded signing-metadata version 2 additionally requires the canonical
`bounded_authorization` object:

- `contract`: `bounded2`, or `plain1` for a plain host account without bounds
- `base_signature_arg_layout`: exact base arg count and per-position maximums
- `spend_effects` (empty on `plain1`), `max_fee` (required on `bounded2`, where
  any value from 0 to 2^53 - 1 is valid; absent on `plain1`), and `rekey`: `refused` (no rekey path, except to a
  listed address when `rekey_list` is set) or `spending_key` (the spending key
  authorizes a pure rekey: alone, or with the cosigner on a cosigned account)
- optional `rekey_list`: `contract` (`rekey_list1`), `depth` (4), and the
  account's `root`; beside `rekey: refused` (*only these*), or beside
  `rekey: spending_key` with a cosigner (*plus cosigned*). Its
  entries are the stored `rekey_to` creation parameter, and its salts derive from
  the spending key, so the key file carries everything a listed rekey needs
- `runtime_args` and `derived_args`: canonical declarations, possibly empty;
  derived kinds are `merkle_allowlist_proof` (512 bytes) and `rekey_list_proof`
  (160 bytes, exactly one with a `rekey_list`)
- `argument_layout`: complete ordered slots with source, maximum, and the
  `spend`, `spending_rekey`, and `listed_rekey` path masks
- `layer3_policy`: exactly `custom`, `fixed_allowlist`, `merkle_allowlist`,
  `fixed_allowlist_custom`, `merkle_allowlist_custom`, or `none`
- optional `cosigner`: contract, witness key type, resolved public key and Witness
  Key ID, maximum signature size, and `required_on`, exactly `[spend]`, or
  `[spend, spending_rekey]` beside `rekey: spending_key`; its argument slot source
  is `cosigner`, required on those paths and forbidden on `listed_rekey`
- the final stored bytecode plus `argument_layout` and the durable opcode
  profile are the independent sources for program, argument, and opcode budgets

Bounded payloads with metadata version 1, non-bounded payloads with metadata
version 2, unknown nested fields, duplicate object members, invalid or
or colliding argument declarations are rejected. Backup and restore preserve the object unchanged.

Stored LogicSig bytecode and stored signing metadata are authoritative for
signing:

- generic LogicSig signing reads bytecode and orders caller-supplied runtime
  args using stored `signing_args`
- DSA-backed LogicSig signing reads bytecode and stored `signing_args`, signs
  with the stored key material, and uses `base_key_type` to find the signer-side
  provider for the signature construction, which packs the cryptographic signature args
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
derivation inputs. `lsig_derivation` is the derivation record, not part of the
address; changing metadata alone never rederives or changes the key address. For every LogicSig key, the final stored bytecode itself is the
complete address authority.

Signer scanning binds accepted authority to the category-sensitive canonical
filename:

```text
CanonicalName(payload) = Selector(payload) || ExtensionForCategory(payload.category)
```

After decrypting a `.key` or `.cos` candidate, the scanner derives the payload
selector and category. It accepts the file only when the basename equals the
canonical name. A witness payload in `<id>.key`, an account payload in
`<address>.cos`, or any selector mismatch is skipped and reported; `.cos.json`
is never a private-credential candidate. Writers and restore derive
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
- An auto-salted record's opcode profile is checked when it parses. An unsalted
  record (no `lsig_derivation`) without a valid opcode profile still parses,
  but key scan skips it with an `incompatible_key_format` warning
  (`scanLogicSigResources` in `internal/keys/keys.go` refuses it), so it never
  signs. New template-derived key types use `derivation_version: 3`.
- The stored bytecode, not a live template or regenerated TEAL, is the signing
  authority.

Templates are the source for generation, discovery, and new key creation;
they are not consulted at sign time. `template_fingerprint` is provenance only:
versioned (`1:` prefix) and identifier-independent, covering behavior and a
YAML template's `valid_rekey_target`. Key
inventory surfaces may compare it with the registered local definition and
report a template conflict or unavailable template, but those notices do not
invalidate a key. The comparison is exact: a stored fingerprint that is not
byte-identical to the registered one, another version prefix or no prefix included,
is a conflict.

#### Signing authority

The key file is the signing authority. Templates and live providers are not
consulted to reconstruct missing signing metadata.

- A v1 signing-metadata LogicSig key file persists the TEAL bytecode and the
  signing-time argument contract captured at generation.
- Generic LogicSig keys store final bytecode, derivation metadata, and runtime
  argument schema. Unsalted keys carry no `lsig_derivation`.
- DSA-backed LogicSig keys additionally store `base_key_type`; that signature
  construction's provider must be available because the signer must produce and pack
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

### Source token files

A cosigner policy document's external sources may authenticate with a token.
Tokens are kept in the store, never in a document: one file per policy
selector, `source_tokens/<selector>.enc` in the selected generation, where
the selector is a cosigner key's Witness Key ID or `default` for the node
default document. `internal/sourcetokens` owns the format, its
reads and writes, and the runtime index.

- **Encryption.** The file is a term envelope of class `source-tokens`
  whose selector is the policy selector, so a file renamed to another
  selector fails to open.
- **Plaintext.** `aplane.source-tokens.v1`, canonical compact JSON:
  `{"format":"aplane.source-tokens.v1","selector":"<selector>","tokens":{"<source>":{"set_at":"<RFC 3339 UTC>","value":"<token>"}}}`,
  sources sorted, with `\"` and `\\` the only escapes. A reader refuses
  anything else, a duplicate or unknown member included. `set_at` records
  when each token was set, to the second.
- **Limits.** At most 8 tokens. A source name follows the policy document
  rule (`^[a-z0-9][a-z0-9_-]*$`, at most 64 characters). A token is 1 to
  1,024 bytes of visible ASCII (0x21 to 0x7E). The encrypted file is at most
  4 KiB; a set that would exceed it, under the current term or any later
  one, is refused.
- **Role and selector.** Token files exist only on cosigner nodes; one on a
  signer node is a role conflict. Candidate validation refuses a file whose
  selector is neither `default` nor a cosigner key the generation holds.
  Nothing checks whether a document uses a token.
- **Writing.** Setting or removing a token is an in-place, durable write of
  the selected generation (temp file, fsync, rename, directory fsync) under
  the store mutation lock, on an unlocked cosigner node; it mints no
  generation. Setting needs `default` or a held cosigner key. Removing the
  last token deletes the file; nothing is archived. The admin messages
  `source_token_set`, `source_token_remove` and `source_token_list` drive
  them ([ARCH_ADMIN.md](ARCH_ADMIN.md)); a listing reads the files, names and
  set times only, and zeroes what it decrypts.
- **Runtime index.** Reload decrypts every token file into an immutable
  index keyed by selector and source, published with the policy. A set or
  remove publishes a new index once its write is durable; a write whose
  durability is uncertain publishes what the file then holds. A replaced
  index is zeroed when its last reader has released, never while one may
  hold it. Lock cleanup zeroes the index after the key users have drained;
  a locked node has none. An unlock request on a node already unlocked
  reloads nothing, so it neither replaces nor clears the index the session
  in service holds, and a set or remove beside it is the change that
  stands. An unlock reload, from locked or recovery, holds the store
  mutation lock, so no set or remove lands during it. An unlock reload that
  fails clears the index when it closed the keyring, and leaves it when a
  keyring stayed open: one begun in recovery leaves recovery a keyring
  whatever step failed. A node that goes from unlocked to recovery keeps its
  index with the keyring, and so does an unlock the fence refuses; a recovery
  entered because the reload of an unlock of a locked node failed validation
  has none. A lock removes a kept index and a later reload
  replaces it. In recovery no lookup runs, and a policy check is answered
  no token names from the index. A token sent in a request
  header is a Go string, which cannot be zeroed; zeroing covers the index.
- **Lifecycle.** Key deletion moves the key's file to
  `deleted/source_tokens/`; archive prune accepts it; a generation mint
  copies token files with the generation; a passphrase change re-encrypts
  them under the new term with the same object context. A backup carries a
  cosigner key's file with the key, and restore, its rollback and
  `apstore rebuild` write it back ([Backup and restore](#backup-and-restore));
  the node default's file is not backed up.
- **Damage.** A token file that does not decrypt or decode fails reload into
  recovery (a generation-validation failure, as a malformed key file is; see
  [Runtime reload behavior](#runtime-reload-behavior)); one on a signer node
  is a role conflict instead, which fails the node closed. A recovery-mode restore with `replace_existing` replaces a
  damaged file of a key the backup carries tokens for. Otherwise
  `apstore source token discard <selector>`, run while the daemon is stopped,
  deletes the named file without reading it, under the exclusive store lock;
  nothing is archived and no audit record is written. The next unlock loads
  the remaining files, and the selector's sources refuse with
  `token_not_set` until a token is set again. `apadmin policy rescue` reads
  token files only for its missing-token advisory, so a damaged one never
  fails a rescue: the names are then not known, and rescue names the
  selector whose file it could not read and the discard command, or an
  entry of `source_tokens/` that is no token file, which discard cannot
  name, to be removed by hand with the daemon stopped. A rescue
  apply is still refused before anything is committed, since candidate
  validation admits a generation only with every token file whole.

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

Format (version 2): `APSTAGES`, big-endian `uint16` version, 32-byte
selector, 32-byte genesis, big-endian `uint64` entry count, sorted records
of `(uint64 stage, 32-byte address)`, JSON metadata (`key_type`, optional
`hint`), and SHA-256 over everything preceding the checksum. The reader caps
files at 64 MiB and rejects invalid lengths, duplicate indices/addresses,
overflow and wrong identity. A file of any other version is discarded like
any other unusable table and rebuilt by stage rediscovery.

The cache is sparse: its entry count is neither history coverage nor the
next stage. A matching hint at 50,000 inserts that stage immediately, without
deriving 0–49,999. Completed unsuccessful probes remain cached. General
search prefers the persisted observation, or local release candidates when
no observation exists. It finds the first missing stage above that anchor;
after an initial 16-position interval, three forward probes alternate with
one probe into the lowest gap. Coverage persists across restart; no maximum
cached stage implies coverage below it. Explicit operator windows stay bounded.

Candidates come from the table's hint (a backup's, or the signer's own last
observation), local release candidates, an operator's stage hint, and the
chain. With `networks.<token>.indexer` configured, a recovery grant without an
operator's hint first tries the stage the account's last confirmed rekey reads,
found in one Indexer request for one result, and skipped for a
minute after that network's Indexer failed to answer a lookup
(see [ARCH_SIGNING.md](ARCH_SIGNING.md#rotating-accounts-rotating1)). That
probe is an ordinary derivation: its address is retained like any probe, a
miss included, and repairs or confirms an unverified record at that stage; a
stage held with a verified other address is not derived again. The Indexer is
never a hint source: the candidate is not stored as the hint and does not
steer the search that follows, and only the worker's own seed-derived match
becomes a `local_observation`.

The optional hint records `stage`, optional `observed_round`, `authorizer`
and source (`local_observation` or `backup`). Only a seed-derived address
matching the configured chain produces a local observation. Merge hints by
round: known beats absent, higher beats lower, local beats backup on ties,
and otherwise retain the existing value. Neither hint nor checksum confers
signing authority. Loaded mappings must be re-derived before acceptance;
verified memory is tied to the credential inventory lifetime.

Placement and lifecycle:

- the cache sits beside `generations/`, outside generation transactions;
  mints and rollbacks do not rewind it
- backups omit the full file, but may carry an optional stage hint in the
  sealed manifest; a restore without a hint uses bounded discovery, which,
  with an Indexer configured, begins with the chain's candidate
- deletion closes handles and removes the file; inventory reload starts a new
  derivation epoch and forgets verified memory while retaining cached progress,
  observations and open handles (the selector binds the seed, so a reload
  cannot change the credential behind a held table, and running requests and
  recovery grants continue)
- passphrase changes need no cache encryption changes
- publication uses a private, atomic, durable whole-file write; background
  work batches writes. Publication holds a separate write lock; lookups and
  foreground memory updates do not wait for disk I/O. Prepare/sign wake the
  worker only when they leave unpublished progress; re-deriving cached entries
  or seeing the same stage again at a later round is not a change to publish.
  Restart before that write may require a fresh prepare. A failed publication retains verified memory, warns
  and retries. A wrong record is repaired in both indexes without discarding
  independent entries. File-level corruption may discard the cache.

While unlocked, the worker prepares the immediate successor before additional
lookahead, bounded by `rotating.stage_horizon` and family ceilings. A zero
lookahead still prepares the successor required to spend. SLH-DSA
caps lookahead at two and address derivations at four per pass. Unknown
authorizers are searched under the existing automatic per-unlock allowance
(default 1,024) or explicit operator grants. Finding the stage ends discovery;
preparing its successor does not require historical derivation. Neither cache
count nor an exhausted search proves an account has exited rotation.
Seeds remain held only during derivation, outside cache I/O and pacing.
The audit log independently restores released-transaction and leaf memory.

### Backup and restore matrix

This matrix describes restoring a template-backed or library-visible key.
Credential backups carry each key's own per-key policy when present, and a
cosigner key's source token file when present, but no `default.json`, node
default source tokens, or template YAML; native default-enabled keys follow
the direct key restore path.

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

A restored rotating account gets its signing authority from its key file.
The signer derives candidate stages and checks them against the live
authorizer on its own chain. It rebuilds the stage address cache under
`identities/default/stages/`; managed backups may supply recovery hints,
but do not carry the cache or audit log. Until the live stage is proven,
signing refuses with `rotating_stage_unproven`.

Preserve the audit log separately to retain release alerts and XMSS or WOTS+C
leaf-use history. Reconstructing the stage addresses does not reconstruct
which leaves have signed. Missing history can cause undetected reuse even
when the restored credential and live-stage discovery are valid.

### Runtime reload behavior

Unlock/reload publishes a new runtime snapshot only after validation succeeds.
The relevant order is:

1. open or reuse the product store keyring,
2. load root `node.yaml` and verify the product store's `node.yaml.hmac`,
3. load and validate product runtime config and the policy documents for the
   node role (`default.json` and every `policies/<selector>.json`), and
   decrypt every source token file into the source token index, published
   with them,
4. apply node role to key type discovery and service dispatch,
5. register enabled compiled/YAML key type state,
6. register enabled installed templates,
7. scan active key files and validate the scanned inventory against node role,
8. publish runtime key indexes and key type discovery data,
9. activate the key session,
10. emit audit and IPC notifications.

`productruntime.Runtime.reloadLocked` runs this through the function wired by
`startup.WireReloadFunc`, which is `templates.ReloadService.Reload`.

An unlock runs this order only when the signer is not already unlocked. A
reload with the passphrase replaces the keyring at step 1 and the policy,
source token index and key indexes after it, and one that fails validation
publishes an empty key snapshot, so an unlock request on an unlocked signer
does not reload: it verifies the passphrase and answers with the session's
key count, and the session in service keeps its keyring, policy, key indexes
and source token index. A reload with the passphrase that fails closes the
keyring it opened only when none was open before, as in an unlock of a locked
signer. An unlock begun in recovery finds recovery's keyring open; its reload
replaces it with one opened from the same store root, and a failure leaves
that one, with the generation binding and the source token index, so the
reconcile, restore and rollback recovery needs still run. Unlock attempts run one at a time. An unlock's
reload, from locked or recovery, holds the store mutation lock from its state
check to the end of the reload, as watcher-driven reloads and admin
mutations do, and the unlock publishes the unlocked state after releasing
it. The startup unlock of a headless signer reloads before the admin
listener starts.

Reload failures fail closed. For policy/config failures, the previous in-memory
snapshot remains active when one exists. Any malformed, misnamed, wrong-class,
undecryptable, unsupported, or unexpected entry in `keys/`, and any
template/key-type content defect, fails reload with a generation-validation
error: the runtime publishes an empty snapshot and enters recovery with signing
blocked, whichever reload found it. An unlock enters it through its recovery
unlock. A reload without the passphrase (the watcher's, an in-place write's
such as key generation or deletion, a template administration's, a
reconcile's, or one after a store-root commit) enters it before it returns,
under the store mutation lock its caller holds (`productruntime.Runtime.Reload`),
and recovery keeps the keyring for the reconcile that lifts it once the
generation is repaired. The daemon logs the entry with its cause and pushes a
`status` in recovery to the admin session, since no reply reports it; a key
change's reply is `recovery_blocked` with the cause
([ARCH_ADMIN.md](ARCH_ADMIN.md)). A reload failure of another kind, such as a `keys/`
directory that cannot be read, leaves the runtime state of the watcher's and
an in-place write's reload as it was, and the caller reports it; a caller
after a store-root commit enters recovery on any failure. Two key files in
`keys/` that resolve to one signing address (`keys.ErrAddressCollision`) are
a content defect too: the reload publishes an empty snapshot, and a reload
without the passphrase enters recovery for it as for a validation failure.
An unlock that meets one still answers a failed unlock. Entries
are not dropped from an otherwise published snapshot. A
source token file that cannot be read, opened or decoded as its selector's,
and an entry of `source_tokens/` that is not a token file, are damage of the
same kind (`sourcetokens.ErrDamaged`): the reload fails with a
generation-validation error before any key is scanned, but after the verified
policy is published, as it is when a key file is damaged, so the recovery an
unlock then enters, with signing blocked, shows and exports that policy. A `source_tokens/` directory that cannot be
read at all fails the unlock instead, as an unreadable `keys/` does.

Role-conflicting key inventory is not ordinary per-item invalidity. It is a
node-level contradiction: reload must fail closed without publishing a new
active key snapshot for the contradictory inventory.

Disabled key type state affects discovery and generation. It does not remove
already-valid key files from active key scans.

Node role is stronger than disabled/enabled state: a role-forbidden active key
is not published as valid runtime inventory.

A source token file is checked at reload only for what it is: it decrypts as
its own selector's, its name is canonical, and its schema and limits hold
(admission, not load). A damaged one fails the reload. One on a signer node
is a role conflict and fails the node closed, as a role-forbidden key does.

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
- `DisabledOrphanedKeyTypes`
- `CompiledIdempotentKeyTypes`
- `CompiledConflictingKeyTypes`
- `GenericErr`
- `ComposedErr`
- `NamespaceDefects`

The invalid, invalid-state-record, compiled-invalid, external-edit, orphaned
(enabled and disabled), and `NamespaceDefects` buckets are content defects that
fail reload. The external-edit and orphaned buckets are the template record
defects (`RecordDefects`) an offline `apstore template repair` acts on.

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
- does not watch `source_tokens/`: the daemon is the only writer of token
  files and publishes the token index itself after each write
- a `store-root.enc` replacement is a reload candidate; reload authenticates the new
  active generation. Restore, rollback, and reconcile then re-arm the watcher on
  the new generation's directories; after a policy apply, ASA set update, or passphrase change the
  key and key type watches stay on the superseded generation until the next
  re-arm or restart, so only store-root replacement triggers a reload for
  out-of-band file edits in that window
- missing key and key type directories are tracked and added later when created
- when unlocked, qualifying changes trigger immediate reload; one that finds
  a content defect in the selected generation enters recovery
  ([Runtime reload behavior](#runtime-reload-behavior))
- when locked or in recovery, the watcher remains running and marks the
  product runtime dirty; a recovery a reload entered therefore does not lift
  when the defect's file is removed, but at the reconcile or unlock that
  follows
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
| `apstore template repair` | With the signer stopped, re-pins an externally edited record's fingerprint to its stored template, or deletes a defective record and archives its `.template`, in a new `template-repair` generation. | None. | No unused-key guard: a dropped type's keys keep signing from stored metadata. |
| Key generation | Requires discoverable/generatable key type allowed by node role. | Writes new encrypted key. | LogicSig key stores signing authority at creation time. |
| Key deletion | None. | Archives active key file, with its own policy document and, on a cosigner, its source token file. | Archived keys are not signable. |
| Backup create | Records source node role metadata in the managed archive manifest. | Reads selected active key files, their own policy documents and a cosigner key's source token file into encrypted backup payloads. | Source store unchanged; the node default's tokens are not carried. |
| Backup import | None in active identity. | None in active identity. | Validates archive before publishing to managed backup locker. |
| Restore preview | None. | None. | Decrypts and reports only: the keys a restore would admit and the ones it would skip. A node-role mismatch refuses. |
| Restore apply | None. | Admits each selected complete credential with its archived policy and source tokens, skipping and reporting one it cannot admit, classifies canonical-plaintext identity/conflict of each, then commits all pending entries as one generation behind one `store-root.enc` replacement. | Destination default policy, its source tokens and configuration remain authoritative; reload publishes all entries, the token index included, and uncertain durability enters recovery mode. |
| Restore rollback | None. | Reconstructs the sealed parent of the latest clean rollback-eligible credential restore into a fresh generation, its per-key token files sealed again under the current term. | A rollback generation is not itself eligible for another rollback. |
| Restore reconcile | None. | Validates the visible generation after interrupted or uncertain completion. | Exits recovery mode only after clean validation and reload. |
| Rebuild absent store | Writes root `node.yaml` from explicit `--role` or the authenticated manifest source role. | Restores the selected keys it admits, with their policies and source tokens, into a new product store, skipping and reporting the rest. | Manifest role is the default; `--role` overrides it; destination key-class gates remain authoritative. |
| Store passphrase change | Mints a fresh term and generation, re-encrypts every term-encrypted generation member, renews integrity sidecars, and atomically replaces `store-root.enc`. | Re-encrypts keys, and active and archived source token files, each under its own object context. | Logical authority and state are unchanged; the old passphrase and term no longer authorize the current generation. |
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
13. Cosigned account keys use the cosigned flow (`cosigned1`); normal `/sign`
    rejects them.
14. Live backup restore validates the full selected credential set before one
    generation commit. It must not change the node default policy or its
    source tokens, templates, key-type state, or configuration; it writes only
    credentials, each restored key's own archived policy document (with a
    current-term sidecar), and each restored cosigner key's archived source
    tokens (sealed under the current term with the `source-tokens` object
    context). A differing destination per-key policy or token file is a
    conflict requiring `replace_existing`. It must not replace a conflicting
    credential, policy or token file without explicit authorization, or enter
    the signing or token index before commit and reload complete.
15. Template/provider fingerprint conflicts are generation/provenance
    problems, not automatic invalidation of otherwise valid key files.
    Comparisons are exact: the fingerprint is identifier-independent, and a
    stored value that is not byte-identical to the current one, another
    version prefix included, is a conflict.

## Backup and restore

The key-type side of restore is in the
[Backup and restore matrix](#backup-and-restore-matrix).

Backup and restore are implemented in `internal/backup`; live generation
orchestration is owned by `internal/signerapp/backupadmin`.

The authority boundary is:

> Backup owns credentials, each key's own policy document, and each cosigner
> key's source tokens. The destination owns its node default policy, the node
> default's source tokens, and operational configuration.

A backup preserves complete managed credential records, not only raw private
key bytes. This includes durable LogicSig bytecode, signing-argument contracts,
bounded authorization, and other versioned signing metadata carried by
`.key` and `.cos` payloads. A key's own policy document travels with it on both
node roles, and a cosigner key's source token file travels with it on a
cosigner; restore does not import the node default policy, the node default's
tokens, or operational configuration.

### Export and archive shape

Export:

1. discovers canonical managed credentials from active `.key` and `.cos`
   files; deleted artifacts are excluded
2. opens each credential with its object-bound destination term envelope
3. parses and validates the complete credential payload, then canonicalizes it
4. re-encrypts the canonical payload with standalone envelope version 2 under
   the export passphrase
5. writes `apb/<selector>.apb`
6. for each exported credential with a verified policy document of its own,
   encrypts the exact document bytes the same way and writes
   `policies/<selector>.apb`
7. on a cosigner, for each exported credential with a source token file,
   opens the file under its object context, checks its schema, and encrypts
   its canonical plaintext the same way as `source_tokens/<selector>.apb`;
   the node default's token file is not exported

Standalone envelope version 2 fixes the Argon2id tuple at time 2, memory
65,536 KiB, and parallelism 4. Readers reject omitted, partial, or altered KDF
parameters before decoding the envelope body or invoking Argon2id; changing the
tuple requires a new envelope version. Encoded credential envelopes are limited
to 1 MiB, policy envelopes to 2 MiB, source token envelopes to 8 KiB (a 4 KiB
token file's plaintext re-encrypted under the export passphrase), and the
sealed manifest to 8 MiB; archive readers enforce each bound while reading the
regular file rather than after an unbounded allocation. An archive holds at
most 24,600 entries and 1 GiB extracted: three members per key (credential,
policy and source tokens) at the 8,192-key cosigner cap is 24,576, plus
`README.md`, `manifest.sealed` and the three member directories. The sealed
manifest of such an archive is about 5.5 MB. Backup creation refuses to
package an archive extraction would reject.

An all-credentials backup is fail-hard: if any selected active credential, or
the policy or source token file of one, cannot be read, decrypted,
canonicalized, or exported, no archive is published. It never silently reports a partial archive as a complete backup.
A selected-keys backup that names an address twice is refused before
anything is written, as restore refuses a duplicate selector; it would
otherwise export and count the key twice.

A managed archive contains exactly:

- `README.md`
- one or more `apb/<selector>.apb` files
- zero or more `policies/<selector>.apb` files, each for a credential in the
  archive that has a policy document of its own
- zero or more `source_tokens/<selector>.apb` files, each for a cosigner
  credential in the archive that has a source token file; never one named
  `default`
- `manifest.sealed`

The sealed manifest plaintext uses schema
`aplane.credential-backup.manifest.v1`, schema version 1. It records the
source node role, packaging time, and the complete member inventory
(`path`, `sha256`, `size`). An optional `rotating_stage_hints` map keyed by
account contains `stage`, optional `observed_round` and `authorizer`,
`genesis_hash` (hex), and full `key_type`. Creation snapshots available
observations without a chain read. Restore and fresh-store rebuild validate
identity against selected credentials, then merge candidates with source
`backup` only after successful installation. Bad auxiliary hints are ignored;
cache publication failure warns without reversing a successful restore.
Archives with no hints remain readable. Hints are not current authority.
Backups carry no node default policy, node default source tokens, approval
defaults, genesis-hash mappings, templates, endpoints, client enrollment, or
other operator configuration. The manifest is encrypted under the export passphrase.
Knowing that passphrase authenticates the archive as produced or endorsed by a
passphrase holder; it is not independent origin authentication.

Every archive reader authenticates the manifest and verifies exact membership
before trusting payload metadata. Missing, added, duplicated, non-canonical, or
altered members are rejected, and so are a policy or source tokens for no
credential in the archive, and source tokens named for the node default or an
account address. Internal pre-release manifests, bundle wrappers,
and legacy envelope versions are unsupported; this is the first supported
backup contract and no migration from earlier internal tags is provided.

### Import and inspection

`apadmin backup import` asks the daemon to validate an external tar archive
deeply before publishing it under `backups/default/`. The commit request
carries the sensitive export passphrase; the daemon authenticates the archive
inventory and admits each credential for this node's role with the loader
restore uses, then zeros the passphrase without persisting it.
Archive-level damage refuses the import, as it refuses a restore, and so
does an archive in which nothing would restore on this node. A credential a
restore would skip does not: restore skips it as well, so the rest of the
archive stays restorable, and the import result names it with the reason.
A backup of another node role, none of whose keys this node can hold, is
refused in one line that says so. Client-side archive inspection is not an authorization
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
before revealing addresses or key types. Preview admits every credential as a
whole-archive restore would and reports each admitted credential's identity,
destination presence, and the source names it carries a token for, never a
token, and each credential the restore would skip with the reason; it
performs no store mutation. A preview lists the names of at most 4,096 tokens
across its keys, so it fits one admin frame, and counts the names it leaves
out per key. A preview with nothing left to restore
still succeeds, so every reason is shown.
Wrong-passphrase and unauthenticated failures share the restore rate limiter.
It counts only attempts that read the archive with the passphrase: a preview
or restore refused before that, for the signer's state or a keyring a lock
closed, is not charged.
Authenticated `list_backups`, `read_backup_chunk`, and `preview_restore`
requests are accepted while the identity is either unlocked or
recovery-blocked, allowing an operator to select, export, and inspect repair
material without enabling signing. Locked identities remain rejected.

`apstore verify` is fail-closed: an archive-level failure, or any credential a
restore would skip, returns the stable local `verification_failed` code and a
nonzero process exit. It lists every credential a restore would skip, with the
reason.

### Live direct restore

The current admin protocol exposes a direct credential restore:

- `restore_backup`: archive path, optional selectors, export passphrase, and
  optional `replace_existing`
- `restore_backup_result`: operation ID, archive SHA-256, resulting
  generation, restored/identical/conflicting credentials, the credentials it
  skipped with the reason (`skipped`), the keys whose archived policy was
  installed (`policies_restored`), the keys whose archived source tokens
  were installed (`source_tokens_restored`), key count, stable code, and error
- `rollback_restore`: rolls back only the latest clean, rollback-eligible
  credential restore
- `reconcile_store`: validates/reconciles the visible generation and exits
  recovery mode only when the store is clean

These operations remain authorized by the stable `identity.restore` action.
Restore, rollback, and reconciliation are callable while an authenticated
identity is recovery-blocked so they can repair or resolve store damage.

Restore authenticates the archive and admits each selected credential before
any write. Admission runs per credential: one the node cannot admit is skipped
with its archived policy and source tokens and reported with the reason, and
the rest restore.
Nothing is skipped silently: the preview, the `restore_backup_result`, the
restore audit record (`skipped_keys`) and apadmin's restore screens list every
skipped credential.

These failures refuse the whole restore before any write:

- archive authentication or decryption of the sealed manifest
- the manifest and archive structure: exact membership, and a policy or
  source tokens with no credential in the archive
- archive and member size bounds, and a credential, policy or source token
  member that does not read or decrypt under the export passphrase (the
  manifest sealed its digest, so it is damage to the archive)
- source/destination node-role compatibility of the archive
- a duplicate selector, or a selection (`addresses[]`) naming an address the
  archive lacks
- a selection naming a credential admission skips: an explicit request is
  never narrowed
- a restore with nothing left to restore

A credential is skipped when its decrypted payload or archived policy fails
admission:

- payload/format versions and strict canonical decoding, such as an unknown
  field
- filename, selector, category, and key-type agreement
- public/private-key and address consistency
- LogicSig bytecode/address consistency and off-curve requirements
- complete standalone signing metadata for LogicSig credentials
- bounded-authorization consistency
- whether the destination node role allows its key type
- required destination runtime/provider support
- its archived policy decoding as that key's document for the destination role
- its archived source tokens decoding as that cosigner key's token file
  (`aplane.source-tokens.v1`, its selector the credential's Witness Key ID,
  within the token limits) small enough to seal within 4 KiB under any term;
  only a cosigner credential, which only a cosigner node admits, has them

A skipped credential repairs nothing: in recovery mode, destination damage
that only its archived copy would have replaced still refuses the restore,
and the refusal names that credential and why its copy was skipped.

Deep verify (at create, at import, and in `apstore verify`), restore preview
and offline rebuild admit each credential through the loader restore uses, so
they admit and skip exactly the credentials restore does and report the same
reason. Backup creation and `apstore verify` still fail an archive with any
credential a restore would skip, so a backup created on this release
verifies completely and `apstore verify` answers whether every key would
restore. Import, checked against the importing node's role, accepts such an
archive and lists what a restore would skip. Restore adds the selection and
collision checks.

Destination collision classification compares canonical decrypted plaintext,
not ciphertext. An identical credential is an idempotent no-op. A different
credential is a conflict requiring `replace_existing`. An existing
credential that cannot be decrypted or decoded is also a replaceable conflict,
which permits an explicitly authorized restore to repair damage in recovery
mode.

After admission, restore mints exactly one generation. The parent generation
is copied, the admitted credentials are applied into staged `keys/`, derived
witness public metadata is updated, the staged generation is validated and
synced, the outgoing generation is sealed, and one durable store-root rename
commits the operation. Archived per-key policy documents are applied in that
same generation, on both node roles. A differing destination document is a
conflict requiring `replace_existing`; a destination document is kept when the
archive carries none. Archived source tokens are applied the same way on a
cosigner: each is written as the key's `source_tokens/<selector>.enc`, sealed
under the current term with the `source-tokens` object context. A destination
token file whose canonical plaintext differs from the archive's, or that does
not decrypt or decode, is a conflict requiring `replace_existing` (the
conflict names the encrypted file's digest, never a digest of the tokens); an
identical one is a no-op; a destination file is kept when the archive carries
none. A recovery-mode restore counts a key whose token file it replaces among
the selectors it repairs. The reload after the commit publishes the token
index from the new generation. Restore never writes templates, key-type
activation records, the node default policy or its token file, config, or
network mappings.

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
path for an absent product store. Before its first prompt it refuses an existing
identity directory or root `node.yaml`. It writes `node.yaml` before the mint and
removes it again when the mint fails before commit; after an uncertain commit
it keeps the file, since the root may select the new generation. It loads its
selection with the loader restore uses, before it asks for a store passphrase,
and applies the admitted credentials, their policies and their source tokens
into a newly staged first generation. `--address` limits the rebuild to the selected credentials;
without it every `.apb` payload is admitted. Each credential it skips is
printed with the reason. A rebuild that names a skipped credential, or has
nothing left to rebuild, is refused before the store passphrase prompt and
writes nothing. The sealed manifest source role supplies the default role. An
explicit `--role` overrides the manifest role, with a warning when the two
differ. Credentials whose key class the chosen role forbids are skipped.

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
- source token files and the token index: `internal/sourcetokens`;
  token writes: `internal/signerapp/keyadmin`
- live key type/template admin locking and reload: `internal/signerapp/templateadmin`
- backup/restore: `internal/backup`, `internal/signerapp/backupadmin`
- signing execution: `internal/signerapp/signing`

Related documents:

- [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md): index of compatibility-bearing
  contracts, which names this document as the owner of the store formats
- [ARCH_SECURITY.md](ARCH_SECURITY.md#authorization): product principals and actions
- [ARCH_DATA_MODEL.md](ARCH_DATA_MODEL.md): durable/runtime/wire data model
- [DEV_KEYTYPES.md](DEV_KEYTYPES.md): developer guide for adding key types
- [USER_KEYTYPES.md](USER_KEYTYPES.md): operator key type management
- [USER_STORE_MGMT.md](USER_STORE_MGMT.md): backup and restore guide
