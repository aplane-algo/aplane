# Signer Store Ownership Architecture

**Status:** implemented.

This document is the source of truth for which process may access or mutate
`APSIGNER_DATA`. It complements the on-disk format contract in
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) and the closed product-principal/action
model in [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md).

Each signer or sentry data root contains one product store at
`identities/default/` and managed backups at `backups/default/`. Store-owning
APIs accept no identity locator, and live mutation/inspection uses one
process-wide product-store lock.

## Trust statement

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

## Access inventory

The following classification is compatibility-bearing. A new direct
`APSIGNER_DATA` consumer must be added here with an explicit execution mode or
moved behind an existing owner.

### Daemon-owned normal runtime

| Owner | Store access |
|---|---|
| `internal/signerapp/productruntime`, `storemut`, `keyadmin`, `templateadmin`, `templates` | Product settings, store mutation locking, keys and templates |
| `internal/signerapp/backupadmin` and `internal/backup` when invoked by it | Managed backup, restore, rollback, reconciliation |
| `internal/keystore`, `internal/keys`, `internal/keymgmt` | Active credential state |
| `internal/genstore`, `internal/storepass` | Atomic store-root publication, reconciliation/quarantine, archive bounds, and fresh-term passphrase rotation |
| `internal/policy`, `internal/noderole` when invoked by the daemon | Authenticated policy and node-role state |
| `internal/sentry/sentryrefs` when invoked by the daemon | Public sentry-reference inventory |
| `internal/tokenfile` when invoked by signer administration | Product bearer-token state |

Normal operators reach these owners through authenticated HTTP or the admin protocol over IPC/SSH;
they do not call the storage packages directly.

`internal/signerapp/productruntime` owns the product runtime aggregate; the
aggregate has no identity ID or selectable runtime registry.

### Offline bootstrap and rescue

| Command | Classification |
|---|---|
| `apstore initialize` | Offline mutation; root on systemd or data-root owner in same-UID mode |
| `apstore rebuild` | Offline mutation into an absent product store |
| `apstore verify` and offline policy check/verify | Offline read-only recovery inspection |
| `apstore policy sign` | Offline mutation for a signer that cannot load policy |
| `apadmin policy rescue` production apply/edit | Offline policy repair for a stopped daemon |
| `apstore generations prune` | Offline pruning of retained authoritative generations; non-authoritative quarantine deletion is a separate authenticated live operation |
| `apstore permissions` | Offline bootstrap, audit, and ownership migration |
| `apstore keys list` | Offline credential inventory for recovery diagnostics |
| `appass` | Offline root/service-owner mutation of startup credentials and `unlock.yaml` |

Offline mutations require a stopped daemon, exclusive store lock, no-follow
inventory validation, and the installation-mode owner check. They preserve the
narrow root-owned `identities/default/passphrase.cred` exception and the
installer-owned `install/` metadata artifacts.

Root-run `apadmin policy rescue` saves hold one exclusive lock across policy
publication and managed-store ownership normalization. The already-held guard
is passed into the offline policy store so nested save code does not reacquire
the same flock, and a daemon cannot start between publication and repair.

### External-file-only operations

Backup inspection and validation of explicitly supplied external artifacts do
not require signer-store access. Output selected by an operator is created as
operator-owned state outside `APSIGNER_DATA`.

### Operator clients

The multi-UID clients `apadmin`, `apapprover`, `approbe`, and systemd-attach
`apconsole` resolve the public runtime socket without reading signer
configuration. `apadmin` owns every general running-daemon administration
workflow: policy editing, template and key-type administration, sentry-reference
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

## Filesystem primitives

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

## Implemented rollout

The migration order is fixed:

1. harden writers and ownership traversal;
2. establish config-free runtime-socket discovery and move normal clients;
3. add missing authenticated policy, sentry-reference, and generation reads;
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
