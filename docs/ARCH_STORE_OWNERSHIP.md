# Signer Store Ownership Architecture

**Status:** implemented.

This document is the source of truth for which process may access or mutate
`APSIGNER_DATA`. It complements the on-disk format contract in
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) and the authenticated principal/grant
model in [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md).

## Trust statement

Membership in the operator-facing `aplane` Unix group grants connectivity to
the local administrative IPC socket. It does not grant signer-store authority,
an authenticated admin session, an application grant, or direct access to
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
An explicit custom socket for a systemd-managed signer must remain outside the
store and its parent runtime directory must be service-user-owned and
non-writable by group and other users. Valid legacy configurations that placed
a custom socket inside the store can be migrated while stopped; the daemon
then refuses that configuration until the socket is moved.

## Access inventory

The following classification is compatibility-bearing. A new direct
`APSIGNER_DATA` consumer must be added here with an explicit execution mode or
moved behind an existing owner.

### Daemon-owned normal runtime

| Owner | Store access |
|---|---|
| `internal/signerapp/identity`, `storemut`, `keyadmin`, `templateadmin`, `templates` | Identity settings, store mutation locking, keys and templates |
| `internal/signerapp/backupadmin` and `internal/backup` when invoked by it | Managed backup, restore, rollback, reconciliation |
| `internal/keystore`, `internal/keys`, `internal/keymgmt` | Active credential state |
| `internal/genstore`, `internal/rotationinventory`, `internal/storepass` | Generation publication, reconciliation, and key-term rotation |
| `internal/policy`, `internal/noderole` when invoked by the daemon | Authenticated policy and node-role state |
| `internal/sentry/sentryrefs` when invoked by the daemon | Public sentry-reference inventory |
| `internal/tokenfile` when invoked by signer administration | Identity bearer-token state |

Normal operators reach these owners through authenticated HTTP or admin IPC;
they do not call the storage packages directly.

### Offline bootstrap and rescue

| Command | Classification |
|---|---|
| `apstore initialize` | Offline mutation; root on systemd or data-root owner in same-UID mode |
| `apstore rebuild` | Offline mutation into an absent identity |
| `apstore verify` and offline policy check/verify | Offline read-only recovery inspection |
| `apstore policy sign` | Offline mutation for a signer that cannot load policy |
| `apstore generations prune` | Offline mutation pending a separately authorized live-prune design |
| `appass` | Offline root/service-owner mutation of startup credentials and `unlock.yaml` |

Offline mutations require a stopped daemon, exclusive store lock, no-follow
inventory validation, and the installation-mode owner check. They preserve the
narrow root-owned `identities/<identity>/passphrase.cred` exception and the
installer-owned `install/` metadata artifacts.

### External-file-only operations

Backup inspection and validation of explicitly supplied external artifacts do
not require signer-store access. Output selected by an operator is created as
operator-owned state outside `APSIGNER_DATA`.

### Operator clients

The multi-UID clients `apadmin`, `apapprover`, `approbe`, systemd-attach
`apconsole`, daemon-backed `apstore`, and online `appolicy` resolve the public
runtime socket without reading signer configuration. Policy editing,
sentry-reference administration, generation listing, and managed backup
transfer use typed admin operations. Operator-selected exports are written to
operator-owned locations. Same-UID child `apconsole` retains direct config and
node-role access as an explicit local-mode exception.

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
socket without relaxing ancestor checks, trusted-boundary policies require an
explicit embedder/test constructor, and migration alone receives a removable
legacy socket. Migration validates the complete legacy inventory before mutation,
removes the recognized stale legacy `<data-root>/aplane.sock`, removes group
access at the root first, repairs recognized objects through opened
descriptors, syncs directories, and independently audits the private result. A
clean audit is authority to proceed; an incomplete audit is not.

`apstore permissions audit` is read-only. `apstore permissions migrate`
requires the normal offline execution mode and exclusive store lock. A
systemd-managed daemon checks the private profile before loading configuration
or opening the store lock and refuses startup with a migration command when it
finds unsafe state.

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
