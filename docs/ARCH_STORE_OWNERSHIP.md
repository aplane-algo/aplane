# Signer Store Ownership Architecture

**Status:** migration in progress on `codex/collapse-group-trust-tier`.

This document is the source of truth for which process may access or mutate
`APSIGNER_DATA`. It complements the on-disk format contract in
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) and the authenticated principal/grant
model in [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md).

## Trust statement

Membership in the operator-facing `aplane` Unix group grants connectivity to
the local administrative IPC socket. It does not grant signer-store authority,
an authenticated admin session, an application grant, or direct access to
encrypted custody material.

The target systemd deployment has two distinct filesystem roots:

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
narrow root-owned `identities/<identity>/passphrase.cred` exception.

### External-file-only operations

Backup inspection and validation of explicitly supplied external artifacts do
not require signer-store access. Output selected by an operator is created as
operator-owned state outside `APSIGNER_DATA`.

### Transitional direct clients to eliminate

These are known migration dependencies, not approved target-state access:

| Client | Current direct dependency | Replacement |
|---|---|---|
| `apadmin` | signer `config.yaml`, root node role, signer cache files, identity-local TEAL output | public socket resolver, authenticated settings/server-side resolution, operator output directory |
| `apapprover` | signer config for IPC discovery | public socket resolver |
| daemon-backed `apstore` | signer config before command routing; sentry references and generation list are direct | public socket resolver and typed admin operations |
| `appolicy` | offline-only store and node-role reads | implemented online policy adapter; keep explicit recovery mode |
| `approbe` | signer config parsing for socket discovery | public socket resolver |
| systemd-attach `apconsole` | signer config and node-role reads | public socket resolver and authenticated settings |
| same-UID child `apconsole` | signer config and node role | retained as an explicit same-UID exception |

## Filesystem primitives

`internal/fsutil` owns low-level durable publication. Store callers select a
closed artifact profile rather than arbitrary mode/UID/GID combinations. A
durable replacement uses a random exclusive temporary regular file, applies
ownership and its permission ceiling to the unpublished file descriptor,
syncs it, renames it in the destination directory, and syncs that directory.
Symlink and non-regular destinations are rejected. The transitional legacy
profile is named explicitly and is removed after supported stores migrate.

`internal/storeperm` owns read-only audit and, eventually, migration/startup
validation. It inventories without following symlinks and reports unsafe
ancestors, ownership, modes, hardlinks, and unexpected file types. A clean
audit is authority to proceed; an incomplete audit is not.

## Rollout invariants

The migration order is fixed:

1. harden writers and ownership traversal;
2. establish config-free runtime-socket discovery and move normal clients;
3. add missing authenticated policy, sentry-reference, and generation reads;
4. move the socket to the protected runtime directory;
5. audit and migrate a stopped legacy store;
6. enable strict startup enforcement and private creation defaults;
7. delete the legacy group-shared paths.

At no point may the store become `0700` before every normal multi-UID client
can find and use the runtime socket without traversing the store.
