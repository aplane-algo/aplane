# Signer Administration

> The apsigner admin RPC carried over local IPC and the `apadmin` TUI that drives it.
> The [Admin Protocol Contract](#admin-protocol-contract) is compatibility-bearing;
> the [Signer Admin TUI](#signer-admin-tui) section describes one client of it and is not.

Every live administrative action reaches the signer through the admin protocol:
the TUI, `apadmin` test mode, and `apapprover` are clients of the same
message catalog, and the signer remains responsible for authorization, lock-state
enforcement, store serialization, and audit emission.

## Contents

- [Admin Protocol Contract](#admin-protocol-contract)
  - [Envelope](#envelope)
  - [Transport and Handshake](#transport-and-handshake)
  - [Implementation Boundary](#implementation-boundary)
  - [Message Catalog](#message-catalog)
  - [Key Payload Shapes](#key-payload-shapes)
  - [Writable Settings](#writable-settings)
  - [Admin Lock Semantics](#admin-lock-semantics)
  - [Error Codes and Semantics](#error-codes-and-semantics)
  - [Admin Client Capabilities](#admin-client-capabilities)
- [Signer Admin TUI](#signer-admin-tui)
  - [Model / View / Update](#model--view--update)
  - [View States](#view-states)
  - [Cosigner Reference Manager](#cosigner-reference-manager)
  - [Admin Panel](#admin-panel)
  - [Policies View](#policies-view)
  - [Local Activity And Idle Locking](#local-activity-and-idle-locking)
  - [Error Handling](#error-handling)
  - [Key Files](#key-files)
- [Related Documentation](#related-documentation)

## Admin Protocol Contract

> Compatibility-bearing wire shapes for the apsigner admin RPC carried over local IPC.
> For overall compatibility scope, see [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).
> For the principal/action authorization model that gates these messages, see [ARCH_SECURITY.md](ARCH_SECURITY.md#authorization).

This contract is consumed by `apadmin` (TUI, batch commands, and test mode), `apapprover`, and any other process that drives signer administration over the admin transport. It documents the envelope, transport handshake, message catalog, payload shapes, writable settings, lock semantics, error codes, and per-client capabilities.

### Envelope

Line-delimited JSON over the admin transport stream. Messages carry:

- `kind`: `request`, `response`, or `notification`
- `type`
- `id` for requests/responses

This envelope applies to the IPC admin protocol only, not the HTTP API.
`kind` is mandatory on admin-protocol messages; missing `kind` is a protocol error.

### Transport and Handshake

Generic clients normally see `auth_required` first. The server may instead send
a protocol `error` before auth when it rejects the session before the handshake
can begin, for example while another pre-auth admin client is already pending.
The `apadmin` TUI may see `client_exists` before auth for displacement
negotiation. `client_exists`, `displace_confirm`, and `displaced` are not part
of the generic transport contract.

Before authenticating, a client may answer `auth_required` with
`initialize_store` instead of `auth`. The server handles that one request
without a passphrase-authenticated session, only over local IPC, and then ends
the bootstrap exchange. `initialize_store` is not part of the authenticated
dispatch table: after auth it is rejected as `unknown_message_type`.

Admin sessions bind directly to the one product runtime. The auth shape has
no runtime selector. Strict known-field decoding rejects unknown fields before
passphrase verification or runtime work.

Admin sessions share one process-wide authenticated-pending slot and one
active admin slot, plus one pre-auth pending slot until a session's passphrase
has been verified.

Transport notes:

- the line-delimited JSON admin protocol is carried only over local IPC; SSH does not carry it,
- local client discovery precedence is explicit `--ipc-path`, explicit `-d`
  discovery, `APSIGNER_IPC_PATH`, environment/profile-selected data-directory
  discovery, then the system runtime path; an inherited socket override cannot
  retarget a command whose store was explicitly selected with `-d`,
- systemd local IPC is discovered at `/run/apsigner/aplane.sock` without
  reading the conventional private `/var/lib/apsigner` configuration;
  same-UID local mode may use `<data_dir>/aplane.sock`, and custom private
  managed stores require an explicit IPC path so an unreadable selected root
  cannot silently retarget a client to the singleton system signer,
- the current admin protocol version is 6.0; `auth_required` carries it as
  `protocol_version:{major,minor}`; clients must send their version in
  `auth.protocol_version`; major-version mismatches
  are rejected during authentication, and minor-version mismatches are logged
  but accepted; v6 intentionally removes the retired `pending_attempts`
  generation-inventory field and does not provide a v5 compatibility shim,
- post-auth admin connections use one dispatcher-owned reader in `internal/transport`,
- the dispatcher routes by envelope semantics (`kind` + `id`) rather than message-type allowlists,
- the generic client helpers in `internal/transport` expect `auth_required` for
  a normal handshake and preserve pre-auth protocol `error` messages as
  formatted server rejections,
- displacement negotiation is process-wide; TUI and batch clients handle the
  pre-auth `client_exists`/`displace_confirm` exchange, but a later successful
  `auth_only` handshake remains non-owning and does not replace the owner,
- generic clients observe some auth/displacement failures as formatted protocol errors rather than stable typed transport errors.
- admin frames are bounded to 4 MiB (`protocol.MaxAdminMessageBytes`) before JSON
  decoding; both the server and client readers enforce it, and an oversized frame
  closes the connection.

### Implementation Boundary

`internal/protocol` is the compatibility-bearing IPC wire contract. It
owns protocol versions, message types and IDs, JSON field names, envelopes,
framing primitives, sensitive wire values, and stable error codes.

`internal/adminproto` is the transport-neutral service vocabulary used behind
that boundary, plus the framed server connection abstraction. Its requests and
results are internal domain values, not a second JSON schema. The authenticated
session in `internal/signerapp/adminserver` explicitly adapts between the two.
Domain services must not construct `protocol.BaseMessage` values or serialize
their results directly: projections intentionally omit internal state, signer
paths, and recovery material while emitting only the documented wire fields.

### Message Catalog

Source: `internal/protocol/messages.go`. Unsupported client messages yield a generic `error` response.

#### Session and Store Lifecycle

Client to Server:

- `auth` (pre-auth handshake response to `auth_required`; verifies, binds, and unlocks before authenticated dispatch)
- `auth_only` (pre-auth handshake response intended for bound-runtime reads;
  verifies and binds without changing locked state, creates a non-owning
  observer session, and is restricted by a server-enforced public-read
  request allowlist)
- `unlock`
- `lock_identity`
- `initialize_store`
- `change_store_passphrase`
- `displace_confirm` (pre-auth confirmation that permits a later controlling
  `auth` session to replace the active owner; ignored for `auth_only` ownership)

Server to Client:

- `auth_required`
- `auth_result`
- `unlock_result`
- `lock_identity_result`
- `initialize_store_result`
- `change_store_passphrase_result`
- `status`
- `error`
- `signer_locked`
- `client_exists`
- `displaced`

#### Key Management

Client to Server:

- `list_keys`
- `generate_key`
- `delete_key`
- `export_key`
- `import_key`
- `get_key_details`

Server to Client:

- `keys_list`
- `generate_result`
- `delete_result`
- `export_result`
- `import_result`
- `key_details`
- `keys_changed`

#### Key Type Templates

Client to Server:

- `list_library_templates`
- `show_library_template`
- `install_library_template`
- `activate_key_type`
- `deactivate_key_type`
- `list_key_types`
- `list_installed_templates`
- `show_installed_template`
- `import_installed_template`
- `remove_installed_template`

Server to Client:

- `library_templates`
- `show_library_template_result`
- `install_library_template_result`
- `installed_templates`
- `show_installed_template_result`
- `import_installed_template_result`
- `remove_installed_template_result`
- `activate_key_type_result`
- `deactivate_key_type_result`
- `key_types`

#### Signing Approval and Client Enrollment

Client to Server:

- `sign_response`
- `list_pending_enrollments`
- `approve_enrollment`
- `reject_enrollment`
- `import_client_key`
- `list_enrolled_keys`
- `revoke_enrolled_key`
- `revoke_all_enrolled_keys`

Server to Client:

- `sign_request`
- `sign_request_canceled`
- `client_enrollment_request`
- `enrollment_changed`
- `pending_enrollments_list`
- `approve_enrollment_result`
- `reject_enrollment_result`
- `import_client_key_result`
- `enrolled_keys_list`
- `revoke_enrolled_key_result`
- `revoke_all_enrolled_keys_result`

#### Backup and Restore

Client to Server:

- `backup`
- `list_backups`
- `delete_backup`
- `begin_backup_import`
- `append_backup_import`
- `commit_backup_import`
- `abort_backup_import`
- `read_backup_chunk`
- `preview_restore`
- `restore_backup`
- `rollback_restore`
- `reconcile_store`

Server to Client:

- `backup_result`
- `backups_list`
- `delete_backup_result`
- `begin_backup_import_result`
- `append_backup_import_result`
- `commit_backup_import_result`
- `abort_backup_import_result`
- `backup_chunk`
- `restore_preview`
- `restore_backup_result`
- `rollback_restore_result`
- `reconcile_store_result`

#### Admin and Policy Settings

Client to Server:

- `get_admin_settings`
- `update_admin_setting`
- `get_policy`
- `get_policy_document`
- `check_policy`
- `apply_policy`

Server to Client:

- `admin_settings`
- `update_admin_setting_result`
- `policy`
- `policy_document`
- `check_policy_result`
- `apply_policy_result`

#### Cosigner References And Store Inventory

Client to Server:

- `list_cosigner_references`
- `get_cosigner_reference`
- `import_cosigner_reference`
- `remove_cosigner_reference`
- `export_cosigner_public`
- `list_generations`
- `prune_generation_quarantine`
- `discard_abandoned_generations`
- `list_deleted_archive`
- `prune_deleted_archive`

Server to Client:

- `cosigner_references_list`
- `cosigner_reference`
- `import_cosigner_reference_result`
- `remove_cosigner_reference_result`
- `export_cosigner_public_result`
- `generations_list`
- `prune_generation_quarantine_result`
- `discard_abandoned_generations_result`
- `deleted_archive_list`
- `prune_deleted_archive_result`

### Key Payload Shapes

#### Session and Store Lifecycle

- `auth` / `auth_only`: `passphrase`, required `protocol_version`; unknown
  fields are rejected after the protocol major is validated
- `auth_result`: `success`, optional `code`, optional `error`
- `unlock` / `unlock_result`: `passphrase` -> `success`, optional `key_count`, `code`, `error`
- `lock_identity`: optional `reason` -> `lock_identity_result`: `success`, optional `code`, `error`; authorizes `identity.lock`, calls the server-side lock path, and normal `signer_locked` notifications remain the state-change signal
- `initialize_store`: `passphrase` -> `initialize_store_result`: `success`, optional `metadata_dir`, optional `helper_warning`, `code`, `error`; local IPC only, creates the product store's keyring root and format marker and may write the configured passphrase helper
- `change_store_passphrase`: `current_passphrase`, `new_passphrase` -> `change_store_passphrase_result`: `success`, optional `keys_migrated`, optional `templates_migrated`, optional `policy_sidecars_migrated`, optional `node_role_sidecars_migrated`, optional `prior_generations`, optional `helper_warning`, optional `root_committed`, `code`, `error`; local IPC only, rejects identical current/new passphrases, seals the current generation, builds a successor generation re-encrypted under a fresh key term (live encrypted artifacts and integrity sidecars), and makes the new passphrase, term, and generation authoritative in one store-root replacement; `root_committed` reports whether that replacement became visible (it can be true alongside an error when root durability needs recovery confirmation); reports retained historical generations, preserves post-commit progress fields on failures, and treats passphrase-helper failure as a post-commit warning
- `status`: `state`, `key_count`, optional `warnings[]` (operator alerts the
  signer raised on its own, currently rotating account alerts; each `status`
  message replaces the previous set, and the signer pushes a new `status`
  whenever the set changes)
- `error`: optional `code`, `error`
- `signer_locked`: `reason`
- `displaced`: `reason`

The pre-auth `auth` request verifies the passphrase and may also unlock and
reload the bound runtime. Therefore `auth_result{success:false}` does not
always mean a bad passphrase. If passphrase verification succeeds but unlock or
reload fails, the signer returns `auth_result` with `code:"unlock_failed"` and
an `error` prefixed with `auth ok but unlock failed:`. Clients should surface
that case as a serious post-auth load/integrity failure, not as ordinary
credential rejection. A direct authenticated `unlock` request reports failed
unlock/reload after passphrase verification through
`unlock_result{success:false, code:"unlock_failed"}`.

An unlock can also succeed into recovery mode: when the passphrase verifies
but generation reconciliation or validation of the selected generation fails,
the result reports `success:true` with a zero key count and
`code:"recovery_blocked"`. The signer store is unlocked for administration only;
signing stays blocked until the operator resolves the store from recovery
mode. Clients must treat `recovery_blocked` as a store-integrity state
distinct from both `unlock_failed` and credential rejection.

The pre-auth `auth_only` request performs the same passphrase verification and
runtime binding but never authorizes or invokes `identity.unlock`. It is a
distinct message type so an older server rejects it before processing instead
of ignoring a new flag and unlocking. First-party clients use it only for
operations whose handlers require an authenticated bound runtime. It does not
occupy or replace the active admin-owner slot and cannot receive approval
notifications, fail pending approvals, or trigger disconnect cleanup. The server permits only
`get_admin_settings`, cosigner-reference list/get/public-export, generation
inventory, and enrolled-client inventory (`list_enrolled_keys`,
`list_pending_enrollments`) requests; those requests still pass through their
ordinary principal/action authorization checks and locked/unlocked/recovery-state
interlocks.

#### Key Management

- `generate_key`: `key_type`, optional `name`, optional `parameters`; accepted over IPC, but generated recovery material is not returned over the admin protocol. the rotating key type (`aplane.rotating-triple-wots.v1`) requires the parameter `network` (a network the signer knows, or a base64 genesis hash)
- `generate_result`: `success`, optional `address`, `key_type`, `parameters`, `code`, `error`; `mnemonic` and `word_count` fields remain in the schema but are omitted by signer responses
- `delete_key`: `address` -> `delete_result`: `success`, optional `code`, `error`
- `export_key`: `address`, `passphrase` -> `error code:"authorization_denied"`; mnemonic export is disabled, use encrypted backups for recovery
- `import_key`: `key_type`, `mnemonic`, optional `parameters` -> `import_result`: `success`, optional `address`, `key_type`, `code`, `error`; accepted only over local IPC because it carries recovery material
- `get_key_details`: `address` -> `key_details`: `success`, optional `address`, `key_type`, `parameters`, optional `public_key_hex`, `display_teal`, `code`, `error`
- `key_details.parameters` for guarded account keys projects the embedded cosigner verifier as `Cosigner: <Witness Key ID>` and does not expose the raw `cosigner_public_key` parameter
- `key_details` may include optional `template_provenance_status` and `template_provenance_note`; these are informational, version-aware comparisons between the key's stored template fingerprint provenance and the registered local definition, and do not gate signing. The fingerprint is behavior-only and versioned, so only a same-version, different-hash pair is a `conflict`; a different-version or malformed comparison is `unavailable` (benign), never a `conflict`
- `keys_list`: `keys`, where each key has `address`, `key_type`, optional `name`, optional `template_provenance_status`, optional `template_provenance_note`
- `keys_changed`: `key_count`

> **Boundary note — admin `keys_list` is not the HTTP key inventory.** The admin
> transport entry is `protocol.AdminKeyInfo` (thin: address, key type, name,
> template provenance), projected from the admin service DTO `adminproto.KeyInfo`.
> It is deliberately *not* `pkg/signerapi.KeyInfo`, the richer HTTP `/keys` shape
> that also carries `signing_flow`, `logic_sig_resources`, `signing_args`, and capability
> flags for SDK clients. The two are distinct wire surfaces that happen to share a
> concept; do not add HTTP-only fields to the admin type, and do not assume a
> client-facing field exists on the admin list. Extend the HTTP `KeyInfo` for
> client needs and the admin `AdminKeyInfo`/`adminproto.KeyInfo` pair for TUI needs.

#### Key Type Templates

- `list_library_templates` -> `library_templates`: `templates[]`, optional `code`, `error`; each template has optional `key_type`, `template_type`, `display_name`, `description`, `source_path`, `file_name`, `parameters[]`, `runtime_args[]`, plus `installed`, optional `enabled`, optional `conflict`, optional `invalid`. In this catalog response, `runtime_args[]` is live template metadata for keys created in the future; key-file and `/keys` `signing_args[]` is the durable signing-argument schema captured when an existing key was created.
- `show_library_template`: `key_type`, `template_type` -> `show_library_template_result`: `success`, optional `key_type`, `template_type`, `source_path`, `source_sha256`, `source_mtime`, `template_yaml`, `code`, `error`; available to any authenticated controlling (non-`auth_only`) session with an unlocked runtime and the `templates.view` action; it needs no stronger action because it returns plaintext reference library YAML, not decrypted installed-template source. `source_sha256` is the exact-byte SHA-256 of `template_yaml`; `source_mtime` is the source file's Unix modification time and is informational rather than tamper-proof.
- `install_library_template`: `key_type`, `template_type` -> `install_library_template_result`: `success`, optional `key_type`, `template_type`, `already_exists`, `code`, `error`
- `list_installed_templates` -> `installed_templates`: `templates[]`, optional `code`, `error`; each template has `key_type`, `template_type`, optional `size`, and `enabled`
- `show_installed_template`: `key_type` -> `show_installed_template_result`: `success`, optional `key_type`, `template_type`, sensitive `template_yaml`, `code`, `error`; available through authenticated IPC admin sessions
- `import_installed_template`: sensitive `template_yaml` -> `import_installed_template_result`: `success`, optional `key_type`, `template_type`, `already_exists`, `code`, `error`; available through authenticated IPC admin sessions
- `remove_installed_template`: `key_type` -> `remove_installed_template_result`: `success`, optional `key_type`, `template_type`, `removed`, `code`, `error`; available through authenticated IPC admin sessions
- `activate_key_type`: `key_type` -> `activate_key_type_result`: `success`, optional `key_type`, `already_exists`, `code`, `error`; this wire message activates compiled providers and enables installed YAML templates. The `apadmin` CLI exposes this as `keytype enable`. For installed YAML templates, `already_exists:true` means the template was already enabled.
- `deactivate_key_type`: `key_type` -> `deactivate_key_type_result`: `success`, optional `key_type`, `removed`, `code`, `error`; this wire message deactivates compiled providers and disables installed YAML templates. The `apadmin` CLI exposes this as `keytype disable`. `removed:true` means the enabled/disabled state changed, and in-use rejection returns `code:"key_type_in_use"` when installed-template disable or compiled-provider disable is blocked.
- `list_key_types` -> `key_types`: `key_types[]`, optional `code`, `error`; entries mirror the HTTP `/keytypes` schema except that they omit `signing_flow` and `bounded_authorization`; both surfaces carry optional `cosigner_component_key_type`, which `apadmin` uses to filter enrolled public cosigner references for guarded-account generation

#### Signing Approval and Client Enrollment

- `sign_request`: `address`, `txn_sender`, `description`, `timestamp`, `first_valid`, `last_valid`, optional `violations`. The message `id` is a fresh, single-use prompt ID that apsigner generates for each prompt; it is never the HTTP client's `request_id`, so a `sign_response` can approve only the prompt the operator was shown.
- `sign_request_canceled`: optional `reason`; server-originated notification that a delivered `sign_request` is no longer actionable. Reasons are `client_canceled` and `timeout`. Admin clients must remove a matching active or queued signing prompt and must not send a later `sign_response` for that request.
- `sign_response`: `approved`, optional `reason`; server-side handling attaches the admin session's approver principal for audit attribution
- `client_enrollment_request`: `ssh_fingerprint`, optional `label`, `remote_addr`, `timestamp`; a client asked over SSH (`request-enrollment` username, `enroll [<label>]` command) to have its key enrolled, and the request now waits in the signer's queue. Its ID is `enroll-<fingerprint>`. It is sent when a new request is queued and, for every request still waiting, when an admin session authenticates, so a client may see the same request announced more than once. The label is the client's requested display text, bounded and printable, and carries no authority. The admin client answers with `approve_enrollment` or `reject_enrollment` by fingerprint; there is no response to this notification itself, and the SSH client is not waiting on it.
- `enrollment_changed`: `reason`, optional `fingerprint`; server-originated notification that what `list_pending_enrollments` or `list_enrolled_keys` would return has changed, whatever made the change: a request arriving over SSH, an answer or import from this admin session or from another admin client, or an enrolled key's client connection opening or closing (the `connected` flag). `reason` is one of `requested`, `approved`, `rejected`, `imported`, `revoked`, `revoked_all`, `connected`, `disconnected`; `fingerprint` names the key concerned and is absent for `revoked_all`. It is sent once the change has taken effect in the live state, before the result of the request that made it, and is sent even when the write behind the change is not yet durable (the result reports that). A repeat request refreshes the waiting entry's label, address, and time, and an approval or import that only clears the request of a key already enrolled (the retry after a failed queue write) changes the queue, so both are announced. A refused operation, or one that changed nothing (an import of an enrolled key with no request waiting), is not announced, and neither is an enrollment-request connection, whose request is announced instead. It carries no list: an admin client showing the queue or the registry re-fetches it with `list_pending_enrollments` and `list_enrolled_keys`. There is no response to this notification.
- `list_pending_enrollments` -> `pending_enrollments_list`: `requests[]`, oldest first, each with `fingerprint`, optional `label`, `key_type`, optional `remote_addr`, and `requested_at` (Unix seconds)
- `approve_enrollment`: `fingerprint`, optional `label` -> `approve_enrollment_result`: `success`, optional `code`, `error`, `fingerprint`, `label`; enrolls the waiting request's key in `identities/default/.ssh/authorized_keys` with the request's label (or `label`, which replaces it), removes the request, and audits `CLIENT_ENROLLED` with the admin session's attribution. No credential is issued, because the client's key is its credential. A fingerprint with no waiting request, or a `label` that is not printable single-line text of at most 64 bytes, fails with `code:"invalid_request"`. A registry write that took effect but is not yet durable still clears the request and audits the enrollment; the result then carries the durability failure.
- `reject_enrollment`: `fingerprint` -> `reject_enrollment_result`: `success`, optional `code`, `error`, `fingerprint`; removes the waiting request without enrolling its key and audits `CLIENT_ENROLLMENT_REJECTED`. A fingerprint with no waiting request fails with `code:"invalid_request"`, as does a request whose key is already enrolled (an approval that enrolled the key but could not clear its request): approving again clears it, or the key is revoked.
- `import_client_key`: `public_key` (one OpenSSH public-key line), optional `label` -> `import_client_key_result`: `success`, optional `code`, `error`, `fingerprint`, `label`, `added`; enrolls the key directly (pre-enrollment), using the line's comment as the label when none is given, and clears a waiting request for the same key. `added` is false when the key was already enrolled. A malformed line, a line carrying authorized_keys options (`from=`, `restrict`, ...; this version implements none, so the key would otherwise be enrolled without the restriction asked for), more than one line, an unsupported key type, or a label (given or taken from the comment) that is not printable single-line text of at most 64 bytes fails with `code:"invalid_request"`.
- `list_enrolled_keys` -> `enrolled_keys_list`: `keys[]`, each with `fingerprint`, optional `label`, `key_type`, and `connected` (the key has at least one live SSH connection); waiting requests are listed by `list_pending_enrollments`
- `revoke_enrolled_key`: `fingerprint` -> `revoke_enrolled_key_result`: `success`, optional `code`, `error`, `closed_connections`; removes the key from the registry and closes every SSH connection it authenticated. An empty or unknown fingerprint fails with `code:"invalid_request"`.
- `revoke_all_enrolled_keys` -> `revoke_all_enrolled_keys_result`: `success`, optional `code`, `error`, `revoked_count`, `closed_connections`; the emergency lever: empties the registry and closes every client connection

#### Backup and Restore

- `backup`: `export_passphrase`, optional `addresses[]` ->
  `backup_result`: `success`, optional `archive_path`,
  `archive_checksum`, `archive_size`, `key_count`, `addresses[]`,
  `verified`, `code`, `error`. Backup is all-or-nothing; a selected
  credential that fails canonical validation fails the request.
- `list_backups` -> `backups_list`: `backups[]`, optional `code`,
  `error`; each item has a basename-only compatibility `path`, file name,
  packaging metadata, checksum, and size. Successful backup-create and import
  responses likewise expose only archive basenames, never the signer store
  root. A successful checksum read is not a claim that encrypted archive
  contents were authenticated. This read-only operation is available to
  authenticated sessions in either unlocked or recovery state so the TUI can
  select repair material while signing remains blocked.
- `delete_backup`: `archive_path` -> `delete_backup_result`.
- backup import is a bounded transfer: `begin_backup_import` carries
  `file_name`, removes any incomplete prior upload for the product store, allocates
  one daemon-owned temporary archive, and returns an opaque `upload_id`;
  `append_backup_import` accepts at most 256 KiB at the exact next `offset`;
  cumulative uploaded bytes are capped at 1 GiB;
  `commit_backup_import` carries the sensitive `export_passphrase`, verifies
  the declared size and SHA-256, authenticates the sealed manifest, deeply
  validates every credential payload, and only then atomically publishes the
  archive. Commit first renames the writable upload into a reserved immutable
  claim while holding the store mutation lock. Hashing, extraction, and
  memory-hard credential verification run outside that lock; the lock is
  reacquired only to publish the validated claim. Validation extraction uses a
  reserved owner-private directory on the signer store filesystem rather than
  process-global temporary storage. The final rename is the commit point. A
  directory-sync failure after that point returns `success:true` with a
  `warning`, because reporting failure would invite a retry after the archive
  is already visible under its final name.
  Commit is a synchronous, potentially long-running request; first-party
  clients use a dedicated bounded timeout rather than the ordinary 30-second
  admin-request timeout. The daemon zeros the passphrase after the request and
  never persists it; `abort_backup_import`
  durably removes an incomplete upload. Daemon startup also removes incomplete
  uploads left by a prior process. Abort remains available to an authenticated,
  authorized bound session while the signer store is locked because it can only
  remove unpublished transfer residue.
- `read_backup_chunk`: `file_name`, `offset` -> `backup_chunk`: `file_name`,
  `offset`, at most 256 KiB of `data`, `eof`, `success`, optional `code`, and
  `error`. This lets an operator export
  a managed archive without filesystem access to the private signer store.
  It requires the signer store to be unlocked or recovery-blocked.
- `preview_restore`: `archive_path`, sensitive `export_passphrase` ->
  `restore_preview`: resolved archive path, `keys[]`, `errors[]`, optional
  `code`, `error`. Each key reports address, key type, destination
  presence, `has_policy`, and validation error. Preview never mutates the store and, like
  `list_backups`, is available in unlocked or recovery state.
- `restore_backup`: `archive_path`, optional `addresses[]`, sensitive
  `export_passphrase`, optional `replace_existing` ->
  `restore_backup_result`: `success`, operation ID, archive SHA-256,
  generation ID, `restored[]`, `identical[]`, `conflicts[]`, `key_count`,
  optional `policies_restored[]`, `code`, `error`. The server validates the whole set, then publishes one
  `credential-restore` generation.
- `rollback_restore` -> `rollback_restore_result`: `success`, operation
  ID, generation ID, key count, `code`, `error`. It applies only to the
  current clean rollback-eligible `credential-restore` generation; a rollback
  generation is not eligible for another rollback.
- `reconcile_store` -> `reconcile_store_result`: `success`, current
  generation ID, signer state, `code`, `error`. It exits recovery mode only
  after the visible store validates cleanly.
- restore passphrases are JSON strings on the wire but enter mutable byte
  buffers at the protocol boundary so handlers can zero them after use.
- all restore operations retain the stable authorization action
  `identity.restore`. Import admission, list, preview, restore, rollback, and
  reconciliation are available to an authenticated recovery-mode session so
  repair material can be admitted and inspected, damaged credentials replaced,
  and the clean generation promoted. A locked session remains rejected with
  `signer_locked`.
- protocol v4 removes the pre-release
  `recover_backup/list_recovered/review_recovered/activate_recovered/`
  `rollback_recovered/purge_recovered` lifecycle and its review token and
  acknowledgement fields.

#### Admin and Policy Settings

- `admin_settings`: `user_auto_approve`, `lock_on_disconnect`, `passphrase_timeout`, `passphrase_method`, optional `node_role`, `ssh_enabled`, optional `ssh_listen_address`, optional `ssh_port`, `ssh_fingerprint`, `ssh_clients`, `signer_port`, `teal_compile_network`, optional `endpoint_advertise_url`, optional `endpoint_display_url`, `theme`
- `update_admin_setting`: `key`, `value` (string-typed on wire)
- `update_admin_setting_result`: `success`, `key`, optional `value`, `code`, `error`

#### Policy Messages

Policy documents are the v1 JSON documents (`aplane.policy.v1`) specified in
[ARCH_POLICY.md](ARCH_POLICY.md#the-boundary). There is no `target` field;
the node role selects the field set a document may carry, and every document
is addressed by its `key`: `default` for the node default, or the selector of
the key it governs (an Algorand address on a signer node, a Witness Key ID on
a cosigner node). Every `document` value carries the exact document bytes as
a string, and every `sha256` is the SHA-256 of those exact bytes; the server
never re-serializes a document.

Shared shapes:

- request document (check and apply): `key` (`default` or a selector; must equal the document's signed `key` field), `document`
- document summary: `key`, `sha256`, `size`, optional `signed_at_unix` (diagnostic sidecar timestamp)
- key status: `key`, `status`: `own` (key held, document of its own), `default` (key held, follows the node default), or `key_not_held` (document for a key the node does not hold); constants `adminproto.PolicyKeyOwn`, `PolicyKeyDefault`, `PolicyKeyNotHeld`
- policy problem: optional `key`, optional `pointer` (JSON Pointer into that document), `message`

Messages:

- `get_policy` -> `policy`: `success`, `node_role`, `documents[]` (document summaries without bytes: the default first, then per-key documents sorted by key), `keys[]` (one entry per held key and per stored document for a key not held, sorted by key; the default is not a key and is not listed), `policy_set_sha256`, optional `generation_id`, optional `code`, optional `error`. `policy_set_sha256` is the lowercase hex SHA-256 over the sorted lines `<key> <document sha256>\n`, one per document, where `<key>` is `default` or the selector. Returns `policy_unavailable` when no policy is loaded.
- `get_policy_document`: `key` (`default` or a selector) -> `policy_document`: `success`, `key`, `document` (exact bytes), `sha256`, optional `signed_at_unix`, optional `code`, optional `error`. Returns `policy_document_not_found` when `key` is empty or names a key with no document of its own (it follows the node default).
- `check_policy`: `documents[]`, optional `remove[]` (keys whose own documents the candidate change would delete) -> `check_policy_result`: `success`, `valid`, optional `errors[]`, optional `warnings[]`, optional `code`, optional `error`. Validates the candidate change for the node role without writing. `valid` is true when `errors` is empty. Warnings never block an apply; they report document advisories (such as a `reject_*` setting that overrides a route's `allow_close` or `allow_clawback`, a route for a transaction type the document rejects, or a cosigner document with routes but no fee cap) and documents in the resulting state for keys the node does not hold (`key_not_held`). A key on the default is covered, not a gap.
- `apply_policy`: `documents[]`, optional `remove[]`, `expected_policy_set_sha256` -> `apply_policy_result`: `success`, optional `errors[]`, optional `policy` (the new `policy` view, including the committed `generation_id`), optional `commit_uncertain`, optional `code`, optional `error`.

Apply rules, the same on both node roles:

- The change adds or replaces each listed document and deletes each key in `remove`; unlisted documents are kept. Each document's `key` must equal its signed `key` field, and its signed `role` must equal the node role. A key may appear only once across `documents` and `remove`; removing a key with no document of its own is rejected; removing `default` is rejected (apply a new one instead). The resulting set must hold a default.
- `expected_policy_set_sha256` is required and must equal the active `policy_set_sha256`.
- A node holds at most 8,192 per-key policy documents (`policyapply.MaxPolicies`), on either role; a change past the cap is rejected with `policy_set_too_large` before anything is written. The default does not count. Key generation, import, and restore refuse an 8,193rd cosigner credential (`keys.MaxCosignerCredentials`).
- Response sizes are bounded: `policy` and `apply_policy_result` carry document summaries, never bytes, so with both caps full and every field at its longest they encode to about 3 MB, inside the 4 MiB admin frame. `policy_document` carries one document of at most 1 MiB; admin messages are encoded without HTML escaping, so a document string at most doubles (only quotes, backslashes, JSON whitespace, and U+2028/U+2029 are escaped) and the response stays near 2 MiB.
- The server verifies the active policy, checks the concurrency base, validates the change, and mints one new generation (operation `policy-apply`) carrying the documents and fresh sidecars, then reloads the bound product runtime without a restart. A change that leaves the policy set unchanged commits nothing.
- Failure is fail-closed: request, validation, stale-base, locked-store, or current-policy verification errors leave the active generation unchanged.
- A runtime in recovery mode refuses `apply_policy` with `recovery_blocked`: recovery admits only reconcile, rollback, restore, and prune, and no policy generation is minted on top of a store that failed validation.
- `commit_uncertain` means the generation may be visible but its durability or the runtime reload is unconfirmed; signing is blocked pending reconciliation or recovery.

Result codes include `expected_policy_set_sha256_required`,
`policy_snapshot_changed`, `policy_validation_failed` (with `errors[]`),
`invalid_policy_request`, `policy_set_too_large`, `policy_unavailable`, `policy_document_not_found`, `policy_verify_failed`,
`identity_locked`, `recovery_blocked`, `policy_commit_uncertain`,
`policy_reload_failed`, and `policy_save_failed`.

`get_policy`, `get_policy_document`, and `check_policy` require `policy.view`; `apply_policy` requires
`policy.update`. Policy messages are not exposed through apshell or MCP.

Policy selection semantics:

- every key is governed by exactly one document: its own `policies/<selector>.json` when it has one, otherwise the node default `default.json`; a key's own document replaces the default wholesale and inherits nothing (see [ARCH_POLICY.md](ARCH_POLICY.md#policy-selection))
- normal signing selects the document by signing auth address, not by transaction sender, so rekeyed accounts use the auth address; user-role component signing selects by the guarded account; cosigner component signing selects by the request `component_key`
- admin settings do not expose or mutate policy fields; documents change only through a whole-document `apply_policy`
- documents placed by hand in a stopped store apply only after `apstore policy sign` and the next unlock

#### Cosigner References And Generation Inventory

- `list_cosigner_references` -> `cosigner_references_list`: `references[]`, optional `code`, `error`; returns product-store public cosigner-reference records. Read-only store inspection does not wait behind a store mutation; it returns retryable `store_busy` instead.
- `get_cosigner_reference`: `name` -> `cosigner_reference`: `success`, optional `reference`, `code`, `error`
- `import_cosigner_reference`: `name`, `envelope_json` -> `import_cosigner_reference_result`: `success`, optional `reference`, `code`, `error`; the server parses, validates, and durably publishes the public reference under the store mutation lock
- `remove_cosigner_reference`: `name` -> `remove_cosigner_reference_result`: `success`, `name`, `removed`, `code`, `error`
- `export_cosigner_public`: `witness_key_id` -> `export_cosigner_public_result`: `success`, `witness_key_id`, `envelope_json`, `code`, `error`; only public witness metadata crosses the protocol
- `list_generations` -> `generations_list`: current generation, sealed priors,
  bounded non-authoritative `quarantined[]` metadata, pending staging, retained
  unsealed parent, `code`, `error`; this is read-only inspection and never
  reconciles or prunes. Each quarantine record includes the generation and
  parent IDs, manifest and live-inventory digests, at-mint inventory-match
  classification, entry count, encoded byte count, and `term_verified`,
  `term_unavailable`, and `term_failed` counts. If a store mutation is
  active, the request returns retryable `store_busy` rather than waiting for
  the ordinary IPC timeout.
- `prune_generation_quarantine`: `generation_ids[]`, `confirm` ->
  `prune_generation_quarantine_result`: `success`, `pruned[]`, optional `code`,
  `error`; deletion is restricted to explicitly selected quarantine IDs,
  requires `confirm:true`, and records a durable audit intent before mutation.
  An already-absent selected ID is successful and reported as such, making an
  interrupted multi-ID request safely retryable.
- `discard_abandoned_generations`: `generation_ids[]`, `confirm` ->
  `discard_abandoned_generations_result`: `success`, `discarded[]`, optional
  `code`, `error`.
- `list_deleted_archive` -> `deleted_archive_list`: canonical `entries[]` with
  `path` and `encoded_bytes`, aggregate `entry_count`, `encoded_bytes`, and a
  `warning` when release headroom has been consumed; optional `code`, `error`.
- `prune_deleted_archive`: canonical `entries[]`, `confirm` ->
  `prune_deleted_archive_result`: `success`, `pruned[]`, optional `code`,
  `error`. Each result carries `path`, `encoded_bytes`, and optional
  `already_absent`, so interrupted explicit selections are safely retryable.

Cosigner-reference reads/exports require `cosigners.view`; imports/removals require
`cosigners.manage`, an unlocked signer store, and emit mutation audit events. A
reference alias selects the witness public key embedded during guarded-key
generation, so public visibility does not make catalog mutation
security-neutral. Import is idempotent for an identical reference and rejects
a name already bound to a different Witness Key ID; replacement requires an
explicit remove followed by import. Import and removal audit events include
the affected Witness Key ID, and the store mutation lock serializes
publication. Generation inventory requires `generations.view`. Live quarantine
deletion requires `identity.generation.quarantine.prune`, an unlocked or
recovery-admin runtime, explicit confirmation, and durable audit. Retained
authoritative generation pruning remains a distinct offline
`apstore generations prune` recovery/maintenance operation.
In-place unvalidatable abandoned publications use
`discard_abandoned_generations` with explicit IDs and confirmation, the
separate `identity.generation.abandoned.discard` action, and a durable intent
audit before mutation.

Deleted-archive inspection requires `generations.view`. Live archive pruning
requires `identity.archive.prune`, an unlocked or recovery-admin runtime,
explicit confirmation, and a durable audit intent written before any removal.
Only selected-generation `deleted/keys/`, `deleted/keytypes/`, and
`deleted/policies/` canonical paths are accepted. An archived policy document
and its `.hmac` sidecar must be selected together; arbitrary filesystem paths
are not an admin-protocol surface.

### Writable Settings

Writable admin settings:

- `user_auto_approve` (`User Auto-Approve`; approval switch). When on, it satisfies all signer review requirements without an operator prompt, including Always Review, and approves unmatched requests. Hard policy rejections and signer validation still apply. No connected approval client is required.
- `lock_on_disconnect`
- `passphrase_timeout`
- `theme`

Node role is not a writable admin setting. It is initialized once in root
`node.yaml`, integrity-bound to the store, and changed only by creating a
separate signer data root.

YAML-only runtime settings:

- `endpoint.signer_port`: loopback REST API port behind the signer endpoint.
  Admin settings may report it as `signer_port` but do not mutate it.
- `endpoint.ssh.listen_address`: SSH listener bind host/address. It defaults
  to `127.0.0.1`; admin settings may report it as `ssh_listen_address` but do
  not mutate it.
- `endpoint.ssh.port`: SSH listener port. Admin settings may report it as
  `ssh_port` but do not mutate it.
- `endpoint.advertise_url`: optional operator-declared endpoint handoff URL
  used by endpoint export when `--host`/`--url` are omitted. Admin settings may
  report it but do not mutate it.
- `approval_wait`: product-runtime manual signing approval timeout. It is
  not projected through admin IPC.

Policy has no scalar admin setting surface. Read, validation, and mutation use
`get_policy`, `check_policy`, and `apply_policy` with complete v1 JSON
documents.

### Admin Lock Semantics

- `list_key_types` requires an authenticated, runtime-bound admin session but
  does not require the product runtime to be unlocked. Template-backed key
  types are visible only after the product runtime loads them into the process
  registry. Like HTTP `/keytypes`, this is a metadata surface; internal
  registration may be split between client-visible metadata and signer-side
  execution registries, but the response schema remains the same key-type
  metadata schema.
- `list_library_templates` requires the product runtime to be unlocked because it reports product-store
  installed state against the encrypted template store.
- `show_library_template` requires the product runtime to be unlocked for the same runtime-bound
  template administration surface, even though the returned library YAML is plaintext reference material.
- `install_library_template` requires the product runtime to be unlocked because it writes into the encrypted `default` template store and immediately reloads that runtime.

### Error Codes and Semantics

Failure messages carry optional `code` alongside `error`. Central protocol
error-message codes are defined in `internal/protocol/error_codes.go`:

- `invalid_message_format`
- `expected_auth_message`
- `invalid_auth_message`
- `authentication_failed`
- `invalid_passphrase`
- `unlock_failed`
- `signer_locked`
- `no_runtime_bound`
- `authorization_denied`
- `invalid_request`
- `unknown_message_type`
- `key_not_found`
- `node_fail_closed`
- `internal_error`

Consumers should branch on message `type` and `code` first, and use `error` for display or fallback handling.

Specific admin result messages may define additional stable result-local codes,
including `key_type_in_use` for template disable/removal or compiled-provider disable and
`restore_rate_limited` for managed restore preview/restore throttling. The Go
source of truth for these result-local codes is `internal/protocol`, except the
policy result codes (for example `policy_snapshot_changed`, `policy_unavailable`,
and `identity_locked`), which `internal/signerapp/policyapply` and
`internal/signerapp/admin` define; producers and CLI consumers must share those
constants instead of maintaining parallel
string lists. See the corresponding payload sections and contract tests before
treating the central protocol list as exhaustive. Consumers should dispatch on
`code` when present and treat prose `error` as display text or untyped fallback,
not as an authoritative result-code source.

IPC failure semantics:

- protocol-level failures are reported through `error` messages or result messages with `success:false`,
- `code` is additive and optional on the wire,
- the transport does not provide a complete typed error taxonomy end-to-end.

`node_fail_closed` rejects both new authentication and every request from an
already-authenticated admin session after a process-wide invariant failure.
The operator must repair the underlying store/role conflict and restart the
signer; the session cannot resume administrative work in-process.

### Admin Client Capabilities

| Capability | `apadmin` TUI | `apadmin` batch commands | `apadmin` test mode | `apapprover` | `appass` |
|-----------|----------------|--------------------------|------------------|--------------|----------|
| Auth handshake | yes | yes | yes | yes | no |
| Displacement negotiation | yes | automatic | automatic | automatic | no |
| Unlock | yes | no | yes | no | no |
| Key management | yes | no | partial | no | no |
| Managed backup/restore | yes | yes (`backup`, `restore`, `changepass`) | no | no | no |
| Signing approval | yes | no | no | yes | no |
| Client enrollment approval | yes | yes (`clients`) | no | yes | no |
| Enrolled-client list, revocation, and import | yes | yes (`clients`) | no | no | no |
| Key-type, template, cosigner-reference, generation, and endpoint administration | yes | yes (`keytype`, `template`, `cosigner`, `generations`, `endpoint`) | no | no | no |
| Policy view and apply | yes | yes (`policy`) | no | no | no |
| Admin settings | yes | no | no | no | no |
| Async notifications | yes | no | limited | limited | no |

`automatic` means the client confirms displacement through the generic
`internal/transport` handshake, which answers `client_exists` with
`displace_confirm` without asking the operator; only the TUI asks first.
`apadmin` batch commands are the production subcommands defined in
`cmd/apadmin/command_catalog.go` and implemented in `internal/apadminapp`; they
are distinct from test mode. Key generate/import/delete and unlock are available
non-interactively only in test mode.
`appass` edits config offline; it is outside the live IPC surface.

These client capabilities describe the one product surface. Backend admin
operations use the one process-owned runtime; `apadmin`, `apapprover`, and
`appass` expose no runtime-selection UI.

`apadmin` test mode details:

- test mode is only present in builds compiled with `-tags testmode`,
- default builds keep the `-test` flag surface but reject it with a stub error instead of exposing the non-interactive path.

The `apadmin` TUI's policy workflow is described in
[Policies View](#policies-view).

## Signer Admin TUI

`apadmin` is the signer admin TUI. It is built on
[Bubble Tea](https://github.com/charmbracelet/bubbletea) and communicates with
`apsigner` over the [admin protocol](#admin-protocol-contract) through a local Unix socket. For remote
administration, SSH into the signer machine and run `apadmin` there. The TUI is a separate
admin-protocol client and does **not** route through `internal/engine` or the
`apshell` REPL/MCP pipeline (see [ARCH_SHELL.md](ARCH_SHELL.md#repl-surface) and
[ARCH_SHELL.md](ARCH_SHELL.md#mcp-surface) for those).

The implementation lives in `internal/signerapp/signertui/`.

### Model / View / Update

The TUI follows the standard Bubble Tea pattern:

| Aspect | Detail |
|--------|--------|
| Input | Key events, forms, async IPC messages |
| Output | Rendered screen with layouts and borders |
| State | `Model` owns view state, IPC connection, caches, and pending requests |

| Phase | Files |
|-------|-------|
| Model definition | `model.go` (Model struct, ViewState, initialization) |
| Async messages | `messages.go` |
| IPC / transport | `ipc_client.go`, `connector.go` |
| Update dispatch | `update.go` plus per-view `update_*.go` files |
| View dispatch | `view.go` plus per-view `view_*.go` files |
| Activity tracking | `activity.go` |
| Restore helpers | `restore_helpers.go` |

Per-view `update_*.go` and `view_*.go` files cover authentication, the key list,
admin panel, KeyType Library, signing approval, client enrollment
approval, the enrolled-client list with revocation, generate / import /
delete forms, cosigner public-key export, and managed backup restore. The `view.go` dispatcher selects the renderer by current
`ViewState`; the `update.go` dispatcher selects the handler the same way.

Popup panels use a shared overflow viewport instead of truncating content.
`Ctrl+Up` / `Ctrl+Down` scroll that outer panel incrementally,
`Ctrl+PgUp` / `Ctrl+PgDn` move by larger steps, and `Ctrl+Home` / `Ctrl+End`
jump to its boundaries. The popup displays its visible line range whenever it
overflows. Views with an existing purpose-built list, editor, or approval
viewport retain that viewport so nested scroll handlers do not compete.

Signing and client-enrollment approval popups stay in front of every other
screen until the operator answers, apsigner withdraws the request, or the
operator defers an enrollment popup with Esc.
Results that arrive meanwhile update the screen underneath, and answering or a
withdrawal returns to that screen; a second pending approval shows next.
apsigner rejects pending signing approvals when the admin session ends or the
signer locks. Disconnect, reconnect, reauthentication, displacement, and lock
clear local popups too; persisted enrollment requests remain queued and are
announced again on a later login.

Each in-progress generate, import, delete, key-type install, or backup records
its request ID. An untyped failure (an authorization denial, a send error, or a
signer message the TUI cannot decode) whose ID names that request returns the
operation to the screen it started from, as its own failure result would.
Progress screens ignore Esc, so nothing may strand them. An error for any other
request, such as a background refresh, leaves the operation waiting for its own
result, matching the policy-load flow.

In parameter forms, `j`, `k`, space, `<`, and `>` type into free-text fields;
they navigate or cycle only on choice fields and the submit button. Tab and the
arrow keys always navigate. Parameter fields accept ASCII only and refuse other
input with an error rather than rewriting it.

Long byte parameters, including bounded contract-admin public keys, use an atomic paste control
instead of an editable multi-line field. Activating the control accepts the
next terminal bracketed-paste event, stores the complete validated value, and
renders a read-only single-line preview with its middle elided. This behavior
is shared by standalone `apadmin` and the admin pane embedded in `apconsole`.

### View States

`ViewState` (defined in `internal/signerapp/signertui/model.go`) is an enum that
identifies the current screen. The enum has families for:

- Authentication and unlock (`ViewAuth`, `ViewUnlock`)
- Key list and details (`ViewKeyList`, `ViewKeyDetails`, `ViewTEALFullDisplay`)
- Approval popups (`ViewSigningPopup`, `ViewClientEnrollmentPopup`)
- Enrolled clients (`ViewEnrolledClients`, opened with `c` from the key
  list): the enrollment requests waiting for approval (`a` approve, `x`
  reject) followed by every enrolled key with fingerprint, label, key type,
  and live connection state (`r` revoke, `A` revoke all); `i` opens the key
  import form (`ViewImportClientKey`: a public-key file on this machine plus
  an optional label). The screen has no manual refresh: it re-fetches both
  lists on every `enrollment_changed` notification while it, one of its
  sub-views, or a popup raised over it is showing, so requests arriving over
  SSH, answers from another admin client, and clients connecting or
  disconnecting appear on their own. The enrollment popup queues requests announced while
  one is on screen and shows them in turn; a request announced again at
  login is shown once. `Esc` on the popup defers the request rather than
  rejecting it: nothing is sent, the request stays in the signer's queue and
  on the Enrolled Clients screen, the next waiting request takes the popup,
  and a later announcement at the next login shows it again. A repeated client
  request refreshes the queued entry (announced as `enrollment_changed`, which
  updates the Enrolled Clients lists) but does not raise the popup again. `Esc` on the signing popup still rejects, since a signing
  client is waiting on the answer. A signing popup refuses approval for one
  second after it comes into view (rejection is immediate): a requester can
  withdraw a request and send another in its place, and a key pressed for the
  first must not approve the second. `apapprover` reads whole lines, which the
  terminal buffers until Enter, so instead of a delay it shows each request
  with a fresh four-digit code and approves only `y <code>` for the request on
  screen
- Generate / import flows (form, params, loading, display)
- Signer-side public cosigner-reference management (`ViewCosignerReferences`,
  details, import, removal confirmation, and removal progress), the cosigner
  picker for guarded generation (`ViewCosignerPicker`), cosigner generate-type
  selection (`ViewCosignerGenerateType`), and cosigner public export
  (`ViewCosignerExportPath`, `ViewCosignerExporting`, `ViewCosignerExportResult`,
  `ViewCosignerExportJSON`)
- Managed backup create flow (`ViewBackupConfirm`, `ViewBackingUp`, `ViewBackupDisplay`)
- Managed backup restore flow (`ViewRestoreList` through `ViewRestoreDisplay`)
- Store recovery screen (`ViewStoreRecovery`): reconcile, direct credential restore, or rollback of the latest
  eligible restore. While the signer reports the `recovery` runtime state the
  screen is blocking — Escape does not leave it, ordinary administration stays
  unavailable, and the status bar shows "Signer Recovery (signing disabled)"
  until the visible store validates cleanly. The client preserves the server's three-way runtime state
  (`locked` / `recovery` / `unlocked`); recovery is never rendered as
  unlocked.
- Destructive confirmations (`ViewDeleteConfirm`, `ViewRevokeClientConfirm`, `ViewLockConfirm`, `ViewDisplaceConfirm`)
- Policies (`ViewPolicies`, `ViewPolicyDocument`, `ViewPolicyApplyForm`,
  `ViewPolicyApplyReview`, `ViewPolicyEdit`)
- Settings panel (`ViewAdminPanel`)
- KeyType Library (`ViewTemplateLibrary`, install confirm/loading, `ViewLibraryTemplateDetails`)
- `ViewError`

See `internal/signerapp/signertui/model.go` for the authoritative enum values and the
one-line comments that document each screen's purpose.

### Cosigner Reference Manager

On signer nodes, `e` from the key list opens the public cosigner-reference
manager. Rows are alias-first and show a compact Witness Key ID; the details
screen shows the complete grouped ID, witness key type, public-key digest,
import time, and all aliases for the same authority. It deliberately does not
render the raw public-key hex. Imports reuse the full-ID enrollment review and
return to the manager when they were started there. Removing a reference is an
explicit alias-scoped mutation whose confirmation defaults to Cancel.

From reference details, `Generate account` filters the signer-advertised key
types by `cosigner_component_key_type`. A sole compatible type proceeds directly
to its parameter view with the stable Witness Key ID selected; multiple types
use a dedicated filtered chooser. Canceling returns to the reference details
instead of losing the manager context.

The manager is role-gated and is not offered on cosigner nodes. It communicates
through the existing list/import/remove cosigner-reference admin messages, so
the signer remains responsible for authorization, lock-state enforcement,
store serialization, and audit emission.

On cosigner nodes, witness-key details and the successful witness-generation
screen offer `Export cosigner key`. The cosigner returns the public witness
envelope over the admin protocol, and the operator-side `apadmin` process
validates it, lays it out canonically, and either writes it to the chosen local
path or displays full JSON directly in the terminal. The file is the key and
nothing else; the result screen names the address clients should add, from
`endpoint.advertise_url` when it is configured, so the address is handed over
by the operator rather than carried in the file. `SHOW JSON` releases the terminal through Bubble Tea's execution lifecycle and writes
the complete original JSON for manual selection using terminal soft wrapping
and scrollback. Enter restores the export screen. No clipboard commands or OSC 52
sequences are emitted. File export or batch stdout also preserves the original
JSON bytes. Files are written on the machine running `apadmin`. Ordinary account keys do not expose
this action. The output path is directly editable and does not rename the
witness credential or add an authority claim to the public envelope. Imports
recognize the `.aplane-cosigner.json` suffix and may prefill an editable alias
from its sanitized filename stem.

The import form accepts the public witness document only; a file that carries
an endpoint block or any other field is refused before review. apadmin never
reads or writes client endpoint registries, client SSH identities, host trust,
aliases, or caches.

The manager exposes `p: Paste JSON` alongside `i: Import file`. The paste field
captures a complete bracketed terminal paste without interpreting its contents
as navigation keys, replacing the previous document. Input over 64 KiB clears
the buffer and reports an error. Backspace/Delete clears the field. The
document goes through the same parser and import review as a file. Returning
from review
preserves the paste for correction; canceling or completing import clears it.

Endpoint creation, enrollment requests, and live route discovery belong to apshell.
The reference details screen shows signer-owned metadata only.

TEAL exports save to the working directory of the apadmin process. Address-list
generation inputs require full account addresses; client aliases and sets are
resolved only by apshell.

### Admin Panel

The admin panel (Settings) opens from the key list with `s` and exposes live
signer settings and status:

- `user_auto_approve`
- `lock_on_disconnect`
- `passphrase_timeout`
- Color theme
- Admin transport, node role, passphrase unlock method, and TEAL compile network
- A `Policies` row that opens the policies view
- SSH enabled state, port, fingerprint, and connected-client count
- Build information

Backup creation and managed restore open directly from the key list with `b`
and `r`.

### Policies View

`p` on the key list or Settings, and the Settings `Policies` row, open a
list of the node's policy documents and key coverage, loaded with the
`get_policy` admin message (`internal/signerapp/signertui/policy_view.go`).
The list is the same on both node roles:

- the `default` row first, labelled `node default (governs every key without
  its own policy)`,
- then every held key (address on a signer node, Witness Key ID on a cosigner
  node) with its status: `own policy` or `default`,
- then stored documents for keys the node does not hold: `policy, key not
  held`.

Each row with a document shows its size, SHA-256, and applied time from the
sidecar's diagnostic `signed_at`; the header shows the `policy_set_sha256`.
Enter fetches that document with `get_policy_document` and opens a read-only
scrollable view of its exact bytes; Esc returns. A key on `default` has no
document of its own to open.

A policy document changes only through one check, review, and apply workflow
(`internal/signerapp/signertui/policy_apply.go`), which follows the same steps
as `apadmin policy apply FILE`. It has two sources for the candidate document:
`a` loads one policy file, and `e` opens the in-place editor described below.
For a loaded file:

1. A path prompt reads the file with the shared reader in
   `internal/signerapp/policyreview`. The read happens inside the event loop,
   so the path must be a regular file: a symlink, FIFO, or device is refused
   rather than opened. The file's `"key"` field selects the document:
   `default` or one key. The TUI refuses a file for a key the node does not
   hold, which the batch command only warns about; pre-staging a policy for a
   key that is not yet held stays a batch operation.
2. `check_policy` validates the exact bytes. Errors are shown on the prompt
   and stop the load; warnings carry into the review.
3. `get_policy_document` fetches the document that governs the key now: the
   key's own, or the node default it follows, and `policyreview.DiffCandidate`
   produces the same effective tightened/loosened/changed diff the batch
   command prints, so a first document for a key is shown as a change from
   the default. A file that decodes equal to the governing document reports
   `Policy unchanged` and cannot be applied.
4. Only `y` confirms. `apply_policy` carries, as its concurrency base, the
   `policy_set_sha256` of the summary the review was built from: the one that
   decided in step 3 whether the key has a document of its own. It is captured
   when the check returns and is never replaced by a later summary, so the
   daemon rejects the apply if the active policy changed after the review was
   built. On success the list reloads and
   shows the new generation ID; on failure the review shows the daemon's error
   and must be left and restarted. A `commit_uncertain` result means the
   daemon has entered recovery without sending a status message, so the TUI
   opens the Store Recovery screen with the daemon's error.

Request IDs tie each response to the pending step. An untyped failure such as
an authorization denial releases the pending step only when its request ID
names that step; an error for another request, such as a background key-list
refresh, leaves the step waiting for its own response. A request that cannot
be sent fails its own step the same way. `diff` without applying, `remove`, multi-file applies, and stdin
remain `apadmin policy` verbs; `apadmin policy rescue` covers a stopped daemon.
The `apadmin policy` verbs (`status`, `export`, `check`, `diff`, `apply`,
`remove`, `template`) cover the full surface. The editor adds no RPC: the TUI
uses the same `get_policy`, `get_policy_document`, `check_policy`, and
`apply_policy` messages as the verbs.

#### Policy Editor

`e` in the policies list or the document view opens `ViewPolicyEdit`
(`internal/signerapp/signertui/policy_edit.go`), a `bubbles/textarea` holding
one document's JSON. The editor is only another source for the workflow above:
`ctrl+s` sends the text through steps 2 to 4, and nothing is stored before the
confirmed apply.

- **What it opens on.** The default row and a key with `own policy` open on
  that document, fetched with `get_policy_document`. A single-line document is
  indented for editing; whitespace does not change what a policy allows, so an
  unedited reformat still reports `Policy unchanged`. A key on `default` opens
  on the node's current default, fetched the same way and rendered by
  `policyreview.Template` with the key filled in under a header comment; the
  editor marks it `No policy of its own yet`. Applying it unedited gives the key a
  document of its own that does what the default did, so a key's policy always
  starts from exactly what it was already doing; on a cosigner node that is
  the deny-all default. A key the node does not hold cannot be edited.
- **Cosigner presets.** On a cosigner node, `e` on the default row or on a key
  on `default` first opens a starting-text picker (`ViewPolicyPresetPick`,
  `policy_preset.go`). Its first choice is the path above; each other choice
  opens the editor on `policyreview.PresetTemplate` for that row's key,
  without a daemon request. A key with `own policy`, and every row on a
  signer node, open the editor directly. See
  [ARCH_POLICY.md](ARCH_POLICY.md#admin-surface).
- **Comments.** The text may carry `//` and `/* */` comments outside strings.
  `policyreview.DocumentFromText` removes them before the check, so the
  daemon receives and stores strict JSON; the review's "stores the edited
  text exactly" is the text without its comments.
- **Local checks before the daemon's.** A JSON syntax error is reported with
  its line and column without a request; comments are blanked in place for
  that check so the position is the one in the text shown. The `"key"`
  field must stay the document being edited (`default` or the key); setting
  another key's policy is a file load. The node must hold the key, as for
  file loads.
- **The text is never lost to an error.** A rejected check keeps the editor
  open with the daemon's problems under the text. Leaving the review, declined
  or failed, returns to the editor with the text intact; after a failed apply
  the policy summary is reloaded so the next attempt names the current policy
  set. Esc on changed text asks once before discarding.
- **No check against a reloading summary.** `ctrl+s` is refused while the
  summary is reloading. Together with the captured concurrency base in step 4,
  this keeps a review from being built on one policy state and applied against
  another.
- **Nothing is silently shortened.** The text area drops inserted lines past
  10,000 without notice. A document is opened only if the editor holds all of
  it (compared as JSON, since the component normalizes whitespace); otherwise
  editing is refused in favor of export, edit, and load. A paste that is cut
  off at that limit is reported.
- **Keys.** Every key except `ctrl+s` and `esc` goes to the text area, so the
  list's single-letter shortcuts are inert while editing. Paste is the
  terminal's own paste, which arrives as key input. The component's `ctrl+v`
  binding is disabled: it would read the machine's clipboard through an
  external helper program and return a message the view does not receive.

### Local Activity And Idle Locking

`apadmin` treats only Bubble Tea `tea.KeyMsg` input as local user activity.
Window resizes, timers, IPC responses, server notifications, and background
polling do not count. The TUI does not report local activity to the signer;
keyboard activity only re-arms apadmin's own local idle-disconnect timer.

The signer remains authoritative for lock state and term-key zeroing. After
`apadmin` learns the effective passphrase timeout from admin settings, it
arms a local idle timer from the latest local activity baseline. If the UI is
still idle when that timer fires, it disconnects the admin session. Any signer
lock that follows that disconnect is decided by the signer-owned
`lock_on_disconnect` setting. Manual lock actions are separate explicit
`lock_identity` requests. After a local idle disconnect, `apadmin` immediately
returns to the authentication view and starts a fresh pre-auth reconnect so the
operator sees the login screen instead of the stale authenticated view.
Disconnect, reconnect, reauthentication, and server lock notifications clear
pending activity and idle state. Every end of an admin session (disconnect,
reconnect, reauthentication, local idle disconnect, or displacement by another
apadmin) also zeroes the restore passphrase and drops cosigner workflow state,
pending approvals, and a pending manual lock. Every path into the unlocked
state (signer status, unlock, or a completed recovery reconcile) loads the same
keys, key types, cosigner references, and settings.

### Error Handling

Errors surface in `ViewError` or inline in the active screen's status area,
allowing retry. The TUI never panics on IPC errors; it transitions back to a
recoverable view.

### Key Files

| File | Purpose |
|------|---------|
| `internal/signerapp/signertui/model.go` | `Model`, `ViewState`, initialization |
| `internal/signerapp/signertui/update.go` | Top-level Update dispatch |
| `internal/signerapp/signertui/view.go` | Top-level View dispatch |
| `internal/signerapp/signertui/activity.go` | Local keystroke activity tracking and idle-disconnect timers |
| `internal/signerapp/signertui/ipc_client.go` | IPC connection to the signer |
| `internal/signerapp/signertui/connector.go` | Local Unix socket admin connector |
| `internal/signerapp/signertui/update_*.go`, `view_*.go` | Per-view handlers and renderers |

## Related Documentation

- [ARCH_SHELL.md](ARCH_SHELL.md#repl-surface) — `apshell` REPL (separate UI surface)
- [ARCH_SHELL.md](ARCH_SHELL.md#mcp-surface) — `apshell` MCP server (separate UI surface)
- [ARCH_SECURITY.md](ARCH_SECURITY.md) — Admin protocol authentication
- [ARCH_SECURITY.md](ARCH_SECURITY.md#authorization) — Signer authorization model
