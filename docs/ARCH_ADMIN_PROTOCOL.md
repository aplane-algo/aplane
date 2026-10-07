# Admin Protocol Contract

> Compatibility-bearing wire shapes for the apsigner admin RPC carried over local IPC.
> For overall compatibility scope, see [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).
> For the principal/grant authorization model that gates these messages, see [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md).

This contract is consumed by `apadmin` (TUI and test mode), `apapprover`, `appass`, and any other process that drives signer administration over the admin transport. It documents the envelope, transport handshake, message catalog, payload shapes, writable settings, lock semantics, and error codes.

## Envelope

Line-delimited JSON over the admin transport stream. Messages carry:

- `kind`: `request`, `response`, or `notification`
- `type`
- `id` for requests/responses

This envelope applies to the IPC admin protocol only, not the HTTP API.
`kind` is mandatory on admin-protocol messages; missing `kind` is a protocol error.

## Transport and Handshake

Generic clients normally see `auth_required` first. The server may instead send
a protocol `error` before auth when it rejects the session before the handshake
can begin, for example while another pre-auth admin client is already pending.
The `apadmin` TUI may see `client_exists` before auth for displacement
negotiation. `client_exists`, `displace_confirm`, and `displaced` are not part
of the generic transport contract.

Admin sessions bind directly to the one product runtime. The v5 auth shape has
no runtime selector. Strict known-field decoding rejects unknown fields before
passphrase verification or runtime work.

IPC and SSH share one process-wide authenticated-pending slot and one active
admin slot. Local IPC additionally has one pre-auth pending slot until its
passphrase has been verified.

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
- admin frames are bounded to 4 MiB before JSON decoding on both transports.

## Implementation Boundary

`internal/protocol` is the compatibility-bearing IPC/SSH wire contract. It
owns protocol versions, message types and IDs, JSON field names, envelopes,
framing primitives, sensitive wire values, and stable error codes.

`internal/adminproto` is the transport-neutral service vocabulary used behind
that boundary, plus the framed server connection abstraction. Its requests and
results are internal domain values, not a second JSON schema. The authenticated
session in `internal/signerapp/adminserver` explicitly adapts between the two.
Domain services must not construct `protocol.BaseMessage` values or serialize
their results directly: projections intentionally omit internal state, signer
paths, and recovery material while emitting only the documented wire fields.

## Message Catalog

Source: `internal/protocol/messages.go`. Unsupported client messages yield a generic `error` response.

### Session and Store Lifecycle

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

### Key Management

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

### Key Type Templates

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

### Signing Approval and Client Enrollment

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
- `pending_enrollments_list`
- `approve_enrollment_result`
- `reject_enrollment_result`
- `import_client_key_result`
- `enrolled_keys_list`
- `revoke_enrolled_key_result`
- `revoke_all_enrolled_keys_result`

### Backup and Restore

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

### Admin and Policy Settings

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

### Cosigner References And Store Inventory

Client to Server:

- `list_cosigner_references`
- `get_cosigner_reference`
- `import_cosigner_reference`
- `remove_cosigner_reference`
- `export_cosigner_public`
- `list_generations`
- `prune_generation_quarantine`
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
- `deleted_archive_list`
- `prune_deleted_archive_result`

## Key Payload Shapes

### Session and Store Lifecycle

- `auth` / `auth_only`: `passphrase`, required `protocol_version`; unknown
  fields are rejected after the protocol major is validated
- `auth_result`: `success`, optional `code`, optional `error`
- `unlock` / `unlock_result`: `passphrase` -> `success`, optional `key_count`, `code`, `error`
- `lock_identity`: optional `reason` -> `lock_identity_result`: `success`, optional `code`, `error`; authorizes `identity.lock`, calls the server-side lock path, and normal `signer_locked` notifications remain the state-change signal
- `initialize_store`: `passphrase` -> `initialize_store_result`: `success`, optional `metadata_dir`, optional `helper_warning`, `code`, `error`; local IPC only, creates the product store's keyring root and format marker and may write the configured passphrase helper
- `change_store_passphrase`: `current_passphrase`, `new_passphrase` -> `change_store_passphrase_result`: `success`, optional `keys_migrated`, optional `templates_migrated`, optional `policy_sidecars_migrated`, optional `node_role_sidecars_migrated`, optional `prior_generations`, optional `helper_warning`, optional `root_committed`, optional `rotation_pending`, `code`, `error`; local IPC only, rejects identical current/new passphrases, appends and completes a durable key-term rotation for live encrypted artifacts and integrity sidecars, reports retained historical generations, preserves post-commit progress fields on failures, and treats passphrase-helper failure as a post-commit warning
- `status`: `state`, `key_count`
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
mode.

The pre-auth `auth_only` request performs the same passphrase verification and
runtime binding but never authorizes or invokes `identity.unlock`. It is a
distinct message type so an older server rejects it before processing instead
of ignoring a new flag and unlocking. First-party clients use it only for
operations whose handlers require an authenticated bound runtime. It does not
occupy or replace the active admin-owner slot and cannot receive approval
notifications or trigger disconnect cleanup. The server permits only
`get_admin_settings`, cosigner-reference list/get/public-export, and generation
inventory requests; those requests still pass through their ordinary grant
checks and locked/unlocked/recovery-state interlocks.

### Key Management

- `generate_key`: `key_type`, optional `name`, optional `parameters`; accepted over IPC and SSH, but generated recovery material is not returned over the admin protocol
- `generate_result`: `success`, optional `address`, `key_type`, `parameters`, `code`, `error`; `mnemonic` and `word_count` fields remain in the schema but are omitted by signer responses
- `delete_key`: `address` -> `delete_result`: `success`, optional `code`, `error`
- `export_key`: `address`, `passphrase` -> `error code:"authorization_denied"`; mnemonic export is disabled, use encrypted backups for recovery
- `import_key`: `key_type`, `mnemonic`, optional `parameters` -> `import_result`: `success`, optional `address`, `key_type`, `code`, `error`; accepted only over local IPC because it carries recovery material
- `get_key_details`: `address` -> `key_details`: `success`, optional `address`, `key_type`, `parameters`, `display_teal`, `code`, `error`
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

### Key Type Templates

- `list_library_templates` -> `library_templates`: `templates[]`, optional `code`, `error`; each template has optional `key_type`, `template_type`, `display_name`, `description`, `source_path`, `file_name`, `parameters[]`, `runtime_args[]`, plus `installed`, optional `enabled`, optional `conflict`, optional `invalid`. In this catalog response, `runtime_args[]` is live template metadata for keys created in the future; key-file and `/keys` `signing_args[]` is the durable signing-argument schema captured when an existing key was created.
- `show_library_template`: `key_type`, `template_type` -> `show_library_template_result`: `success`, optional `key_type`, `template_type`, `source_path`, `source_sha256`, `source_mtime`, `template_yaml`, `code`, `error`; accepted over IPC and SSH because it returns plaintext reference library YAML, not decrypted installed-template source. `source_sha256` is the exact-byte SHA-256 of `template_yaml`; `source_mtime` is the source file's Unix modification time and is informational rather than tamper-proof.
- `install_library_template`: `key_type`, `template_type` -> `install_library_template_result`: `success`, optional `key_type`, `template_type`, `already_exists`, `code`, `error`
- `list_installed_templates` -> `installed_templates`: `templates[]`, optional `code`, `error`; each template has `key_type`, `template_type`, optional `size`, and `enabled`
- `show_installed_template`: `key_type` -> `show_installed_template_result`: `success`, optional `key_type`, `template_type`, sensitive `template_yaml`, `code`, `error`; available through authenticated IPC admin sessions
- `import_installed_template`: sensitive `template_yaml` -> `import_installed_template_result`: `success`, optional `key_type`, `template_type`, `already_exists`, `code`, `error`; available through authenticated IPC admin sessions
- `remove_installed_template`: `key_type` -> `remove_installed_template_result`: `success`, optional `key_type`, `template_type`, `removed`, `code`, `error`; available through authenticated IPC admin sessions
- `activate_key_type`: `key_type` -> `activate_key_type_result`: `success`, optional `key_type`, `already_exists`, `code`, `error`; this wire message activates compiled providers and enables installed YAML templates. The `apadmin` CLI exposes this as `keytype enable`. For installed YAML templates, `already_exists:true` means the template was already enabled.
- `deactivate_key_type`: `key_type` -> `deactivate_key_type_result`: `success`, optional `key_type`, `removed`, `code`, `error`; this wire message deactivates compiled providers and disables installed YAML templates. The `apadmin` CLI exposes this as `keytype disable`. `removed:true` means the enabled/disabled state changed, and in-use rejection returns `code:"key_type_in_use"` when installed-template disable or compiled-provider disable is blocked.
- `list_key_types` -> `key_types`: `key_types[]`, optional `code`, `error`; entries mirror most of the HTTP `/keytypes` schema, omit `signing_flow`, and include optional `cosigner_component_key_type` so `apadmin` can filter enrolled public cosigner references for guarded-account generation without changing the public HTTP/SDK DTO

### Signing Approval and Client Enrollment

- `sign_request`: `address`, `txn_sender`, `description`, `timestamp`, `first_valid`, `last_valid`, optional `violations`
- `sign_request_canceled`: optional `reason`; server-originated notification that a delivered `sign_request` is no longer actionable. Reasons are `client_canceled` and `timeout`. Admin clients must remove a matching active or queued signing prompt and must not send a later `sign_response` for that request.
- `sign_response`: `approved`, optional `reason`; server-side handling attaches the admin session's approver principal for audit attribution
- `client_enrollment_request`: `ssh_fingerprint`, optional `label`, `remote_addr`, `timestamp`; a client asked over SSH (`request-enrollment` username, `enroll [<label>]` command) to have its key enrolled, and the request now waits in the signer's queue. Its ID is `enroll-<fingerprint>`. It is sent when a new request is queued and, for every request still waiting, when an admin session authenticates, so a client may see the same request announced more than once. The label is the client's requested display text, bounded and printable, and carries no authority. The admin client answers with `approve_enrollment` or `reject_enrollment` by fingerprint; there is no response to this notification itself, and the SSH client is not waiting on it.
- `list_pending_enrollments` -> `pending_enrollments_list`: `requests[]`, oldest first, each with `fingerprint`, optional `label`, `key_type`, optional `remote_addr`, and `requested_at` (Unix seconds)
- `approve_enrollment`: `fingerprint`, optional `label` -> `approve_enrollment_result`: `success`, optional `code`, `error`, `fingerprint`, `label`; enrolls the waiting request's key in `identities/default/.ssh/authorized_keys` with the request's label (or `label`, which replaces it), removes the request, and audits `CLIENT_ENROLLED` with the admin session's attribution. No credential is issued, because the client's key is its credential. A fingerprint with no waiting request fails with `code:"invalid_request"`.
- `reject_enrollment`: `fingerprint` -> `reject_enrollment_result`: `success`, optional `code`, `error`; removes the waiting request without enrolling its key and audits `CLIENT_ENROLLMENT_REJECTED`. A fingerprint with no waiting request fails with `code:"invalid_request"`.
- `import_client_key`: `public_key` (one OpenSSH public-key line), optional `label` -> `import_client_key_result`: `success`, optional `code`, `error`, `fingerprint`, `label`, `added`; enrolls the key directly (pre-enrollment), using the line's comment as the label when none is given, and clears a waiting request for the same key. `added` is false when the key was already enrolled. A malformed line or an unsupported key type fails with `code:"invalid_request"`.
- `list_enrolled_keys` -> `enrolled_keys_list`: `keys[]`, each with `fingerprint`, optional `label`, `key_type`, and `connected` (the key has at least one live SSH connection); `pending_count` is the number of requests waiting for approval
- `revoke_enrolled_key`: `fingerprint` -> `revoke_enrolled_key_result`: `success`, optional `code`, `error`, `closed_connections`; removes the key from the registry and closes every SSH connection it authenticated. An empty or unknown fingerprint fails with `code:"invalid_request"`.
- `revoke_all_enrolled_keys` -> `revoke_all_enrolled_keys_result`: `success`, optional `code`, `error`, `revoked_count`, `closed_connections`; the emergency lever: empties the registry and closes every client connection

### Backup and Restore

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
  `offset`, at most 256 KiB of `data`, and `eof`. This lets an operator export
  a managed archive without filesystem access to the private signer store.
  It requires the signer store to be unlocked or recovery-blocked.
- `preview_restore`: `archive_path`, sensitive `export_passphrase` ->
  `restore_preview`: resolved archive path, `keys[]`, `errors[]`, optional
  `code`, `error`. Each key reports address, key type, destination
  presence, and validation error. Preview never mutates the store and, like
  `list_backups`, is available in unlocked or recovery state.
- `restore_backup`: `archive_path`, optional `addresses[]`, sensitive
  `export_passphrase`, optional `replace_existing` ->
  `restore_backup_result`: `success`, operation ID, archive SHA-256,
  generation ID, `restored[]`, `identical[]`, `conflicts[]`, `key_count`,
  `code`, `error`. The server validates the whole set, then publishes one
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
### Admin and Policy Settings

- `admin_settings`: `user_auto_approve`, `lock_on_disconnect`, `passphrase_timeout`, `passphrase_method`, optional `node_role`, `ssh_enabled`, optional `ssh_listen_address`, optional `ssh_port`, `ssh_fingerprint`, `ssh_clients`, `signer_port`, `teal_compile_network`, optional `endpoint_advertise_url`, optional `endpoint_display_url`, `theme`
- `update_admin_setting`: `key`, `value` (string-typed on wire)
- `update_admin_setting_result`: `success`, `key`, optional `value`, `code`, `error`

### Policy Messages

Policy documents are the v1 JSON documents specified in
[ARCH_POLICY_FORMAT.md](ARCH_POLICY_FORMAT.md). There is no `target` field;
the node role selects the document type. Every `document` value carries the
exact document bytes as a string, and every `sha256` is the SHA-256 of those
exact bytes; the server never re-serializes a document.

Shared shapes:

- request document (check and apply): `key` (Witness Key ID; omitted for the signer document), `document`
- document summary: `key`, `sha256`, `size`, optional `signed_at_unix` (diagnostic sidecar timestamp)
- key status (cosigner): `key`, `status` — `active` (key held, document present), `no_policy` (key held, no document; the key rejects every request), or `key_not_held` (document for a key the node does not hold)
- policy problem: optional `key`, optional `pointer` (JSON Pointer into that document), `message`

Messages:

- `get_policy` -> `policy`: `success`, `node_role`, `documents[]` (document summaries, without bytes), `keys[]` (cosigner nodes), `policy_set_sha256`, optional `generation_id`, optional `code`, optional `error`. `policy_set_sha256` is the lowercase hex SHA-256 over the sorted lines `<key> <document sha256>\n`, one per document (empty key for the signer document). Returns `policy_unavailable` when no policy is loaded.
- `get_policy_document`: optional `key` (omitted for the signer document) -> `policy_document`: `success`, `key`, `document` (exact bytes), `sha256`, optional `signed_at_unix`, optional `code`, optional `error`. Returns `policy_document_not_found` when the key has no document.
- `check_policy`: `documents[]`, optional `remove[]` (cosigner Witness Key IDs the candidate change would delete) -> `check_policy_result`: `success`, `valid`, optional `errors[]`, optional `warnings[]`, optional `code`, optional `error`. Validates the candidate change for the node role without writing. `valid` is true when `errors` is empty. Warnings never block an apply; they report cosigner key coverage gaps in the resulting state (`no_policy`, `key_not_held`) and policy advisories, such as a `reject_*` setting that overrides a route's `allow_close` or `allow_clawback`.
- `apply_policy`: `documents[]`, optional `remove[]`, `expected_policy_set_sha256` -> `apply_policy_result`: `success`, optional `errors[]`, optional `policy` (the new `policy` view, including the committed `generation_id`), optional `commit_uncertain`, optional `code`, optional `error`.

Apply rules:

- A signer node takes exactly one document with no `key` and no removals.
- A cosigner node adds or replaces each listed document, deletes each key in `remove`, and keeps unlisted documents. Each document's `key` must equal its signed `key` field. A key may appear only once across `documents` and `remove`; removing a key with no document is rejected.
- `expected_policy_set_sha256` is required and must equal the active `policy_set_sha256`.
- A cosigner node holds at most 8,192 policy documents (`policyapply.MaxCosignerPolicies`); a change past the cap is rejected with `policy_set_too_large` before anything is written. Key generation, import, and restore refuse an 8,193rd cosigner credential (`keys.MaxCosignerCredentials`).
- Response sizes are bounded: `policy` and `apply_policy_result` carry document summaries, never bytes, so with both caps full and every field at its longest they encode to about 3 MB, inside the 4 MiB admin frame. `policy_document` carries one document of at most 1 MiB; admin messages are encoded without HTML escaping, so a document string at most doubles (only quotes, backslashes, JSON whitespace, and U+2028/U+2029 are escaped) and the response stays near 2 MiB.
- The server verifies the active policy, checks the concurrency base, validates the change, and mints one new generation (operation `policy-apply`) carrying the documents and fresh sidecars, then reloads the bound product runtime without a restart. A change that leaves the policy set unchanged commits nothing.
- Failure is fail-closed: request, validation, stale-base, locked-store, or current-policy verification errors leave the active generation unchanged.
- `commit_uncertain` means the generation may be visible but its durability or the runtime reload is unconfirmed; signing is blocked pending reconciliation or recovery.

Result codes include `expected_policy_set_sha256_required`,
`policy_snapshot_changed`, `policy_validation_failed` (with `errors[]`),
`invalid_policy_request`, `policy_set_too_large`, `policy_unavailable`, `policy_document_not_found`, `policy_verify_failed`,
`identity_locked`, `policy_commit_uncertain`, `policy_reload_failed`, and
`policy_save_failed`.

`get_policy`, `get_policy_document`, and `check_policy` require `policy.view`; `apply_policy` requires
`policy.update`. Policy messages are not exposed through apshell or MCP.

## Writable Settings

Writable admin settings:

- `user_auto_approve` (`User Auto-Approve`; operator-default fallback approval switch)
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

### Cosigner References And Generation Inventory

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
  classification, entry count, and encoded byte count. If a store mutation is
  active, the request returns retryable `store_busy` rather than waiting for
  the ordinary IPC timeout.
- `prune_generation_quarantine`: `generation_ids[]`, `confirm` ->
  `prune_generation_quarantine_result`: `success`, `pruned[]`, optional `code`,
  `error`; deletion is restricted to explicitly selected quarantine IDs,
  requires `confirm:true`, and records a durable audit intent before mutation.
  An already-absent selected ID is successful and reported as such, making an
  interrupted multi-ID request safely retryable.
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
Only selected-generation `deleted/keys/` and `deleted/keytypes/` canonical paths
are accepted; arbitrary filesystem paths are not an admin-protocol surface.

Policy key-override semantics:

- a signer `policy.json` may include `key_overrides`, a map from signing auth address to sparse blocks of scalar settings and `limits` (see [ARCH_POLICY_FORMAT.md](ARCH_POLICY_FORMAT.md#key-override-inheritance))
- normal signing selects an override by signing auth address, not by transaction sender, so rekeyed accounts use the auth address
- cosigner documents have no overrides; each cosigner key has its own self-contained document selected by the request `component_key`
- admin settings do not expose or mutate policy fields; overrides change only through a whole-document `apply_policy`
- documents placed by hand in a stopped store apply only after `apstore policy sign` and the next unlock

## Admin Lock Semantics

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

## Error Codes and Semantics

Central protocol error-message codes are defined in
`internal/protocol/error_codes.go`. Result payloads may also define
message-specific stable codes.

`node_fail_closed` rejects both new authentication and every request from an
already-authenticated admin session after a process-wide invariant failure.
The operator must repair the underlying store/role conflict and restart the
signer; the session cannot resume administrative work in-process.
