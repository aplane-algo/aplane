# Admin Protocol Contract

> Compatibility-bearing wire shapes for the apsigner admin RPC carried over local IPC and the SSH `aplane-admin` subsystem.
> For overall compatibility scope, see [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).
> For the principal/grant authorization model that gates these messages, see [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md).

This contract is consumed by `apadmin` (TUI and test mode), `apapprover`, `appass`, and any other process that drives signer administration over the admin transport. It documents the envelope, transport handshake, message catalog, payload shapes, writable settings, lock semantics, and error codes.

## Envelope

Line-delimited JSON over the admin transport stream. Messages carry:

- `kind`: `request`, `response`, or `notification`
- `type`
- `id` for requests/responses

This envelope applies to the IPC and SSH admin protocol only, not the HTTP API.
`kind` is mandatory on admin-protocol messages; missing `kind` is a protocol error.

## Transport and Handshake

Generic clients normally see `auth_required` first. The server may instead send
a protocol `error` before auth when it rejects the session before the handshake
can begin, for example while another pre-auth admin client is already pending.
The `apadmin` TUI may see `client_exists` before auth for displacement
negotiation. `client_exists`, `displace_confirm`, and `displaced` are not part
of the generic transport contract.

Admin sessions bind to one identity runtime. Product-mode clients normally omit
`identity_id`, which defaults to the product identity. Local IPC remains
product-scoped: an explicit non-product `identity_id` is rejected unless the
transport was already pre-bound to that identity. SSH admin sessions may be
pre-bound by the SSH-authenticated identity; in that case an omitted
admin-protocol `identity_id` defaults to the SSH identity and an explicit
mismatched `identity_id` is rejected before runtime unlock or admin work.

The UI presents one product admin workflow. Internally, active
and pending admin sessions are stored per identity so approval routing,
notifications, displacement, disconnect cleanup, and lock-on-disconnect affect
only the bound identity.

Transport notes:

- the same line-delimited JSON admin protocol is carried over local IPC and the SSH `aplane-admin` subsystem,
- the current admin protocol version is 3.2; `auth_required` carries it as
  `protocol_version:{major,minor}`; clients must send their version in
  `auth.protocol_version`; major-version mismatches
  are rejected during authentication, and minor-version mismatches are logged
  but accepted,
- post-auth admin connections use one dispatcher-owned reader in `internal/transport`,
- the dispatcher routes by envelope semantics (`kind` + `id`) rather than message-type allowlists,
- the generic client helpers in `internal/transport` expect `auth_required` for
  a normal handshake and preserve pre-auth protocol `error` messages as
  formatted server rejections,
- displacement negotiation is handled only by the `apadmin` TUI path and is identity-scoped internally,
- generic clients observe some auth/displacement failures as formatted protocol errors rather than stable typed transport errors.

## Message Catalog

Source: `internal/protocol/messages.go`. Unsupported client messages yield a generic `error` response.

### Session and Identity

Client to Server:

- `auth` (pre-auth handshake response to `auth_required`; required before authenticated dispatch)
- `unlock`
- `lock_identity`
- `initialize_store`
- `change_store_passphrase`
- `displace_confirm` (apadmin TUI displacement flow only)

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

### Signing Approval and Tokens

Client to Server:

- `sign_response`
- `token_provisioning_response`
- `revoke_token`

Server to Client:

- `sign_request`
- `sign_request_canceled`
- `token_provisioning_request`
- `revoke_token_result`

### Backup and Restore

Client to Server:

- `backup`
- `list_backups`
- `delete_backup`
- `preview_restore`
- `recover_backup`
- `list_recovered`
- `review_recovered`
- `activate_recovered`
- `rollback_recovered`
- `purge_recovered`

Server to Client:

- `backup_result`
- `backups_list`
- `delete_backup_result`
- `restore_preview`
- `recover_backup_result`
- `recovered_list`
- `review_recovered_result`
- `activate_recovered_result`
- `rollback_recovered_result`
- `purge_recovered_result`

### Admin and Policy Settings

Client to Server:

- `get_admin_settings`
- `update_admin_setting`
- `get_policy_snapshot`
- `validate_policy`
- `replace_policy`

Server to Client:

- `admin_settings`
- `update_admin_setting_result`
- `policy_snapshot`
- `validate_policy_result`
- `replace_policy_result`

## Key Payload Shapes

### Session and Identity

- `auth`: `passphrase`, optional `identity_id`, required `protocol_version`
- `auth_result`: `success`, optional `code`, optional `error`
- `unlock` / `unlock_result`: `passphrase` -> `success`, optional `key_count`, `code`, `error`
- `lock_identity`: optional `reason` -> `lock_identity_result`: `success`, optional `code`, `error`; authorizes `identity.lock`, calls the server-side lock path, and normal `signer_locked` notifications remain the state-change signal
- `initialize_store`: `passphrase` -> `initialize_store_result`: `success`, optional `metadata_dir`, optional `helper_warning`, `code`, `error`; local IPC only, creates the identity keystore metadata/master-key state and may write the configured passphrase helper
- `change_store_passphrase`: `current_passphrase`, `new_passphrase` -> `change_store_passphrase_result`: `success`, optional `keys_migrated`, optional `templates_migrated`, optional `recovered_files_migrated`, optional `policy_sidecars_migrated`, optional `node_role_sidecars_migrated`, `code`, `error`; local IPC only, rejects identical current/new passphrases and rotates active-key, template, and recovered-batch encryption, policy integrity sidecars, and keystore metadata
- `status`: `state`, `key_count`
- `error`: optional `code`, `error`
- `signer_locked`: `reason`
- `displaced`: `reason`

The pre-auth `auth` request verifies the passphrase and may also unlock and
reload the bound identity. Therefore `auth_result{success:false}` does not
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
`code:"recovery_blocked"`. The identity is unlocked for administration only;
signing stays blocked until the operator resolves the store from recovery
mode.

### Key Management

- `generate_key`: `key_type`, optional `name`, optional `parameters`; accepted over IPC and SSH, but generated recovery material is not returned over the admin protocol
- `generate_result`: `success`, optional `address`, `key_type`, `parameters`, `code`, `error`; `mnemonic` and `word_count` fields remain in the schema but are omitted by signer responses
- `delete_key`: `address` -> `delete_result`: `success`, optional `code`, `error`
- `export_key`: `address`, `passphrase` -> `error code:"authorization_denied"`; mnemonic export is disabled, use encrypted backups for recovery
- `import_key`: `key_type`, `mnemonic`, optional `parameters` -> `import_result`: `success`, optional `address`, `key_type`, `code`, `error`; accepted only over local IPC because it carries recovery material
- `get_key_details`: `address` -> `key_details`: `success`, optional `address`, `key_type`, `parameters`, `display_teal`, `code`, `error`
- `key_details.parameters` for guarded account keys projects the embedded sentry verifier as `Sentry: <Witness Key ID>` and does not expose the raw `sentry_public_key` parameter
- `key_details` may include optional `template_provenance_status` and `template_provenance_note`; these are informational, version-aware comparisons between the key's stored template fingerprint provenance and the registered local definition, and do not gate signing. The fingerprint is behavior-only and versioned, so only a same-version, different-hash pair is a `conflict`; a different-version or malformed comparison is `unavailable` (benign), never a `conflict`
- `keys_list`: `keys`, where each key has `address`, `key_type`, optional `name`, optional `template_provenance_status`, optional `template_provenance_note`
- `keys_changed`: `key_count`

> **Boundary note — admin `keys_list` is not the HTTP key inventory.** The admin
> transport entry is `protocol.AdminKeyInfo` (thin: address, key type, name,
> template provenance), projected from the admin service DTO `adminproto.KeyInfo`.
> It is deliberately *not* `pkg/signerapi.KeyInfo`, the richer HTTP `/keys` shape
> that also carries `signing_flow`, `lsig_size`, `signing_args`, and capability
> flags for SDK clients. The two are distinct wire surfaces that happen to share a
> concept; do not add HTTP-only fields to the admin type, and do not assume a
> client-facing field exists on the admin list. Extend the HTTP `KeyInfo` for
> client needs and the admin `AdminKeyInfo`/`adminproto.KeyInfo` pair for TUI needs.

### Key Type Templates

- `list_library_templates` -> `library_templates`: `templates[]`, optional `code`, `error`; each template has optional `key_type`, `template_type`, `display_name`, `description`, `source_path`, `file_name`, `parameters[]`, `runtime_args[]`, plus `installed`, optional `enabled`, optional `conflict`, optional `invalid`. In this catalog response, `runtime_args[]` is live template metadata for keys created in the future; key-file and `/keys` `signing_args[]` is the durable signing-argument schema captured when an existing key was created.
- `show_library_template`: `key_type`, `template_type` -> `show_library_template_result`: `success`, optional `key_type`, `template_type`, `source_path`, `source_sha256`, `source_mtime`, `template_yaml`, `code`, `error`; accepted over IPC and SSH because it returns plaintext reference library YAML, not decrypted identity-local template source. `source_sha256` is the exact-byte SHA-256 of `template_yaml`; `source_mtime` is the source file's Unix modification time and is informational rather than tamper-proof.
- `install_library_template`: `key_type`, `template_type` -> `install_library_template_result`: `success`, optional `key_type`, `template_type`, `already_exists`, `code`, `error`
- `list_installed_templates` -> `installed_templates`: `templates[]`, optional `code`, `error`; each template has `key_type`, `template_type`, optional `size`, and `enabled`
- `show_installed_template`: `key_type` -> `show_installed_template_result`: `success`, optional `key_type`, `template_type`, sensitive `template_yaml`, `code`, `error`; local IPC only because it returns decrypted template source
- `import_installed_template`: sensitive `template_yaml` -> `import_installed_template_result`: `success`, optional `key_type`, `template_type`, `already_exists`, `code`, `error`; local IPC only because it carries template source for encrypted installation
- `remove_installed_template`: `key_type` -> `remove_installed_template_result`: `success`, optional `key_type`, `template_type`, `removed`, `code`, `error`; local IPC only
- `activate_key_type`: `key_type` -> `activate_key_type_result`: `success`, optional `key_type`, `already_exists`, `code`, `error`; this wire message activates compiled providers and enables installed YAML templates. The `apstore` CLI exposes this as `keytype enable`. For installed YAML templates, `already_exists:true` means the template was already enabled.
- `deactivate_key_type`: `key_type` -> `deactivate_key_type_result`: `success`, optional `key_type`, `removed`, `code`, `error`; this wire message deactivates compiled providers and disables installed YAML templates. The `apstore` CLI exposes this as `keytype disable`. `removed:true` means the enabled/disabled state changed, and in-use rejection returns `code:"key_type_in_use"` when installed-template disable or compiled-provider disable is blocked.
- `list_key_types` -> `key_types`: `key_types[]`, optional `code`, `error`; entries mirror most of the HTTP `/keytypes` schema but omit the guarded-routing fields `signing_flow` and `sentry_component_key_type` (admin clients are not guarded-send routers)

### Signing Approval and Tokens

- `sign_request`: `address`, `txn_sender`, `description`, `timestamp`, `first_valid`, `last_valid`, optional `violations`
- `sign_request_canceled`: optional `reason`; server-originated notification that a delivered `sign_request` is no longer actionable. Reasons are `client_canceled` and `timeout`. Admin clients must remove a matching active or queued signing prompt and must not send a later `sign_response` for that request.
- `sign_response`: `approved`, optional `reason`; server-side handling attaches the admin session's approver principal for audit attribution
- `token_provisioning_request`: `identity_id`, `ssh_fingerprint`, `remote_addr`, `timestamp`
- `token_provisioning_response`: `approved`, optional `reason`
- `revoke_token` / `revoke_token_result`: `success`, optional `code`, `error`

### Backup and Restore

- `backup`: `export_passphrase`, optional `addresses[]` -> `backup_result`: `success`, optional `archive_path`, `archive_checksum`, `archive_size`, `key_count`, `addresses[]`, `verified`, `skipped_keys`, `code`, `error`; an all-keys backup (no `addresses[]`) may succeed partially: key files whose decrypted payload fails canonical validation are excluded from the archive and reported in the optional `skipped_keys` map (address -> reason), and admin clients must surface these prominently. Explicitly selected addresses fail closed instead of being skipped, and a store where every key fails validation errors rather than producing an empty archive.
- `list_backups` -> `backups_list`: `backups[]`, optional `code`, `error`; each backup has `path`, `file_name`, optional Unix `created_at`, optional `size`, optional `checksum`, optional `verified`
- `delete_backup`: `archive_path` -> `delete_backup_result`: `success`, optional `code`, `error`
- `preview_restore`: `archive_path`, `export_passphrase` -> `restore_preview`: optional resolved `archive_path`, `keys[]`, `errors[]`, `code`, `error`; each key has `address`, optional `key_type`, `already_exists`, `has_template`, `template_type`, `error`
- `recover_backup`: `archive_path`, optional `addresses[]`, `export_passphrase`
  -> `recover_backup_result`: `success`, optional `restore_id`,
  `archive_name`, `archive_checksum`, `entry_count`, `code`, `error`; success
  publishes one destination-encrypted inactive batch and does not reload
- `list_recovered` -> `recovered_list`: optional `batches[]`, `code`, `error`;
  each batch carries restore ID, creation time, archive name/checksum, source
  role and policy status/digest, and entry count
- `review_recovered`: `restore_id` -> `review_recovered_result`: `success`,
  restore/batch state, archive and policy digests, destination approval mode,
  optional unattended-signing warning, factual policy comparison, ordered
  `security_changes[]`, secondary
  `changed_paths[]`, optional Boolean
  `source_user_auto_approve`, optional
  `source_genesis_hash_mappings[]` (`genesis_hash`, `network`),
  entries, active conflict fingerprints, opaque
  `review_token`, optional `unattended_signing_ack_required`, recorded
  acknowledgement flag, replacement state, `code`, `error`.
  The policy comparison is informational. It carries no downgrade verdict, and
  no acknowledgement is derived from it: archive-reported source policy cannot
  be authenticated by the destination store, so any verdict built on it could
  be suppressed by the archive.
  `unattended_signing_ack_required` is derived from verified destination state
  alone. It is true whenever the destination identity auto-approves unmatched
  signing requests, whatever the archive reports; absence means a pre-3.2
  server, and updated clients then fall back to the destination approval mode.
  The typed `source_*` fields report what the archive recorded. They are
  present when the source recorded them and absent otherwise; there is no
  status enum and no unknown-settings list, because the archive's sealed
  manifest authenticated the values before recovery recorded them.
  Authentication proves who packaged the claim; the fields still carry no
  signing, policy, or acknowledgement authority.
  `policy_downgrade_ack_required` and the `downgrade` member of
  `security_changes[]` were removed with the downgrade classifier. Clients
  compiled against an earlier contract ignore their absence.
- `activate_recovered`: `restore_id`, `review_token`, optional
  `acknowledge_unattended_signing`, optional `replace_existing` ->
  `activate_recovered_result`: `success`, restore ID, activated entries,
  optional operator-facing `warnings[]`, resulting `key_count`, `code`,
  `error`; warnings include non-fatal bundled-template skips decided against
  current destination state during activation. The server enforces
  `acknowledge_unattended_signing` against the pinned review. A deprecated
  `acknowledge_policy_transition` sent by an older protocol-v3 client is
  accepted and ignored; protocol v4 drops it entirely.
- `rollback_recovered`: `restore_id` -> `rollback_recovered_result`: `success`,
  restore ID, resulting `key_count`, `code`, `error`; refusals before any
  mutation use `recovered_rollback_refused` (nothing to roll back) or
  `recovered_rollback_diverged` (the current generation was mutated after
  activation and no longer matches its at-mint inventory); failures after
  mutation began use `recovered_rollback_failed` and enter recovery mode
- `purge_recovered`: `restore_id` -> `purge_recovered_result`: `success`,
  restore ID, `code`, `error`
- admin protocol v3 does not dispatch the v2 `restore_backup` mutation
- restore `export_passphrase` fields are JSON strings on the wire but are parsed into mutable byte buffers at the protocol boundary so server handlers can zero them after use; raw JSON transport buffers are best-effort and may retain bytes until their normal lifetime ends

### Admin and Policy Settings

- `admin_settings`: `user_auto_approve`, `lock_on_disconnect`, `passphrase_timeout`, `passphrase_method`, optional `node_role`, `ssh_enabled`, optional `ssh_listen_address`, optional `ssh_port`, `ssh_fingerprint`, `ssh_clients`, `signer_port`, `teal_compile_network`, optional `endpoint_advertise_url`, optional `endpoint_display_url`, `theme`
- `update_admin_setting`: `key`, `value` (string-typed on wire)
- `update_admin_setting_result`: `success`, `key`, optional `value`, `code`, `error`
- `get_policy_snapshot`: optional `target` (`signer` or `sentry`, omitted means `signer`); requests the active signer-owned stored policy projection for display/editing
- `policy_snapshot`: `success`, optional `target`, optional `identity_id`, optional `policy_yaml`, optional `policy_sha256`, optional `canonical`, optional `code`, optional `error`; on success, `policy_yaml` is canonical YAML for the active stored policy and `policy_sha256` is the SHA-256 of those emitted bytes
- `validate_policy`: optional `target` (`signer` or `sentry`, omitted means `signer`), `policy_yaml`; parses and runtime-validates the submitted YAML in the selected policy domain without writing it
- `validate_policy_result`: `success`, optional `target`, optional `identity_id`, optional `code`, optional `error`
- `replace_policy`: optional `target` (`signer` or `sentry`, omitted means `signer`), `policy_yaml`, optional `expected_current_sha256`; requests wholesale replacement of the selected policy document with exact submitted YAML bytes. `expected_current_sha256`, when present, must match the active canonical snapshot SHA-256 or the server returns `policy_snapshot_changed`.
- `replace_policy_result`: `success`, optional `target`, optional `identity_id`, optional `policy_yaml`, optional `policy_sha256`, optional `canonical`, optional `code`, optional `error`; on success, the response is the resulting active canonical snapshot, not necessarily the exact uploaded bytes

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
- `approval_wait`: identity-effective manual signing approval timeout. It is
  not projected through admin IPC.

Policy has no scalar admin setting surface. Read, validation, and mutation use
`get_policy_snapshot`, `validate_policy`, and `replace_policy` with the complete
canonical YAML document.

Key-type override semantics:

- `policy.yaml` may include `key_overrides`, a map from concrete signing key selector to sparse policy blocks
- override blocks inherit unset fields from the identity-wide effective policy
- nested `key_overrides` are rejected at policy load
- normal signing selects an override by signing auth address, not by transaction sender, so rekeyed accounts use the auth address
- sentry component signing selects an override by the request `component_key` Witness Key ID
- overrides are YAML-only; admin IPC/TUI settings do not expose or mutate `key_overrides`
- `get_policy_snapshot` may expose key overrides read-only as part of the canonical YAML snapshot
- `replace_policy` may replace YAML that contains `key_overrides`; it validates the complete policy in the selected target before writing and applies immediately on success
- `policy.yaml` and sentry-domain `policy.yaml` are verified against their `.hmac` sidecars and loaded into the bound identity runtime on unlock/reload; policy-mutation admin IPC requires an unlocked identity and writes the selected document plus sidecar; direct `key_overrides` YAML edits apply only after `apstore policy sign` and the next reload/unlock

Whole-policy replacement:

- `replace_policy` first verifies the current on-disk sidecar for the selected target, then parses and runtime-validates the submitted YAML
- successful replacement writes the exact submitted YAML bytes plus a fresh sidecar, verifies the saved file, and updates the bound identity runtime without requiring a restart
- failure is fail-closed: parse, validation, stale-snapshot, locked-identity, or current-policy verification errors do not overwrite the existing policy
- `replace_policy_result.policy_yaml` is canonical YAML for display; clients that need byte preservation should retain their own uploaded bytes

## Admin Lock Semantics

- `list_key_types` requires an authenticated, identity-bound admin session but
  does not require the identity runtime to be unlocked. Template-backed key
  types are visible only after that identity loads them into the process
  registry. Like HTTP `/keytypes`, this is a metadata surface; internal
  registration may be split between client-visible metadata and signer-side
  execution registries, but the response schema remains the same key-type
  metadata schema.
- `list_library_templates` requires the identity runtime to be unlocked because it reports identity-local
  installed state against the encrypted template store.
- `show_library_template` requires the identity runtime to be unlocked for the same identity-bound
  template administration surface, even though the returned library YAML is plaintext reference material.
- `install_library_template` requires the identity runtime to be unlocked because it writes into the encrypted identity-scoped template store and immediately reloads that identity.

## Error Codes and Semantics

Central protocol error-message codes are defined in
`internal/protocol/error_codes.go`. Result payloads may also define
message-specific stable codes.
