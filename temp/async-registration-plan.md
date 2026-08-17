# Async Client Registration Plan

> **Superseded 2026-08-16.** The single-product decision in
> [single-tenant.md](single-tenant.md) keeps token enrollment synchronous,
> connection-bound, and dependent on a live product operator. There is no
> durable registration queue or later collection protocol. This file is
> retained as historical design context only.

## Goal

Allow `apshell request-token` to submit a durable client registration request when an operator is not actively approving in `apadmin`, then let the client collect the approved token later using the same SSH key. Keep the current synchronous approval flow available as an operator/admin mode.

The operator-facing unit is a pending client registration with a short receipt, optional user message, and the SSH public key that will be enrolled if approved.

## Current Flow

Today `request-token` uses the SSH token-provisioning path:

1. Client connects as SSH user `request-token:<identity>`.
2. Client runs exec command `provision`.
3. Signer requires a live apadmin operator.
4. Signer sends `token_provisioning_request` to apadmin.
5. apadmin approves/rejects synchronously.
6. Signer enrolls the SSH public key, loads/generates `aplane.token`, writes the token to the SSH channel, and audits success.

This fails bootstrap when the enrolling client and the approving admin cannot be online at the same time.

## Proposed UX

Default async submission:

```text
(disc) testnet> request-token "Thom laptop"
Registration request submitted.

Receipt: APLANE-REG-7K4M-2Q9D
Identity: default
Client key: SHA256:...
Message: Thom laptop

Ask an operator to approve this receipt in apadmin.
You can close this shell and run 'request-token --collect APLANE-REG-7K4M-2Q9D' later.
```

Collection after approval:

```text
(disc) testnet> request-token --collect APLANE-REG-7K4M-2Q9D
Token received and saved to /path/aplane.token
You can now use 'connect' to connect to the Signer.
```

Synchronous mode remains available:

```text
request-token --sync
request-token --sync "Thom laptop"
```

The apadmin toggle controls server behavior when the client does not pass an explicit mode:

- `sync`: existing behavior; requires live operator and blocks.
- `async`: store pending request and return receipt immediately.

Recommendation: default the server setting to `async` for new configs after implementation, but preserve existing behavior until docs/release notes make that switch explicit. If compatibility risk is a concern, ship with default `sync` first and flip later.

## Command Syntax

Extend `request-token` parsing:

```text
request-token [<host>] [--ssh-port <port>] [--sync|--async] [--message <text>] [message]
request-token --collect <receipt> [<host>] [--ssh-port <port>]
```

Rules:

- A trailing quoted/unquoted message is accepted when it is not a host.
- `--message` is the unambiguous scripting form.
- Message is optional, plain text, capped at 512 bytes, and displayed/stored as untrusted text.
- `--sync` and `--async` are mutually exclusive.
- `--collect` is mutually exclusive with new-request message/mode flags except host/port.

## Receipt

Receipt format:

```text
APLANE-REG-XXXX-XXXX
```

Properties:

- Random, non-sequential, human-friendly.
- Not secret.
- Collision checked against pending/completed records.
- Included in client output, apadmin pending list, approval popup, and audit events.
- The receipt identifies the request; authorization remains bound to the SSH public key that submitted it.

## Durable Storage

Add identity-scoped registration storage:

```text
identities/<identity>/
  pending_registrations/
    <receipt>.json
```

Record shape:

```json
{
  "version": 1,
  "receipt": "APLANE-REG-7K4M-2Q9D",
  "identity_id": "default",
  "ssh_fingerprint": "SHA256:...",
  "public_key": "ssh-ed25519 ...",
  "remote_addr": "203.0.113.4:51234",
  "message": "Thom laptop",
  "created_at": "2026-04-27T18:42:00Z",
  "expires_at": "2026-04-28T18:42:00Z",
  "status": "pending",
  "approved_at": null,
  "rejected_at": null,
  "approved_by": "",
  "rejection_reason": ""
}
```

Use atomic file writes with `0600` records and `0700` directory permissions. The record does not contain the API token.

Suggested TTL:

- Pending requests expire after 24 hours by default.
- Expired records are hidden from the default apadmin pending list.
- Cleanup can be opportunistic on signer startup and registration list reads.

Duplicate handling:

- Same identity + same public key + pending record: return the existing receipt and update `remote_addr`, `message`, and `expires_at` only if that is clearly useful; otherwise leave the original untouched.
- Same identity + same public key + approved record already collected: collection should be idempotent if still retained, but do not keep approved records indefinitely.
- Different key creates a different receipt.

## Server API Shape

Add a provisioning command version while keeping `provision` intact:

```text
provision
provision-async <json>
collect <receipt>
```

`provision` remains the sync-compatible current command.

`provision-async` payload:

```json
{
  "mode": "server-default|sync|async",
  "message": "optional user message"
}
```

Responses:

- Sync success: stdout is the token, preserving current client behavior for `provision`.
- Async submit success: stdout is JSON containing `status:"pending"`, `receipt`, `identity_id`, `ssh_fingerprint`, `expires_at`.
- Collect success: stdout is the token, then the client saves it like today.
- Pending collection: non-zero exit with a clear message like `registration pending: APLANE-REG-...`.
- Rejected/expired collection: non-zero exit with reason.

The collect command must verify that the SSH public key on the collection connection matches the public key stored in the registration record.

## Signer-Side Flow

Async submit:

1. Re-check identity support/decommission state.
2. Validate and cap message.
3. Store or load pending registration for identity + public key.
4. Notify any connected apadmin sessions that pending registrations changed.
5. Return receipt to the client.

Approval:

1. apadmin lists pending registrations.
2. Operator opens one and approves/rejects.
3. Signer authorizes `token.provision`.
4. On approve, signer enrolls the stored SSH key.
5. Signer marks record `approved`; token is not delivered to apadmin and not stored in the registration record.
6. On reject, signer marks record `rejected` with reason.

Collection:

1. Client connects again as `request-token:<identity>` using the same SSH key.
2. Client runs `collect <receipt>`.
3. Signer loads the record and checks identity, status, expiry, and public key match.
4. Signer loads/generates the identity token.
5. Signer writes token to the SSH channel.
6. Signer audits token delivery and marks record collected or deletes it.

## Admin Protocol Changes

Keep existing synchronous messages:

- `token_provisioning_request`
- `token_provisioning_response`

Add async registration messages:

- `list_client_registrations`
- `client_registrations`
- `client_registration_request` notification, optional but useful for live refresh
- `client_registration_response`

Minimal payload fields:

```json
{
  "receipt": "APLANE-REG-7K4M-2Q9D",
  "identity_id": "default",
  "ssh_fingerprint": "SHA256:...",
  "remote_addr": "203.0.113.4:51234",
  "message": "Thom laptop",
  "created_at": 1777315320,
  "expires_at": 1777401720,
  "status": "pending"
}
```

The existing `token_provisioning_request` should also gain optional fields:

- `receipt,omitempty`
- `message,omitempty`

These fields are backward-compatible for JSON clients.

## apadmin UI

Add a settings toggle:

```text
Client registration mode: Async / Sync
```

Persist it as an identity admin setting or identity config field. Prefer putting it with identity runtime/admin settings rather than global config, because token provisioning is identity-scoped.

Add a pending registrations view:

- Shows receipt, SSH fingerprint, message, age, expiry.
- Enter opens approval popup.
- Approve/reject actions mirror current token provisioning approval popup.
- Popup warning text should say approval enrolls the SSH key and allows the same key to collect the current identity API token.

When mode is sync, current popup behavior remains unchanged.

## Security Properties

Valid improvements:

- Operator no longer has to be online at submission time.
- Approval is durable and auditable.
- Receipt supports out-of-band coordination.
- Token delivery remains bound to SSH public key possession.

Required safeguards:

- Do not store the API token in registration records.
- Do not approve by receipt alone; approve the stored key bound to that receipt.
- Do not allow collection from a different SSH public key.
- Expire pending requests.
- Cap message length and treat message as display-only untrusted text.
- Audit submit, approve, reject, collect, expire, and key enrollment failures.

Residual model:

- First-use SSH host trust remains TOFU unless the signer host key is verified out-of-band.
- Receipt is an identifier, not a secret.
- One identity token still means approval grants access equivalent to any other client holding `aplane.token`.

## Implementation Slices

1. Add registration store package under signer ownership.
   - Record type, atomic read/write/update/list/delete.
   - Receipt generation.
   - TTL filtering and cleanup.
   - Unit tests.

2. Extend SSH provisioning server/client protocol.
   - Add async submit and collect exec commands.
   - Preserve `provision` behavior.
   - Add same-key collection check.
   - Unit tests in `internal/sshtunnel`.

3. Add signer runtime services.
   - Runtime methods for submit/list/respond/collect.
   - Approval response authorizes and enrolls key.
   - Audit hooks.

4. Extend admin protocol.
   - New message constants and structs.
   - Envelope allowlists and tests.
   - Handler methods.

5. Update apadmin/signertui.
   - Pending registrations list or section.
   - Approval popup with receipt/message.
   - Settings toggle for sync/async mode.

6. Update apshell command.
   - Parse `--message`, trailing message, `--sync`, `--async`, `--collect`.
   - Render receipt and collection instructions.
   - Save collected token with existing token file path and permissions.

7. Docs and compatibility notes.
   - Update `docs/ARCH_CONTRACTS.md`, `docs/ARCH_SECURITY.md`, `docs/USER_COMMANDS.md`, and install/bootstrap docs.

## Open Decisions

1. Should the initial shipped default be `sync` for compatibility or `async` for the new bootstrap UX?
2. Should approved-but-uncollected requests expire separately from pending requests?
3. Should collection be `request-token --collect <receipt>` only, or should plain `request-token` auto-collect the most recent approved request for the same key?
4. Should remote `apadmin` preflight change after async registration exists, or should remote apadmin still require a fully enrolled client?
5. Should apapprover support async registration lists, or only the full apadmin TUI?
