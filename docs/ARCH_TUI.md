# Signer Admin TUI Architecture (signertui)

`apadmin` is the signer admin TUI. It is built on
[Bubble Tea](https://github.com/charmbracelet/bubbletea) and communicates with
`apsigner` over the admin protocol through a local Unix socket. For remote
administration, SSH into the signer machine and run `apadmin` there. The TUI is a separate
admin-protocol client and does **not** route through `internal/engine` or the
`apshell` REPL/MCP pipeline (see [ARCH_REPL.md](ARCH_REPL.md) and
[ARCH_MCP.md](ARCH_MCP.md) for those).

The implementation lives in `internal/signerapp/signertui/`.

## Model / View / Update

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
| IPC / transport | `ipc_client.go`, `connector.go`, `client_home.go` |
| Update dispatch | `update.go` plus per-view `update_*.go` files |
| View dispatch | `view.go` plus per-view `view_*.go` files |
| Activity tracking | `activity.go` |
| Restore helpers | `restore_helpers.go` |

Per-view `update_*.go` and `view_*.go` files cover authentication, the key list,
admin panel, KeyType Library, signing approval, token
provisioning approval, generate / import / export / delete forms, and managed
backup restore. The `view.go` dispatcher selects the renderer by current
`ViewState`; the `update.go` dispatcher selects the handler the same way.

Popup panels use a shared overflow viewport instead of truncating content.
`Ctrl+Up` / `Ctrl+Down` scroll that outer panel incrementally,
`Ctrl+PgUp` / `Ctrl+PgDn` move by larger steps, and `Ctrl+Home` / `Ctrl+End`
jump to its boundaries. The popup displays its visible line range whenever it
overflows. Views with an existing purpose-built list, editor, or approval
viewport retain that viewport so nested scroll handlers do not compete.

Signing and client-enrollment approval popups stay in front of every other
screen until the operator answers them or apsigner withdraws the request.
Results that arrive meanwhile update the screen underneath, and answering or a
withdrawal returns to that screen; a second pending approval shows next.
apsigner rejects every pending approval when the admin session ends or the
signer locks, so disconnect, reconnect, reauthentication, displacement, and lock
drop them from the TUI as well.

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

## View States

`ViewState` (defined in `internal/signerapp/signertui/model.go`) is an enum that
identifies the current screen. The enum has families for:

- Authentication and unlock (`ViewAuth`, `ViewUnlock`)
- Key list and details (`ViewKeyList`, `ViewKeyDetails`, `ViewTEALFullDisplay`)
- Approval popups (`ViewSigningPopup`, `ViewTokenProvisioningPopup`)
- Generate / import flows (form, params, loading, display)
- Signer-side public cosigner-reference management (`ViewCosignerReferences`,
  details, import, removal confirmation, and removal progress)
- Managed backup create flow (`ViewBackupConfirm`, `ViewBackingUp`, `ViewBackupDisplay`)
- Managed backup restore flow (`ViewRestoreList` through `ViewRestoreDisplay`)
- Store recovery screen (`ViewStoreRecovery`): reconcile, direct credential restore, or rollback of the latest
  eligible restore. While the signer reports the `recovery` runtime state the
  screen is blocking — Escape does not leave it, ordinary administration stays
  unavailable, and the status bar shows "Signer Recovery (signing disabled)"
  until the visible store validates cleanly. The client preserves the server's three-way runtime state
  (`locked` / `recovery` / `unlocked`); recovery is never rendered as
  unlocked.
- Destructive confirmations (`ViewDeleteConfirm`, `ViewRevokeTokenConfirm`, `ViewDisplaceConfirm`)
- Settings panel (`ViewAdminPanel`)
- KeyType Library (`ViewTemplateLibrary`, install confirm/loading, `ViewLibraryTemplateDetails`)
- `ViewError`

See `internal/signerapp/signertui/model.go` for the authoritative enum values and the
one-line comments that document each screen's purpose.

## Cosigner Reference Manager

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
reads or writes client endpoint registries, tokens, host trust, aliases, or
caches.

The manager exposes `p: Paste JSON` alongside `i: Import file`. The paste field
captures a complete bracketed terminal paste without interpreting its contents
as navigation keys, replacing the previous document. Input over 64 KiB clears
the buffer and reports an error. Backspace/Delete clears the field. The
document goes through the same parser and import review as a file. Returning
from review
preserves the paste for correction; canceling or completing import clears it.

Endpoint creation, token enrollment, and live route discovery belong to apshell.
The reference details screen shows signer-owned metadata only.

TEAL exports save to the working directory of the apadmin process. Address-list
generation inputs require full account addresses; client aliases and sets are
resolved only by apshell.

## Admin Panel

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

## Policies View

`p` on the key list or Settings, and the Settings `Policies` row, open a
list of the node's active policy documents, loaded with the
`get_policy` admin message (`internal/signerapp/signertui/policy_view.go`):

- signer nodes show one `policy.json` row,
- cosigner nodes show one row per Witness Key ID with its status: `active`,
  `no policy (rejects every request)`, or `policy, key not held`.

Each row with a document shows its size, SHA-256, and applied time from the
sidecar's diagnostic `signed_at`; the header shows the `policy_set_sha256`.
Enter fetches that document with `get_policy_document` and opens a read-only
scrollable view of its exact bytes; Esc returns.

A policy document changes only through one check, review, and apply workflow
(`internal/signerapp/signertui/policy_apply.go`), which follows the same steps
as `apadmin policy apply FILE`. It has two sources for the candidate document:
`a` loads one policy file, and `e` opens the in-place editor described below.
For a loaded file:

1. A path prompt reads the file with the shared reader in
   `internal/signerapp/policyreview`. The read happens inside the event loop,
   so the path must be a regular file: a symlink, FIFO, or device is refused
   rather than opened. On a cosigner node the file's `"key"`
   field selects the document. The TUI refuses a file for a Witness Key ID the
   node does not hold, which the batch command only warns about; pre-staging a
   policy for a key that is not yet held stays a batch operation.
2. `check_policy` validates the exact bytes. Errors are shown on the prompt
   and stop the load; warnings carry into the review.
3. If the key has an active document, `get_policy_document` fetches it and
   `policyreview` produces the same tightened/loosened/changed diff the batch
   command prints. A file that decodes equal to the active document reports
   `Policy unchanged` and cannot be applied.
4. Only `y` confirms. `apply_policy` carries, as its concurrency base, the
   `policy_set_sha256` of the summary the review was built from: the one that
   decided in step 3 whether the key has an active document. It is captured
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

### Policy Editor

`e` in the policies list or the document view opens `ViewPolicyEdit`
(`internal/signerapp/signertui/policy_edit.go`), a `bubbles/textarea` holding
one document's JSON. The editor is only another source for the workflow above:
`ctrl+s` sends the text through steps 2 to 4, and nothing is stored before the
confirmed apply.

- **What it opens on.** An active document is fetched with
  `get_policy_document`. A single-line document is indented for editing;
  whitespace does not change what a policy allows, so an unedited reformat
  still reports `Policy unchanged`. A cosigner key with no document opens on
  the locked starting document from `policy.LockedCosignerDocumentV1`: a valid
  document with no routes, which rejects every request exactly as a missing
  document does. An edit therefore always starts from zero permissions.
- **Local checks before the daemon's.** A JSON syntax error is reported with
  its line and column without a request. On a cosigner node the `"key"` field
  must stay the key being edited; setting another key's policy is a file load.
  The node must hold the key, as for file loads.
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

## Local Activity And Idle Locking

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

## Error Handling

Errors surface in `ViewError` or inline in the active screen's status area,
allowing retry. The TUI never panics on IPC errors; it transitions back to a
recoverable view.

## Key Files

| File | Purpose |
|------|---------|
| `internal/signerapp/signertui/model.go` | `Model`, `ViewState`, initialization |
| `internal/signerapp/signertui/update.go` | Top-level Update dispatch |
| `internal/signerapp/signertui/view.go` | Top-level View dispatch |
| `internal/signerapp/signertui/activity.go` | Local keystroke activity reporting and idle lock timers |
| `internal/signerapp/signertui/ipc_client.go` | IPC connection to the signer |
| `internal/signerapp/signertui/connector.go` | Local Unix socket admin connector |
| `internal/signerapp/signertui/update_*.go`, `view_*.go` | Per-view handlers and renderers |

## Related Documentation

- [ARCH_REPL.md](ARCH_REPL.md) — `apshell` REPL (separate UI surface)
- [ARCH_MCP.md](ARCH_MCP.md) — `apshell` MCP server (separate UI surface)
- [ARCH_SECURITY.md](ARCH_SECURITY.md) — Admin protocol authentication
- [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md) — Signer authorization model
