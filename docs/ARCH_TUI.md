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
- Signer-side public sentry-reference management (`ViewSentryReferences`,
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
- Settings panel (`ViewAdminPanel`) and shared policy editor workflow (`ViewPolicyEditor`)
- KeyType Library (`ViewTemplateLibrary`, install confirm/loading, `ViewLibraryTemplateDetails`)
- `ViewError`

See `internal/signerapp/signertui/model.go` for the authoritative enum values and the
one-line comments that document each screen's purpose. Compatibility-only
policy view states in the enum are not active `apadmin` entry points.

## Sentry Reference Manager

On signer nodes, `e` from the key list opens the public sentry-reference
manager. Rows are alias-first and show a compact Witness Key ID; the details
screen shows the complete grouped ID, witness key type, public-key digest,
import time, and all aliases for the same authority. It deliberately does not
render the raw public-key hex. Imports reuse the full-ID enrollment review and
return to the manager when they were started there. Removing a reference is an
explicit alias-scoped mutation whose confirmation defaults to Cancel.

From reference details, `Generate account` filters the signer-advertised key
types by `sentry_component_key_type`. A sole compatible type proceeds directly
to its parameter view with the stable Witness Key ID selected; multiple types
use a dedicated filtered chooser. Canceling returns to the reference details
instead of losing the manager context.

The manager is role-gated and is not offered on sentry nodes. It communicates
through the existing list/import/remove sentry-reference admin messages, so
the signer remains responsible for authorization, lock-state enforcement,
store serialization, and audit emission.

On sentry nodes, witness-key details and the successful witness-generation
screen offer `Export enrollment`. The sentry returns the existing public
witness envelope over the admin protocol, while the operator-side `apadmin`
process either writes it to the chosen local path or displays full JSON directly
in the terminal. `SHOW JSON` releases the terminal through Bubble Tea's execution lifecycle and writes
the complete original JSON for manual selection using terminal soft wrapping
and scrollback. Enter restores the export screen. No clipboard commands or OSC 52
sequences are emitted. File export or batch stdout also preserves the original
JSON bytes. Files are written on the machine running `apadmin`. Ordinary account keys do not expose
this action. The output path is directly editable and does not rename the
witness credential or add an authority claim to the public envelope. Imports
recognize the `.aplane-sentry.json` suffix and may prefill an editable alias
from its sanitized filename stem.

When the sentry advertises a portable endpoint, the export review offers an
explicit, default-on `Include advertised endpoint` choice. The operator-side
TUI composes the daemon-verified witness envelope and the validated endpoint
into `aplane.sentry-enrollment.v1`; opting out or lacking an advertised
endpoint retains the compatible witness-only file. Composition never adds a
token, host trust, client alias, or private material.

The import form also accepts a combined `aplane.sentry-enrollment.v1` bundle.
The complete artifact is validated, and only the public witness reference is
imported into the signer. Bundled endpoint metadata is informational; configure
transaction-client routing separately in apshell. apadmin never reads or writes
client endpoint registries, tokens, host trust, aliases, or caches.

The manager exposes `p: Paste JSON` alongside `i: Import file`. The paste field
captures a complete bracketed terminal paste without interpreting its contents
as navigation keys, replacing the previous document. Input over 64 KiB clears
the buffer and reports an error. Backspace/Delete clears the field. Both public
witness and combined enrollment documents use the existing artifact parser and
import review. Returning from review
preserves the paste for correction; canceling or completing import clears it.

Endpoint creation, token enrollment, and live route discovery belong to apshell.
The reference details screen shows signer-owned metadata only.

TEAL exports save to the working directory of the apadmin process. Address-list
generation inputs require full account addresses; client aliases and sets are
resolved only by apshell.

## Admin Panel

The admin panel is accessible from the key list via `a` and exposes live
signer settings and status:

- `user_auto_approve`
- `lock_on_disconnect`
- `passphrase_timeout`
- Signer-managed backup creation and managed backup restore
- SSH enabled state, port, fingerprint, and connected-client count
- Signer port, TEAL compile network, and theme
- The shared guided policy editor, opened with `p` from the key list or
  through the secondary `Policy` row in Settings

`apadmin` embeds `internal/signerapp/policytui` for online policy editing. The TUI
requests the active signer-owned snapshot over the admin protocol, selects
`policy.yaml` on signer nodes or sentry-domain `policy.yaml` on sentry nodes, and
applies edits as whole-document replacements guarded by
`expected_current_sha256`. The signer validates draft YAML in the selected
policy domain, writes the YAML plus a fresh sidecar, and returns a canonical
snapshot after a successful apply. `apadmin policy rescue` uses the same editor
offline for store-locked edits, scriptable save/check/export, and signing-to-sentry
conversion.

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
pending activity and idle state.

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
| `internal/signerapp/signertui/policy_editor.go` | Shared policy editor embedding and admin-protocol store adapter |
| `internal/signerapp/signertui/update_*.go`, `view_*.go` | Per-view handlers and renderers |

## Related Documentation

- [ARCH_REPL.md](ARCH_REPL.md) — `apshell` REPL (separate UI surface)
- [ARCH_MCP.md](ARCH_MCP.md) — `apshell` MCP server (separate UI surface)
- [ARCH_SECURITY.md](ARCH_SECURITY.md) — Admin protocol authentication
- [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md) — Signer authorization model
