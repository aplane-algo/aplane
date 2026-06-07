# Signer Admin TUI Architecture (signertui)

`apadmin` is the signer admin TUI. It is built on
[Bubble Tea](https://github.com/charmbracelet/bubbletea) and communicates with
`apsigner` over the admin protocol — local mode uses a Unix socket; remote
mode opens the SSH `aplane-admin` subsystem. The TUI is a separate
admin-protocol client and does **not** route through `internal/engine` or the
`apshell` REPL/MCP pipeline (see [ARCH_REPL.md](ARCH_REPL.md) and
[ARCH_MCP.md](ARCH_MCP.md) for those).

The implementation lives in `internal/signertui/`.

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

## View States

`ViewState` (defined in `internal/signertui/model.go`) is an enum that
identifies the current screen. The enum has families for:

- Authentication and unlock (`ViewAuth`, `ViewUnlock`)
- Key list and details (`ViewKeyList`, `ViewKeyDetails`, `ViewTEALFullDisplay`)
- Approval popups (`ViewSigningPopup`, `ViewTokenProvisioningPopup`)
- Generate / import flows (form, params, loading, display)
- Managed backup create flow (`ViewBackupConfirm`, `ViewBackingUp`, `ViewBackupDisplay`)
- Managed backup restore flow (`ViewRestoreList` through `ViewRestoreDisplay`)
- Destructive confirmations (`ViewDeleteConfirm`, `ViewRevokeTokenConfirm`, `ViewDisplaceConfirm`)
- Settings panel (`ViewAdminPanel`) and shared policy editor workflow (`ViewPolicyEditor`)
- KeyType Library (`ViewTemplateLibrary`, install confirm/loading, `ViewLibraryTemplateDetails`)
- `ViewError`

See `internal/signertui/model.go` for the authoritative enum values and the
one-line comments that document each screen's purpose. Legacy policy view
states may still appear in the enum for compatibility handlers, but they are
not active apadmin entry points.

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

`apadmin` embeds `internal/policytui` for online policy editing. The TUI
requests the active signer-owned snapshot over the admin protocol, selects
`policy.yaml` on signer nodes or `attestation.yaml` on attestor nodes, and
applies edits as whole-document replacements guarded by
`expected_current_sha256`. The signer validates draft YAML in the selected
policy domain, writes the YAML plus a fresh sidecar, and returns a canonical
snapshot after a successful apply. `appolicy` uses the same editor offline for
store-locked edits, scriptable save/check/export, and signing-to-attestation
conversion.

## Local Activity And Idle Locking

`apadmin` treats only Bubble Tea `tea.KeyMsg` input as local user activity.
Window resizes, timers, IPC responses, server notifications, and background
polling do not count. The TUI does not report local activity to the signer;
keyboard activity only re-arms apadmin's own local idle-disconnect timer.

The signer remains authoritative for lock state and master-key zeroing. After
`apadmin` learns the effective passphrase timeout from admin settings, it
arms a local idle timer from the latest local activity baseline. If the UI is
still idle when that timer fires, it disconnects the admin session. Any signer
lock that follows that disconnect is decided by the signer-owned
`lock_on_disconnect` setting. Manual lock actions are separate explicit
`lock_identity` requests. Disconnect, reconnect, reauthentication, and server
lock notifications clear pending activity and idle state.

## Error Handling

Errors surface in `ViewError` or inline in the active screen's status area,
allowing retry. The TUI never panics on IPC errors; it transitions back to a
recoverable view.

## Key Files

| File | Purpose |
|------|---------|
| `internal/signertui/model.go` | `Model`, `ViewState`, initialization |
| `internal/signertui/update.go` | Top-level Update dispatch |
| `internal/signertui/view.go` | Top-level View dispatch |
| `internal/signertui/activity.go` | Local keystroke activity reporting and idle lock timers |
| `internal/signertui/ipc_client.go` | IPC connection to the signer |
| `internal/signertui/connector.go` | SSH `aplane-admin` connector for remote mode |
| `internal/signertui/policy_editor.go` | Shared policy editor embedding and admin-protocol store adapter |
| `internal/signertui/update_policyviewer.go`, `view_policyviewer.go` | Legacy policy snapshot viewer handlers retained for compatibility paths |
| `internal/signertui/update_*.go`, `view_*.go` | Per-view handlers and renderers |

## Related Documentation

- [ARCH_REPL.md](ARCH_REPL.md) — `apshell` REPL (separate UI surface)
- [ARCH_MCP.md](ARCH_MCP.md) — `apshell` MCP server (separate UI surface)
- [ARCH_SECURITY.md](ARCH_SECURITY.md) — Admin protocol authentication
- [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md) — Signer authorization model
