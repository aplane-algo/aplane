# Quickstart

<sub><a href="USER_QUICKSTART_LOCALNET.md">QuickStart using LocalNet</a></sub>

This performs a local APlane install, including both client and signer, at `~/aplane`.

## 1. Install

```bash
curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | bash
```
The bootstrap defaults to a local install; pass `--systemd` only for a managed service install.

The installer will:
- Download the latest release for your platform
- Verify the release checksum, and verify the minisign signature when the
  release provides one and `minisign` is installed on your machine
- Install to `~/aplane` (you'll be asked to confirm)
- Prompt you to set a keystore passphrase
- Write MCP configs to `~/aplane/apclient/.mcp.json` and
  `~/aplane/apclient/.codex/config.toml`
- Optionally add environment setup to your shell rc for standalone commands

The two key environment variables that APlane uses are APSIGNER_DATA and APCLIENT_DATA. The script that sets them for your installation is at ~/aplane/apenv.sh.

## 2. Launch the console

`apconsole` brings together the signer admin UI, transaction shell, and daemon
logs. These interfaces are also available through standalone commands:

- **`apsigner`** — the signing daemon (encrypted keys, approval + audit)
- **`apadmin`** — the apsigner management TUI where you unlock the keystore,
  manage keys and key types, approve signing requests, etc.
- **`apshell`** — a transaction shell where you build and submit
  transactions

`apshell` can run on a different machine from the signer. `apadmin` uses local
IPC on the signer host; remote operators log in to that host. With APlane's
`apconsole`, we will use the admin and shell interfaces together on the local
machine, with `apsigner` running as a separate daemon.

```bash
~/aplane/start.sh
```
This command sets the required environment variables and launches `apconsole`.
In split view, the signer admin pane sits above the daemon logs on the left,
and the shell occupies the full height on the right. This layout needs a
terminal of at least 133 columns by 39 rows when the console starts the daemon.
Smaller terminals show one pane at a time.

The admin UI needs an 80×24 content area. If it shows **Window too small**,
enlarge the terminal or use `F4` to zoom the admin pane. Console borders and
headers take additional space: use at least an 82×30 terminal for a focused
admin pane.

Use `F1`, `F2`, and `F3` to focus the signer, shell, and daemon panes. You can
also use `Shift`+arrow to navigate between panes. `F4` toggles a focused pane
view. Press `?` for the built-in help overlay.

By default, the shell starts up using testnet. Use `network mainnet` to switch
to mainnet if desired.

## 3. Unlock the signer

By default, `apconsole` starts focused on the signer admin pane. If it is not,
press `F1` to focus it. Enter the keystore passphrase you set during
installation. This unlocks the signer, giving it access to your encrypted keystore
(which is empty).

## 4. Generate a signing key

In the signer pane, press `g` and select `falcon1024` to generate a native
Falcon-1024 post-quantum key.

In APlane terminology, a "key" is a file managed by the signer that contains all information
(private key material, LogicSig and parameters, etc.) necessary to sign for an account.

## 5. Enroll the client

The first time you connect with a client, the signer must enroll the client's
SSH key. This is a human-approved process done via the signer admin.

In the shell pane, run:

```
enroll
```
The command returns at once with the request waiting. You will see an
approval prompt in the signer admin pane (or, if it was not open, the request
is shown when you log in and on the Enrolled Clients screen). Navigate to it
with `F1`, compare the client SSH key fingerprint with the one shown in the
shell, and accept it. (`Esc` leaves the request waiting for later; it does
not reject it.)

Approval enrolls the client's SSH key at the signer; the key is the client's
only credential.

## 6. Confirm or reconnect

After the key is enrolled, connect from the shell pane:

```
connect
```
The shell defaults to Algorand testnet; you can see this in the shell prompt.
If you want to use mainnet, use the "network" command to switch. For the rest
of this quickstart, we will stay on testnet.

## 7. Find your Falcon address

In apshell, list your signer-managed addresses:

```
keys
```

Copy the address for the new `falcon1024` key you generated in step 4.

## 8. Fund it on testnet

Open the AlgoKit testnet funding page in your browser:

```text
https://lora.algokit.io/testnet/fund
```

Fund the Falcon address you copied in the previous step, then wait for the faucet transaction to confirm.

Back in the shell pane, verify the balance:

```
balance <your-falcon-address> algo
```
Because you did the "keys" command in step 7, the shell knows all of your available account addresses and
lets you use tab-completion.

## 9. Send a one-ALGO transaction to yourself

Submit a self-send from the Falcon address back to the same address.

```
send 1 algo from <your-falcon-address> to <your-falcon-address>
```
The shipped signer policy includes a `self-transfer` route that permits this
payment to proceed through policy evaluation. A route match does not approve
it. With the shipped `auto_approve_self_noop_transfer: false` and
`user_auto_approve: false`, this one-ALGO self-send requires operator approval.

Press `F1`, inspect the transaction, and approve only if it matches your
request. Use `F4` to zoom the admin pane if needed, then `F2` to return to
the shell.

The shell reports the transaction result. Copy the transaction ID into
[Lora on testnet](https://lora.algokit.io/testnet) to inspect the transaction.
It uses a native Falcon signature, with no LogicSig or resource "dummy"
transactions. A self-send leaves the transferred ALGO in the same account;
the transaction fee is still deducted.

This demonstrates the full workflow: the shell builds and submits the
transaction, and the signer checks policy and signs it.

Under the shipped policy, a transfer to another address falls through to the
operator default and requires approval unless `user_auto_approve` is on. See
[USER_POLICY.md](USER_POLICY.md) for routes and per-key policies;
`apadmin policy template --key <address>` writes a starting document for one
key with the fields explained.

## Further Exploration

On a signer node, the default key types are native `ed25519` and
`falcon1024`. To try LogicSig key types, such as `aplane.falcon1024.v1` or the bundled
templates, open the signer admin pane, press `s` for settings, then press `k`
for key types. The KeyType Library lets you enable compiled providers and
templates for the product store.

To try a cosigned account, first set up a separate cosigner node and generate its
`aplane.witness-falcon1024.v1` key. Choose **Export Cosigner Key**; the file
holds the public key only, and the result screen shows the address to give
clients. In the primary signer's KeyType Library, enable the plain host
`aplane.falcon1024.v1`. Start **Generate account**, select that key type, open
**Require a cosigner (Falcon-1024)**, and choose **Use key file...** (or **Paste
public JSON...**). Compare the full Witness Key ID before importing, choose
whether to allow rekeys or add rekey-to addresses, then review and generate
the account. The
Corridor preset of the default-enabled `aplane.falcon1024-b.v1` is a cosigned
account too, with on-chain limits.

In apshell, run `endpoints add <cosigner-url>`, for example
`endpoints add ssh://cosigner.example:1127`. Accept the suggested connection
name, then compare the full client SSH key fingerprint displayed in apshell
and the **Client Access Request** in cosigner-side apadmin before approving.
The command configures the client route and requests access; if enrollment is
pending, approve it and rerun the command. It then confirms the node is a
cosigner and reports the keys it advertises. With apshell connected to the primary signer, run
`cosigner status` to inspect the cosigned account's current cosigner route before
funding or rekeying. Route availability does not establish transaction-policy
or on-chain validity.

A new cosigner's default policy rejects every signing request. Before using
the cosigned account, configure an explicit cosigner policy for the intended
transactions, including a fee limit. See [USER_POLICY.md](USER_POLICY.md) for
cosigner policies and [USER_KEYTYPES.md](USER_KEYTYPES.md) for account setup.

## Optional: MCP for Agents

The installer writes MCP config files at:

```text
~/aplane/apclient/.mcp.json
~/aplane/apclient/.codex/config.toml
```
The `.codex/config.toml` file is project-scoped Codex configuration. Start
Codex from `~/aplane/apclient` and trust that directory to load the APlane MCP
server without touching `~/.codex`.

Start your MCP-capable agent in this directory. It will use an instance of the
shell in "MCP mode" as the MCP server.

If you connect an agent through that MCP server, first ask it to call
`mcp_manual` for the operating model, then `mcp_reference` for the live apshell
command surface. MCP essentially gives the
agent an `execute` command that acts as a general command-line interface, much as humans execute via the
command line.

## What's next

- [USER_INSTALL.md](USER_INSTALL.md) — Full install guide (client-only, production, multi-instance)
- [USER_CONFIG.md](USER_CONFIG.md) — Configuration reference
- [USER_JSAPI.md](USER_JSAPI.md) — JavaScript API reference for automation
- [USER_STORE_MGMT.md](USER_STORE_MGMT.md) — Key backup and restore
