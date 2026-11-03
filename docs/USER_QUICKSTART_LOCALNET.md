# LocalNet Quickstart

<sub><a href="USER_QUICKSTART.md">QuickStart using TestNet</a></sub>

This is the LocalNet version of the quickstart. It performs a local APlane
install at `~/aplane`, configures APlane for a running AlgoKit LocalNet, funds a
new Falcon address from the LocalNet KMD wallet, and submits a local transaction.

## 1. Install

```bash
curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | bash
```

The bootstrap defaults to a local install; pass `--systemd` only for a managed
service install.

The installer will:
- Download the latest release for your platform
- Verify the release checksum, and verify the minisign signature when the
  release provides one and `minisign` is installed on your machine
- Install to `~/aplane` (you'll be asked to confirm)
- Prompt you to set a keystore passphrase
- Write MCP configs to `~/aplane/apclient/.mcp.json` and
  `~/aplane/apclient/.codex/config.toml`
- Optionally add environment setup to your shell rc for standalone commands

## 2. Start AlgoKit LocalNet

AlgoKit LocalNet must already be running before APlane can configure itself for
it. From any terminal:

```bash
algokit localnet status
```

It should report `RUNNING`. If not, start it:

```bash
algokit localnet start
```

## 3. Configure APlane for LocalNet

Source `apenv.sh` to set the APlane environment variables, then run
`aplocalnet` to configure APlane for the running LocalNet:

```bash
source ~/aplane/apenv.sh
aplocalnet
```

By default, `aplocalnet` checks algod at `http://localhost:4001` and assumes KMD
at `http://localhost:4002`. If your LocalNet uses alternate ports, run
`aplocalnet` with both endpoint overrides:

```bash
aplocalnet --algod-url http://localhost:<algod-port> --kmd-url http://localhost:<kmd-port>
```

Select the `apply` action in the TUI to apply the configuration. This:

- Points apshell at the LocalNet algod and sets `localnet` as the default network
- Updates `apsigner` `config.yaml` with the LocalNet genesis hash
- Enables the bundled `algokit-localnet` plugin in `$APCLIENT_DATA/plugins.yaml`
- Persists `--kmd-url` into `~/aplane/apenv.sh` when a KMD override is provided

## 4. Launch the console

Because `apenv.sh` is already sourced in this terminal, you can run:

```bash
apconsole
```

Use `F1`, `F2`, and `F3` to focus the admin, shell, and daemon panes.
The split layout needs at least 133 columns by 39 rows when the console
starts the daemon; smaller terminals use a focused pane. Allow at least
82 columns by 30 rows for the admin UI. `F4` toggles the focused pane view;
`?` opens help. See the [console layout](USER_QUICKSTART.md#2-launch-the-console).

## 5. Unlock the signer

By default, apconsole starts focused on the signer admin pane. Enter the
keystore passphrase you set during installation. This unlocks the signer, giving
it access to your encrypted keystore.

## 6. Generate a signing key

In the signer pane, press `g` and select `falcon1024` to generate a native
Falcon-1024 post-quantum key.

## 7. Enroll the client

The first time a client connects, the signer must enroll the client's SSH key,
a human-approved step. In the shell pane, run:

```
enroll
```

The command returns at once with the request waiting. You will see an approval
prompt in the signer admin pane (or, if it was not open, the request is shown
when you log in and on the Enrolled Clients screen). Navigate to it with `F1`
or `Shift`+left arrow. Compare the complete SSH-key fingerprint with the
one shown by `enroll`, then accept the matching request.

Once approved, connect from the shell pane:

```
connect
```

## 8. Find your Falcon address

In apshell, list your signer-managed addresses:

```
keys
```

Copy the address for the new `falcon1024` key you generated in step 6.

The prompt should show `localnet`, as configured by `aplocalnet`. If needed,
select it explicitly (`connect` connects to the signer, not a network):

```
network localnet
```

## 9. Fund your Falcon address

`localnet fund` depends on the Algorand Key Management Daemon (KMD), which by
default runs on port 4002. It signs the funding transaction from a pre-funded
LocalNet wallet account; it does not use or import APlane signer keys.

In the shell pane:

```
localnet fund <your-falcon-address>
```

Verify the balance:

```
balance <your-falcon-address> algo
```

## 10. Send a one-ALGO transaction to yourself

Submit a self-send from the Falcon address back to the same address:

```
send 1 algo from <your-falcon-address> to <your-falcon-address>
```

The shipped policy's self-transfer route permits this payment, but a route
match does not approve it. With `auto_approve_self_noop_transfer: false` and
`user_auto_approve: false`, this one-ALGO self-send requires operator approval.
Press `F1`, inspect the request, and approve it only if it matches. Use `F4`
to zoom the admin pane if needed, then `F2` to return to the shell.
The transferred ALGO stays in the account; the transaction fee is deducted.

apshell prints the submitted transaction ID. To inspect the transaction in
Lora, go to https://lora.algokit.io, select `LocalNet`, and search for the
transaction ID. If your LocalNet algod is not using the default
`http://localhost:4001`, open Lora's settings and set the correct algod URL.

This demonstrates the full workflow: the shell builds and submits a LocalNet
transaction, and the signer checks policy and signs it with your new key.

## Further Exploration

On signer nodes, APlane exposes only the native `ed25519` and `falcon1024` key
types. To try LogicSig key types, such as `aplane.falcon1024.v1` or the bundled
templates, open the signer admin pane, press `s` for settings, then press `k`
for key types. The KeyType Library lets you enable compiled providers and
templates for the product store.

For more detail, see [USER_KEYTYPES.md](USER_KEYTYPES.md).

## Optional: MCP for Agents

The installer writes MCP config files at:

```text
~/aplane/apclient/.mcp.json
~/aplane/apclient/.codex/config.toml
```

The `.codex/config.toml` file is project-scoped Codex configuration. Start
Codex from `~/aplane/apclient` and trust that directory to load the APlane MCP
server without touching `~/.codex`. Other MCP-capable agents can use
`.mcp.json`; they will use an instance of the shell in "MCP mode" as the MCP
server.

If you connect an agent through that MCP server, first ask it to call
`mcp_manual` for the operating model, then `mcp_reference` for the live apshell
command surface.

## What's next

- [USER_INSTALL.md](USER_INSTALL.md) — Full install guide (client-only, production, multi-instance)
- [USER_CONFIG.md](USER_CONFIG.md) — Configuration reference
- [USER_JSAPI.md](USER_JSAPI.md) — JavaScript API reference for automation
- [USER_STORE_MGMT.md](USER_STORE_MGMT.md) — Key backup and restore
