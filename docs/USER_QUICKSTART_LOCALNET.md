# LocalNet Quickstart

<sub><a href="USER_QUICKSTART.md">QuickStart using TestNet</a></sub>

This is the LocalNet version of the quickstart. It performs a local APlane
install at `~/aplane`, configures APlane for a running AlgoKit LocalNet, funds a
new Falcon address from the LocalNet KMD wallet, and submits a local transaction.

## 1. Install

```bash
curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | bash
```

If you are on Linux, you will be asked if you want a local or systemd install.
Select "local".

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

This launches `apconsole`, which shows the signer admin pane, shell pane, and
signer daemon pane together. Use `F1`, `F2`, and `F3` to focus those panes.
`F4` toggles a focused pane view. Press `?` for the built-in help overlay.

## 5. Unlock the signer

By default, apconsole starts focused on the signer admin pane. Enter the
keystore passphrase you set during installation. This unlocks the signer, giving
it access to your encrypted keystore.

## 6. Generate a signing key

In the signer pane, press `g` and select `aplane.falcon1024.v1` to generate a
Falcon-1024 post-quantum key.

## 7. Get an access token

The first time a client connects, it needs a human-approved access token from
the signer daemon. In the shell pane, run:

```
request-token
```

You will see an approval prompt in the signer admin pane. Navigate to it with
`F1` or `Shift`+left arrow and accept it.

If the shell does not auto-connect after approval, run:

```
connect
```

## 8. Find your Falcon address

In apshell, list your signer-managed addresses:

```
keys
```

Copy the address for the new `aplane.falcon1024.v1` key you generated in step 6.

The shell should connect to LocalNet automatically; the prompt will reflect the
new network. If needed, run:

```
connect
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

By default, the signer requires human approval on all transactions. Approve the
request in the signer admin pane. If the approval window is small, use `F4` to
zoom in, then `F4` again to zoom back out.

apshell prints the submitted transaction ID. To inspect the transaction in
Lora, go to https://lora.algokit.io, select `LocalNet`, and search for the
transaction ID. If your LocalNet algod is not using the default
`http://localhost:4001`, open Lora's settings and set the correct algod URL.

This proves the signer can build, sign, and submit a real LocalNet transaction
with your new key.

## Further Exploration

By default, APlane exposes the `ed25519`, `aplane.falcon1024.v1`, and
`aplane.falcon1024-allowlist.v1` key types. To try additional LogicSig templates from
the bundled library, open the signer admin pane, press `s` for settings, then
press `k` for key types. The KeyType Library lets you enable additional
compiled providers and templates for the current identity.

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

If you connect an agent through that MCP server, first ask it to read the
`mcp_reference` MCP command. That returns the apshell command reference so the
agent can inspect the available command surface before acting.

## What's next

- [USER_INSTALL.md](USER_INSTALL.md) — Full install guide (client-only, production, multi-instance)
- [USER_CONFIG.md](USER_CONFIG.md) — Configuration reference
- [USER_JSAPI.md](USER_JSAPI.md) — JavaScript API reference for automation
- [USER_STORE_MGMT.md](USER_STORE_MGMT.md) — Key backup and restore
