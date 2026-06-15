# Quickstart

<sub><a href="USER_QUICKSTART_LOCALNET.md">QuickStart using LocalNet</a></sub>

This performs a local APlane install, including both client and signer, at `~/aplane`.

## 1. Install

```bash
curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | bash
```
If you are on Linux, you will be asked if you want a local or systemd install. Select "local".

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

There is a standalone unified console, apconsole, that gives you a unified view of the APlane components. APlane uses three independent components that are separate processes:

- **`apsigner`** — the signing daemon (encrypted keys, approval + audit)
- **`apadmin`** — the apsigner management TUI where you unlock the keystore,
  manage keys and key types, approve signing requests, etc.
- **`apshell`** — a transaction shell where you build and submit
  transactions

All three of these components can run on completely different machines while working together, but with APlane's `apconsole` we will run all three together on the local machine. It is a convenience wrapper around these three
that gives you a unified view.

```bash
~/aplane/start.sh
```
This shell command sets the required environment variables and launches apconsole. You will see this:

![Quickstart screenshot 1](https://raw.githubusercontent.com/aplane-algo/aplane.io/main/img/qs1.png)

At the top-left is the signer admin panel; the shell is at the top-right. The signer daemon itself runs at the bottom.

Use `F1`, `F2`, and `F3` to focus the signer, shell, and daemon panes. You can
also use `Shift`+arrow to navigate between panes. `F4` toggles a focused pane
view. Press `?` for the built-in help overlay.

By default, the shell starts up using testnet. Use `network mainnet` to switch
to mainnet if desired.

## 3. Unlock the signer

By default, apconsole starts focused on the top-left signer admin pane. If for some reason it isn't, 
hit F1 or use <shift>-arrow to navigate to it. Enter the keystore passphrase you set during 
installation. This unlocks the signer, giving it access to your encrypted keystore
(which is empty).

## 4. Generate a signing key

In the signer pane, press `g` and select `aplane.falcon1024.v1` to generate a
Falcon-1024 post-quantum key.

In APlane terminology, a "key" is a file managed by the signer that contains all information 
(private key material, LogicSig and parameters, etc.) necessary to sign for an account.

## 5. Get an access token

The first time you connect with a client, it needs to obtain an access token
from the signer daemon. This is a human-approved process done via the signer admin.

In the shell pane, run:

```
request-token
```
You will see an approval prompt in the signer admin pane. Navigate to it with F1 or <Shift>-LeftArrow and accept it. 

![Quickstart screenshot 2](https://raw.githubusercontent.com/aplane-algo/aplane.io/main/img/qs2.png)

Approval results in the shell being given an access token by the signer.

## 6. Confirm or reconnect

After the token is delivered, the shell will auto-connect to the signer. If for some reason it does not, retry from apshell:

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

Copy the address for the new `aplane.falcon1024.v1` key you generated in step 4.

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
By default, the signer requires human approval on all transactions. You will see an approval window pop up
in the signer admin panel.

![Quickstart screenshot 3](https://raw.githubusercontent.com/aplane-algo/aplane.io/main/img/qs3.png)

Navigate to the admin panel. Since the approval window is small, hit F4 to zoom in.

![Quickstart screenshot 4](https://raw.githubusercontent.com/aplane-algo/aplane.io/main/img/qs4.png)
  
Approve and zoom back out with F4 again. In the shell, you see the transaction results. If you copy the
transaction ID and paste it into Lora at https://lora.algokit.io/testnet, you
will see the transaction. If you click on "Group" you can see the entire Falcon PQ group, including
the "dummy" transactions that Algorand Falcon transactions require.

![Quickstart screenshot 5](https://raw.githubusercontent.com/aplane-algo/aplane.io/main/img/qs5.png)

This proves the signer can build, sign, and submit a real testnet transaction with your new key.

## Further Exploration

By default, APlane exposes only the `ed25519` and Falcon-1024
(`aplane.falcon1024.v1`) key types. To try additional LogicSig templates from
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
server without touching `~/.codex`.

Start your MCP-capable agent in this directory. It will use an instance of the
shell in "MCP mode" as the MCP server.

If you connect an agent through that MCP server, first ask it to read the
`mcp_reference` MCP command. That returns the apshell command reference so the
agent can inspect the available command surface before acting. MCP essentially gives the
agent an `execute` command that acts as a general command-line interface, much as humans execute via the 
command line.

## What's next

- [USER_INSTALL.md](USER_INSTALL.md) — Full install guide (client-only, production, multi-instance)
- [USER_CONFIG.md](USER_CONFIG.md) — Configuration reference
- [USER_JSAPI.md](USER_JSAPI.md) — JavaScript API reference for automation
- [USER_STORE_MGMT.md](USER_STORE_MGMT.md) — Key backup and restore
