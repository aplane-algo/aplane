# algokit-localnet

`algokit-localnet` is APlane's bundled LocalNet operations plugin. It provides
the production command surface for working with an AlgoKit LocalNet from
`apshell`.

The plugin is written in Go and talks directly to LocalNet HTTP APIs:

- algod, default `http://localhost:4001`
- KMD, default `http://localhost:4002`

It does not shell out to `algokit`, `ak`, or `goal`. That is deliberate: APlane
plugins run in a filesystem sandbox, so a user-local AlgoKit executable and its
Docker-related files are not reliably visible to the plugin process. Direct HTTP
access to localhost fits the plugin sandbox and keeps the runtime dependency to
the plugin binary plus a running LocalNet.

## Build

From this directory:

```bash
make build
```

From the repository root:

```bash
make bundled-plugins
```

This produces the standalone plugin executable:

```text
plugins/algokit-localnet/algokit-localnet
```

The plugin is built as a bundled plugin. Release installers package it under
`plugins.available/algokit-localnet`, so it is present on disk but not loaded by
`apshell` until `algokit-localnet` is listed in `$APCLIENT_DATA/plugins.yaml`.

## Configuration

For a standard AlgoKit LocalNet, no plugin-specific configuration is required.
The defaults match AlgoKit's local sandbox:

| Variable | Default |
|----------|---------|
| `APLANE_LOCALNET_ALGOD_URL` | `http://localhost:4001` |
| `APLANE_LOCALNET_KMD_URL` | `http://localhost:4002` |
| `APLANE_LOCALNET_TOKEN` | `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` |
| `APLANE_LOCALNET_WALLET` | `unencrypted-default-wallet` |
| `APLANE_LOCALNET_WALLET_PASSWORD` | empty |

The plugin also receives the current apshell algod URL/token during
initialization. The explicit `APLANE_LOCALNET_*` environment variables take
precedence when set.

## Commands

```text
localnet status
localnet genesis
localnet accounts
localnet fund <address|alias> [amount] [algo|microalgo] [from <address|alias>]
```

Examples:

```text
localnet status
localnet accounts
localnet fund alice
localnet fund alice 100 algo
localnet fund alice 2500000 microalgo from LPB4KVPDCWWU6RHQARBAVVFCZRQKV7BXTKDGRZAPRS7STX6DQMPQKMWALQ
```

When `from` is omitted, the plugin picks the KMD wallet account with the largest
spendable balance that can cover the transfer plus fee.

## Enabling From an Install

Release installers place this plugin under:

```text
$APCLIENT_DATA/plugins.available/algokit-localnet
```

Enable it by adding the directory name to `$APCLIENT_DATA/plugins.yaml`:

```yaml
enabled_plugins:
  - algokit-localnet
```

Installer-written client configs allow only `mainnet` and `testnet` by default.
To run this plugin with `network localnet`, also add `localnet` to
`$APCLIENT_DATA/config.yaml`:

```yaml
networks_allowed:
  - mainnet
  - testnet
  - localnet
```

## Security Scope

This plugin signs funding transactions through LocalNet KMD. It does not access
APlane signer keys or import LocalNet keys into APlane. It is scoped to the
`localnet` execution context and should only be pointed at disposable LocalNet
networks.
