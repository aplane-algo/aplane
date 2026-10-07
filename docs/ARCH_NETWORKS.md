# Network Context Architecture

This document explains how APlane names networks, selects node endpoints,
partitions client state, and maps signer policy to transaction chain identity.
Compatibility-bearing field names, wire shapes, and validation rules remain in
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

## Core Model

APlane uses a **network context token** as a local namespace. The token is a
human-chosen string such as:

- `mainnet`
- `testnet`
- `betanet`
- `voi_mainnet`
- `localnet`
- `private-dev`

The token is not a cryptographic chain identity. It is used to select local
configuration and state:

- client default network selection,
- client network allow-list checks,
- client algod endpoint lookup,
- client cache partitioning,
- signer TEAL compilation endpoint lookup,
- signer ASA transfer guard buckets,
- plugin execution context,
- SDK config behavior.

This network context token is a configuration key, not a credential: client
authentication is the enrolled SSH key. SSH authentication
completes before transaction network context is evaluated and does not bind a
connection to one network token.

Cryptographic chain identity comes from transaction `GenesisHash`. `GenesisID`
is display and diagnostic data only in signer policy and planning paths.

## Token Syntax

Network context tokens are intentionally filesystem-safe because they are used
in cache filenames and config map keys.

Valid tokens:

- are 1-64 characters,
- start with a lowercase ASCII letter or digit,
- contain only lowercase ASCII letters, digits, `_`, or `-`.

Invalid examples:

- `VoiMainnet` - uppercase characters,
- `_voi` - starts with `_`,
- `voi/mainnet` - contains `/`,
- empty string.

The source of truth is `internal/config/networkid.go`.

## Built-In Algorand Tokens

The tokens `mainnet`, `testnet`, and `betanet` are reserved for the canonical
Algorand networks. Their genesis-hash mappings are compiled into the source:

| Token | Genesis hash |
|-------|--------------|
| `mainnet` | `wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=` |
| `testnet` | `SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=` |
| `betanet` | `mFgazF+2uRS1tMiL9dsj01hJGySEmPN28B/TjjvpVW0=` |

Custom config cannot remap those built-in hashes and cannot assign custom
hashes to the reserved token names.

The source of truth is `internal/config/genesishash.go`.

## Client Behavior

`apshell` loads client config from `config.yaml` in `APCLIENT_DATA` or the
directory passed with `-d`.

Relevant fields:

```yaml
network: voi_mainnet
networks_allowed:
  - voi_mainnet
networks:
  voi_mainnet:
    algod:
      server: http://localhost:4001
      token: your-token
```

`network` is the startup context token. `networks_allowed` is an optional
allow-list; an empty list means every syntactically valid token is allowed.
`networks` is keyed by network context token. `networks.<token>.algod` selects
the algod endpoint. Top-level `algod` is not part of the current client config
schema.

The `network <token>` command switches the active client context after syntax
and allow-list validation. The token then drives endpoint lookup and local
client state selection. Cache paths are token-scoped, so `voi_mainnet` has a
different client cache namespace than `testnet`.

## Signer Behavior

`apsigner` process config also uses network context tokens:

```yaml
teal_compile_network: voi_mainnet
networks:
  voi_mainnet:
    algod:
      server: http://localhost:4001
      token: your-token
    genesis_hash: "base64-or-hex-32-byte-genesis-hash"
```

`teal_compile_network` selects the algod endpoint used for TEAL compilation.
`networks` is keyed by token. `networks.<token>.genesis_hash` maps a custom
transaction genesis hash to that token for signer policy and signing-plan
validation. Top-level `algod` and `genesis_hash_networks` maps are not part of
the current config schema; use `networks.<token>.algod` and
`networks.<token>.genesis_hash`.

Each custom network token has at most one configured genesis hash. If two
private or local networks have different genesis hashes, they must use distinct
network tokens or the token's config must be updated when switching instances.

At startup, the signer builds an effective resolver by merging built-in
Algorand mappings with configured custom mappings. Config load fails closed on:

- invalid token syntax,
- invalid genesis hash encoding or length,
- attempts to use reserved tokens for custom hashes,
- attempts to remap built-in genesis hashes,
- duplicate hashes mapped to different tokens,
- duplicate custom tokens mapped to different hashes.

Managed backups project only the validated custom genesis-hash-to-network
bindings into the archive's sealed manifest. Built-in mappings are not
duplicated, and algod URLs, tokens, endpoints, and the rest of the network
connection configuration are excluded. Recovery treats this projection as
operator context only; it never imports the mappings or changes the
destination resolver.

## Transaction Planning

The signer planner validates every transaction against the genesis-hash
resolver before planning or signing.

Rules:

- unknown transaction genesis hashes are rejected,
- all transactions in a group must have the same `GenesisHash`,
- `GenesisID` differences do not reject an otherwise same-hash group,
- `GenesisID` may still appear in descriptions and diagnostics.

This prevents a display string from becoming the trust anchor for policy.

This APlane release implements one compiled authorization contract: consensus
v42. Client transaction construction validates algod's reported consensus
identifier before using suggested parameters. First-party planning and executable
workflows refresh that validation before asking apsigner to plan, requesting
signatures, or submitting/simulating pre-signed bytes, so prebuilt and
plugin-produced groups cannot bypass it. A successful SuggestedParams check is
reused for at most 30 seconds by the same algod client, avoiding a redundant
round trip inside one interactive workflow; changing the active network or
algod client invalidates it. Other identifiers fail closed. The signer itself
remains network-independent: during `/plan` or `/sign` it validates the
transaction genesis hash for policy context, then applies the compiled v42
LogicSig and native-PQ rules.

## ASA Transfer Guards

Signer safety policy stores transfer guard thresholds in `limits` as raw units:

```json
"limits": {
  "voi_mainnet": {
    "asa:123456": { "review_above": "1000000", "reject_above": "5000000" }
  }
}
```

The first map key is the network context token. The second key is the asset,
`algo` or `asa:<id>`. Each value is a raw on-chain unit threshold written as a
decimal string. `review_above` requires operator review above the configured
value; `reject_above` rejects above the configured value.

At enforcement time:

```text
txn.GenesisHash -> resolver -> network token -> limits[token][asset]
```

Unknown genesis hashes fail closed before a transaction can use the wrong policy
bucket.

## Admin Protocol

Admin IPC reads, checks, and applies whole policy documents through
`get_policy`, `check_policy`, and `apply_policy`. Network context tokens remain
opaque JSON object keys; the admin surfaces must not hard-code `mainnet`,
`testnet`, or `betanet`.

The exact message contracts are documented in
[ARCH_ADMIN_PROTOCOL.md](ARCH_ADMIN_PROTOCOL.md).

## Plugins And SDKs

Plugins receive the active network context token in execution context and
environment. Plugins must treat it as an opaque string and use the execution
context network, not only the initialization network.

The Go SDK config loader follows the same free-form token syntax as the client
config loader.

## Source Of Truth

Primary files:

- `internal/config/networkid.go` - token syntax validation,
- `internal/config/genesishash.go` - built-in and custom genesis-hash resolver,
- `internal/config/config.go` - client config validation,
- `internal/serverconfig/serverconfig.go` - signer config validation,
- `internal/engine/engine.go` - client network switching,
- `internal/apshellapp/network.go` - shell-facing network switching workflow,
- `internal/signerapp/signing/planner.go` - signer transaction network validation,
- `internal/policy/lint.go` - policy lookup by transaction genesis hash,
- `internal/signerapp/asametadata` - signer-wide ASA metadata cache and display formatting,
- `internal/signerapp/admin/service.go` - target-aware admin policy service and policy snapshot/validation/replacement,
- `internal/protocol/messages.go` - whole-policy admin IPC wire fields,
- external `aplane-algo/aplanesdk/go/config.go` - Go SDK config token validation.

Contract and user-facing docs:

- [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md)
- [USER_CONFIG.md](USER_CONFIG.md)
- [USER_CONFIG_REFERENCE.md](USER_CONFIG_REFERENCE.md)
- [ARCH_PLUGINS.md](ARCH_PLUGINS.md)

## Operational Example

For a Voi mainnet deployment:

```yaml
# apshell config.yaml
network: voi_mainnet
networks:
  voi_mainnet:
    algod:
      server: http://voi-node.example:4001
      token: your-token
```

```yaml
# apsigner config.yaml
teal_compile_network: voi_mainnet
networks:
  voi_mainnet:
    algod:
      server: http://voi-node.example:4001
      token: your-token
    genesis_hash: "base64-or-hex-32-byte-voi-mainnet-genesis-hash"
```

With that configuration:

- apshell uses `voi_mainnet` for endpoint lookup and cache context,
- signer TEAL compilation uses `networks.voi_mainnet.algod`,
- signer policy maps Voi transactions to `limits.voi_mainnet`,
- review and rejection messages show ASA amounts in display units when the Voi
  algod endpoint can resolve metadata for those assets.
