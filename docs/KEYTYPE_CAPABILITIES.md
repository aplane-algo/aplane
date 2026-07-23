# Key Type Capability Matrix

This matrix summarizes the account operations each APlane key type can authorize
at the key-type or LogicSig layer.

Assume DSA signatures and sentry signatures, if applicable, have been produced
and verify successfully. For example, `Y` for `aplane.falcon1024.v1` means the
operation is allowed by the key type after the Falcon signature verifies over
the transaction ID; it does not mean an unsigned transaction can pass. For
guarded sentry key types, the table describes the on-chain guarded-account
LogicSig after both the user and sentry component signatures are present.
Composed templates add their own suffix checks after base DSA verification.
Generic TEAL-only templates have no base DSA gate, so their entries describe
the TEAL policy directly.

Legend:

- `Y`: allowed by the key type shape.
- `N`: denied by the key type shape.
- `C`: conditionally allowed by key-type parameters, runtime arguments,
  timelocks, allowlists, or sentry transfer policy.

Signer policy, sentry policy, operator approval, transaction validity, network
rules, fees, and account state can still reject a transaction that is marked
`Y` or `C` here.

State proof transactions (`stpf`) are protocol/system transactions and are not
included as normal user-account operations.

| Key type | Pay | ALGO close | ASA transfer | ASA opt-in | ASA close | ASA clawback | ASA config | ASA freeze | App ops | Keyreg | Rekey |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `ed25519` | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| `aplane.falcon1024.v1` | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| `aplane.ed25519.v1` | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| `aplane.falcon1024-allowlist.v1` | C | N | C | Y | N | N | N | N | N | N | C |
| `aplane.falcon1024-allowlist.v2` | C | N | C | Y | N | N | N | N | N | N | C |
| `aplane.falcon1024-allowlist-alock.v1` | C | N | C | C | N | N | N | N | N | N | C |
| `aplane.falcon1024-timelock.v1` | C | N | C | C | N | N | N | N | N | N | C |
| `aplane.falcon1024-sentry1024.v1` | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| `aplane.corridor.v1` | C | N | C | Y | N | N | N | N | N | N | C |
| `aplane.htlc.v1` | C | C | C | C | C | N | N | N | N | N | N |

## Capability Columns

- `Pay`: ALGO payment transaction (`pay`).
- `ALGO close`: payment with non-zero `CloseRemainderTo`.
- `ASA transfer`: normal asset transfer (`axfer`) without clawback source.
- `ASA opt-in`: zero-amount self `axfer`.
- `ASA close`: asset transfer with non-zero `AssetCloseTo`.
- `ASA clawback`: asset transfer with non-zero `AssetSender` not equal to
  `Sender`.
- `ASA config`: asset create, reconfigure, or destroy (`acfg`).
- `ASA freeze`: asset freeze or unfreeze (`afrz`).
- `App ops`: app create, call, opt-in, close-out, clear-state, update, or delete
  (`appl`).
- `Keyreg`: participation key registration (`keyreg`).
- `Rekey`: any transaction with non-zero `RekeyTo`.

## Condition Notes

- `ed25519`, `aplane.falcon1024.v1`, and `aplane.ed25519.v1` do not restrict
  transaction type or special transaction fields at the key-type layer. Local
  signer policy remains the safety boundary.
- `aplane.falcon1024-allowlist.v1` is a bounded1 template. It admits only pure
  payments and pure asset transfers to self or an inline allowlisted recipient,
  plus asset opt-in. It rejects
  close, clawback, and all non-transfer transaction types. Rekey is allowed
  only as the bounded1 pure self-payment form authorized by the spending key;
  the allowlist does not gate that rekey path.
- `aplane.falcon1024-timelock.v1` admits the same bounded transfer effects only
  when `FirstValid >= unlock_round`; the round condition also gates pure
  spending-key rekey. Close, clawback, and non-transfer types are rejected.
- `aplane.falcon1024-allowlist.v2` is the bounded Merkle allowlist. Non-self
  payment and asset-transfer destinations require a signer-generated 512-byte
  fixed-depth proof against the root derived from the key-file recipient list.
  Self-send, asset opt-in, and pure spending-key rekey require no proof. Close,
  clawback, and non-transfer types are rejected.
- `aplane.falcon1024-allowlist-alock.v1` admits only pure `pay` and `axfer`
  spends to self or a compiled recipient. Optional asset-ID and amount limits
  narrow that set. It rejects close, clawback, and every other transaction
  type. Rekey is restricted to the pure payment normal form and additionally
  requires the external Falcon contract-admin signature.
- `aplane.falcon1024-sentry1024.v1` requires guarded signing assembly.
  Once both the user and sentry component signatures verify, the on-chain
  guarded-account LogicSig does not restrict transaction type or special
  transaction fields. The sentry policy that decides whether to issue the
  sentry component signature is separate from this table: current sentry
  authorization is transfer-route based, rejects non-transfer sentry targets,
  and rejects rekey by default.
- `aplane.corridor.v1` is a bounded-sentry template. Its on-chain LogicSig
  requires the Falcon spending signature and sentry signature for every spend,
  then permits `pay` and `axfer` only when the receiver is self or is proven by
  a signer-derived 512-byte fixed-depth Merkle proof against the key-file
  recipient list. Close and clawback fields and non-transfer transaction types
  are rejected. Rekey is only the bounded pure 0-ALGO self-payment form and
  requires the distinct offline Falcon contract-admin signature; the sentry is
  forbidden on that path.
- `aplane.htlc.v1` allows claim paths to the configured recipient before
  timeout with the configured preimage, refund paths to the configured refund
  address after timeout, and approved ASA opt-in for configured
  `allowed_optin_assets`.
