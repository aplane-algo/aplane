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
| `aplane.falcon1024_ed25519.v1` | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| `aplane.ecdsak1.v1` | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| `aplane.falcon1024-allowlist.v1` | C | C | C | Y | C | C | Y | Y | Y | Y | Y |
| `aplane.falcon1024-allowlist.v2` | C | C | C | Y | C | C | Y | Y | Y | Y | Y |
| `aplane.ed25519-allowlist.v1` | C | C | C | Y | C | C | Y | Y | Y | Y | Y |
| `aplane.falcon1024-hashlock.v1` | C | C | C | C | C | C | C | C | C | C | C |
| `aplane.falcon1024-timelock.v1` | C | C | C | C | C | C | C | C | C | C | C |
| `aplane.falcon1024-sentry-ed25519.v1` | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| `aplane.falcon1024-sentry-falcon1024.v1` | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| `aplane.corridor.v1` | C | C | C | Y | C | N | N | N | N | N | C |
| `aplane.allowlist.v1` | C | C | C | C | C | N | N | N | N | N | N |
| `aplane.timed-allowlist.v1` | C | C | C | C | C | N | N | N | N | N | N |
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

- `ed25519`, `aplane.falcon1024.v1`, `aplane.ed25519.v1`,
  `aplane.falcon1024_ed25519.v1`, and `aplane.ecdsak1.v1` do not restrict
  transaction type or special transaction fields at the key-type layer. Local
  signer policy remains the safety boundary.
- `aplane.falcon1024-allowlist.v1` and `aplane.ed25519-allowlist.v1`
  restrict only `pay` and `axfer`
  destination fields. Payment receivers and asset receivers must be self or
  allowlisted. Close destinations must be zero, self, or allowlisted. Other
  transaction types keep the base signature authorization surface.
  `AssetSender` is not denied by these templates, so clawback-shaped `axfer` is
  possible when destination checks pass.
- `aplane.falcon1024-hashlock.v1` keeps the base Falcon authorization surface
  but additionally requires the configured SHA256 preimage.
- `aplane.falcon1024-timelock.v1` keeps the base Falcon authorization surface
  but additionally requires `FirstValid >= unlock_round`.
- `aplane.falcon1024-allowlist.v2` restricts only `pay` and `axfer`
  destination fields. Payment receivers and asset receivers must be self or
  proven with a signer-generated 512-byte fixed-depth Merkle proof against the
  root derived from the key-file recipient list. Close destinations must be
  zero or the just-validated receiver. Other transaction types keep the base
  Falcon authorization surface. `AssetSender` is not denied by this template,
  so clawback-shaped `axfer` is possible when destination checks pass.
- `aplane.falcon1024-sentry-ed25519.v1` and
  `aplane.falcon1024-sentry-falcon1024.v1` require guarded signing assembly.
  Once both the user and sentry component signatures verify, the on-chain
  guarded-account LogicSig does not restrict transaction type or special
  transaction fields. The sentry policy that decides whether to issue the
  sentry component signature is separate from this table: current sentry
  authorization is transfer-route based, rejects non-transfer sentry targets,
  and rejects rekey by default.
- `aplane.corridor.v1` also requires guarded signing assembly, but unlike the
  plain guarded providers its on-chain LogicSig restricts spending to a
  recipient corridor. After both the user and sentry component signatures
  verify, `pay` and `axfer` are allowed only when the receiver is self or a
  recipient proven with a signer-generated 512-byte fixed-depth Merkle proof
  against the root derived from the key-file recipient list; close destinations
  must be zero or the just-validated receiver. Clawback-shaped `axfer`
  (non-zero `AssetSender`) is denied, and non-transfer transaction types are
  rejected. Rekey is allowed only as a pure 0-ALGO self-payment carrying the
  rekey, and the sentry's off-chain rekey policy decides whether a specific
  sender → rekey-target edge is authorized before issuing the sentry component
  signature.
- `aplane.allowlist.v1` allows `pay` and normal `axfer` only to configured
  allowlisted recipients. Close destinations must be zero or allowlisted. ASA
  opt-in is allowed only for configured `allowed_optin_assets`.
- `aplane.timed-allowlist.v1` has the same destination and opt-in rules as
  `aplane.allowlist.v1`, but normal spend paths additionally require
  `FirstValid >= unlock_round`. Approved ASA opt-in can happen before unlock.
- `aplane.htlc.v1` allows claim paths to the configured recipient before
  timeout with the configured preimage, refund paths to the configured refund
  address after timeout, and approved ASA opt-in for configured
  `allowed_optin_assets`.
