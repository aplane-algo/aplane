# Key Type Capability Matrix

This matrix summarizes the account operations each APlane key type can authorize
at the key-type or LogicSig layer.

Assume DSA signatures and cosigner signatures, if applicable, have been produced
and verify successfully. For example, `Y` for `aplane.falcon1024.v1` means the
operation is allowed by the key type after the Falcon signature verifies over
the transaction ID; it does not mean an unsigned transaction can pass. For a
cosigned account, the table describes the program after both the spending and
the cosigner signatures are present.
Composed templates add their own suffix checks after base DSA verification.
Generic TEAL-only templates have no base DSA gate, so their entries describe
the TEAL policy directly.

Legend:

- `Y`: allowed by the key type shape.
- `N`: denied by the key type shape.
- `C`: conditionally allowed by key-type parameters, runtime arguments,
  timelocks, allowlists, or cosigner transfer policy.

Signer policy, cosigner policy, operator approval, transaction validity, network
rules, fees, and account state can still reject a transaction that is marked
`Y` or `C` here.

State proof transactions (`stpf`) are protocol/system transactions and are not
included as normal user-account operations.

| Key type | Pay | ALGO close | ASA transfer | ASA opt-in | ASA close | ASA clawback | ASA config | ASA freeze | App ops | Keyreg | Rekey |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `ed25519` | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| `falcon1024` | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| `aplane.falcon1024.v1`, `aplane.ed25519.v1`, no parameters | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| `aplane.falcon1024.v1`, `aplane.ed25519.v1`, overlays only (`plain1`) | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | C |
| `aplane.falcon1024.v1`, `aplane.ed25519.v1`, with bounds (`bounded2`) | C | N | C | C | N | N | N | N | N | N | C |
| `aplane.htlc.v1` | C | C | N | N | N | N | N | N | N | N | N |
| `aplane.rotating-triple-xmss.v1` | C | N | C | C | C | C | C | C | C | C | C |
| `aplane.rotating-triple-slhdsa.v1` | C | N | C | C | C | C | C | C | C | C | C |
| `aplane.rotating-triple-wotsc.v1` | C | N | C | C | C | C | C | C | C | C | C |

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

- `ed25519`, native `falcon1024`, and the plain programs of `aplane.falcon1024.v1` and
  `aplane.ed25519.v1` (no parameters) do not restrict transaction type or special
  transaction fields at the key-type layer. Local signer policy remains the safety
  boundary.
- A plain host account with overlays only (`aplane.falcon1024.v1` or
  `aplane.ed25519.v1` with a rekey setting and no bounds, contract `plain1`) admits
  every transaction that doesn't rekey, of any type, closes and clawback included,
  with no fee ceiling. Rekey is the pure self-payment form only, on the paths its
  setting gives: none (`refused`), the spending key (with the cosigner on a cosigned
  account), a listed address (`only_these`), or both (`plus_cosigned`). On a
  cosigned plain host the cosigner signs every spend and cosigned rekey, and its
  policy is what restricts them: current cosigner authorization requires
  transfer-route coverage or an explicitly allowed pure rekey edge, so other
  non-transfer targets reject.
- A plain host account with bounds (`aplane.falcon1024.v1` or `aplane.ed25519.v1`
  with any bounds parameter, contract `bounded2`) is a bounded account. Each
  account's shape decides which of `pay`, `axfer`, and `asset_opt_in` it admits,
  whether a recipient list (inline or Merkle) limits non-self destinations, whether
  spending waits for an unlock round, and whether a cosigner signs every spend. A
  limits-only account has neither a list nor an unlock round, so any destination is
  a `Y`. It rejects close, clawback, and all non-transfer transaction types. Rekey
  is the `bounded2` pure self-payment form authorized by the spending key, which no
  recipient list or unlock round gates: never (`refused`), to any address
  (`spending_key`; on a cosigned account the cosigner must sign too), only to an
  address on the account's rekey-to list (`only_these`, with a signer-built list
  proof and no cosigner, which is every Corridor account), or both (`plus_cosigned`,
  cosigned accounts only: a listed target with the spending key alone, any other
  with the cosigner too). A timelock takes any of these, so every rekey path it has
  can leave the lock early; only `refused` keeps it. A Merkle list needs a
  signer-generated 512-byte proof for a non-self destination; self-send and asset
  opt-in need none.
- `aplane.rotating-triple-wotsc.v1` admits any transaction type, but every transaction must rekey to an address other
  than the sender, must not close out ALGO, and must have a validity window
  of at most 100 rounds; that is the condition behind every `C`. The signer
  sets the rekey itself, always to the account's next stage, and signs only
  through the `rotating1` flow, one transaction at a time.
- `aplane.rotating-triple-xmss.v1` admits the same transactions under the
  same conditions. Its program additionally requires the XMSS signature's
  leaf index to lie in the stage's 64-leaf range of the shared tree, which
  the signer satisfies by choosing the leaf. See
  [KEYTYPE_ROTATING_TRIPLE_HYBRID.md](KEYTYPE_ROTATING_TRIPLE_HYBRID.md) for the
  full specification of the rotating key types.
- `aplane.htlc.v1` admits only an ALGO payment that closes the account: to the
  configured recipient with the configured preimage, in a transaction that expires
  before timeout, or to the configured refund address after timeout.

The SLH-DSA rotating triple admits the same transactions and rotation guards as
XMSS. Its stateless hash scheme has no leaf range or leaf-reuse restriction.
