# Building Transfer Networks with Bounded Accounts

> Scope: This whitepaper explains bounded accounts and their use in transfer
> networks, using APlane's current bundled `bounded1` templates. It is an
> architectural explanation, not an implementation specification. Exact
> behavior is defined in [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md) and
> [KEYTYPE_CAPABILITIES.md](KEYTYPE_CAPABILITIES.md); the Corridor profile is
> specified in [ARCH_GUARDED.md](ARCH_GUARDED.md); operational guidance is in
> [USER_KEYTYPES.md](USER_KEYTYPES.md).

![Network of bounded accounts](https://raw.githubusercontent.com/aplane-algo/aplane.io/main/img/mesh.png)

## 1. What is a bounded account?

A bounded account uses a stateless authorization program to restrict the
transactions it can accept. The program defines who must sign, which kinds of
transactions are permitted, and what conditions each transaction must satisfy.
Those conditions can include approved destinations, a fee ceiling, asset and
amount restrictions, or a round before which spending is prohibited.

An allowlisted bounded account is one example: its transfers can go only to
itself or to specified recipients. Connecting such accounts through their
allowlists creates a transfer network. This is useful for treasury operations,
payment networks, and automated agents whose permitted destinations can be
defined in advance.

The term **bounded** describes the accepted transaction set. It does not, by
itself, promise a cumulative spending budget or protection against every use
of a stolen spending key. In particular, the rules for replacing the program
are part of the account's security model.

## 2. How the bounds are enforced

APlane implements these bounds with Algorand Logic Signatures. A transaction
supplies the authorization program and its required signatures and proofs.
The network checks that the program corresponds to the account's current
authority and accepts the transaction only if the program succeeds.

The current bundled bounded templates use Falcon-1024 spending signatures.
Falcon supplies authentication; the LogicSig program supplies the transaction
restrictions. Native Falcon authorization alone does not provide those bounds.

The `bounded1` framework checks three things:

1. **Authentication.** The base spending signature is required on every path.
2. **Transaction shape.** Only explicitly supported transaction forms are
   admitted, with a fee ceiling and checks for close, clawback, and rekey effects.
3. **Spending conditions.** An admitted spend must satisfy the selected
   template's rules, such as destination membership or a timelock. Additional
   signatures are required where the template specifies them.

The bundled profiles admit ALGO payments, ordinary Algorand Standard Asset
(ASA) transfers, and asset opt-ins, subject to their individual conditions.
They reject ALGO close-out, ASA close-out, clawback execution, application
calls, asset configuration or freeze operations, key registration, and other
unsupported transaction types. A transaction combining rekeying and spending
is also rejected.

Rekeying has its own narrow form: a zero-ALGO payment to the sender itself,
with a nonzero rekey target and no close or clawback effects. It must satisfy
the profile's rekey authorization. The compiled fee ceiling applies to both
spending and rekeying; the current bundled templates set it to 10,000 microAlgos
(0.01 ALGO) per protected transaction. This is a ceiling, not a fixed fee or
a guarantee that every path is viable under every network fee schedule.

No stateful application deployment is required. Each authorization program is
fixed, and its code accompanies the transaction when used. The account still
has ordinary on-chain state, including its current authorization address.
Rekeying changes that authority rather than editing the existing program.

## 3. Choosing the account's rules

APlane ships several bounded profiles. An allowlist is one possible policy;
bounded accounts also include profiles without destination restrictions.

| Key type | Spending conditions | Pure rekey authorization |
|---|---|---|
| `aplane.falcon1024-allowlist.v1` | Self or an inline recipient list | Spending key alone |
| `aplane.falcon1024-allowlist.v2` | Self or membership in a Merkle recipient list | Spending key alone |
| `aplane.falcon1024-allowlist-alock.v1` | Self or an inline recipient list, with optional asset and per-transaction amount limits | Spending key plus a separate Falcon contract-admin key |
| `aplane.corridor.v1` | Self or membership in a Merkle recipient list, plus a Falcon cosigner signature for every spend | Spending key plus a separate Falcon contract-admin key |
| `aplane.falcon1024-timelock.v1` | Transaction's first valid round must reach the configured unlock round | Spending key, subject to the same round condition |

Inline recipient lists support up to 30 addresses. The Merkle profiles support
up to 65,536 recipients, committing to the list through a fixed root. The
signer stores the recipient list and derives a membership proof when needed;
the on-chain program verifies that proof. Updating the stored list alone
cannot change the root embedded in the existing program.

The rekey-locked allowlist's optional ALGO limit is in microAlgos; its optional
ASA amount limit is in the asset's base units. These are per-transaction
limits. They do not count previous transfers or establish a daily budget.

For a network intended to contain spending-key theft, the rekey-locked
allowlist or Corridor supplies an essential additional property: the spending
key cannot remove the bounds by itself. Allowlist v1 and v2 do not provide
that separation. Their spending key can authorize a pure rekey to a different
authority and then spend under that authority's rules.

## 4. Building a network with stable addresses

An existing account can become bounded by rekeying it to the address of a
bounded LogicSig program. Its address, balance, and asset holdings remain in
place; its authorization changes.

<p align="center">
  <img src="https://raw.githubusercontent.com/aplane-algo/aplane.io/main/img/rekey.png" alt="An account keeps its address while changing its authorizing program" width="320">
</p>

To construct a network:

1. Establish the stable account addresses that will be its nodes.
2. Define each node's permitted recipients and other bounds. Choose who must
   authorize spends and who must co-authorize changes to those bounds.
3. Generate the corresponding bounded credentials and programs, using the
   stable node addresses in their recipient lists.
4. Authorize each account's rekey to its chosen program using its current
   authority. Verify the resulting authority before treating the network as
   bounded.

This separation solves a circular address problem. If two program-derived
accounts each embed the other's address, constructing either address can
depend on knowing the other first. Rekeying lets the programs refer to already
established account addresses instead. Rings, meshes, and mutual links can
therefore be constructed without recursively defining program addresses.

A listed recipient creates a permitted destination edge, **A → B**. Whether a
particular transfer can use that edge also depends on its asset, amount,
required signatures, and other applicable conditions. Self-transfers and
asset opt-ins follow the selected profile's rules.

The graph needs no separate on-chain routing registry: each authorizing
program enforces its own account's outbound bounds. Destination allowlists
do not restrict who can send funds into an account. Nor does one account's
allowlist establish what a recipient will do after receiving them. The graph
depends on every participating account's current authority and rules.

Corridor adds an online authorization dependency. A cosigner must approve
each spend and provide its signature. It can refuse a transfer that the
compiled bounds would otherwise permit, but its signature cannot make an
out-of-bounds spend pass the program.

## 5. Controlled exits and changing the graph

A network can designate an exit by including an account whose onward spending
is unrestricted, such as a treasury or exchange deposit address. The bounded
sender controls whether it may transfer to that address; it does not control
funds after they reach the exit. Any permitted sequence of transfers leading
to an exit must be considered when assessing containment.

Changing an account's destinations requires changing its authorizing program.
Rekeying provides that mechanism while preserving the account address, so
counterparties do not need a replacement address. The current program decides
which signatures and conditions are required to authorize the change.

The program and APlane's signer draw this line in different places. The
program accepts any nonzero rekey target that the admin signature binds. The
signer is narrower: for an admin-authorized rekey it requires a destination
credential it holds and can validate, meaning a native Ed25519 or Falcon-1024
key or a plain `aplane.ed25519.v1` or `aplane.falcon1024.v1` LogicSig. Another
bounded program does not qualify as a replacement target in that workflow.
Rekeying the bounded account to its own address names no new credential and
keeps its bounds. An account that was merely rekeyed to the program is
different: rekeying it to itself hands it back to its original key, which must
pass the same destination checks.

Consequently, replacing an admin-locked allowlist currently requires an
administrative transition through an eligible local credential, followed by
an ordinary rekey to the replacement program under signer policy. The
intermediate authority does not carry the old program's bounds. It is a
controlled custody operation, not a one-step replacement of the allowlist. See
[the admin-rekey contract](ARCH_BOUNDED_DSA.md#frozen-v1-decisions) for the
precise destination checks and workflow.

## 6. Spending, cosigning, and administrative authority

The spending key authorizes ordinary use of the account. For the rekey-locked
allowlist and Corridor, a separately custodied contract-admin key must also
authorize a pure rekey. Both signatures are required: the admin key cannot
spend alone, rekey alone, or recover an account whose spending key has been lost.

Corridor separates the cosigner from that administrative authority. Its
cosigner signature is required for spends and is absent from the admin-rekey
path. With the spending and contract-admin keys, the account can therefore
leave a failed cosigner without that cosigner's cooperation, through the
supported administrative workflow. The contract-admin key and the cosigner
key should be distinct and separately managed.

Rekey authority can remove the restrictions entirely. The security claim for
an admin-locked account therefore assumes the additional admin authority
remains uncompromised and does not authorize an unsafe transition. Separating
that authority makes possession of the spending key alone insufficient to
replace the program.

APlane's JSON signer and cosigner policies provide another layer: they decide
whether the software will issue the required signatures. They can impose
additional restrictions or review requirements, but they do not rewrite the
compiled LogicSig. Editing a policy JSON file cannot relax an on-chain bound.
Conversely, a restriction that exists only in signer policy is not itself an
on-chain guarantee if the relevant private keys are compromised.

## 7. What containment does and does not mean

While the bounded program remains the account's authority, every transaction
authorized through it must meet its checks. For an admin-locked allowlist, a
stolen spending key alone cannot redirect an ordinary transfer outside the
allowed recipients or remove the program. Corridor additionally requires the
cosigner's participation in every spend.

That is a specific containment property, not a guarantee that the account
cannot lose value:

- An attacker with sufficient spending authorization may make repeated
  permitted transfers, including transfers toward an approved exit. A
  per-transaction amount limit does not cap their aggregate value.
- Fees are outflows too. The fee ceiling limits each protected transaction,
  not the total fees payable over the account's lifetime.
- The program checks transactions authorized by this account. Asset-level
  authorities, such as an ASA's clawback authority, require a separate threat
  assessment; rejecting clawback execution by this account does not remove
  those external powers.
- A bounded transaction's checks do not establish the safety of every other
  transaction in its group. The complete operation still needs review.
- Recipient lists constrain addresses, not the intentions or future custody
  of their owners. An allowlisted recipient can be compromised or have its
  authority changed.

The implementation and custody of the spending, cosigner, and admin keys
remain part of the security model. Using stateless programs removes the need
to maintain application state for these bounds; it does not eliminate code
defects or operational mistakes.

## 8. Bounded accounts as a network primitive

Bounded accounts make an account's permitted behavior explicit and enforceable
by the ledger. Allowlists turn those individual bounds into transfer paths;
stable account addresses let the paths form cycles and meshes; and authorized
rekeying provides a way to change the topology.

The useful design choice is the complete set of rules: which transfers are
allowed, who must approve them, and who can authorize replacing those rules.
A network intended to contain spending-key compromise needs all three to be
specified, including controlled exits and administrative transitions. No
stateful application is required to enforce the bundled account bounds.
