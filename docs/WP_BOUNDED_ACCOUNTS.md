# Building Transfer Networks with Bounded Accounts

> Scope: This whitepaper explains bounded accounts and their use in transfer
> networks, using the presets of APlane's general bounded type, which
> implement the `bounded2` contract. It is an
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
Those conditions can include approved destinations, a fee ceiling, or a round
before which spending is prohibited.

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

APlane's general bounded type uses Falcon-1024 spending signatures.
Falcon supplies authentication; the LogicSig program supplies the transaction
restrictions. Native Falcon authorization alone does not provide those bounds.

The `bounded2` contract checks three things:

1. **Authentication.** The base spending signature is required on every path.
2. **Transaction shape.** Only explicitly supported transaction forms are
   admitted, with a fee ceiling and checks for close, clawback, and rekey effects.
   A rekey is accepted or rejected here and never reaches the next step.
3. **Spending conditions.** An admitted spend must satisfy the account's
   rules, such as destination membership or a timelock. Additional
   signatures are required where the account specifies them.

The presets admit ALGO payments, ordinary Algorand Standard Asset
(ASA) transfers, and asset opt-ins, subject to their individual conditions.
They reject ALGO close-out, ASA close-out, clawback execution, application
calls, asset configuration or freeze operations, key registration, and other
unsupported transaction types. A transaction combining rekeying and spending
is also rejected.

Rekeying has its own narrow form: a zero-ALGO payment to the sender itself,
with a nonzero rekey target and no close or clawback effects. Depending on the
account, the spending key authorizes this form to any target (with the cosigner
too, on a cosigned account), or alone, only to a target on the account's
rekey-to list, fixed when the account is created. A cosigned account may have
both: a listed target with the spending key alone, any other with the cosigner
too. Its spending conditions, such as a recipient list or an unlock round, do
not apply to a rekey. The compiled fee ceiling applies to both
spending and rekeying; the general bounded type sets it to 10,000 microAlgos
(0.01 ALGO) per protected transaction. This is a ceiling, not a fixed fee or
a guarantee that every path is viable under every network fee schedule.

No stateful application deployment is required. Each authorization program is
fixed, and its code accompanies the transaction when used. The account still
has ordinary on-chain state, including its current authorization address.
Rekeying changes that authority rather than editing the existing program.

## 3. Choosing the account's rules

APlane ships its bounded profiles as presets of the general bounded type
`aplane.falcon1024-b.v1`. A boundary file selects any other shape the type
offers, such as an ALGO-only account or a timelock with a recipient list. An
allowlist is one possible policy; bounded accounts also include profiles
without destination restrictions: a timelock with no list, and a limits-only
account (`recipient_scope: any`), which only the fee ceiling and transfer kinds
bound.

| Preset | Spending conditions | Pure rekey authorization |
|---|---|---|
| Allowlist | Self or a recipient list | Spending key alone, to any address |
| Locked Allowlist | Self or a recipient list | Spending key alone, only to an address on the rekey-to list |
| Corridor | Self or membership in a Merkle recipient list, plus a Falcon cosigner signature for every spend | Spending key alone, only to an address on the rekey-to list; the cosigner is not asked |
| Timelock | Transaction's first valid round must reach the configured unlock round | Spending key alone, only to an address on the rekey-to list |

A timelock never lets the spending key rekey to any address, with or without a
cosigner: the unlock round is a spending condition, so a rekey would not wait
for it. That applies to a listed
rekey too, so a timelock's rekey-to list is a way around the lock, and the lock
holds only while the holders of the listed keys cooperate.

The rekey-to list holds up to 16 addresses and is compiled into the program as a
salted Merkle root that reveals nothing about its entries. The signer keeps the
entries and builds the proof a listed rekey needs; a rekey to any other address
fails on chain, unless the account takes cosigned rekeys.

A boundary file can also give a cosigned account a cosigned rekey: the spending
key and the cosigner together, to any target the cosigner's policy allows, alone
(`spending_key`) or beside a rekey-to list (`plus_cosigned`). The cosigner's
`rekey_policy` then decides where such a rekey may go. A listed rekey never asks
the cosigner, so its policy cannot stop one.

Inline recipient lists support up to 30 addresses. The Merkle profiles support
up to 65,536 recipients, committing to the list through a fixed root. The
signer stores the recipient list and derives a membership proof when needed;
the on-chain program verifies that proof. Updating the stored list alone
cannot change the root embedded in the existing program.

For a network intended to contain spending-key theft, Locked Allowlist or
Corridor supplies an essential additional property: the spending key cannot
remove the bounds on its own. Both can be rekeyed only to a listed address, so a
stolen spending key can at most hand the account to a key the owner chose in
advance, and gains control only if it holds that key too. The Allowlist preset
does not provide that. Its spending key can authorize a pure rekey to a
different authority and then spend under that authority's rules. Neither does
a cosigned account that takes cosigned rekeys: the spending key and the
cosigner together can rekey it anywhere. The price of refusing every other
rekey is that a mistake in the account's rules cannot be repaired in place; the
rekey-to list leaves one way out, a handover to a listed key, which also takes a
Corridor account away from a lost cosigner.

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
   authorize spends and whether the bounds can ever change.
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
particular transfer can use that edge also depends on its required signatures
and other applicable conditions. Self-transfers and
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

For the Allowlist preset, the spending key can rekey the account straight to a
replacement program, and a cosigned account that takes cosigned rekeys can do
the same with the cosigner's signature. A Locked Allowlist, Corridor or Timelock
account can be rekeyed only to an address on its rekey-to list; the listed key
can then rekey it onward to a replacement program, keeping the address. An
account with no rekey path, which only an expert template can declare, cannot
change its destinations at all: replacing it means moving its funds, while it
can still spend, to a new account built with the new rules, and retiring the old
address.

## 6. Spending and cosigning authority

The spending key authorizes ordinary use of the account and a pure rekey as
well: to any address for the Allowlist preset, and only to a listed address for
Locked Allowlist, Corridor and Timelock. Corridor adds a cosigner whose
signature is required for every spend, but not for a listed rekey: if the
cosigner is lost for good, the account can no longer spend, but the spending
key can still hand it to a listed key. The cosigner key and the spending key
should be distinct and separately managed.

Rekey authority can remove the restrictions entirely. That is why the
containment claim for Locked Allowlist and Corridor rests on refusing every
rekey but one to a listed address, not on how well some rekey key is guarded. A
cosigned account that takes cosigned rekeys makes no such claim: it is only as
strong as the spending key and the cosigner together, since both keys, or a
cosigner node whose policy is compromised, can rekey it anywhere. A listed key does become part of the security model:
whoever holds it can take the account over once the spending key hands it on, so
list only keys kept apart from the spending key. For a post-quantum account, a
listed key should be post-quantum too, such as a native Falcon-1024 account; an
Ed25519 listed key would put the account on a classical key after a handover.

APlane's JSON signer and cosigner policies provide another layer: they decide
whether the software will issue the required signatures. They can impose
additional restrictions or review requirements, but they do not rewrite the
compiled LogicSig. Editing a policy JSON file cannot relax an on-chain bound.
Conversely, a restriction that exists only in signer policy is not itself an
on-chain guarantee if the relevant private keys are compromised.

## 7. What containment does and does not mean

While the bounded program remains the account's authority, every transaction
authorized through it must meet its checks. For Locked Allowlist or Corridor,
a stolen spending key cannot redirect an ordinary transfer outside the allowed
recipients or replace the program with one of its own choosing: either
program can be left only for a listed key. Corridor additionally requires the
cosigner's participation in every spend.

That is a specific containment property, not a guarantee that the account
cannot lose value:

- An attacker with sufficient spending authorization may make repeated
  permitted transfers, including transfers toward an approved exit. The
  presets do not limit assets or amounts on-chain.
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

The implementation and custody of the spending and cosigner keys remain part
of the security model. Using stateless programs removes the need
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
stateful application is required to enforce these account bounds.
