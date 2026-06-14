# Building Constrained Networks on Algorand

**Using LogicSigs and Rekeying for Provable Transfer Constraints**

![Constrained network diagram](https://raw.githubusercontent.com/aplane-algo/aplane.io/main/img/mesh.png)

## 1. Overview

Suppose you want to restrict token movement to a set of approved corridors
whose endpoint accounts are predetermined. Value remains within
a controlled transfer graph. This might be useful for payment networks, corporate treasury systems,
agentic buyer/seller ecosystems, etc.

So even if keys are leaked or stolen, or if a software defect causes an agent to attempt a transfer to an 
unintended destination, those tokens can move only along pre-set paths.

You can do this on Algorand simply using logic signatures and rekeying. Unlike on many other chains, no 
stateful application state is necessary. This results in a smaller attack surface. The LogicSigs handle 
*who* can send and *where* they can send to, while rekeying allows you to change the graph topology.

Let's first zoom in on a single sender account.

## 2. Constraining accounts with a Whitelisted Falcon LogicSig

A **constrained account** is an account whose effective authorizer is
a canonical Algorand Falcon LogicSig that has been extended to enforce one or
more whitelisted destination addresses. We'll call this key type "whitelisted
Falcon".

For such accounts:

- the account's transactions carry a valid Falcon signature checked by the
  LogicSig, and
- every destination field - `Receiver` and `CloseRemainderTo` for
  payments, `AssetReceiver` and `AssetCloseTo` for asset transfers - is either
  the account itself or a member of a **destination whitelist compiled into the
  LogicSig program**.

Two properties make this the right primitive:

- **Stateless.** The LogicSig program evaluates only the transaction in front of it.
  There is no application state to corrupt, migrate, or contend on; the
  authorization rule is the program, and the program is fixed.
- **Signature-bearing.** The guarantee must be "only the **key holder** can move value, but only
  within the whitelist."

The graph node accounts themselves can start life as either standard Algorand
accounts or Falcon LogicSig accounts. What matters is that their addresses are
fixed before the whitelist programs are compiled. While they are members of the
graph, they are rekeyed to the whitelisted Falcon LogicSigs. The whitelist logic
is the same regardless: destinations are compiled as literal addresses and
compared against the transaction's destination fields. Everything outside the
whitelist is unreachable through those constrained transfer paths.

The LogicSig itself is an extension of the canonical Algorand Falcon verification LogicSig.

```text
falcon_verify() // canonical Falcon verification

txn Receiver  == Sender || is_whitelisted(Receiver)      -> else err
txn CloseRemainderTo == Zero || Sender || is_whitelisted  -> else err
```

## 3. From accounts to a network

A directed edge **A → B** exists exactly when `B` is in `A`'s whitelist. The
network graph is the **emergent union of per-account whitelists** -
there is no adjacency table, route map, or registry, and no
privileged component mediates a transfer. Each node enforces its own outbound
edges, and multi-hop paths exist only where consecutive operators have
constructed consecutive edges.

## 4. Construction: the rekeyed formation

A whitelist account presents a **circularity**: a LogicSig account's address is
derived from its program, and the program embeds its peers' addresses. In any
cycle — a closed mesh, a ring, mutual links — the addresses become mutually
recursive and cannot be computed, so the accounts cannot be built as pure
contract accounts.

The resolution is to separate *identity* from *program*:

1. **Fix node identities first** as accounts whose addresses do not depend on
   any whitelist.
2. **Compile each whitelist** LogicSig program against those now-fixed peer addresses.
3. **Rekey** each node to its whitelist program.

Because an account's address is independent of the program it is rekeyed to,
the **address is stable** while the **authorizer becomes the whitelist**. The
circularity dissolves: step 2 references the fixed addresses from step 1, never
the whitelist programs themselves.

This same mechanism also provides **reconfiguration**. To change a node's
destination addresses, compile a new whitelist program and rekey to it: the
account address is unchanged, counterparties update nothing, the change takes
effect atomically at a round boundary, and the sequence of authorizer changes is
publicly auditable on-chain. Topology is built, and later evolved, purely by
construction.

## 5. Boundary nodes (controlled exits)

Let's say you have a closed transfer graph; funds that enter the graph stay in
the graph.
A constrained region needs a sanctioned way out. Include a **standard,
unconstrained signature account** as one entry in a node's whitelist: that
single edge is the controlled exit, and every other destination remains walled.
For example, that exit could be a CEX deposit address, or a general treasury
account. Value leaves the constrained region only through that labeled path.

The exit is itself swappable by construction - rekey the node to a whitelist
that names a different exit account, address unchanged.

## 6. Composition: atomic multi-hop

Independent legs bind into a single Algorand **atomic group** with no
application involved. A two-hop transfer A → B → C groups A's leg with B's leg;
the group settles **all-or-nothing**. Three properties follow directly, and each
is a consequence of the building block rather than an added feature:

- **No intermediate custody.** B receives and forwards within one atomic unit;
  it never holds the value in a settled intermediate state.
- **Active participation.** B's forwarding leg requires **B's own signature** -
  an intermediary is a participant, not passive plumbing.
- **Constraint under composition.** B can forward only where **B's whitelist**
  allows. If any leg violates its constraint, the entire group reverts, so an
  individually-valid earlier leg does not commit.

## 7. Enforcement and security

- **On-chain, not policy.** The constraint is evaluated by Algorand consensus on
  every transaction. There is no alternative path around the rule; a stolen key
  can still travel only the whitelist.
- **Bounded blast radius.** Compromise of an account's key lets an attacker
  initiate transfers, but only to that account's whitelisted destinations.
- **Reconfiguration is the apex authority.** Whoever can rekey an account can
  replace its constraints entirely. This authority must be *separated from the
  spend key* and hardened. Rekey authority must not be satisfiable by the spend
  key alone; the LogicSig program can enforce this additional constraint.
- **Immutability option.** Using a LogicSig *without* rekey capability
  (enforced by the LogicSig) makes its constraints permanent - the strongest
  posture, where reconfiguration is never needed.

## 8. Conclusion

Constrained transfer networks require no smart contracts on Algorand. A
signature-bearing whitelist LogicSig gives each account a non-bypassable,
ledger-enforced set of outbound edges; rekeying gives a stable-address way to
construct the topology despite circular references and to evolve it later
without disturbing counterparties; and Algorand's native atomic groups compose
these edges into all-or-nothing multi-hop flows in which intermediaries are
constrained, signing participants. Two primitives — whitelist and rekey —
yield auditable, reconfigurable, atomically-routable constrained networks.

---

*— End of Document —*
