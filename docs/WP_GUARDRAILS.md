# Easy Algorand Guardrails

![Constrained network diagram](https://raw.githubusercontent.com/aplane-algo/aplane.io/main/img/mesh.png)

## 1. Overview

Suppose you want to restrict token movement to approved transfer corridors: 
predetermined routes through a controlled transfer graph. This is useful for payment networks, 
corporate treasury systems, agentic buyer/seller ecosystems, and other cases where the 
topology is relatively stable.

You can do this on Algorand simply using logic signatures and rekeying. Unlike on many other chains, no 
stateful application state is necessary, resulting in a smaller attack surface. The logic signatures handle 
*who* can send and *where* they can send to, while rekeying allows you to change the graph topology.

## 2. Whitelisted Falcon LogicSig

The canonical Falcon implementation on Algorand today uses LogicSigs.

A LogicSig is a cryptographic mechanism that allows 
an account's transaction authorization to be determined by a small
TEAL program rather than a standard Algorand private key. In the case of
Falcon accounts, the TEAL verifies that a transaction's Falcon signature sidecar
was indeed produced by the account's authorized private key.

For a new "whitelisted Falcon" key type, we simply take the canonical Algorand
Falcon TEAL program and extend it with code that ensures the transaction's destination is
included in a set of allowed destinations. 

```text
  falcon_verify()

  // If verified, we know the right key signed.
  // Then enforce the destination guardrail:

  assert primary_destination == Sender || is_whitelisted(primary_destination)
  assert close_destination == Zero || Sender || is_whitelisted(close_destination)

  // If all assertions pass, transaction is allowed.
```

Two properties make this the right primitive:

- **Stateless.** The LogicSig program evaluates only the transaction in front of it.
  There is no application state to corrupt, migrate, or contend on; the
  authorization rule is the program, and the program is fixed.
- **Signature-bearing.** The guarantee must be "only the **key holder** can move value, but only
  within the whitelist."

The definition of "Sender"'s actual address is evaluated at runtime and is not 
hard-coded in the TEAL. That means that standard accounts can rekey to a specific 
whitelist LogicSig and become whitelisted themselves, adopting as their whitelist
the destinations that *are* hardcoded in the LogicSig program. 

## 3. From accounts to a network

A directed edge **A → B** exists exactly when `B` is in `A`'s whitelist. The
network graph is the **emergent union of per-account whitelists**;
there is no adjacency table, route map, or registry, and no
privileged component mediates a transfer. Each node enforces its own outbound
edges.

## 4. Construction

This technique for building guardrails separates an account's stable identity
from the LogicSig program that authorizes its spending and constrains its
destination set.

1. **Fix identities first** as accounts whose addresses do not depend on
   the whitelist being built.
2. **Compile each whitelist** LogicSig program against those now-fixed peer
   addresses.
3. **Rekey** each account to its whitelist program.

The graph accounts themselves can start life as either standard Algorand Ed25519
accounts or Falcon LogicSig accounts. What matters is that their addresses are
fixed before the whitelist programs are compiled.

This order is especially important for closed graphs with cycles. If nodes in a
mesh, ring, or mutual-link pair were built as pure whitelist LogicSig accounts,
each address would be derived from a program that embeds peer addresses. Those
peer addresses could themselves depend on programs that embed the first address,
creating a circular dependency.

Rekeying breaks that circularity. A rekeyed account keeps its original address,
while its authorizing LogicSig defines the whitelist. Step 2 references fixed
account addresses, not recursively-defined whitelist program addresses.

This same mechanism also provides **reconfiguration**. Changing to a new set of
allowed destinations is as simple as rekeying the account to a new whitelist
LogicSig. The account address is unchanged and counterparties update nothing.
Topology is built, and later evolved, purely by construction.

<p align="center">
  <img src="https://raw.githubusercontent.com/aplane-algo/aplane.io/main/img/rekey.png" alt="Rekey diagram" width="320">
</p>

## 5. Boundary accounts (controlled exits)

Let's say you have a closed transfer graph; funds that enter the graph stay in
the graph. A constrained region needs a sanctioned way out. Include a **standard,
unconstrained signature account** as one entry in a constrained account's whitelist: that
single edge is the controlled exit, and every other destination remains walled.
For example, that exit could be a CEX deposit address, or a general treasury
account. 

The exit is itself swappable by construction - rekey the constrained account to a whitelist
that names a different exit account, address unchanged.

## 6. Enforcement and security

- **Consensus-level enforcement.** The constraint is evaluated by Algorand consensus on
  every transaction. There is no alternative path around the rule; a stolen key
  can still only send to whitelisted destinations.
- **Bounded blast radius.** Compromise of an account's key lets an attacker
  initiate transfers, but only to that account's whitelisted destinations.
- **Reconfiguration is the apex authority.** Whoever can rekey an account can
  replace its constraints entirely. This authority must be *separated from the
  spend key* and hardened. Rekey authority must not be satisfiable by the spend
  key alone; the LogicSig program can enforce this additional constraint. 

## 7. Conclusion

Building guardrails on Algorand requires no on-chain smart contracts. A
signature-bearing whitelist LogicSig gives each account a non-bypassable,
ledger-enforced set of approved destinations, and rekeying gives a stable-address
way to construct the topology despite circular references and to evolve it later
without disturbing counterparties.

---

*- End of Document -*
