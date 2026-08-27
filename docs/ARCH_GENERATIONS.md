# Atomic Store Root and Generational Storage

This document is the storage contract for the signer product store. The only
supported layout uses one authenticated commit record for both cryptographic
authority and active-generation selection. There is no compatibility path for
the retired `CURRENT` plus `keyring.enc` layout.

## Layout

```text
<data-root>/
  config.yaml
  node.yaml
  audit.log
  backups/default/
  library/templates/
  identities/default/
    .keystore
    store-root.enc
    config.yaml
    unlock.yaml
    aplane.token
    passphrase | passphrase.cred
    sentries/<name>.json
    quarantine/generations/<gen-id>/
    generations/<gen-id>/
      manifest.json
      seal.json
      keys/*.key|*.sen|*.wit.json
      keytypes/*.json|*.template
      deleted/keys/*.key|*.sen
      deleted/keytypes/*.template
      policy.yaml
      policy.yaml.hmac
      node.yaml.hmac
```

The generation boundary includes all mutable state whose confidentiality or
integrity depends on a keyring term. Process and product configuration, tokens,
unlock helpers, SSH state, sentry references, backups, the plaintext template
library, and the root node-role document are not generational.

`quarantine/` is non-authoritative. Normal resolution, signing, historical
reads, successor construction, and rollback never search it.

## Store root

`store-root.enc` has strict schema `aplane.store-root.v1`. It contains:

- the passphrase-wrapped `aplane.keyring.v3` subobject;
- `current_generation_id`;
- the current selection term;
- a domain-separated HMAC over the selector and exact wrapped-keyring digest.

The wrapped keyring is AEAD-authenticated under the Argon2id-derived KEK. After
unwrap, the selection term must equal the keyring's current term and the
selection MAC must verify. Unknown fields, trailing content, noncanonical
encoding, unsafe KDF parameters, and oversized input fail closed.

The selector is outside the KEK-sealed payload so an unlocked runtime can mint
an ordinary successor without retaining the passphrase. Such commits reread
the exact root under the mutation lock, authenticate it, preserve the wrapped
keyring subobject byte-for-byte, and change only the selector and selection
MAC. Passphrase change replaces the wrapped keyring and selector together.

The store root authenticates state but is not an external freshness oracle.
An adversary able to restore an older authentic root can roll authority back.
Detecting such replay needs a monotonic hardware or remote authority outside
this store.

## Active-path capability

Passphrase unlock authenticates `store-root.enc`, validates the selected
generation, and binds its ID into a `storepaths.Paths` capability or returns a
`storepaths.GenPaths`. Lower-level packages cannot derive active selection from
public filesystem state. `genstore.Resolve` accepts only an already-bound
capability; an unbound path fails.

Root-changing operations repeat a fresh exact root read under the store
mutation lock. A cached runtime generation or serialized root is never commit
authority.

## Generation manifest and seal

Every generation has a strict, complete `manifest.json` recording its ID,
parent, operation identity, creation time, at-mint inventory, and optional
restore rollback capability. Self-parent lineage and incomplete manifests are
invalid.

The selected generation is mutable through ordinary durable key, template,
policy, and sidecar operations. A `seal.json` beside it is stale precommit
residue and has no authority.

Immediately before selection moves, the outgoing generation receives an
authenticated seal. The seal binds the exact manifest bytes and complete final
inventory:

- active credentials and installed templates;
- deleted credentials and templates;
- policy document and integrity sidecar;
- node-role integrity sidecar;
- term numbers, sizes, and exact digests.

A retained generation must have a valid seal. Old-term retained generations
also require an exact historical seal anchor in the active keyring. A term key
alone never grants historical authority.

Generations are copied as independent files, never hardlinks. Once non-current,
they are immutable except for explicit generation pruning.

## Ordinary generation commit

Credential restore, restore rollback reconstruction, initialization, rebuild,
and passphrase change mint generations. Ordinary key or policy mutations do
not.

The commit order is:

1. acquire the store mutation lock and any maintenance fence;
2. freshly authenticate the root and selected generation;
3. create a private `.staging-<gen-id>` directory;
4. independently copy the parent, or construct an authorized empty successor;
5. apply the transaction and validate the complete namespace;
6. write the complete manifest and sync the staging tree bottom-up;
7. rename staging to `generations/<gen-id>` and sync `generations/`;
8. write and sync the outgoing generation seal;
9. durably replace `store-root.enc` once;
10. reload and validate the selected generation.

A failure before root replacement leaves the old root authoritative. A visible
candidate after a replacement or directory-sync error is commit-uncertain and
enters recovery; callers do not blindly retry. Once the one root rename is
visible and directory-durable, there is no second witness or publication step.

## Passphrase and term rotation

Changing the passphrase also replaces the current data-encryption term:

1. authenticate and seal the outgoing generation;
2. retain its exact seal and manifest buffers;
3. create a fresh random term and successor keyring;
4. preserve historical keys and exact anchors, adding the outgoing anchor;
5. stage an empty successor;
6. read every source member once and verify it against the retained seal;
7. re-encrypt term envelopes and re-sign integrity sidecars under the new term;
8. validate and publish the complete successor;
9. replace `store-root.enc` with the new wrapped keyring and selector in one
   durable operation;
10. update the configured passphrase helper and reload.

Helper update failure is a post-commit warning. It never rolls the store back.
There is no pending rotation, resumable rewrap, rotation snapshot, rotation
baseline, or unlock-time completion pass.

Retained generations are not rewritten during rotation. Exact historical
anchors and anchor-gated reads preserve historical least authority.

## Restore rollback

Credential restore may add a strict `rollback_capability` to its manifest. The
capability binds the originating operation, archive digest, authenticated
source generation, clean-cutover decision, and exact inventory authority.

Passphrase change carries it only when the outgoing live inventory still
matches its effective authenticated authority. Routine mutations cause that
comparison to fail. Rollback reconstructs authorized source content into a new
current-term successor; it never repoints the root at historical ciphertext.

## Reconciliation and quarantine

Reconciliation first authenticates the root and validates its selected
generation. Until that succeeds, it deletes nothing.

- Incomplete `.staging-*` directories and durable-write temporary files have
  never carried authority and are removed.
- Sealed, referenced, and declared-parent generations are retained.
- A complete, non-current, unsealed, unreferenced final directory is ambiguous:
  it may be crashed-mint residue or newer state orphaned by restoration of an
  older authentic root. It is classified and quarantined, never adopted or
  deleted.

Quarantine eligibility requires a valid ID, strict complete manifest, closed
regular-file-only layout, bounded enumeration, and live inventory digests.
At-mint mismatch is recorded but is not a veto because a formerly selected
generation may have legitimate post-mint mutations.

Available term validation is classification, not authority. Known-term checks
are recorded as `verified` or `failed`; a member whose term is absent from the
current keyring is `term_unavailable`. All remain relocatable when structural
and bounded checks pass. This is essential when an old root restored across a
passphrase change lacks the orphan's newer term.

A candidate that cannot be safely parsed, enumerated, or bounded remains in
place. Reconciliation and further mints fail closed until authenticated
operator remediation. Quarantine capacity overflow behaves the same way.
Explicit removal of an in-place unvalidatable final directory uses the
separate `identity.generation.abandoned.discard` action, explicit confirmation,
and a durable intent audit. It refuses current, rollback-parent, and sealed
generation state.

Eligible candidates are atomically renamed to
`quarantine/generations/<gen-id>` and both parent directories are synced.
Quarantine is bounded to eight generations and 1 GiB. Live pruning requires
the stable `identity.generation.quarantine.prune` action, explicit
confirmation, and durable intent audit before deletion.

A crashed changepass before root replacement can leave its complete successor
in quarantine. That ciphertext is non-authoritative; a later changepass remains
blocked until an authenticated operator prunes it.

If an orphan crossed a passphrase change, quarantine preserves its ciphertext
but does not imply it is decryptable with the restored root or passphrase. The
newer overwritten root must also be recovered from a coherent snapshot.

## Deleted archive capacity

The selected generation's deleted archive is bounded by release-contract
constants:

- 4,096 entries;
- 256 MiB total encoded bytes;
- warning thresholds reserve one entry and one maximum standalone-envelope
  allocation for an emergency deletion.

If a release ever lowers these layout constants below an existing store's
usage, generation minting and changepass refuse until authenticated archive
prune restores compliance. The health and status surfaces retain a warning
whenever the emergency reserve is consumed.

Deletes preflight the exact append and fail before active-state mutation if the
hard bound would be exceeded. Mints check the parent before staging and the
successor after apply. An over-limit selected generation blocks ordinary
validation, mint, and passphrase change until pruned.

`apadmin archive list` reports exact usage and the reserve warning.
`apadmin archive prune --confirm <deleted/path>...` accepts only canonical
`deleted/keys/*.key|*.sen` and `deleted/keytypes/*.template` selections. It
requires `identity.archive.prune`, a recovery-capable authenticated runtime,
and durable intent audit before mutation. It changes only the selected
generation; retained copies disappear only with retained-generation pruning.

## Recovery and restoration

Keyring unwrap remains independent of selected-generation health. A valid root
and passphrase with damaged selected state enters authenticated recovery with
signing blocked. Invalid or absent root authority requires `apstore rebuild`;
the implementation never chooses the newest-looking generation.

Credential recovery restore can repair only explicitly selected credential
damage when all destination authority outside those credentials validates.
Damage to policy, node-role integrity, key types/templates, deleted archives,
unselected credentials, or the selected directory itself is not repaired by
inventing authority; restore refuses and directs the operator to rebuild.

Filesystem restoration of `identities/default/` is stopped-signer and
all-or-nothing. Restoring only `store-root.enc`, only generation directories,
or files from independently captured snapshots is unsupported. Quarantine
prevents destructive cleanup after such a mistake but does not make a mixed
restore valid.

## Security invariants

- One root selects exactly one published generation and one current term.
- The durable root is wholly old or wholly new after a crash.
- A root never selects an unpublished or unsynced generation.
- Every changepass successor term consumer uses the new current term.
- Every old-term input promoted during changepass matches the exact outgoing
  seal buffer and inventory entry.
- Historical terms require exact active-root anchors.
- Non-current generations are immutable.
- Invalid selection authority never triggers automatic adoption or signing.
- Wrapped key authority and generation selection change in one rename.
- Restore rollback eligibility is carried only after an authenticated clean
  decision.
- Credential recovery never fabricates destination authority.
- Deleted-archive count and bytes remain within closed release bounds.
- Ambiguous complete publications are quarantined or preserved, never
  automatically adopted or destroyed.
- Quarantine cannot influence signing, history, rollback, or selection.

The commit and substitution properties are modeled in
[`formal/store_root_commit.tla`](formal/store_root_commit.tla). The normal
configuration checks the invariants; `store_root_commit_negative.cfg` is an
expected-failure control that removes exact outgoing-seal verification.
