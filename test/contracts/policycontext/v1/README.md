# Policy context digests and the node context file

`digests.json` pins the canonical encoding behind `context_sha256` and
`snapshot_sha256` (`internal/policycontext`). Each case gives a context's
parts and the digests they must produce.

Fields are written in a fixed order. A text or byte string is an unsigned
LEB128 varint length followed by its bytes; a number is a big-endian uint64.

- `context_sha256` is the SHA-256, in lowercase hex, of:
  1. the text `aplane.policy-context.v1`;
  2. the role;
  3. the rules version;
  4. the network count, then each token in byte order, each followed by its
     32-byte genesis hash;
  5. the asset count, then each asset sorted by genesis hash bytes and then
     ID: its genesis hash, its ID, its origin, its decimals, its unit name and
     its name.
- `snapshot_sha256` is the SHA-256 of the text `aplane.policy-snapshot.v1`,
  then the context digest text, then the policy set digest text.

Confirmation times, the token an asset was confirmed under, and its creator
are not part of the context's meaning and are not encoded. To re-record after
an intended encoding change, which is a contract change:

```bash
go test ./internal/policycontext -run TestDigestFixtures -update-digests
```

## Node context file

`node-context.json` pins the `aplane.policy-node-context.v1` file an export
writes as `.appolicy/node.json` beside the policy documents
(`policycontext.Export`). It holds:

- `exported_at` (RFC 3339, whole seconds, UTC), `role` and `rules_version`;
- `networks`: every network token with the genesis hash it names, sorted by
  token;
- `assets`: the effective ASA table, built-ins and confirmations, sorted as
  for the digest, each with `genesis_hash`, `asset_id`, `name`, `unit_name`,
  `decimals` and `origin`;
- `context_sha256`, the digest above of those parts;
- `baseline`: the node's documents at export as `key` and exact-byte
  `sha256`, sorted by key, with their `policy_set_sha256` and the composite
  `snapshot_sha256`.

A reader recomputes every digest from the file's own contents and refuses a
file whose digests do not match, an unknown field, another format or rules
version, a token listed twice, or two tokens naming one chain. The file is
an offline copy, not an authority: the digests catch damage and hand edits,
and an apply still checks the node's live snapshot. To re-record after an
intended format change, which is a contract change:

```bash
go test ./internal/policycontext -run TestExportFixture -update-digests
```
