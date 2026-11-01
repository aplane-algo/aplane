# Policy context digests

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
