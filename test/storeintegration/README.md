# Store process integration tests

This package exercises signer storage independently of algod and the shared
`/tmp/aplane-test-env` fixture. Every test starts from a genuine blank signer
data directory, initializes it through `apstore`, and launches real `apsigner`,
offline `apstore`, and live `apadmin` processes.

Run the normal lifecycle and crash matrices with:

```bash
make store-lifecycle-test
make store-crash-test
make store-capacity-test
```

The lifecycle matrix covers generate/import, cryptographic signing, managed
backup export/verification, fresh atomic restore, passphrase rotation,
historical-generation authority, and restart. The crash matrix covers these
durability boundaries:

- `changepass.successor_published`: the complete successor exists but the old
  root remains authoritative; restart accepts only the old passphrase and
  quarantines the abandoned publication.
- `changepass.store_root_replaced`: the new root is authoritative; restart
  accepts only the new passphrase and loads the complete successor without a
  resume protocol.
- `restore.store_root_replaced`: the restored generation is committed but the
  daemon has not reloaded it; restart validates and loads the committed state.
- `restore.reload_started` with error injection: the committed generation
  cannot reload, so signing remains blocked until explicit authenticated
  rollback.

The package also verifies that malformed active credentials put the signer in
recovery mode, block signing, and leave the damaged evidence untouched, and
that interrupted restore cleanup can be explicitly rolled back, an unreadable
credential can be repaired from recovery mode with explicit replacement.
Focused service coverage separately verifies that a rollback generation cannot
itself be rolled back.

The opt-in capacity gate fills the deleted archive to the exact operational
warning threshold, proves the maximum-sized emergency-deletion reserve, runs a
full changepass, and records copy time, re-encryption time, seal size, and
retained disk cost. It writes and processes roughly 256 MiB and is therefore
kept out of ordinary unit-test runs.

Checkpoints exist only in an `apsigner` built with the `storetest` tag. Normal
builds compile a no-op implementation and do not interpret checkpoint
environment variables. The Make targets build the tagged daemon automatically.

To test the exact staged production binaries rather than test-built commands:

```bash
make bin-amd64
make store-release-drill
```

Use `STORE_RELEASE_BIN_DIR=/absolute/path` for downloaded or externally staged
`apsigner`, `apstore`, and `apadmin` binaries. `apstore` performs only offline
initialization and verification; every running-daemon workflow uses `apadmin`.
The drill intentionally avoids
test-only checkpoints and performs initialize, generate, sign, backup, fresh
restore, rotate, restart, and sign again.

The existing `make integration-test-localnet` remains the network acceptance
layer. Its Ed25519 backup/restore case now funds the restored address and submits
a signer-produced transaction, while the changepass case submits and confirms a
transaction after rotation and restart.

Direct `go test ./...` leaves this process suite disabled. Set
`APLANE_STORE_INTEGRATION=1` only when invoking the package deliberately; the
Make targets do this for local and CI runs.
