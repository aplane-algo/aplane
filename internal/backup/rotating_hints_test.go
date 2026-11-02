// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/stagetable"
	"github.com/aplane-algo/aplane/internal/storepaths"
	wots "github.com/aplane-algo/aplane/lsig/rotatingtriplewots/signerreg"
)

func TestRotatingHintArchiveRestoreAndRebuild(t *testing.T) {
	wots.Register()
	var seed rotatinghybrid.Seed
	seed[0] = 19
	defer crypto.ZeroBytes(seed[:])
	var genesis [32]byte
	genesis[0] = 7
	payload, account, err := wots.NewKeyPayload(&seed, genesis)
	if err != nil {
		t.Fatal(err)
	}
	defer payload.ZeroSecrets()
	data, err := keys.MarshalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(data)
	paths := mintFirstGenerationForBackupTest(t, storepaths.NewPaths(t.TempDir()))
	kr := cryptotest.Keyring(t, testExportMasterKey)
	sealed, err := kr.Seal(data, crypto.AccountKeyContext(account))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys.AccountKeyFilePathActive(genstoretest.Active(t, paths), account), sealed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := noderole.SaveInitial(paths, noderole.RoleSigner, timeForBackupTest()); err != nil {
		t.Fatal(err)
	}
	round := uint64(123)
	hint := RotatingStageHint{Stage: 50000, ObservedRound: &round, KeyType: payload.KeyType, GenesisHash: hex.EncodeToString(genesis[:])}
	req := testCreateKeysArchiveRequest(paths, BuildManagedArchivePath(paths, "20261102-010203"), nil, noderole.RoleSigner, kr)
	req.RotatingStageHints = map[string]RotatingStageHint{account: hint, "not-selected": hint}
	if _, err := CreateKeysArchive(req); err != nil {
		t.Fatal(err)
	}
	root, cleanup, err := PrepareRestoreSource(req.ArchivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	manifest, err := OpenSealedManifest(root, req.ExportPassphrase)
	if err != nil || len(manifest.RotatingStageHints) != 1 {
		t.Fatalf("manifest: %v %+v", err, manifest.RotatingStageHints)
	}
	set, err := LoadManagedRestoreSet(paths, req.ArchivePath, nil, req.ExportPassphrase, noderole.RoleSigner)
	if err != nil {
		t.Fatal(err)
	}
	defer set.ZeroSecrets()
	if len(set.Entries) != 1 || set.Entries[0].StageHint == nil || set.Entries[0].StageHint.Stage != 50000 {
		t.Fatal("restore lost candidate")
	}
	hints, err := LoadRebuildHints(root, nil, req.ExportPassphrase)
	if err != nil || len(hints) != 1 {
		t.Fatalf("rebuild hints: %v %+v", err, hints)
	}
	tables := stagetable.NewStore(storepaths.NewPaths(t.TempDir()))
	PublishRotatingHints(tables, hints, t.Logf)
	addr, _ := types.DecodeAddress(account)
	table, err := tables.Table(addr, genesis[:], nil, payload.KeyType)
	if err != nil || table.Len() != 0 || table.RecoveryHint() == nil || table.NextCandidate() != 50000 {
		t.Fatalf("restored hint must not add trusted addresses: %v", err)
	}
	// A newer local observation wins over this older backup.
	newer := round + 1
	if err := table.SetHint(stagetable.Hint{Stage: 50003, Round: &newer, Source: "local_observation"}); err != nil {
		t.Fatal(err)
	}
	tables.Invalidate()
	PublishRotatingHints(tables, hints, t.Logf)
	table, err = tables.Table(addr, genesis[:], nil, payload.KeyType)
	if err != nil || table.RecoveryHint().Stage != 50003 {
		t.Fatal("old backup replaced newer local observation")
	}
	// Identity mismatches are ignored without changing credential authority.
	for _, bad := range []RotatingStageHint{
		{Stage: 50000, KeyType: "wrong", GenesisHash: hint.GenesisHash},
		{Stage: 50000, KeyType: hint.KeyType, GenesisHash: "wrong"},
	} {
		if h := validatedRotatingHint(set.Entries[0], map[string]RotatingStageHint{account: bad}); h != nil {
			t.Fatal("wrong credential hint accepted")
		}
	}
}
