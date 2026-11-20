// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"bytes"
	"os"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/storepaths"
	slh "github.com/aplane-algo/aplane/lsig/rotatingtripleslhdsa/signerreg"
	wots "github.com/aplane-algo/aplane/lsig/rotatingtriplewotsc/signerreg"
	xmss "github.com/aplane-algo/aplane/lsig/rotatingtriplexmss/signerreg"
)

// TestRotatingArchiveRestoreKeepsTheAccount sends a rotating aplane key of
// each family through the encrypted archive and back. The restored key has
// the same type, seed and network, and its first stage is the account's
// address, with no stage cache carried in the archive.
func TestRotatingArchiveRestoreKeepsTheAccount(t *testing.T) {
	for _, kind := range []struct {
		keyType  string
		register func()
		payload  func(*rotatinghybrid.Seed, [32]byte) (*keys.Payload, string, error)
	}{
		{rotatingkey.RotatingTripleXmssV1, xmss.Register, xmss.NewKeyPayload},
		{rotatingkey.RotatingTripleWotscV1, wots.Register, wots.NewKeyPayload},
		{rotatingkey.RotatingTripleSlhdsaV1, slh.Register, slh.NewKeyPayload},
	} {
		t.Run(kind.keyType, func(t *testing.T) {
			kind.register()
			var seed rotatinghybrid.Seed
			seed[0] = 137
			defer seed.Zero()
			var genesis [32]byte
			genesis[0] = 11
			payload, account, err := kind.payload(&seed, genesis)
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
			if err := os.WriteFile(keystest.AccountKeyFilePath(genstoretest.Active(t, paths), account), sealed, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := noderole.SaveInitial(paths, noderole.RoleSigner, timeForBackupTest()); err != nil {
				t.Fatal(err)
			}
			req := testCreateKeysArchiveRequest(paths, BuildManagedArchivePath(paths, "20261115-010203"), nil, noderole.RoleSigner, kr)
			if _, err := CreateKeysArchive(req); err != nil {
				t.Fatal(err)
			}
			set, err := LoadManagedRestoreSet(paths, req.ArchivePath, nil, req.ExportPassphrase, noderole.RoleSigner)
			if err != nil {
				t.Fatal(err)
			}
			defer set.ZeroSecrets()
			if len(set.Entries) != 1 {
				t.Fatalf("restore set has %d keys, want 1", len(set.Entries))
			}
			restored, err := keys.ParsePayload(set.Entries[0].keyJSON())
			if err != nil {
				t.Fatal(err)
			}
			defer restored.ZeroSecrets()
			if restored.KeyType != kind.keyType || !bytes.Equal(restored.PrivateKey, seed[:]) || !bytes.Equal(restored.GenesisHash, genesis[:]) {
				t.Fatal("the restored key's type, seed or network differs")
			}
			ops, err := signing.GetRotatingStageOps(kind.keyType)
			if err != nil {
				t.Fatal(err)
			}
			first, err := ops.StageAddress(&signing.RotatingKeyMaterial{Seed: restored.PrivateKey, GenesisHash: restored.GenesisHash}, 0)
			if err != nil {
				t.Fatal(err)
			}
			if first.String() != account {
				t.Fatalf("the restored key's first stage is %s, want the account %s", first, account)
			}
		})
	}
}
