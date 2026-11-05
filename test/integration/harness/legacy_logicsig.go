// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package harness

import (
	"context"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storepaths"
	lsigsignerreg "github.com/aplane-algo/aplane/lsig/signerreg"
)

// legacyFixtureSeedSizes lists the plain LogicSig types this fixture can build
// and the seed each one derives from. A newly internal provider is not added
// implicitly: it needs its own derivation input here.
var legacyFixtureSeedSizes = map[string]int{
	"aplane.falcon1024.v1": 64,
	"aplane.ed25519.v1":    32,
}

// IsLegacyLogicSigFixture reports whether keyType enters a test signer through
// RestoreLegacyLogicSig rather than through generation.
func IsLegacyLogicSigFixture(keyType string) bool {
	_, ok := legacyFixtureSeedSizes[keyType]
	return ok
}

// RestoreLegacyLogicSig supplies a pre-existing plain LogicSig fixture through
// encrypted backup restore. Public generation/import of these internal types
// must stay refused. A nil seed selects fresh test material; a supplied seed
// pins the existing derivation contract without exposing a mnemonic-import API.
func (v *ApAdminHarness) RestoreLegacyLogicSig(keyType string, seed []byte) (string, error) {
	seedSize, ok := legacyFixtureSeedSizes[keyType]
	if !ok {
		return "", fmt.Errorf("unsupported legacy fixture key type %s", keyType)
	}
	lsigsignerreg.RegisterSigner()
	// This derivation runs in the test process, rather than in apsigner, so
	// configure its providers with the same integration compiler endpoint.
	algodURL, algodToken, err := integrationAlgodEndpoint(IntegrationNetwork())
	if err != nil {
		return "", err
	}
	client, err := algod.MakeClient(algodURL, algodToken)
	if err != nil {
		return "", err
	}
	lsigprovider.ConfigureAlgodClient(client)
	if seed == nil {
		seed = make([]byte, seedSize)
		if _, err := rand.Read(seed); err != nil {
			return "", err
		}
		defer crypto.ZeroBytes(seed)
	}
	paths := storepaths.NewPaths(v.t.TempDir())
	kr, active := genstoretest.MintFirstAtomic(v.t, paths, []byte("legacy-fixture-store"))
	defer kr.Zero()
	paths = genstoretest.BindActive(v.t, paths, active)
	if _, _, err := noderole.SaveInitial(paths, noderole.RoleSigner, time.Now()); err != nil {
		return "", err
	}
	generator, err := keygen.GetGenerator(keyType)
	if err != nil {
		return "", err
	}
	result, err := generator.GenerateFromSeed(context.Background(), paths, seed, kr, keyType, nil)
	if err != nil {
		return "", err
	}
	const exportPassphrase = "legacy-fixture-export"
	archive := backup.BuildManagedArchivePath(paths, "legacy-"+result.Address)
	if _, err := backup.CreateKeysArchive(backup.CreateKeysArchiveRequest{
		Paths: paths, ArchivePath: archive, Addresses: []string{result.Address},
		Keyring: kr, ExportPassphrase: []byte(exportPassphrase),
	}); err != nil {
		return "", err
	}
	// Without APSIGNER_PASSPHRASE, apadmin reads the store passphrase from
	// stdin and the export passphrase meant for restore is consumed as it.
	storePassphrase, err := v.testPassphrase()
	if err != nil {
		return "", err
	}
	storeAuth := []string{"APSIGNER_PASSPHRASE=" + storePassphrase}
	if output, err := v.runWithEnv(storeAuth, exportPassphrase+"\n", "backup", "import", archive); err != nil {
		return "", fmt.Errorf("import legacy fixture: %w: %s", err, output)
	}
	if output, err := v.runWithEnv(storeAuth, exportPassphrase+"\n", "restore", "apply", filepath.Base(archive), "--address", result.Address); err != nil {
		return "", fmt.Errorf("restore legacy fixture: %w: %s", err, output)
	}
	return result.Address, nil
}
