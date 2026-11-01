// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storevalidate_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/asasetstore"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/lsig/clientreg"
)

func TestRecoveryDestinationRefusesDamageOutsideSelectedCredential(t *testing.T) {
	clientreg.RegisterClient()
	tests := map[string]func(t *testing.T, active storepaths.GenPaths){
		"policy sidecar": func(t *testing.T, active storepaths.GenPaths) {
			writeDamage(t, active.DefaultPolicyIntegritySidecar())
		},
		"node-role sidecar": func(t *testing.T, active storepaths.GenPaths) {
			writeDamage(t, active.NodeRoleIntegritySidecar())
		},
		"unselected credential": func(t *testing.T, active storepaths.GenPaths) {
			writeDamage(t, filepath.Join(active.KeysDir(), "UNSELECTED.key"))
		},
		"key-type namespace": func(t *testing.T, active storepaths.GenPaths) {
			if err := os.RemoveAll(active.KeyTypeRecordsDir()); err != nil {
				t.Fatal(err)
			}
		},
		"deleted archive": func(t *testing.T, active storepaths.GenPaths) {
			writeDamage(t, filepath.Join(active.DeletedKeysDir(), "BAD.key"))
		},
		"asa set sidecar without its set": func(t *testing.T, active storepaths.GenPaths) {
			writeDamage(t, active.ASASetIntegritySidecar())
		},
		"unauthenticated asa set": func(t *testing.T, active storepaths.GenPaths) {
			writeDamage(t, active.ASASetPath())
			writeDamage(t, active.ASASetIntegritySidecar())
		},
	}
	for name, damage := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			paths := storepaths.NewPaths(root)
			passphrase := []byte("storevalidate-test-passphrase")
			if _, err := storeinit.Initialize(passphrase, storeinit.Options{ValidateCandidate: storevalidate.FirstGeneration,
				DataDir: root, Paths: paths, Role: noderole.RoleSigner,
			}); err != nil {
				t.Fatal(err)
			}
			active, kr, err := genstore.ResolveStoreRoot(paths, passphrase)
			if err != nil {
				t.Fatal(err)
			}
			defer kr.Zero()
			damage(t, active)
			err = storevalidate.RecoveryDestination(storevalidate.Options{
				Paths: paths, Candidate: active, Keyring: kr,
				ExpectedRole: noderole.RoleSigner, DataDir: root,
				Config: &serverconfig.ServerConfig{},
			}, map[string]bool{"REPAIR": true})
			if err == nil {
				t.Fatal("RecoveryDestination() accepted damaged authority")
			}
		})
	}
}

func writeDamage(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A valid ASA set passes candidate validation; the same store with the set's
// sidecar damaged does not.
func TestCandidateAuthenticatesTheASASet(t *testing.T) {
	clientreg.RegisterClient()
	root := t.TempDir()
	paths := storepaths.NewPaths(root)
	passphrase := []byte("storevalidate-test-passphrase")
	if _, err := storeinit.Initialize(passphrase, storeinit.Options{ValidateCandidate: storevalidate.FirstGeneration,
		DataDir: root, Paths: paths, Role: noderole.RoleSigner,
	}); err != nil {
		t.Fatal(err)
	}
	active, kr, err := genstore.ResolveStoreRoot(paths, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	set, err := asaset.New([]asaset.Entry{{
		Identity:              asaset.Identity{Genesis: asaset.GenesisHash{1}, AssetID: 7},
		UnitName:              "XYZ",
		Decimals:              2,
		Creator:               types.Address{3}.String(),
		ConfirmedAt:           time.Unix(1_785_200_000, 0),
		NetworkAtConfirmation: "private-dev",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := asasetstore.Write(active, set, kr, time.Unix(1_785_200_000, 0)); err != nil {
		t.Fatal(err)
	}
	opts := storevalidate.Options{
		Paths: paths, Candidate: active, Keyring: kr,
		ExpectedRole: noderole.RoleSigner, DataDir: root,
		Config: &serverconfig.ServerConfig{},
	}
	if err := storevalidate.Candidate(opts); err != nil {
		t.Fatalf("Candidate() with a valid asa set error = %v", err)
	}
	writeDamage(t, active.ASASetIntegritySidecar())
	if err := storevalidate.Candidate(opts); err == nil || !strings.Contains(err.Error(), "asa set") {
		t.Fatalf("Candidate() with a damaged asa set sidecar error = %v", err)
	}
}

// Admission is for submitted documents only: a generation whose stored
// default names an unknown network and an asset outside the set, as one
// written before admission was enforced might, still validates, so restore,
// rollback and rotation keep it.
func TestCandidateKeepsDocumentsTheNodeWouldNotAdmit(t *testing.T) {
	clientreg.RegisterClient()
	root := t.TempDir()
	paths := storepaths.NewPaths(root)
	passphrase := []byte("storevalidate-test-passphrase")
	if _, err := storeinit.Initialize(passphrase, storeinit.Options{ValidateCandidate: storevalidate.FirstGeneration,
		DataDir: root, Paths: paths, Role: noderole.RoleSigner,
	}); err != nil {
		t.Fatal(err)
	}
	active, kr, err := genstore.ResolveStoreRoot(paths, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	legacy := policytest.MustDocument(noderole.RoleSigner, policy.DefaultKey,
		`{"limits": {"mainet": {"algo": {"reject_above": "1"}}, "mainnet": {"asa:999999": {"reject_above": "1"}}}}`)
	if err := policy.WriteDefault(active, noderole.RoleSigner, []byte(legacy), kr, time.Unix(1_785_200_000, 0)); err != nil {
		t.Fatal(err)
	}
	if err := storevalidate.Candidate(storevalidate.Options{
		Paths: paths, Candidate: active, Keyring: kr,
		ExpectedRole: noderole.RoleSigner, DataDir: root, Config: &serverconfig.ServerConfig{},
	}); err != nil {
		t.Fatalf("Candidate() with a legacy document = %v, want it valid", err)
	}
}
