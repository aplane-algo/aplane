// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storevalidate_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/lsig"
)

func TestRecoveryDestinationRefusesDamageOutsideSelectedCredential(t *testing.T) {
	lsig.RegisterClient()
	tests := map[string]func(t *testing.T, active storepaths.GenPaths){
		"policy sidecar": func(t *testing.T, active storepaths.GenPaths) {
			writeDamage(t, active.PolicyIntegritySidecar())
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
	}
	for name, damage := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			paths := storepaths.NewPaths(root)
			passphrase := []byte("storevalidate-test-passphrase")
			if _, err := storeinit.Initialize(passphrase, storeinit.Options{
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
