// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
	sigverify "github.com/aplane-algo/aplane/internal/sigconstruction/verify"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/storepaths"
	falconops "github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	lsigsignerreg "github.com/aplane-algo/aplane/lsig/signerreg"
)

// Exercise real encrypted restore and signature verification through production
// registration. Neither a standalone type's enablement nor its creation template
// should be required to recover the saved signing authority: a plain program's
// key restores and signs on a node that never enabled the plain host.
func TestPlainProgramRestoresAndSignsExistingCredentials(t *testing.T) {
	lsigsignerreg.RegisterSigner()
	for _, base := range []string{"aplane.falcon1024.v1", "aplane.ed25519.v1"} {
		t.Run(base, func(t *testing.T) {
			if keytypecatalog.IsDefaultEnabled(base) {
				t.Fatal("fixture must exercise a type this node has not enabled")
			}
			var pub, priv []byte
			if base == "aplane.falcon1024.v1" {
				var err error
				pub, priv, err = falconops.New(nil).GenerateKeypair(bytes.Repeat([]byte{0x42}, 64))
				if err != nil {
					t.Fatal(err)
				}
			} else {
				priv = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
				pub = priv[ed25519.SeedSize:]
			}
			defer crypto.ZeroBytes(priv)
			for _, keyType := range []string{base, "test.retired-template.v1"} {
				t.Run(keyType, func(t *testing.T) {
					paths := mintFirstGenerationForBackupTest(t, storepaths.NewPaths(t.TempDir()))
					payload := keystest.DSALSigKeyJSON(t, keyType, base, pub, priv, saltedLogicSigBytecodeForTest(), saltCounterForTest)
					defer crypto.ZeroBytes(payload)
					parsed, err := keys.ParsePayload(payload)
					if err != nil {
						t.Fatal(err)
					}
					address, err := parsed.Selector()
					parsed.ZeroSecrets()
					if err != nil {
						t.Fatal(err)
					}
					archiveDir := t.TempDir()
					passphrase := []byte("restore-internal-provider-test")
					if err := writeStandaloneBackupFile(filepath.Join(archiveDir, address+".apb"), payload, passphrase); err != nil {
						t.Fatal(err)
					}
					kr := cryptotest.Keyring(t, testExportMasterKey)
					restorer := NewRestorer(paths).WithNodeRole(noderole.RoleSigner)
					if restoredType, err := restorer.RestoreKey(archiveDir, address, kr, passphrase); err != nil || restoredType != keyType {
						t.Fatalf("RestoreKey() = %s, %v", restoredType, err)
					}
					file := filepath.Join(genstoretest.Active(t, paths).KeysDir(), address+keys.AccountKeyExtension)
					if _, err := os.Stat(file); err != nil {
						t.Fatal(err)
					}
					data, err := keys.ReadDecryptedKeyJSONWithKeyring(file, kr)
					if err != nil {
						t.Fatal(err)
					}
					defer crypto.ZeroBytes(data)
					stored, err := keys.ParsePayload(data)
					if err != nil {
						t.Fatal(err)
					}
					defer stored.ZeroSecrets()
					if restoredAddress, err := stored.Selector(); err != nil || restoredAddress != address || stored.KeyType != keyType || stored.BaseKeyType != base || !bytes.Equal(stored.LogicSigBytecode, saltedLogicSigBytecodeForTest()) {
						t.Fatal("restore changed stored account authority")
					}
					if _, exists, err := keytypestate.Get(paths, base); err != nil || exists {
						t.Fatal("restore enabled an internal provider")
					}
					provider := signing.GetProviderForKey(stored.KeyType, stored.BaseKeyType)
					if provider == nil {
						t.Fatal("restored signing provider unavailable")
					}
					material, err := provider.LoadKeyMaterial(signing.ProviderKey{Type: stored.KeyType, BaseKeyType: stored.BaseKeyType, PrivateKey: stored.PrivateKey})
					if err != nil {
						t.Fatal(err)
					}
					defer provider.ZeroKey(material)
					// The keystore stamps durable routing metadata after loading.
					material.BaseKeyType = stored.BaseKeyType
					message := []byte("restored internal signing authority")
					signature, err := provider.SignMessage(material, message)
					if err != nil {
						t.Fatal(err)
					}
					if base == "aplane.falcon1024.v1" {
						if err := sigverify.Verify(sigconstruction.Falcon1024(), pub, message, signature); err != nil {
							t.Fatal(err)
						}
					} else if !ed25519.Verify(pub, message, signature) {
						t.Fatal("restored Ed25519 signature did not verify")
					}
				})
			}
		})
	}
}
