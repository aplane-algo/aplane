// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"bytes"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	ed25519signerreg "github.com/aplane-algo/aplane/internal/signing/ed25519/signerreg"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// signerStoreForArchiveTest returns a signer store holding count Ed25519
// keys, sorted by address, and the canonical payload of each.
func signerStoreForArchiveTest(t *testing.T, count int) (storepaths.Paths, []string, map[string][]byte) {
	t.Helper()
	ed25519signerreg.RegisterSigner()
	paths := mintFirstGenerationForBackupTest(t, storepaths.NewPaths(t.TempDir()))
	kr := cryptotest.Keyring(t, testExportMasterKey)
	payloads := make(map[string][]byte, count)
	for range count {
		address, keyJSON := testEd25519BackupKeyJSON(t)
		sealed, err := kr.Seal(keyJSON, crypto.AccountKeyContext(address))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keystest.AccountKeyFilePath(genstoretest.Active(t, paths), address), sealed, fsutil.StoreFilePerm); err != nil {
			t.Fatal(err)
		}
		payloads[address] = canonicalPayloadForTest(t, keyJSON)
	}
	if _, err := noderole.SaveInitial(paths, noderole.RoleSigner, timeForBackupTest()); err != nil {
		t.Fatal(err)
	}
	return paths, slices.Sorted(maps.Keys(payloads)), payloads
}

func canonicalPayloadForTest(t *testing.T, keyJSON []byte) []byte {
	t.Helper()
	payload, err := keys.ParsePayload(keyJSON)
	if err != nil {
		t.Fatal(err)
	}
	defer payload.ZeroSecrets()
	canonical, err := keys.MarshalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

// archivePlaintextForTest extracts archive and returns every member by path:
// a credential or policy as the plaintext it decrypts to, any other member as
// nil.
func archivePlaintextForTest(t *testing.T, archive string) map[string][]byte {
	t.Helper()
	root := t.TempDir()
	if err := ExtractTarGzArchive(archive, root); err != nil {
		t.Fatal(err)
	}
	members := make(map[string][]byte)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		members[filepath.ToSlash(rel)] = nil
		if filepath.Ext(path) != ".apb" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		plaintext, err := crypto.DecryptStandaloneLimited(data, []byte("export-passphrase"), maxBackupPolicyEnvelopeBytes)
		if err != nil {
			return err
		}
		members[filepath.ToSlash(rel)] = plaintext
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return members
}

func assertArchiveMembers(t *testing.T, archive string, want map[string][]byte) {
	t.Helper()
	got := archivePlaintextForTest(t, archive)
	want = maps.Clone(want)
	want["README.md"] = nil
	want[ManifestFileName] = nil
	if !maps.EqualFunc(got, want, bytes.Equal) {
		t.Fatalf("archive members = %v, want %v", slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(want)))
	}
}

// A complete backup exports every managed credential, listed in address
// order; a selected backup exports only the selection, listed in request
// order. Each carries the policies of exactly what it exported, and each
// member decrypts to the canonical payload or the policy document.
func TestCreateKeysArchiveExportsTheSelection(t *testing.T) {
	paths, addresses, payloads := signerStoreForArchiveTest(t, 3)
	kr := cryptotest.Keyring(t, testExportMasterKey)
	withPolicy := addresses[1]
	doc := []byte(policytest.MustDocument(noderole.RoleSigner, withPolicy, ""))
	if err := policy.WriteKeyPolicy(activePathsForBackupTest(t, paths), noderole.RoleSigner, withPolicy, doc, kr, timeForBackupTest()); err != nil {
		t.Fatal(err)
	}

	all := BuildManagedArchivePath(paths, "20261120-000001")
	result, err := CreateKeysArchive(testCreateKeysArchiveRequest(paths, all, nil, noderole.RoleSigner, kr))
	if err != nil {
		t.Fatalf("CreateKeysArchive(all) error = %v", err)
	}
	if result.KeyCount != 3 || !slices.Equal(result.Addresses, addresses) || !result.Verified {
		t.Fatalf("CreateKeysArchive(all) = %+v, want %v", result, addresses)
	}
	assertArchiveMembers(t, all, map[string][]byte{
		"apb/" + addresses[0] + ".apb":                payloads[addresses[0]],
		"apb/" + addresses[1] + ".apb":                payloads[addresses[1]],
		"apb/" + addresses[2] + ".apb":                payloads[addresses[2]],
		backupPoliciesDir + "/" + withPolicy + ".apb": doc,
	})

	for i, selection := range [][]string{
		{addresses[2], addresses[0]},
		{addresses[2], "", addresses[1]},
	} {
		selected := BuildManagedArchivePath(paths, fmt.Sprintf("20261120-00001%d", i))
		result, err := CreateKeysArchive(testCreateKeysArchiveRequest(paths, selected, selection, noderole.RoleSigner, kr))
		if err != nil {
			t.Fatalf("CreateKeysArchive(%v) error = %v", selection, err)
		}
		want := slices.DeleteFunc(slices.Clone(selection), func(s string) bool { return s == "" })
		if result.KeyCount != len(want) || !slices.Equal(result.Addresses, want) {
			t.Fatalf("CreateKeysArchive(%v) = %+v, want %v", selection, result, want)
		}
		members := make(map[string][]byte)
		for _, address := range want {
			members["apb/"+address+".apb"] = payloads[address]
		}
		if slices.Contains(want, withPolicy) {
			members[backupPoliciesDir+"/"+withPolicy+".apb"] = doc
		}
		assertArchiveMembers(t, selected, members)
	}
}

// A backup refuses, before any archive exists, a selection it cannot export
// whole: an empty store, an address the store does not hold, and a selector
// held in both filename classes. Ambiguity is refused only where the backup
// would export it.
func TestCreateKeysArchiveRefusals(t *testing.T) {
	kr := cryptotest.Keyring(t, testExportMasterKey)
	empty := mintFirstGenerationForBackupTest(t, storepaths.NewPaths(t.TempDir()))
	if _, err := noderole.SaveInitial(empty, noderole.RoleSigner, timeForBackupTest()); err != nil {
		t.Fatal(err)
	}
	emptyArchive := BuildManagedArchivePath(empty, "20261120-000101")
	_, err := CreateKeysArchive(testCreateKeysArchiveRequest(empty, emptyArchive, nil, noderole.RoleSigner, kr))
	if want := "no managed credential files found in " + activePathsForBackupTest(t, empty).KeysDir(); err == nil || err.Error() != want {
		t.Fatalf("CreateKeysArchive(empty store) error = %v, want %q", err, want)
	}

	paths, addresses, _ := signerStoreForArchiveTest(t, 2)
	ambiguous, clean := addresses[0], addresses[1]
	active := activePathsForBackupTest(t, paths)
	sealed, err := os.ReadFile(filepath.Join(active.KeysDir(), ambiguous+keys.AccountKeyExtension))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(active.KeysDir(), ambiguous+keys.CosignerCredentialExtension), sealed, fsutil.StoreFilePerm); err != nil {
		t.Fatal(err)
	}
	const unknown = "UNKNOWNADDRESSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for _, tc := range []struct {
		name      string
		selection []string
		want      string
	}{
		{"complete", nil, "ambiguous managed credential " + ambiguous + ": " + ambiguous + ".cos and " + ambiguous + ".key"},
		{"selected ambiguous", []string{clean, ambiguous}, "failed to export " + ambiguous + ": ambiguous managed credential " + ambiguous + ": both filename classes are present"},
		{"selected unknown", []string{clean, unknown}, "failed to export " + unknown + ": managed credential not found: " + unknown},
	} {
		archive := BuildManagedArchivePath(paths, "20261120-000102")
		_, err := CreateKeysArchive(testCreateKeysArchiveRequest(paths, archive, tc.selection, noderole.RoleSigner, kr))
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s: CreateKeysArchive error = %v, want %q", tc.name, err, tc.want)
		}
		if _, statErr := os.Lstat(archive); !os.IsNotExist(statErr) {
			t.Fatalf("%s: archive stat error = %v, want no archive", tc.name, statErr)
		}
	}

	archive := BuildManagedArchivePath(paths, "20261120-000103")
	result, err := CreateKeysArchive(testCreateKeysArchiveRequest(paths, archive, []string{clean}, noderole.RoleSigner, kr))
	if err != nil || !slices.Equal(result.Addresses, []string{clean}) {
		t.Fatalf("CreateKeysArchive(unambiguous selection) = %+v, %v", result, err)
	}
}
