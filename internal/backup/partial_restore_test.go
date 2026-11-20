// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	ed25519signerreg "github.com/aplane-algo/aplane/internal/signing/ed25519/signerreg"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// mixedArchive is an archive holding one credential this release admits and
// one whose payload carries a field it does not know, each with a policy of
// its own.
type mixedArchive struct {
	root, managed, good, bad string
}

func writeMixedArchiveForTest(t *testing.T, paths storepaths.Paths) mixedArchive {
	t.Helper()
	root, keysDir := newAdmissionArchive(t)
	good, goodJSON := testEd25519BackupKeyJSON(t)
	bad, badJSON := testEd25519BackupKeyJSON(t)
	sealAdmissionMember(t, keysDir, good, goodJSON, admissionPassphrase)
	sealAdmissionMember(t, keysDir, bad, withExtraFieldForTest(t, badJSON), admissionPassphrase)
	for _, selector := range []string{good, bad} {
		sealAdmissionPolicy(t, root, selector, []byte(policytest.MustDocument(noderole.RoleSigner, selector, "")))
	}
	if err := WriteSealedManifest(root, noderole.RoleSigner, time.Unix(1_700_000_000, 0), admissionPassphrase, nil); err != nil {
		t.Fatal(err)
	}
	managed := BuildManagedArchivePath(paths, fmt.Sprintf("mixed-%d", time.Now().UnixNano()))
	if err := CreateTarGzArchive(root, managed); err != nil {
		t.Fatal(err)
	}
	return mixedArchive{root: root, managed: managed, good: good, bad: bad}
}

// unknownFieldReason is why this release refuses a payload with a field it
// does not know.
const unknownFieldReason = `failed to parse backup credential: incompatible key file format: failed to decode canonical payload: json: unknown field "extra"; restore or regenerate the key file using the current key schema`

// skippedForTest is the one entry a mixed archive skips.
func (a mixedArchive) skippedForTest() []SkippedEntry {
	return []SkippedEntry{{Selector: a.bad, Reason: unknownFieldReason}}
}

// A credential this release cannot admit is skipped with its policy: deep
// verify, a whole-archive restore, its preview and a rebuild admit the other
// credential and list the skipped one, whose policy is never reported as
// one without a credential. Verify still fails the archive.
func TestMixedArchiveSkipsTheInadmissibleCredential(t *testing.T) {
	ed25519signerreg.RegisterSigner()
	paths := mintFirstGenerationForBackupTest(t, storepaths.NewPaths(t.TempDir()))
	archive := writeMixedArchiveForTest(t, paths)
	wantSkipped := archive.skippedForTest()

	report, err := DeepVerifyBackupBytes(archive.root, admissionPassphrase)
	if err != nil {
		t.Fatalf("DeepVerifyBackupBytes() error = %v", err)
	}
	wantVerified := []VerifiedCredential{{Address: archive.good, KeyType: "ed25519", HasPolicy: true}}
	if !slices.Equal(report.Verified, wantVerified) || !slices.Equal(report.Skipped, wantSkipped) {
		t.Fatalf("verify = %+v skipped %+v, want %+v skipped %+v", report.Verified, report.Skipped, wantVerified, wantSkipped)
	}
	wantIncomplete := "1 of 2 credentials would be skipped by restore; first " + archive.bad + ": " + unknownFieldReason
	if err := report.Incomplete(); err == nil || err.Error() != wantIncomplete {
		t.Fatalf("Incomplete() = %v, want %q", err, wantIncomplete)
	}

	set, err := LoadManagedRestoreSet(paths, archive.managed, nil, admissionPassphrase, noderole.RoleSigner)
	if err != nil {
		t.Fatalf("LoadManagedRestoreSet() error = %v", err)
	}
	defer set.ZeroSecrets()
	if len(set.Entries) != 1 || set.Entries[0].Selector() != archive.good || set.Entries[0].Policy == nil || !slices.Equal(set.Skipped, wantSkipped) {
		t.Fatalf("restore set = %+v skipped %+v", set.Entries, set.Skipped)
	}

	rebuild, err := LoadRebuildSet(archive.root, nil, admissionPassphrase, noderole.RoleSigner)
	if err != nil {
		t.Fatalf("LoadRebuildSet() error = %v", err)
	}
	defer rebuild.ZeroSecrets()
	if len(rebuild.Entries) != 1 || rebuild.Entries[0].Selector() != archive.good || !slices.Equal(rebuild.Skipped, wantSkipped) {
		t.Fatalf("rebuild set = %+v skipped %+v", rebuild.Entries, rebuild.Skipped)
	}

	preview, err := PreviewRestoreWithNodeRole(paths, archive.managed, admissionPassphrase, noderole.RoleSigner)
	if err != nil {
		t.Fatalf("PreviewRestoreWithNodeRole() error = %v", err)
	}
	wantKeys := []RestoreKeyInfo{{Address: archive.good, KeyType: "ed25519", HasPolicy: true}}
	if !slices.Equal(preview.Keys, wantKeys) || !slices.Equal(preview.Skipped, wantSkipped) {
		t.Fatalf("preview = %+v skipped %+v", preview.Keys, preview.Skipped)
	}
}

// An explicit selection is never narrowed: one naming a credential admission
// skips, or an address the archive lacks, is refused whole. One that leaves
// the skipped credential out restores.
func TestMixedArchiveSelections(t *testing.T) {
	ed25519signerreg.RegisterSigner()
	paths := mintFirstGenerationForBackupTest(t, storepaths.NewPaths(t.TempDir()))
	archive := writeMixedArchiveForTest(t, paths)
	named := "selected credential cannot be restored: " + archive.bad + ": " + unknownFieldReason

	for _, tc := range []struct {
		name      string
		selectors []string
		want      string
	}{
		{"naming it", []string{archive.bad}, named},
		{"naming it with the other", []string{archive.good, archive.bad}, named},
		{"naming a missing address", []string{"MISSING"}, `backup has no credential "MISSING"`},
		{"naming one twice", []string{archive.good, archive.good}, `duplicate backup selector "` + archive.good + `"`},
	} {
		set, err := LoadManagedRestoreSet(paths, archive.managed, tc.selectors, admissionPassphrase, noderole.RoleSigner)
		if err == nil || err.Error() != tc.want || !ArchiveAuthenticated(err) {
			set.ZeroSecrets()
			t.Fatalf("%s: LoadManagedRestoreSet() error = %v, want %q", tc.name, err, tc.want)
		}
		rebuild, err := LoadRebuildSet(archive.root, tc.selectors, admissionPassphrase, noderole.RoleSigner)
		if err == nil || err.Error() != tc.want {
			rebuild.ZeroSecrets()
			t.Fatalf("%s: LoadRebuildSet() error = %v, want %q", tc.name, err, tc.want)
		}
	}
	var refusal *SkipRefusalError
	_, err := LoadManagedRestoreSet(paths, archive.managed, []string{archive.bad}, admissionPassphrase, noderole.RoleSigner)
	if !errors.As(err, &refusal) || !refusal.Named || !slices.Equal(refusal.Skipped, archive.skippedForTest()) {
		t.Fatalf("refusal = %+v, want the named skipped credential", refusal)
	}

	set, err := LoadManagedRestoreSet(paths, archive.managed, []string{archive.good}, admissionPassphrase, noderole.RoleSigner)
	if err != nil {
		t.Fatalf("LoadManagedRestoreSet(good) error = %v", err)
	}
	defer set.ZeroSecrets()
	if len(set.Entries) != 1 || set.Entries[0].Selector() != archive.good || len(set.Skipped) != 0 {
		t.Fatalf("selected set = %+v skipped %+v", set.Entries, set.Skipped)
	}
}

// The refusal names how many credentials it skipped and the first.
func TestSkipRefusalErrorText(t *testing.T) {
	one := []SkippedEntry{{Selector: "A", Reason: "bad"}}
	two := []SkippedEntry{{Selector: "A", Reason: "bad"}, {Selector: "B", Reason: "worse"}}
	for _, tc := range []struct {
		err  SkipRefusalError
		want string
	}{
		{SkipRefusalError{Skipped: one, Named: true}, "selected credential cannot be restored: A: bad"},
		{SkipRefusalError{Skipped: two, Named: true}, "2 selected credentials cannot be restored; first A: bad"},
		{SkipRefusalError{Skipped: one}, "nothing to restore: the backup's only credential is skipped: A: bad"},
		{SkipRefusalError{Skipped: two}, "nothing to restore: all 2 credentials in the backup are skipped; first A: bad"},
	} {
		if got := tc.err.Error(); got != tc.want {
			t.Fatalf("Error() = %q, want %q", got, tc.want)
		}
	}
}

// rebuildForTest rebuilds selector from the extracted archive at root into
// active for role, as apstore rebuild does, sealing a manifest for role
// first when the archive has none. It returns the rebuilt key type.
func rebuildForTest(t *testing.T, active storepaths.GenPaths, role noderole.Role, root, selector string, kr *crypto.Keyring, passphrase []byte) (string, error) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(root, ManifestFileName)); os.IsNotExist(err) {
		if err := WriteSealedManifest(root, role, time.Unix(1_700_000_000, 0), passphrase, nil); err != nil {
			t.Fatal(err)
		}
	}
	set, err := LoadRebuildSet(root, []string{selector}, passphrase, role)
	if err != nil {
		return "", err
	}
	defer set.ZeroSecrets()
	if err := ApplyRebuildSet(active, role, set, kr); err != nil {
		return "", err
	}
	return set.Entries[0].KeyType(), nil
}
