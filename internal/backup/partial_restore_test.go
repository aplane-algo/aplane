// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/genstore"
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

// One credential this release cannot admit refuses a whole-archive restore,
// and verify reports its policy as one with no credential. A selection that
// leaves it out restores; one that names it, or names an address the archive
// lacks, is refused.
func TestMixedArchiveIsAllOrNothing(t *testing.T) {
	ed25519signerreg.RegisterSigner()
	paths := mintFirstGenerationForBackupTest(t, storepaths.NewPaths(t.TempDir()))
	archive := writeMixedArchiveForTest(t, paths)

	report, err := DeepVerifyBackupBytes(archive.root, admissionPassphrase)
	if err != nil {
		t.Fatalf("DeepVerifyBackupBytes() error = %v", err)
	}
	var verified []string
	for _, result := range report.Results {
		line := result.FileName + ": ok"
		if !result.Valid {
			line = result.FileName + ": " + result.Error
		}
		verified = append(verified, line)
	}
	slices.Sort(verified)
	wantVerified := []string{
		archive.bad + ".apb: " + unknownFieldReason,
		archive.good + ".apb: ok",
		"policies/" + archive.bad + ".apb: policy has no credential in the archive",
		"policies/" + archive.good + ".apb: ok",
	}
	slices.Sort(wantVerified)
	if !slices.Equal(verified, wantVerified) || report.FailedFiles != 2 || report.TotalFiles != 4 {
		t.Fatalf("verify = %q (failed %d of %d), want %q", verified, report.FailedFiles, report.TotalFiles, wantVerified)
	}

	for _, tc := range []struct {
		name      string
		selectors []string
		want      string
	}{
		{"whole archive", nil, "validate backup credential " + archive.bad + ": " + unknownFieldReason},
		{"selection naming it", []string{archive.bad}, "validate backup credential " + archive.bad + ": " + unknownFieldReason},
		{"selection naming a missing address", []string{"MISSING"}, "validate backup credential MISSING: read backup file: "},
	} {
		set, err := LoadManagedRestoreSet(paths, archive.managed, tc.selectors, admissionPassphrase, noderole.RoleSigner)
		set.ZeroSecrets()
		if err == nil || !strings.HasPrefix(err.Error(), tc.want) || !ArchiveAuthenticated(err) {
			t.Fatalf("%s: LoadManagedRestoreSet() error = %v, want prefix %q", tc.name, err, tc.want)
		}
	}
	set, err := LoadManagedRestoreSet(paths, archive.managed, []string{archive.good}, admissionPassphrase, noderole.RoleSigner)
	if err != nil {
		t.Fatalf("LoadManagedRestoreSet(good) error = %v", err)
	}
	defer set.ZeroSecrets()
	if len(set.Entries) != 1 || set.Entries[0].Selector() != archive.good || set.Entries[0].Policy == nil {
		t.Fatalf("selected set = %+v", set.Entries)
	}

	preview, err := PreviewRestoreWithNodeRole(paths, archive.managed, admissionPassphrase, noderole.RoleSigner)
	if err != nil {
		t.Fatalf("PreviewRestoreWithNodeRole() error = %v", err)
	}
	wantKeys := map[string]RestoreKeyInfo{
		archive.good: {Address: archive.good, KeyType: "ed25519", HasPolicy: true},
		archive.bad:  {Address: archive.bad, Error: unknownFieldReason},
	}
	if len(preview.Keys) != 2 {
		t.Fatalf("preview keys = %+v", preview.Keys)
	}
	for _, key := range preview.Keys {
		if key != wantKeys[key.Address] {
			t.Fatalf("preview key = %+v, want %+v", key, wantKeys[key.Address])
		}
	}
	if want := []RestoreError{{Address: archive.bad, Error: unknownFieldReason}}; !slices.Equal(preview.Errors, want) {
		t.Fatalf("preview errors = %+v, want %+v", preview.Errors, want)
	}

	active, err := genstore.Resolve(paths)
	if err != nil {
		t.Fatal(err)
	}
	kr := cryptotest.Keyring(t, testExportMasterKey)
	keysDir := ResolveBackupKeysDir(archive.root)
	if _, err := RestoreForRebuild(active, noderole.RoleSigner, keysDir, archive.bad, kr, admissionPassphrase, nil); err == nil || err.Error() != unknownFieldReason {
		t.Fatalf("RestoreForRebuild(bad) error = %v, want %q", err, unknownFieldReason)
	}
}
