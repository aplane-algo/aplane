// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	ed25519signerreg "github.com/aplane-algo/aplane/internal/signing/ed25519/signerreg"
	"github.com/aplane-algo/aplane/internal/storepaths"
	wotsc "github.com/aplane-algo/aplane/lsig/rotatingtriplewotsc/signerreg"
)

var admissionPassphrase = []byte("export-passphrase")

// admissionOutcome is what each consumer of an archive reports for it: a
// deep verify, loading it for a whole-archive restore, its restore preview,
// and loading it for a rebuild. Each is "refused: <error>" for an archive the
// consumer refuses, or the "skipped <selector>: <reason>" lines of the
// credentials it skips. An empty field admits everything.
type admissionOutcome struct {
	verify, restore, preview, rebuild string
}

func skippedOutcome(skipped []SkippedEntry) string {
	lines := make([]string, len(skipped))
	for i, s := range skipped {
		lines[i] = "skipped " + s.Selector + ": " + s.Reason
	}
	return strings.Join(lines, "\n")
}

func refusedOutcome(err error) string {
	return "refused: " + err.Error()
}

// admissionArchive is one archive root and the credential selector it holds.
type admissionArchive struct {
	root, selector string
}

func newAdmissionArchive(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	keysDir := filepath.Join(root, "apb")
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatal(err)
	}
	return root, keysDir
}

func writeAdmissionMember(t *testing.T, keysDir, selector string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(keysDir, selector+".apb"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func sealAdmissionMember(t *testing.T, keysDir, selector string, plaintext, passphrase []byte) {
	t.Helper()
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, selector+".apb"), plaintext, passphrase); err != nil {
		t.Fatal(err)
	}
}

func sealAdmissionPolicy(t *testing.T, root, selector string, document []byte) {
	t.Helper()
	dir := filepath.Join(root, backupPoliciesDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sealAdmissionMember(t, dir, selector, document, admissionPassphrase)
}

// admissionOutcomes runs one archive through every consumer.
func admissionOutcomes(t *testing.T, paths storepaths.Paths, archive admissionArchive, role noderole.Role, hints map[string]RotatingStageHint) admissionOutcome {
	t.Helper()
	if err := WriteSealedManifest(archive.root, role, time.Unix(1_700_000_000, 0), admissionPassphrase, hints); err != nil {
		t.Fatal(err)
	}
	var outcome admissionOutcome

	if report, err := DeepVerifyBackupBytes(archive.root, admissionPassphrase); err != nil {
		outcome.verify = refusedOutcome(err)
	} else {
		outcome.verify = skippedOutcome(report.Skipped)
	}

	managed := BuildManagedArchivePath(paths, fmt.Sprintf("admission-%d", time.Now().UnixNano()))
	if err := CreateTarGzArchive(archive.root, managed); err != nil {
		t.Fatal(err)
	}
	set, err := LoadManagedRestoreSet(paths, managed, nil, admissionPassphrase, role)
	if err != nil {
		if !ArchiveAuthenticated(err) {
			t.Fatalf("restore error %v does not record the authenticated archive", err)
		}
		outcome.restore = refusedOutcome(err)
	} else {
		outcome.restore = skippedOutcome(set.Skipped)
		set.ZeroSecrets()
	}

	if preview, err := PreviewRestoreWithNodeRole(paths, managed, admissionPassphrase, role); err != nil {
		if !ArchiveAuthenticated(err) {
			t.Fatalf("preview error %v does not record the authenticated archive", err)
		}
		outcome.preview = refusedOutcome(err)
	} else {
		outcome.preview = skippedOutcome(preview.Skipped)
	}

	if set, err := LoadRebuildSet(archive.root, nil, admissionPassphrase, role); err != nil {
		outcome.rebuild = refusedOutcome(err)
	} else {
		outcome.rebuild = skippedOutcome(set.Skipped)
		set.ZeroSecrets()
	}
	return outcome
}

// Every consumer of an archive admits a credential by the same loader: deep
// verify, restore, its preview and rebuild admit, skip and refuse the same
// members and report the same reason. A member that does not read or decrypt
// is damage and refuses the archive; a decrypted credential or policy the
// node cannot admit is skipped, which leaves an archive of one credential
// nothing to restore. The table pins it.
func TestCredentialAdmissionAgreesAcrossVerifyRestoreAndRebuild(t *testing.T) {
	ed25519signerreg.RegisterSigner()
	paths := mintFirstGenerationForBackupTest(t, storepaths.NewPaths(t.TempDir()))
	other, _ := testEd25519BackupKeyJSON(t)

	for _, tc := range []struct {
		name string
		role noderole.Role
		// build writes the archive's members and returns its selector and,
		// for the templates, the selector its payload derives.
		build func(t *testing.T, root, keysDir string) (selector, derived string)
		// refusal is the error every consumer refuses the archive with;
		// damage is the one it refuses a damaged credential member with;
		// skip is why every consumer skips the archive's credential.
		refusal, damage, skip string
	}{
		{
			name: "valid credential",
			build: func(t *testing.T, _, keysDir string) (string, string) {
				address, keyJSON := testEd25519BackupKeyJSON(t)
				sealAdmissionMember(t, keysDir, address, keyJSON, admissionPassphrase)
				return address, address
			},
		},
		{
			name: "plaintext member",
			build: func(t *testing.T, _, keysDir string) (string, string) {
				address, keyJSON := testEd25519BackupKeyJSON(t)
				writeAdmissionMember(t, keysDir, address, keyJSON)
				return address, address
			},
			damage: `decrypt backup file: failed to parse encrypted data: json: unknown field "format_version"`,
		},
		{
			name: "member that is not JSON",
			build: func(t *testing.T, _, keysDir string) (string, string) {
				writeAdmissionMember(t, keysDir, other, []byte("not json"))
				return other, other
			},
			damage: "decrypt backup file: failed to parse encrypted data: invalid character 'o' in literal null (expecting 'u')",
		},
		{
			name: "envelope version 3",
			build: func(t *testing.T, _, keysDir string) (string, string) {
				writeAdmissionMember(t, keysDir, other, []byte(`{"envelope_version":3,"nonce":"","ciphertext":""}`))
				return other, other
			},
			damage: "decrypt backup file: envelope_version 3 not supported by standalone decryption (expected 2)",
		},
		{
			name: "member under another passphrase",
			build: func(t *testing.T, _, keysDir string) (string, string) {
				address, keyJSON := testEd25519BackupKeyJSON(t)
				sealAdmissionMember(t, keysDir, address, keyJSON, []byte("other-passphrase"))
				return address, address
			},
			damage: "decrypt backup file: failed to decrypt data: cipher: message authentication failed",
		},
		{
			name: "pre-release bundle",
			build: func(t *testing.T, _, keysDir string) (string, string) {
				sealAdmissionMember(t, keysDir, other, []byte(`{"backup_bundle":1,"key":{}}`), admissionPassphrase)
				return other, other
			},
			skip: `failed to parse backup credential: incompatible key file format: failed to decode canonical payload: json: unknown field "backup_bundle"; restore or regenerate the key file using the current key schema`,
		},
		{
			name: "unknown payload field",
			build: func(t *testing.T, _, keysDir string) (string, string) {
				address, keyJSON := testEd25519BackupKeyJSON(t)
				sealAdmissionMember(t, keysDir, address, withExtraFieldForTest(t, keyJSON), admissionPassphrase)
				return address, address
			},
			skip: `failed to parse backup credential: incompatible key file format: failed to decode canonical payload: json: unknown field "extra"; restore or regenerate the key file using the current key schema`,
		},
		{
			name: "selector mismatch",
			build: func(t *testing.T, _, keysDir string) (string, string) {
				address, keyJSON := testEd25519BackupKeyJSON(t)
				sealAdmissionMember(t, keysDir, other, keyJSON, admissionPassphrase)
				return other, address
			},
			skip: "selector mismatch: filename={sel} derived={derived}",
		},
		{
			name: "key type the role forbids",
			build: func(t *testing.T, _, keysDir string) (string, string) {
				selector, keyJSON := testCosignerComponentBackupKeyJSON(t)
				sealAdmissionMember(t, keysDir, selector, keyJSON, admissionPassphrase)
				return selector, selector
			},
			skip: `role-forbidden: node role inventory conflict: node role "signer" does not allow key type "aplane.witness-falcon1024.v1"`,
		},
		{
			name: "base key type this runtime lacks",
			build: func(t *testing.T, _, keysDir string) (string, string) {
				keyJSON := keystest.DSALSigKeyJSON(t, "example.missing-provider-lsig.v1", "example.missing-provider.v1",
					[]byte{0x01}, []byte{0x02}, logicSigBytecodeForTest())
				selector := selectorForTest(t, keyJSON)
				sealAdmissionMember(t, keysDir, selector, keyJSON, admissionPassphrase)
				return selector, selector
			},
			skip: "base key type example.missing-provider.v1 is not available for restored key type example.missing-provider-lsig.v1",
		},
		{
			name: "oversized member",
			build: func(t *testing.T, _, keysDir string) (string, string) {
				writeAdmissionMember(t, keysDir, other, make([]byte, crypto.MaxStandaloneEnvelopeBytes+1))
				return other, other
			},
			damage: "read backup file: file exceeds size limit 1048576",
		},
		{
			name: "policy with no credential",
			build: func(t *testing.T, root, keysDir string) (string, string) {
				address, keyJSON := testEd25519BackupKeyJSON(t)
				sealAdmissionMember(t, keysDir, address, keyJSON, admissionPassphrase)
				sealAdmissionPolicy(t, root, other, []byte(policytest.MustDocument(noderole.RoleSigner, other, "")))
				return address, address
			},
			refusal: "backup policy " + other + " has no credential in the archive",
		},
		{
			name: "policy that does not decode",
			build: func(t *testing.T, root, keysDir string) (string, string) {
				address, keyJSON := testEd25519BackupKeyJSON(t)
				sealAdmissionMember(t, keysDir, address, keyJSON, admissionPassphrase)
				sealAdmissionPolicy(t, root, address, []byte("{}"))
				return address, address
			},
			skip: "backup policy for {sel}: {policyErr}",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			role := tc.role
			if role == "" {
				role = noderole.RoleSigner
			}
			root, keysDir := newAdmissionArchive(t)
			selector, derived := tc.build(t, root, keysDir)
			got := admissionOutcomes(t, paths, admissionArchive{root: root, selector: selector}, role, nil)
			replacer := strings.NewReplacer("{sel}", selector, "{derived}", derived, "{policyErr}", undecodablePolicyErrorForTest(selector))
			var want admissionOutcome
			if tc.damage != "" {
				tc.refusal = "backup credential {sel}: " + tc.damage
			}
			switch {
			case tc.refusal != "":
				refused := "refused: " + tc.refusal
				want = admissionOutcome{verify: refused, restore: refused, preview: refused, rebuild: refused}
			case tc.skip != "":
				skipped := "skipped {sel}: " + tc.skip
				nothing := "refused: nothing to restore: the backup's only credential is skipped: {sel}: " + tc.skip
				want = admissionOutcome{verify: skipped, restore: nothing, preview: skipped, rebuild: nothing}
			}
			want = admissionOutcome{
				verify:  replacer.Replace(want.verify),
				restore: replacer.Replace(want.restore),
				preview: replacer.Replace(want.preview),
				rebuild: replacer.Replace(want.rebuild),
			}
			if got != want {
				t.Fatalf("outcome\n got: %#v\nwant: %#v", got, want)
			}
		})
	}
}

// A rotating key restores whatever its hint: a hint that matches the key is
// kept, one for another network is dropped.
func TestRotatingHintNeverDecidesAdmission(t *testing.T) {
	wotsc.Register()
	var seed rotatinghybrid.Seed
	seed[0] = 23
	defer crypto.ZeroBytes(seed[:])
	var genesis [32]byte
	genesis[0] = 9
	payload, account, err := wotsc.NewKeyPayload(&seed, genesis)
	if err != nil {
		t.Fatal(err)
	}
	defer payload.ZeroSecrets()
	keyJSON, err := keys.MarshalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(keyJSON)

	for _, tc := range []struct {
		name     string
		genesis  string
		wantHint bool
	}{
		{"matching hint", hex.EncodeToString(genesis[:]), true},
		{"hint for another network", hex.EncodeToString(make([]byte, 32)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths := mintFirstGenerationForBackupTest(t, storepaths.NewPaths(t.TempDir()))
			root, keysDir := newAdmissionArchive(t)
			sealAdmissionMember(t, keysDir, account, keyJSON, admissionPassphrase)
			hints := map[string]RotatingStageHint{account: {Stage: 7, KeyType: payload.KeyType, GenesisHash: tc.genesis}}
			if got := admissionOutcomes(t, paths, admissionArchive{root: root, selector: account}, noderole.RoleSigner, hints); got != (admissionOutcome{}) {
				t.Fatalf("outcome = %#v, want accepted everywhere", got)
			}
			managed := BuildManagedArchivePath(paths, fmt.Sprintf("hint-%d", time.Now().UnixNano()))
			if err := CreateTarGzArchive(root, managed); err != nil {
				t.Fatal(err)
			}
			set, err := LoadManagedRestoreSet(paths, managed, nil, admissionPassphrase, noderole.RoleSigner)
			if err != nil {
				t.Fatal(err)
			}
			defer set.ZeroSecrets()
			preview, err := PreviewRestoreWithNodeRole(paths, managed, admissionPassphrase, noderole.RoleSigner)
			if err != nil {
				t.Fatal(err)
			}
			if (set.Entries[0].StageHint != nil) != tc.wantHint || (preview.Keys[0].StageHint != nil) != tc.wantHint {
				t.Fatalf("restore hint = %+v, preview hint = %+v, want kept = %t", set.Entries[0].StageHint, preview.Keys[0].StageHint, tc.wantHint)
			}
		})
	}
}

// Restore and rebuild install the same files: the credential sealed under the
// destination keyring, which opens to the canonical payload, and for a witness
// the public metadata sidecar; any other credential clears a stale sidecar.
func TestRestoredCredentialFilesAndWitnessMetadata(t *testing.T) {
	ed25519signerreg.RegisterSigner()
	kr := cryptotest.Keyring(t, testExportMasterKey)
	witnessSelector, witnessJSON := testCosignerComponentBackupKeyJSON(t)
	accountSelector, accountJSON := testEd25519BackupKeyJSON(t)
	witnessMetadata := witnessMetadataForTest(t, witnessJSON, witnessSelector)

	for _, tc := range []struct {
		name     string
		role     noderole.Role
		selector string
		keyJSON  []byte
		// stale is a sidecar the destination holds before the restore.
		stale bool
		want  map[string][]byte
	}{
		{
			name: "witness", role: noderole.RoleCosigner, selector: witnessSelector, keyJSON: witnessJSON,
			want: map[string][]byte{
				witnessSelector + keys.CosignerCredentialExtension: canonicalPayloadForTest(t, witnessJSON),
				witnessSelector + keys.WitnessPublicMetadataSuffix: witnessMetadata,
			},
		},
		{
			name: "account", role: noderole.RoleSigner, selector: accountSelector, keyJSON: accountJSON, stale: true,
			want: map[string][]byte{
				accountSelector + keys.AccountKeyExtension: canonicalPayloadForTest(t, accountJSON),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, keysDir := newAdmissionArchive(t)
			sealAdmissionMember(t, keysDir, tc.selector, tc.keyJSON, admissionPassphrase)
			if err := WriteSealedManifest(root, tc.role, time.Unix(1_700_000_000, 0), admissionPassphrase, nil); err != nil {
				t.Fatal(err)
			}

			restored := mintFirstGenerationForBackupTest(t, storepaths.NewPaths(t.TempDir()))
			restoredActive := activePathsForBackupTest(t, restored)
			rebuilt := activePathsForBackupTest(t, mintFirstGenerationForBackupTest(t, storepaths.NewPaths(t.TempDir())))
			if tc.stale {
				for _, active := range []storepaths.GenPaths{restoredActive, rebuilt} {
					if err := os.WriteFile(keys.WitnessPublicMetadataPathActive(active, tc.selector), []byte("stale"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			before := keysDirFilesForTest(t, restoredActive, kr)

			managed := BuildManagedArchivePath(restored, "restored-files")
			if err := CreateTarGzArchive(root, managed); err != nil {
				t.Fatal(err)
			}
			set, err := LoadManagedRestoreSet(restored, managed, nil, admissionPassphrase, tc.role)
			if err != nil {
				t.Fatal(err)
			}
			defer set.ZeroSecrets()
			classification, err := ClassifyRestoreSet(restoredActive, set, kr)
			if err != nil || len(classification.Pending) != 1 {
				t.Fatalf("ClassifyRestoreSet() = %+v, %v", classification, err)
			}
			if err := ApplyCredentialEntry(restoredActive, classification.Pending[0], kr, false); err != nil {
				t.Fatalf("ApplyCredentialEntry() error = %v", err)
			}
			if _, err := rebuildForTest(t, rebuilt, tc.role, root, tc.selector, kr, admissionPassphrase); err != nil {
				t.Fatalf("rebuild error = %v", err)
			}

			for name, active := range map[string]storepaths.GenPaths{"restore": restoredActive, "rebuild": rebuilt} {
				got := keysDirFilesForTest(t, active, kr)
				for file := range before {
					if strings.HasSuffix(file, keys.WitnessPublicMetadataSuffix) && tc.stale {
						continue
					}
					delete(got, file)
				}
				if !maps.EqualFunc(got, tc.want, func(a, b []byte) bool { return string(a) == string(b) }) {
					t.Fatalf("%s installed %q, want %q", name, got, tc.want)
				}
			}
		})
	}
}

// keysDirFilesForTest returns every file in the generation's keys directory:
// a credential as the plaintext it opens to under kr, any other file as its
// bytes.
func keysDirFilesForTest(t *testing.T, active storepaths.GenPaths, kr *crypto.Keyring) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(active.KeysDir())
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(active.KeysDir(), entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if selector, class, ok := keys.ParseManagedCredentialFilename(entry.Name()); ok {
			ctx := crypto.AccountKeyContext(selector)
			if class == keys.ManagedCredentialCosigner {
				ctx = crypto.CosignerCredentialContext(selector)
			}
			if data, err = kr.Open(data, ctx); err != nil {
				t.Fatalf("open %s: %v", entry.Name(), err)
			}
		}
		files[entry.Name()] = data
	}
	return files
}

func witnessMetadataForTest(t *testing.T, keyJSON []byte, selector string) []byte {
	t.Helper()
	payload, err := keys.ParsePayload(keyJSON)
	if err != nil {
		t.Fatal(err)
	}
	defer payload.ZeroSecrets()
	envelope, err := cosignerrefs.NewExportEnvelope(selector, payload.KeyType, hex.EncodeToString(payload.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

func selectorForTest(t *testing.T, keyJSON []byte) string {
	t.Helper()
	payload, err := keys.ParsePayload(keyJSON)
	if err != nil {
		t.Fatal(err)
	}
	defer payload.ZeroSecrets()
	selector, err := payload.Selector()
	if err != nil {
		t.Fatal(err)
	}
	return selector
}

// withExtraFieldForTest returns keyJSON in its canonical layout with one
// more top-level field.
func withExtraFieldForTest(t *testing.T, keyJSON []byte) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(keyJSON, &object); err != nil {
		t.Fatal(err)
	}
	object["extra"] = json.RawMessage("1")
	data, err := json.MarshalIndent(object, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// undecodablePolicyErrorForTest is the error the policy decoder reports for
// an empty signer policy object.
func undecodablePolicyErrorForTest(selector string) string {
	if _, err := policy.DecodePolicyV1([]byte("{}"), selector, noderole.RoleSigner); err != nil {
		return err.Error()
	}
	return ""
}

// admittedEntryForTest admits keyJSON as loadCredentialEntry does a
// decrypted archive member.
func admittedEntryForTest(t *testing.T, keyJSON []byte, role noderole.Role) CredentialEntry {
	t.Helper()
	entry, err := admitCredentialEntry(keyJSON, selectorForTest(t, keyJSON), role)
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

// ApplyCredentialEntry installs only an entry restore loaded: one with no
// credential, or whose credential was cleared, writes nothing. An entry's
// selector and category are unexported, so one from outside this package
// cannot name a selector or category its credential does not have.
func TestApplyCredentialEntryRefusesAnEntryItDidNotLoad(t *testing.T) {
	paths := mintFirstGenerationForBackupTest(t, storepaths.NewPaths(t.TempDir()))
	active := activePathsForBackupTest(t, paths)
	kr := cryptotest.Keyring(t, testExportMasterKey)
	address, keyJSON := testEd25519BackupKeyJSON(t)
	cleared := admittedEntryForTest(t, keyJSON, noderole.RoleSigner)
	cleared.ZeroSecrets()
	before := keysDirFilesForTest(t, active, kr)
	for _, tc := range []struct {
		name  string
		entry CredentialEntry
		want  string
	}{
		{"empty", CredentialEntry{}, `restore entry "" holds no admitted credential`},
		{"cleared", cleared, `restore entry "` + address + `" holds no admitted credential`},
	} {
		if err := ApplyCredentialEntry(active, tc.entry, kr, true); err == nil || err.Error() != tc.want {
			t.Fatalf("%s: ApplyCredentialEntry() error = %v, want %q", tc.name, err, tc.want)
		}
	}
	if after := keysDirFilesForTest(t, active, kr); !maps.EqualFunc(after, before, func(a, b []byte) bool { return string(a) == string(b) }) {
		t.Fatalf("refused entries changed the keys directory: %q, want %q", after, before)
	}
}

// Restore applies copies of the loaded entries: classification hands back
// copies of the set's. Clearing the set clears every copy, so applying one
// afterwards is refused and writes nothing.
func TestApplyCredentialEntryRefusesACopyOfAClearedSet(t *testing.T) {
	ed25519signerreg.RegisterSigner()
	paths := mintFirstGenerationForBackupTest(t, storepaths.NewPaths(t.TempDir()))
	active := activePathsForBackupTest(t, paths)
	kr := cryptotest.Keyring(t, testExportMasterKey)
	root, keysDir := newAdmissionArchive(t)
	address, keyJSON := testEd25519BackupKeyJSON(t)
	sealAdmissionMember(t, keysDir, address, keyJSON, admissionPassphrase)
	if err := WriteSealedManifest(root, noderole.RoleSigner, time.Unix(1_700_000_000, 0), admissionPassphrase, nil); err != nil {
		t.Fatal(err)
	}
	managed := BuildManagedArchivePath(paths, "cleared-set")
	if err := CreateTarGzArchive(root, managed); err != nil {
		t.Fatal(err)
	}
	set, err := LoadManagedRestoreSet(paths, managed, nil, admissionPassphrase, noderole.RoleSigner)
	if err != nil {
		t.Fatal(err)
	}
	classification, err := ClassifyRestoreSet(active, set, kr)
	if err != nil || len(classification.Pending) != 1 {
		t.Fatalf("ClassifyRestoreSet() = %+v, %v", classification, err)
	}
	set.ZeroSecrets()
	before := keysDirFilesForTest(t, active, kr)
	want := `restore entry "` + address + `" holds no admitted credential`
	if err := ApplyCredentialEntry(active, classification.Pending[0], kr, true); err == nil || err.Error() != want {
		t.Fatalf("ApplyCredentialEntry(copy of a cleared entry) error = %v, want %q", err, want)
	}
	if after := keysDirFilesForTest(t, active, kr); !maps.EqualFunc(after, before, func(a, b []byte) bool { return string(a) == string(b) }) {
		t.Fatalf("refused entry changed the keys directory: %q, want %q", after, before)
	}
}
