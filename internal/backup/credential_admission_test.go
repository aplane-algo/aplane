// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"bytes"
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
	"github.com/aplane-algo/aplane/internal/genstore"
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

// admissionOutcome is what each consumer of an archive reports for it: the
// failed results of a deep verify, the error of loading it for restore, the
// per-key errors of a restore preview, and the error of restoring its one
// credential as a rebuild does. An empty field accepts.
type admissionOutcome struct {
	verify, restore, preview, rebuild string
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

	report, err := DeepVerifyBackupBytes(archive.root, admissionPassphrase)
	if err != nil {
		t.Fatalf("DeepVerifyBackupBytes() error = %v", err)
	}
	var failed []string
	for _, result := range report.Results {
		if !result.Valid {
			failed = append(failed, result.FileName+": "+result.Error)
		}
	}
	outcome.verify = strings.Join(failed, "\n")

	managed := BuildManagedArchivePath(paths, fmt.Sprintf("admission-%d", time.Now().UnixNano()))
	if err := CreateTarGzArchive(archive.root, managed); err != nil {
		t.Fatal(err)
	}
	set, err := LoadManagedRestoreSet(paths, managed, nil, admissionPassphrase, role)
	set.ZeroSecrets()
	if err != nil {
		if !ArchiveAuthenticated(err) {
			t.Fatalf("restore error %v does not record the authenticated archive", err)
		}
		outcome.restore = err.Error()
	}

	preview, err := PreviewRestoreWithNodeRole(paths, managed, admissionPassphrase, role)
	if err != nil {
		t.Fatalf("PreviewRestoreWithNodeRole() error = %v", err)
	}
	var previewErrors []string
	for _, e := range preview.Errors {
		previewErrors = append(previewErrors, e.Address+": "+e.Error)
	}
	outcome.preview = strings.Join(previewErrors, "\n")

	active, err := genstore.Resolve(paths)
	if err != nil {
		t.Fatal(err)
	}
	kr := cryptotest.Keyring(t, testExportMasterKey)
	if _, err := RestoreForRebuild(active, role, ResolveBackupKeysDir(archive.root), archive.selector, kr, admissionPassphrase, nil); err != nil {
		outcome.rebuild = err.Error()
	}
	return outcome
}

// Every consumer of an archive admits a credential by the same checks:
// deep verify, restore, its preview and rebuild accept and refuse the same
// members. The table pins what each reports.
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
		want  admissionOutcome
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
			want: admissionOutcome{
				verify:  "{sel}.apb: backup file must be encrypted",
				restore: "validate backup credential {sel}: backup file must be encrypted",
				preview: "{sel}: backup file must be encrypted",
				rebuild: "backup file must be encrypted",
			},
		},
		{
			name: "member that is not JSON",
			build: func(t *testing.T, _, keysDir string) (string, string) {
				writeAdmissionMember(t, keysDir, other, []byte("not json"))
				return other, other
			},
			want: admissionOutcome{
				verify:  "{sel}.apb: backup file must be encrypted",
				restore: "validate backup credential {sel}: backup file must be encrypted",
				preview: "{sel}: backup file must be encrypted",
				rebuild: "backup file must be encrypted",
			},
		},
		{
			name: "envelope version 3",
			build: func(t *testing.T, _, keysDir string) (string, string) {
				writeAdmissionMember(t, keysDir, other, []byte(`{"envelope_version":3,"nonce":"","ciphertext":""}`))
				return other, other
			},
			want: admissionOutcome{
				verify:  "{sel}.apb: unsupported backup envelope_version 3",
				restore: "validate backup credential {sel}: unsupported envelope_version: 3; create a new credential backup with this release",
				preview: "{sel}: unsupported envelope_version: 3; create a new credential backup with this release",
				rebuild: "unsupported envelope_version: 3; create a new credential backup with this release",
			},
		},
		{
			name: "member under another passphrase",
			build: func(t *testing.T, _, keysDir string) (string, string) {
				address, keyJSON := testEd25519BackupKeyJSON(t)
				sealAdmissionMember(t, keysDir, address, keyJSON, []byte("other-passphrase"))
				return address, address
			},
			want: admissionOutcome{
				verify:  "{sel}.apb: decryption failed: failed to decrypt data: cipher: message authentication failed",
				restore: "validate backup credential {sel}: failed to decrypt backup (wrong passphrase?): failed to decrypt data: cipher: message authentication failed",
				preview: "{sel}: failed to decrypt backup (wrong passphrase?): failed to decrypt data: cipher: message authentication failed",
				rebuild: "failed to decrypt backup (wrong passphrase?): failed to decrypt data: cipher: message authentication failed",
			},
		},
		{
			name: "pre-release bundle",
			build: func(t *testing.T, _, keysDir string) (string, string) {
				sealAdmissionMember(t, keysDir, other, []byte(`{"backup_bundle":1,"key":{}}`), admissionPassphrase)
				return other, other
			},
			want: admissionOutcome{
				verify:  "{sel}.apb: failed to parse backup payload: unsupported internal backup bundle format; create a new credential backup with this release",
				restore: "validate backup credential {sel}: unsupported internal backup bundle format; create a new credential backup with this release",
				preview: "{sel}: unsupported internal backup bundle format; create a new credential backup with this release",
				rebuild: "unsupported internal backup bundle format; create a new credential backup with this release",
			},
		},
		{
			name: "unknown payload field",
			build: func(t *testing.T, _, keysDir string) (string, string) {
				address, keyJSON := testEd25519BackupKeyJSON(t)
				sealAdmissionMember(t, keysDir, address, withExtraFieldForTest(t, keyJSON), admissionPassphrase)
				return address, address
			},
			want: admissionOutcome{
				verify:  `{sel}.apb: failed to parse backup payload: failed to parse backup credential: incompatible key file format: failed to decode canonical payload: json: unknown field "extra"; restore or regenerate the key file using the current key schema`,
				restore: `validate backup credential {sel}: failed to parse backup credential: incompatible key file format: failed to decode canonical payload: json: unknown field "extra"; restore or regenerate the key file using the current key schema`,
				preview: `{sel}: failed to parse backup credential: incompatible key file format: failed to decode canonical payload: json: unknown field "extra"; restore or regenerate the key file using the current key schema`,
				rebuild: `failed to parse backup credential: incompatible key file format: failed to decode canonical payload: json: unknown field "extra"; restore or regenerate the key file using the current key schema`,
			},
		},
		{
			name: "selector mismatch",
			build: func(t *testing.T, _, keysDir string) (string, string) {
				address, keyJSON := testEd25519BackupKeyJSON(t)
				sealAdmissionMember(t, keysDir, other, keyJSON, admissionPassphrase)
				return other, address
			},
			want: admissionOutcome{
				verify:  "{sel}.apb: address mismatch: filename={sel}, derived={derived}",
				restore: "validate backup credential {sel}: selector mismatch: filename={sel} derived={derived}",
				preview: "{sel}: selector mismatch: filename={sel} derived={derived}",
				rebuild: "selector mismatch: filename={sel} derived={derived}",
			},
		},
		{
			name: "key type the role forbids",
			build: func(t *testing.T, _, keysDir string) (string, string) {
				selector, keyJSON := testCosignerComponentBackupKeyJSON(t)
				sealAdmissionMember(t, keysDir, selector, keyJSON, admissionPassphrase)
				return selector, selector
			},
			want: admissionOutcome{
				verify:  `{sel}.apb: role-forbidden: node role inventory conflict: node role "signer" does not allow key type "aplane.witness-falcon1024.v1"`,
				restore: `validate backup credential {sel}: role-forbidden: node role inventory conflict: node role "signer" does not allow key type "aplane.witness-falcon1024.v1"`,
				preview: `{sel}: role-forbidden: node role inventory conflict: node role "signer" does not allow key type "aplane.witness-falcon1024.v1"`,
				rebuild: `role-forbidden: node role inventory conflict: node role "signer" does not allow key type "aplane.witness-falcon1024.v1"`,
			},
		},
		{
			name: "base key type this runtime lacks",
			build: func(t *testing.T, _, keysDir string) (string, string) {
				keyJSON := keystest.DSALSigKeyJSON(t, "example.missing-provider-lsig.v1", "example.missing-provider.v1",
					[]byte{0x01}, []byte{0x02}, saltedLogicSigBytecodeForTest(), saltCounterForTest)
				selector := selectorForTest(t, keyJSON)
				sealAdmissionMember(t, keysDir, selector, keyJSON, admissionPassphrase)
				return selector, selector
			},
			want: admissionOutcome{
				verify:  "{sel}.apb: base key type example.missing-provider.v1 is not available for restored key type example.missing-provider-lsig.v1",
				restore: "validate backup credential {sel}: base key type example.missing-provider.v1 is not available for restored key type example.missing-provider-lsig.v1",
				preview: "{sel}: base key type example.missing-provider.v1 is not available for restored key type example.missing-provider-lsig.v1",
				rebuild: "base key type example.missing-provider.v1 is not available for restored key type example.missing-provider-lsig.v1",
			},
		},
		{
			name: "oversized member",
			build: func(t *testing.T, _, keysDir string) (string, string) {
				writeAdmissionMember(t, keysDir, other, make([]byte, crypto.MaxStandaloneEnvelopeBytes+1))
				return other, other
			},
			want: admissionOutcome{
				verify:  "{sel}.apb: failed to read file: file exceeds size limit 1048576",
				restore: "validate backup credential {sel}: read backup file: file exceeds size limit 1048576",
				preview: "{sel}: read backup file: file exceeds size limit 1048576",
				rebuild: "read backup file: file exceeds size limit 1048576",
			},
		},
		{
			name: "policy with no credential",
			build: func(t *testing.T, root, keysDir string) (string, string) {
				address, keyJSON := testEd25519BackupKeyJSON(t)
				sealAdmissionMember(t, keysDir, address, keyJSON, admissionPassphrase)
				sealAdmissionPolicy(t, root, other, []byte(policytest.MustDocument(noderole.RoleSigner, other, "")))
				return address, address
			},
			want: admissionOutcome{verify: "policies/" + other + ".apb: policy has no credential in the archive"},
		},
		{
			name: "policy that does not decode",
			build: func(t *testing.T, root, keysDir string) (string, string) {
				address, keyJSON := testEd25519BackupKeyJSON(t)
				sealAdmissionMember(t, keysDir, address, keyJSON, admissionPassphrase)
				sealAdmissionPolicy(t, root, address, []byte("{}"))
				return address, address
			},
			want: admissionOutcome{
				verify:  "policies/{sel}.apb: backup policy for {sel}: {policyErr}",
				restore: "backup policy for {sel}: {policyErr}",
				preview: "{sel}: backup policy for {sel}: {policyErr}",
				rebuild: "backup policy for {sel}: {policyErr}",
			},
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
			want := admissionOutcome{
				verify:  replacer.Replace(tc.want.verify),
				restore: replacer.Replace(tc.want.restore),
				preview: replacer.Replace(tc.want.preview),
				rebuild: replacer.Replace(tc.want.rebuild),
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
			if _, err := RestoreForRebuild(rebuilt, tc.role, keysDir, tc.selector, kr, admissionPassphrase, nil); err != nil {
				t.Fatalf("RestoreForRebuild() error = %v", err)
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

// ApplyCredentialEntry installs only an entry restore loaded: one with no
// credential, or whose credential was cleared, writes nothing.
func TestApplyCredentialEntryRefusesAnEntryItDidNotLoad(t *testing.T) {
	paths := mintFirstGenerationForBackupTest(t, storepaths.NewPaths(t.TempDir()))
	active := activePathsForBackupTest(t, paths)
	kr := cryptotest.Keyring(t, testExportMasterKey)
	address, keyJSON := testEd25519BackupKeyJSON(t)
	cleared := CredentialEntry{Selector: address, Category: keys.CategoryEd25519, KeyType: "ed25519", KeyJSON: bytes.Clone(keyJSON)}
	cleared.ZeroSecrets()
	mismatched := CredentialEntry{Selector: address, Category: keys.CategoryWitness, KeyType: "ed25519", KeyJSON: canonicalPayloadForTest(t, keyJSON)}
	before := keysDirFilesForTest(t, active, kr)
	for _, tc := range []struct {
		name  string
		entry CredentialEntry
		want  string
	}{
		{"empty", CredentialEntry{}, "incompatible key file format: invalid canonical payload JSON: EOF; restore or regenerate the key file using the current key schema"},
		{"cleared", cleared, "incompatible key file format: invalid canonical payload JSON: EOF; restore or regenerate the key file using the current key schema"},
		{"mismatched", mismatched, "restore entry metadata no longer matches canonical payload"},
	} {
		if err := ApplyCredentialEntry(active, tc.entry, kr, true); err == nil || err.Error() != tc.want {
			t.Fatalf("%s: ApplyCredentialEntry() error = %v, want %q", tc.name, err, tc.want)
		}
	}
	if after := keysDirFilesForTest(t, active, kr); !maps.EqualFunc(after, before, func(a, b []byte) bool { return string(a) == string(b) }) {
		t.Fatalf("refused entries changed the keys directory: %q, want %q", after, before)
	}
}
