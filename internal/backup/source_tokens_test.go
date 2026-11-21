// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// The token values these tests set. No archive member, preview, report or
// error may carry them in the clear.
const (
	keyTokenForBackupTest     = "tok-key-7f3a9c"
	defaultTokenForBackupTest = "tok-default-51be"
)

func sourceTokenFileForBackupTest(t *testing.T, selector string, tokens map[string]string) *sourcetokens.File {
	t.Helper()
	var f *sourcetokens.File
	for _, source := range slices.Sorted(maps.Keys(tokens)) {
		next, err := sourcetokens.SetToken(f, selector, source, []byte(tokens[source]), timeForBackupTest())
		if err != nil {
			t.Fatal(err)
		}
		f.Zero()
		f = next
	}
	return f
}

func writeSourceTokensForBackupTest(t *testing.T, active storepaths.GenPaths, kr *crypto.Keyring, selector string, tokens map[string]string) {
	t.Helper()
	f := sourceTokenFileForBackupTest(t, selector, tokens)
	defer f.Zero()
	if err := sourcetokens.WriteFile(active, f, kr); err != nil {
		t.Fatal(err)
	}
}

// cosignerStoreWithSourceTokens is cosignerStoreWithPolicy with a token for
// the key and one for the node default.
func cosignerStoreWithSourceTokens(t *testing.T) (storepaths.Paths, string) {
	t.Helper()
	paths, selector, _ := cosignerStoreWithPolicy(t)
	kr := cryptotest.Keyring(t, testExportMasterKey)
	active := activePathsForBackupTest(t, paths)
	writeSourceTokensForBackupTest(t, active, kr, selector, map[string]string{"screening": keyTokenForBackupTest})
	writeSourceTokensForBackupTest(t, active, kr, sourcetokens.DefaultSelector, map[string]string{"treasury": defaultTokenForBackupTest})
	return paths, selector
}

func requireNoTokenText(t *testing.T, what string, data []byte) {
	t.Helper()
	for _, token := range []string{keyTokenForBackupTest, defaultTokenForBackupTest} {
		if bytes.Contains(data, []byte(token)) {
			t.Fatalf("%s carries a token in the clear", what)
		}
	}
}

// A backup carries the key's source tokens encrypted under the export
// passphrase, covered by the sealed manifest, and not the node default's.
// Verify, the restore set and the preview name the sources and never a
// token.
func TestBackupCarriesAKeysSourceTokensEncrypted(t *testing.T) {
	paths, selector := cosignerStoreWithSourceTokens(t)
	archivePath := BuildManagedArchivePath(paths, "20261121-010203")
	if _, err := CreateKeysArchive(testCreateKeysArchiveRequest(paths, archivePath, nil, noderole.RoleCosigner, cryptotest.Keyring(t, testExportMasterKey))); err != nil {
		t.Fatalf("CreateKeysArchive() error = %v", err)
	}
	extractDir := t.TempDir()
	if err := ExtractTarGzArchive(archivePath, extractDir); err != nil {
		t.Fatal(err)
	}
	member := "source_tokens/" + selector + ".apb"
	sealed, err := os.ReadFile(filepath.Join(extractDir, filepath.FromSlash(member)))
	if err != nil {
		t.Fatalf("archived source tokens missing: %v", err)
	}
	requireNoTokenText(t, "the archived token member", sealed)
	if _, err := os.Stat(filepath.Join(extractDir, "source_tokens", "default.apb")); !os.IsNotExist(err) {
		t.Fatalf("the node default's tokens were backed up: %v", err)
	}
	plaintext, err := crypto.DecryptStandaloneLimited(sealed, []byte("export-passphrase"), maxBackupSourceTokensEnvelopeBytes)
	if err != nil {
		t.Fatal(err)
	}
	want := sourceTokenFileForBackupTest(t, selector, map[string]string{"screening": keyTokenForBackupTest})
	wantPlaintext, err := sourcetokens.Encode(want)
	want.Zero()
	if err != nil || !bytes.Equal(plaintext, wantPlaintext) {
		t.Fatalf("archived tokens = %d bytes (%v), want the token file's canonical plaintext", len(plaintext), err)
	}
	manifest, err := OpenSealedManifest(extractDir, []byte("export-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(manifest.Members, func(m ManifestMember) bool { return m.Path == member }) {
		t.Fatalf("the sealed manifest does not list %s", member)
	}

	report, err := DeepVerifyBackupBytes(extractDir, []byte("export-passphrase"))
	if err != nil || len(report.Verified) != 1 || !slices.Equal(report.Verified[0].SourceTokens, []string{"screening"}) {
		t.Fatalf("DeepVerifyBackupBytes() = %+v, %v; want the key's source names", report, err)
	}
	preview, err := PreviewRestoreWithNodeRole(paths, archivePath, []byte("export-passphrase"), noderole.RoleCosigner)
	if err != nil || len(preview.Keys) != 1 || !slices.Equal(preview.Keys[0].SourceTokens, []string{"screening"}) {
		t.Fatalf("PreviewRestoreWithNodeRole() = %+v, %v; want the key's source names", preview, err)
	}
	requireNoTokenText(t, "the preview", fmt.Appendf(nil, "%+v", *preview))
	set, err := LoadManagedRestoreSet(paths, archivePath, nil, []byte("export-passphrase"), noderole.RoleCosigner)
	if err != nil {
		t.Fatal(err)
	}
	defer set.ZeroSecrets()
	if got := set.Entries[0].SourceTokenNames(); !slices.Equal(got, []string{"screening"}) {
		t.Fatalf("restore entry source names = %v", got)
	}

	// Tampering with the token member breaks the sealed manifest.
	if err := os.WriteFile(filepath.Join(extractDir, filepath.FromSlash(member)), append(sealed, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSealedManifest(extractDir, []byte("export-passphrase")); err == nil {
		t.Fatal("a modified archived token member passed manifest verification")
	}
}

// An all-credentials backup is fail-hard: a token file that cannot be read
// fails it and publishes nothing.
func TestBackupFailsOnAnUnreadableSourceTokenFile(t *testing.T) {
	paths, selector := cosignerStoreWithSourceTokens(t)
	active := activePathsForBackupTest(t, paths)
	if err := os.WriteFile(active.SourceTokenPath(selector), []byte(`{"envelope_version":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	archivePath := BuildManagedArchivePath(paths, "20261121-010204")
	_, err := CreateKeysArchive(testCreateKeysArchiveRequest(paths, archivePath, nil, noderole.RoleCosigner, cryptotest.Keyring(t, testExportMasterKey)))
	if err == nil || !strings.Contains(err.Error(), "export source tokens for "+selector) {
		t.Fatalf("CreateKeysArchive() error = %v, want the token file's failure", err)
	}
	if _, statErr := os.Stat(archivePath); !os.IsNotExist(statErr) {
		t.Fatalf("a failed backup left an archive: %v", statErr)
	}
}

// A destination without a token file takes the archived one; an identical
// one is kept; a different or unreadable one is a conflict; and a
// destination's tokens are kept when the archive carries none.
func TestClassifyRestoreSourceTokensAgainstDestination(t *testing.T) {
	paths, selector := cosignerStoreWithSourceTokens(t)
	archivePath := BuildManagedArchivePath(paths, "20261121-010205")
	kr := cryptotest.Keyring(t, testExportMasterKey)
	if _, err := CreateKeysArchive(testCreateKeysArchiveRequest(paths, archivePath, nil, noderole.RoleCosigner, kr)); err != nil {
		t.Fatal(err)
	}
	set, err := LoadManagedRestoreSet(paths, archivePath, nil, []byte("export-passphrase"), noderole.RoleCosigner)
	if err != nil {
		t.Fatal(err)
	}
	defer set.ZeroSecrets()
	active := activePathsForBackupTest(t, paths)

	same, err := ClassifyRestoreSet(active, set, kr)
	if err != nil || len(same.Identical) != 1 || len(same.SourceTokens) != 0 || len(same.Conflicts) != 0 {
		t.Fatalf("identical key and tokens: %+v, %v", same, err)
	}

	writeSourceTokensForBackupTest(t, active, kr, selector, map[string]string{"screening": "tok-local"})
	differs, err := ClassifyRestoreSet(active, set, kr)
	if err != nil || len(differs.SourceTokens) != 1 || len(differs.Conflicts) != 1 ||
		differs.Conflicts[0].Reason != "existing source tokens differ from backup" || differs.Conflicts[0].ExistingSHA256 == "" {
		t.Fatalf("destination with other tokens: %+v, %v", differs, err)
	}
	requireNoTokenText(t, "a conflict", fmt.Appendf(nil, "%+v", differs.Conflicts))

	if err := os.WriteFile(active.SourceTokenPath(selector), []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	damaged, err := ClassifyRestoreSet(active, set, kr)
	if err != nil || len(damaged.SourceTokens) != 1 || len(damaged.Conflicts) != 1 ||
		!strings.HasPrefix(damaged.Conflicts[0].Reason, "existing source tokens are unreadable") {
		t.Fatalf("destination with a damaged token file: %+v, %v", damaged, err)
	}

	if err := sourcetokens.RemoveFile(active, selector); err != nil {
		t.Fatal(err)
	}
	missing, err := ClassifyRestoreSet(active, set, kr)
	if err != nil || len(missing.SourceTokens) != 1 || len(missing.Conflicts) != 0 {
		t.Fatalf("destination without a token file: %+v, %v", missing, err)
	}
	if err := ApplySourceTokensEntry(active, missing.SourceTokens[0], kr); err != nil {
		t.Fatal(err)
	}
	restored, ok, err := sourcetokens.ReadFile(active, selector, kr)
	if err != nil || !ok || string(restored.Tokens["screening"].Value) != keyTokenForBackupTest {
		t.Fatalf("restored token file = %v, %v", ok, err)
	}
	restored.Zero()

	// An archive without the key's tokens leaves the destination's alone.
	set.Entries[0].credential.sourceTokens, set.Entries[0].credential.sourceTokenNames = nil, nil
	without, err := ClassifyRestoreSet(active, set, kr)
	if err != nil || len(without.SourceTokens) != 0 || len(without.Conflicts) != 0 {
		t.Fatalf("archive without tokens: %+v, %v", without, err)
	}
}

// writeCosignerArchiveDirForTest writes an extracted cosigner archive holding
// the witness credential and the given members, each sealed under the
// export passphrase, and returns its root and the credential's selector.
func writeCosignerArchiveDirForTest(t *testing.T, members func(selector string) map[string][]byte) (string, string) {
	t.Helper()
	root := t.TempDir()
	selector, payload := testCosignerComponentBackupKeyJSON(t)
	all := map[string][]byte{"apb/" + selector + ".apb": payload}
	for path, plaintext := range members(selector) {
		all[path] = plaintext
	}
	for path, plaintext := range all {
		target := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := writeStandaloneBackupFile(target, plaintext, []byte("export-passphrase")); err != nil {
			t.Fatal(err)
		}
	}
	if err := WriteSealedManifest(root, noderole.RoleCosigner, timeForBackupTest(), []byte("export-passphrase"), nil); err != nil {
		t.Fatal(err)
	}
	return root, selector
}

func encodedTokensForBackupTest(t *testing.T, selector string, tokens map[string]string) []byte {
	t.Helper()
	f := sourceTokenFileForBackupTest(t, selector, tokens)
	defer f.Zero()
	plaintext, err := sourcetokens.Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	return plaintext
}

// Source tokens for no credential in the archive, and the node default's
// tokens, are damage to the archive: every reader refuses it.
func TestArchiveRefusesSourceTokensWithoutTheirCredential(t *testing.T) {
	const other = "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ"
	for name, tc := range map[string]struct {
		member string
		want   string
	}{
		"another key":      {member: "source_tokens/" + other + ".apb", want: "have no credential in the archive"},
		"the node default": {member: "source_tokens/default.apb", want: "unsupported entry"},
		"an address":       {member: "source_tokens/CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM.apb", want: "unsupported entry"},
	} {
		t.Run(name, func(t *testing.T) {
			root, _ := writeCosignerArchiveDirForTest(t, func(string) map[string][]byte {
				return map[string][]byte{tc.member: encodedTokensForBackupTest(t, other, map[string]string{"screening": "x"})}
			})
			if _, err := DeepVerifyBackupBytes(root, []byte("export-passphrase")); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("DeepVerifyBackupBytes() error = %v, want %q", err, tc.want)
			}
			if _, err := LoadRebuildSet(root, nil, []byte("export-passphrase"), noderole.RoleCosigner); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadRebuildSet() error = %v, want %q", err, tc.want)
			}
		})
	}
}

// A token member past the archive's bound is refused while it is read,
// before it is decrypted.
func TestArchiveRefusesAnOversizeSourceTokensMember(t *testing.T) {
	root, selector := writeCosignerArchiveDirForTest(t, func(string) map[string][]byte { return nil })
	member := filepath.Join(root, "source_tokens", selector+".apb")
	if err := os.MkdirAll(filepath.Dir(member), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(member, bytes.Repeat([]byte{'{'}, maxBackupSourceTokensEnvelopeBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteSealedManifest(root, noderole.RoleCosigner, timeForBackupTest(), []byte("export-passphrase"), nil); err != nil {
		t.Fatal(err)
	}
	_, err := DeepVerifyBackupBytes(root, []byte("export-passphrase"))
	if err == nil || !strings.Contains(err.Error(), "read backup source tokens") {
		t.Fatalf("DeepVerifyBackupBytes() error = %v, want the member's size refused", err)
	}
}

// Archived tokens that decrypt but are not this key's token file, or could
// not become one, skip the key with the reason; the key's credential is
// skipped with them, and the reason never quotes a token.
func TestAdmissionSkipsAKeyWhoseSourceTokensItCannotWrite(t *testing.T) {
	long := strings.Repeat("v", 400)
	for name, tc := range map[string]struct {
		tokens func(selector string) []byte
		want   string
	}{
		"another selector's file": {
			tokens: func(string) []byte {
				return encodedTokensForBackupTest(t, "default", map[string]string{"screening": keyTokenForBackupTest})
			},
			want: "the file says it holds the tokens of",
		},
		"not canonical": {
			tokens: func(selector string) []byte {
				return append(encodedTokensForBackupTest(t, selector, map[string]string{"screening": keyTokenForBackupTest}), ' ')
			},
			want: "not in canonical form",
		},
		"too large for a token file": {
			tokens: func(selector string) []byte {
				tokens := map[string]string{}
				for i := range sourcetokens.MaxTokens {
					tokens[fmt.Sprintf("s%d", i)] = long + keyTokenForBackupTest
				}
				return encodedTokensForBackupTest(t, selector, tokens)
			},
			want: sourcetokens.ErrFileTooLarge.Error(),
		},
	} {
		t.Run(name, func(t *testing.T) {
			root, selector := writeCosignerArchiveDirForTest(t, func(selector string) map[string][]byte {
				return map[string][]byte{"source_tokens/" + selector + ".apb": tc.tokens(selector)}
			})
			report, err := DeepVerifyBackupBytes(root, []byte("export-passphrase"))
			if err != nil {
				t.Fatalf("DeepVerifyBackupBytes() error = %v", err)
			}
			if len(report.Verified) != 0 || len(report.Skipped) != 1 || report.Skipped[0].Selector != selector ||
				!strings.Contains(report.Skipped[0].Reason, tc.want) {
				t.Fatalf("report = %+v, want %s skipped for %q", report, selector, tc.want)
			}
			requireNoTokenText(t, "a skip reason", []byte(report.Skipped[0].Reason))
			if _, err := LoadRebuildSet(root, nil, []byte("export-passphrase"), noderole.RoleCosigner); err == nil {
				t.Fatal("LoadRebuildSet() admitted a key whose tokens it cannot write")
			}
		})
	}
}

// A key admission skips is skipped with its tokens: of two archived
// cosigner keys with tokens, the one whose archived policy does not decode
// is skipped, and only the other's tokens are written.
func TestASkippedKeysSourceTokensAreSkippedWithIt(t *testing.T) {
	root := t.TempDir()
	good, goodPayload := testCosignerComponentBackupKeyJSON(t)
	bad, badPayload := keystest.CosignerComponentFalcon1024KeyJSON(t, 0x5a)
	for path, plaintext := range map[string][]byte{
		"apb/" + good + ".apb":           goodPayload,
		"apb/" + bad + ".apb":            badPayload,
		"policies/" + bad + ".apb":       []byte(`{"not":"a policy"}`),
		"source_tokens/" + good + ".apb": encodedTokensForBackupTest(t, good, map[string]string{"screening": keyTokenForBackupTest}),
		"source_tokens/" + bad + ".apb":  encodedTokensForBackupTest(t, bad, map[string]string{"screening": defaultTokenForBackupTest}),
	} {
		target := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := writeStandaloneBackupFile(target, plaintext, []byte("export-passphrase")); err != nil {
			t.Fatal(err)
		}
	}
	if err := WriteSealedManifest(root, noderole.RoleCosigner, timeForBackupTest(), []byte("export-passphrase"), nil); err != nil {
		t.Fatal(err)
	}
	set, err := LoadRebuildSet(root, nil, []byte("export-passphrase"), noderole.RoleCosigner)
	if err != nil {
		t.Fatal(err)
	}
	defer set.ZeroSecrets()
	if len(set.Entries) != 1 || set.Entries[0].Selector() != good || len(set.Skipped) != 1 || set.Skipped[0].Selector != bad {
		t.Fatalf("restore set = %+v skipped %+v, want %s admitted and %s skipped", set.Entries, set.Skipped, good, bad)
	}
	paths := mintFirstGenerationForBackupTest(t, storepaths.NewPaths(t.TempDir()))
	staged := genstoretest.Active(t, paths)
	kr := cryptotest.Keyring(t, testExportMasterKey)
	if err := ApplyRebuildSet(staged, noderole.RoleCosigner, set, kr); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := sourcetokens.ReadFile(staged, bad, kr); err != nil || ok {
		t.Fatalf("the skipped key's tokens were written: %v, %v", ok, err)
	}
	if f, ok, err := sourcetokens.ReadFile(staged, good, kr); err != nil || !ok {
		t.Fatalf("the admitted key's tokens are missing: %v, %v", ok, err)
	} else {
		f.Zero()
	}
}

// Rebuild writes each rebuilt key's archived tokens as its token file,
// sealed under the new store's term.
func TestApplyRebuildSetWritesSourceTokens(t *testing.T) {
	root, selector := writeCosignerArchiveDirForTest(t, func(selector string) map[string][]byte {
		return map[string][]byte{"source_tokens/" + selector + ".apb": encodedTokensForBackupTest(t, selector, map[string]string{"screening": keyTokenForBackupTest})}
	})
	set, err := LoadRebuildSet(root, nil, []byte("export-passphrase"), noderole.RoleCosigner)
	if err != nil {
		t.Fatal(err)
	}
	defer set.ZeroSecrets()
	paths := mintFirstGenerationForBackupTest(t, storepaths.NewPaths(t.TempDir()))
	staged := genstoretest.Active(t, paths)
	kr := cryptotest.Keyring(t, testExportMasterKey)
	if err := ApplyRebuildSet(staged, noderole.RoleCosigner, set, kr); err != nil {
		t.Fatal(err)
	}
	f, ok, err := sourcetokens.ReadFile(staged, selector, kr)
	if err != nil || !ok || string(f.Tokens["screening"].Value) != keyTokenForBackupTest {
		t.Fatalf("rebuilt token file = %v, %v", ok, err)
	}
	f.Zero()
	sealed, err := os.ReadFile(staged.SourceTokenPath(selector))
	if err != nil {
		t.Fatal(err)
	}
	requireNoTokenText(t, "the rebuilt token file", sealed)
}

// ZeroSecrets clears the archived tokens with the credential, through every
// copy of the entry.
func TestCredentialEntryZeroSecretsClearsSourceTokens(t *testing.T) {
	tokens := []byte(keyTokenForBackupTest)
	entry := CredentialEntry{credential: &admittedCredential{keyJSON: []byte("secret"), sourceTokens: tokens}}
	copied := entry
	copied.ZeroSecrets()
	if entry.sourceTokensPlaintext() != nil || !bytes.Equal(tokens, make([]byte, len(tokens))) {
		t.Fatal("ZeroSecrets left the archived tokens")
	}
}

// The entry cap and the sealed manifest bound hold an archive at the
// cosigner caps: a credential, a policy and source tokens for each of
// 8,192 keys, each member at its largest size.
func TestArchiveLimitsHoldThreeMembersPerKeyAtTheCosignerCap(t *testing.T) {
	const members = maxArchiveMembersPerKey * keys.MaxCosignerCredentials
	// README.md, manifest.sealed and the three member directories.
	if entries := members + 5; entries > maxArchiveEntries {
		t.Fatalf("an archive at the cap has %d entries, over the %d limit", entries, maxArchiveEntries)
	}
	selector, _ := testCosignerComponentBackupKeyJSON(t)
	manifest := Manifest{
		Schema: ManifestSchema, SchemaVersion: ManifestSchemaVersion,
		SourceNodeRole: string(noderole.RoleCosigner), CreatedAtUnix: math.MaxInt64,
	}
	digest := strings.Repeat("f", 64)
	for i := range keys.MaxCosignerCredentials {
		// A distinct name of a Witness Key ID's length.
		name := fmt.Sprintf("%0*d", len(selector), i) + ".apb"
		manifest.Members = append(manifest.Members,
			ManifestMember{Path: "apb/" + name, SHA256: digest, Size: int64(crypto.MaxStandaloneEnvelopeBytes)},
			ManifestMember{Path: backupPoliciesDir + "/" + name, SHA256: digest, Size: maxBackupPolicyEnvelopeBytes},
			ManifestMember{Path: backupSourceTokensDir + "/" + name, SHA256: digest, Size: maxBackupSourceTokensEnvelopeBytes},
		)
	}
	plaintext, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	sealed, err := crypto.EncryptStandalone(plaintext, []byte("export-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) > maxSealedManifestBytes {
		t.Fatalf("a manifest at the cap seals to %d bytes, over the %d limit", len(sealed), maxSealedManifestBytes)
	}
	t.Logf("manifest at the cap: %d bytes plaintext, %d sealed (limit %d), %v", len(plaintext), len(sealed), maxSealedManifestBytes, time.Since(start))
}

// The largest token file the store accepts fits the archive's bound on a
// token member once it is re-encrypted under the export passphrase.
func TestTheLargestTokenFileFitsAnArchiveMember(t *testing.T) {
	selector, _ := testCosignerComponentBackupKeyJSON(t)
	kr := cryptotest.Keyring(t, testExportMasterKey)
	tokens := map[string]string{}
	for i := range sourcetokens.MaxTokens {
		tokens[fmt.Sprintf("%s-%d", strings.Repeat("s", sourcetokens.MaxSourceNameBytes-2), i)] = ""
	}
	var largest []byte
	for n := sourcetokens.MaxTokenBytes; n > 0 && largest == nil; n-- {
		for source := range tokens {
			tokens[source] = strings.Repeat("\"", n)
		}
		f := sourceTokenFileForBackupTest(t, selector, tokens)
		if _, err := sourcetokens.Seal(f, kr); err == nil {
			if largest, err = sourcetokens.Encode(f); err != nil {
				t.Fatal(err)
			}
		}
		f.Zero()
	}
	sealed, err := crypto.EncryptStandalone(largest, []byte("export-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) > maxBackupSourceTokensEnvelopeBytes {
		t.Fatalf("the largest token file takes %d bytes in an archive, over the %d limit", len(sealed), maxBackupSourceTokensEnvelopeBytes)
	}
}

// A token member follows its cosigner credential's role rule: on a signer
// node the credential is role-forbidden, and its tokens are skipped with it.
func TestSourceTokensFollowTheirCredentialsRoleRule(t *testing.T) {
	root, selector := writeCosignerArchiveDirForTest(t, func(selector string) map[string][]byte {
		return map[string][]byte{"source_tokens/" + selector + ".apb": encodedTokensForBackupTest(t, selector, map[string]string{"screening": keyTokenForBackupTest})}
	})
	_, err := LoadRebuildSet(root, nil, []byte("export-passphrase"), noderole.RoleSigner)
	var refusal *SkipRefusalError
	if !errors.As(err, &refusal) || len(refusal.Skipped) != 1 || refusal.Skipped[0].Selector != selector ||
		!strings.Contains(refusal.Skipped[0].Reason, "role-forbidden") {
		t.Fatalf("LoadRebuildSet(signer) error = %v, want the cosigner key skipped as role-forbidden", err)
	}
}
