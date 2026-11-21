// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/lsigsalt/lsigsalttest"
	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"
	"github.com/aplane-algo/aplane/internal/signerapp/templaterepair"
	"github.com/aplane-algo/aplane/internal/storelock"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatelibrary"
)

const (
	repairHealthy = "test.apstore-repair-healthy.v1"
	repairEdited  = "test.apstore-repair-edited.v1"
	repairOrphan  = "test.apstore-repair-orphan.v1"
)

// withDamagedTemplateStore runs fn on a store that an unlock would put into
// recovery: an externally edited record with two keys, one of which a re-pin
// leaves in conflict, and an orphaned record, beside a healthy template.
// installed is the fingerprint the edited record's install recorded.
func withDamagedTemplateStore(t *testing.T, fn func(passphrase []byte, installed string, log *bytes.Buffer)) {
	t.Helper()
	t.Setenv("APSIGNER_PASSPHRASE", "")
	var log bytes.Buffer
	appLogger.SetOutput(&log)
	t.Cleanup(func() { appLogger.SetOutput(os.Stderr) })
	withPolicyCommandStore(t, func(_ string, passphrase []byte) {
		bound, kr := deriveTestStore(t, passphrase)
		installed := map[string]string{}
		for _, keyType := range []string{repairHealthy, repairEdited, repairOrphan} {
			parsed, err := templatelibrary.ParseYAML("source.yaml", apstoreRepairYAML(keyType))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := templatelibrary.InstallParsed(bound, parsed, kr); err != nil {
				t.Fatal(err)
			}
			rec, _, err := keytypestate.Get(bound, keyType)
			if err != nil {
				t.Fatal(err)
			}
			installed[keyType] = rec.Fingerprint
		}
		rec, _, err := keytypestate.Get(bound, repairEdited)
		if err != nil {
			t.Fatal(err)
		}
		rec.Fingerprint = "1:" + strings.Repeat("b", 64)
		if err := keytypestate.Put(bound, rec); err != nil {
			t.Fatal(err)
		}
		active, err := genstore.Resolve(bound)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(active.KeyTypeTemplate(repairOrphan)); err != nil {
			t.Fatal(err)
		}
		for i, fingerprint := range []string{installed[repairEdited], "1:" + strings.Repeat("c", 64)} {
			program := lsigsalttest.OffCurve(t, []byte{0x06, 0x81, byte(i + 1), 0x00}, 3)
			payload := keys.NewGenericLSigPayload(repairEdited, nil, program.Bytecode, "", nil, fingerprint)
			if err := payload.SetLogicSigOpcodeProfile(lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling), false); err != nil {
				t.Fatal(err)
			}
			if _, err := keys.SaveNewPayload(bound, payload, false, kr); err != nil {
				t.Fatal(err)
			}
		}
		fn(passphrase, installed[repairEdited], &log)
	})
}

func runTemplateCommand(t *testing.T, input string, args ...string) (string, error) {
	t.Helper()
	return withCapturedStdout(func() error {
		return withTestStdin(input, func() error {
			req, err := parseTemplateCommand(args)
			if err != nil {
				return err
			}
			return cmdTemplateRepair(req)
		})
	})
}

func TestTemplateRepairPreview(t *testing.T) {
	withDamagedTemplateStore(t, func(passphrase []byte, installed string, log *bytes.Buffer) {
		before := apstoreStoreDigest(t)
		out, err := runTemplateCommand(t, string(passphrase)+"\n", "repair")
		if err != nil {
			t.Fatalf("template repair (preview) error = %v", err)
		}
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) != 3 {
			t.Fatalf("preview output = %q, want a header and two defects", out)
		}
		for i, want := range []string{
			"KEY TYPE DEFECT ACTIONS KEYS",
			repairOrphan + " orphaned record (generic) drop 0",
			repairEdited + " external edit (generic) repin or drop 2",
		} {
			if got := strings.Join(strings.Fields(lines[i]), " "); got != want {
				t.Fatalf("preview line %d = %q, want %q", i, got, want)
			}
		}
		if strings.Contains(out, repairHealthy) {
			t.Fatalf("preview lists the healthy template: %q", out)
		}
		for _, want := range []string{
			"has 2 template record defect(s)",
			repairEdited + ": the record pins 1:bbbb",
			"its stored template computes " + installed,
			repairEdited + ": 1 of its 2 key(s) were created from a definition other than the stored template; a repin leaves them reading conflict",
			repairEdited + ": 1 of its 2 key(s) were created from the stored template",
			"repin keeps the stored template as it is now: use it only if you know why the record and the template differ",
			"otherwise drop the record, start apsigner, and import the template again from a file you trust with `apadmin template import`",
			"repair every defect in one run",
		} {
			if !strings.Contains(log.String(), want) {
				t.Fatalf("preview log = %q, want %q", log.String(), want)
			}
		}
		if apstoreStoreDigest(t) != before {
			t.Fatal("a preview changed the store")
		}
	})
}

func TestTemplateRepairCommits(t *testing.T) {
	withDamagedTemplateStore(t, func(passphrase []byte, installed string, log *bytes.Buffer) {
		damaged := currentGenerationForTest(t, passphrase)
		out, err := runTemplateCommand(t, string(passphrase)+"\n",
			"repair", "repin", repairEdited, "drop", repairOrphan, "--confirm")
		if err != nil {
			t.Fatalf("template repair --confirm error = %v", err)
		}
		repaired := currentGenerationForTest(t, passphrase)
		if repaired.GenerationID() == damaged.GenerationID() {
			t.Fatal("the repair committed no generation")
		}
		if !strings.Contains(log.String(), "template repair committed generation "+repaired.GenerationID()+" over "+damaged.GenerationID()+", which is kept") {
			t.Fatalf("repair log = %q, want the new generation and its kept parent", log.String())
		}
		if _, err := os.Stat(damaged.Dir()); err != nil {
			t.Fatalf("damaged generation after the repair: %v", err)
		}
		for _, want := range []string{
			repairEdited + "  external edit (generic)  repin   2     1",
			repairOrphan + "  orphaned record (generic)  drop    0     -",
		} {
			if !strings.Contains(strings.Join(strings.Fields(out), " "), strings.Join(strings.Fields(want), " ")) {
				t.Fatalf("repair output = %q, want %q", out, want)
			}
		}
		if rec, ok, err := keytypestate.GetActive(repaired, repairEdited); err != nil || !ok || rec.Fingerprint != installed {
			t.Fatalf("re-pinned record = %+v, %v, %v", rec, ok, err)
		}
		if _, ok, err := keytypestate.GetActive(repaired, repairOrphan); ok || err != nil {
			t.Fatalf("dropped record = %v, %v; want gone", ok, err)
		}
		// A second preview finds nothing left to repair.
		log.Reset()
		if _, err := runTemplateCommand(t, string(passphrase)+"\n", "repair"); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(log.String(), "has no template record defects") {
			t.Fatalf("preview after the repair = %q, want no defects", log.String())
		}
	})
}

// Every refusal leaves the store root and every generation exactly as they
// were.
func TestTemplateRepairRefusalsChangeNothing(t *testing.T) {
	for _, tc := range []struct {
		name     string
		input    func(passphrase []byte) string
		args     []string
		damage   func(t *testing.T, passphrase []byte)
		want     string
		wantExit int
	}{
		{name: "no --confirm", args: []string{"repair", "repin", repairEdited, "drop", repairOrphan},
			want: "", wantExit: apstoreExitOK},
		{name: "a healthy key type", args: []string{"repair", "repin", repairEdited, "drop", repairOrphan, repairHealthy, "--confirm"},
			want: "key type is not a template record defect: " + repairHealthy, wantExit: apstoreExitFailure},
		{name: "a re-pin of an orphaned record", args: []string{"repair", "repin", repairEdited, repairOrphan, "--confirm"},
			want: "only an external edit can be re-pinned: " + repairOrphan + " has no template file to pin (orphaned record)", wantExit: apstoreExitFailure},
		{name: "a defect left out", args: []string{"repair", "repin", repairEdited, "--confirm"},
			want: "every template record defect must be repaired together: " + repairOrphan, wantExit: apstoreExitFailure},
		{name: "other damage", args: []string{"repair", "repin", repairEdited, "drop", repairOrphan, "--confirm"},
			damage: func(t *testing.T, passphrase []byte) {
				current := currentGenerationForTest(t, passphrase)
				if err := os.WriteFile(filepath.Join(current.KeysDir(), "DAMAGED.key"), []byte("damaged"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "the generation has damage a template repair does not cover: credential content defect", wantExit: apstoreExitFailure},
		{name: "a wrong passphrase", args: []string{"repair", "repin", repairEdited, "drop", repairOrphan, "--confirm"},
			input: func([]byte) string { return "wrong-passphrase\n" },
			want:  "invalid_passphrase", wantExit: apstoreExitUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withDamagedTemplateStore(t, func(passphrase []byte, _ string, log *bytes.Buffer) {
				if tc.damage != nil {
					tc.damage(t, passphrase)
				}
				before := apstoreStoreDigest(t)
				input := string(passphrase) + "\n"
				if tc.input != nil {
					input = tc.input(passphrase)
				}
				_, err := runTemplateCommand(t, input, tc.args...)
				if got := exitCodeForError(err); got != tc.wantExit {
					t.Fatalf("template %v = %v (exit %d), want exit %d", tc.args, err, got, tc.wantExit)
				}
				if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
					t.Fatalf("template %v error = %v, want %q", tc.args, err, tc.want)
				}
				if err == nil && !strings.Contains(log.String(), "nothing was changed; add --confirm") {
					t.Fatalf("dry run log = %q, want the nothing-changed notice", log.String())
				}
				if apstoreStoreDigest(t) != before {
					t.Fatal("a refused repair changed the store")
				}
			})
		})
	}
}

// A staging directory an interrupted repair left does not block the next
// one: the preview says reconciliation is pending, and --confirm reconciles
// first, as an unlock would, and says what it discarded.
func TestTemplateRepairReconcilesFirst(t *testing.T) {
	withDamagedTemplateStore(t, func(passphrase []byte, _ string, log *bytes.Buffer) {
		residue := storepaths.GenerationStagingPrefix + "gen-1700000000-deadbeef"
		if err := os.Mkdir(filepath.Join(keystorePaths().GenerationsDir(), residue), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := runTemplateCommand(t, string(passphrase)+"\n", "repair"); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(log.String(), "reconciliation is pending: 0 uncommitted generation(s) to quarantine and 1 crash residue(s) to discard") {
			t.Fatalf("preview log = %q, want the pending reconciliation", log.String())
		}
		log.Reset()
		if _, err := runTemplateCommand(t, string(passphrase)+"\n",
			"repair", "repin", repairEdited, "drop", repairOrphan, "--confirm"); err != nil {
			t.Fatalf("template repair --confirm error = %v", err)
		}
		for _, want := range []string{"reconciled: discarded crash residue " + residue, "template repair committed generation"} {
			if !strings.Contains(log.String(), want) {
				t.Fatalf("repair log = %q, want %q", log.String(), want)
			}
		}
	})
}

// Damage unlock refuses is told apart from damage only a commit refuses: a
// deleted-archive member does not stop an unlock, and the advice for it is
// to prune it, not to rebuild. A damaged key file is reported once.
func TestTemplateRepairAdvisesByDamage(t *testing.T) {
	t.Run("deleted archive member", func(t *testing.T) {
		withDamagedTemplateStore(t, func(passphrase []byte, _ string, log *bytes.Buffer) {
			current := currentGenerationForTest(t, passphrase)
			const member = "deleted/keytypes/test.apstore-repair-archived.v1.template"
			if err := os.WriteFile(filepath.Join(current.Dir(), filepath.FromSlash(member)), []byte("damaged"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := runTemplateCommand(t, string(passphrase)+"\n", "repair"); err != nil {
				t.Fatal(err)
			}
			want := "remove the member with `apadmin archive prune --confirm " + member + "`"
			if !strings.Contains(log.String(), want) || strings.Contains(log.String(), "apstore rebuild") {
				t.Fatalf("preview log = %q, want %q and no rebuild advice", log.String(), want)
			}
			log.Reset()
			_, err := runTemplateCommand(t, string(passphrase)+"\n", "repair", "repin", repairEdited, "drop", repairOrphan, "--confirm")
			if !errors.Is(err, templaterepair.ErrCommitBlocked) || !strings.Contains(log.String(), want) {
				t.Fatalf("template repair --confirm = %v, log %q; want the commit refused with the prune advice", err, log.String())
			}
		})
	})
	t.Run("damaged key file", func(t *testing.T) {
		withDamagedTemplateStore(t, func(passphrase []byte, _ string, log *bytes.Buffer) {
			current := currentGenerationForTest(t, passphrase)
			if err := os.WriteFile(filepath.Join(current.KeysDir(), "DAMAGED.key"), []byte("damaged"), 0o600); err != nil {
				t.Fatal(err)
			}
			stderr := captureStderr(t, func() {
				if _, err := runTemplateCommand(t, string(passphrase)+"\n", "repair"); err != nil {
					t.Error(err)
				}
			})
			if got := strings.Count(stderr, "Warning: "); got != 1 {
				t.Fatalf("stderr = %q: %d scan warnings, want 1", stderr, got)
			}
			if !strings.Contains(log.String(), "which unlock also refuses") || !strings.Contains(log.String(), "apstore rebuild") {
				t.Fatalf("preview log = %q, want the unlock refusal and its advice", log.String())
			}
		})
	})
}

// Every class of damage that refuses a repair carries its own advice.
func TestTemplateRepairAdvicePerRefusal(t *testing.T) {
	var log bytes.Buffer
	appLogger.SetOutput(&log)
	t.Cleanup(func() { appLogger.SetOutput(os.Stderr) })
	oldDataDirectory := dataDirectory
	t.Cleanup(func() { dataDirectory = oldDataDirectory })
	dataDirectory = t.TempDir()
	generation := keystorePaths().GenerationPaths("gen-1700000000-0badc0de")
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"archive member", &storevalidate.DeletedArchiveMemberError{
			Path: "deleted/policies/K.json", Prune: []string{"deleted/policies/K.json", "deleted/policies/K.json.hmac"}, Err: errors.New("bad"),
		}, "`apadmin archive prune --confirm deleted/policies/K.json deleted/policies/K.json.hmac`"},
		{"stray archive file", &storevalidate.DeletedArchiveStrayError{Path: "deleted/keys/notes.txt", Reason: "unsupported deleted credential"},
			filepath.Join(generation.Dir(), "deleted", "keys", "notes.txt") + " is no deleted-archive member, so `apadmin archive prune` cannot remove it: with apsigner stopped, move it out of the store's deleted/ directory"},
		{"unsealed parent", &templaterepair.UnsealedParentError{Parent: "gen-1600000000-0badc0de"},
			"restore " + keystorePaths().GenerationDir("gen-1600000000-0badc0de") + " from the same snapshot as the rest of the store, or move it out of the store"},
		{"too large", fmt.Errorf("%w: over", templaterepair.ErrGenerationTooLarge), "remove deleted-archive members with `apadmin archive prune` until the generation fits"},
		{"cosigner credential limit", fmt.Errorf("credential inventory: %w", keys.ErrCosignerCredentialLimit), "rebuild the store from a backup with `apstore rebuild --address` for the credentials to keep"},
		{"other damage", fmt.Errorf("%w: key file", templaterepair.ErrOtherDamage), otherDamageAdvice},
	} {
		log.Reset()
		adviseRefusal(fmt.Errorf("template repair refused: %w: %w", templaterepair.ErrCommitBlocked, tc.err), generation)
		if !strings.Contains(log.String(), tc.want) {
			t.Fatalf("%s: advice = %q, want %q", tc.name, log.String(), tc.want)
		}
	}
}

// A stray file in the deleted archive, which archive prune cannot remove, is
// named with the advice to move it out by hand.
func TestTemplateRepairAdvisesOnAStrayArchiveFile(t *testing.T) {
	withDamagedTemplateStore(t, func(passphrase []byte, _ string, log *bytes.Buffer) {
		current := currentGenerationForTest(t, passphrase)
		stray := filepath.Join(current.DeletedKeysDir(), "notes.txt")
		if err := os.WriteFile(stray, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := runTemplateCommand(t, string(passphrase)+"\n", "repair"); err != nil {
			t.Fatal(err)
		}
		if want := stray + " is no deleted-archive member"; !strings.Contains(log.String(), want) {
			t.Fatalf("preview log = %q, want %q", log.String(), want)
		}
	})
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = file
	defer func() { os.Stderr = saved }()
	fn()
	data, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// Write residue the --confirm run's reconciliation discards is reported as
// pending, not as damage that refuses the repair, and a dry run passes.
func TestTemplateRepairPreviewSetsWriteResidueAside(t *testing.T) {
	withDamagedTemplateStore(t, func(passphrase []byte, _ string, log *bytes.Buffer) {
		current := currentGenerationForTest(t, passphrase)
		if err := os.WriteFile(filepath.Join(current.KeyTypeRecordsDir(), "x.json.tmp-123"), []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := runTemplateCommand(t, string(passphrase)+"\n", "repair", "repin", repairEdited, "drop", repairOrphan); err != nil {
			t.Fatalf("dry run error = %v, want the repair planned", err)
		}
		if strings.Contains(log.String(), "refused") || !strings.Contains(log.String(), "1 crash residue(s) to discard") {
			t.Fatalf("preview log = %q, want the residue pending and no refusal", log.String())
		}
		log.Reset()
		if _, err := runTemplateCommand(t, string(passphrase)+"\n", "repair", "repin", repairEdited, "drop", repairOrphan, "--confirm"); err != nil {
			t.Fatalf("template repair --confirm error = %v", err)
		}
		if !strings.Contains(log.String(), "x.json.tmp-123") {
			t.Fatalf("repair log = %q, want the residue reported as discarded", log.String())
		}
	})
}

func TestTemplateRepairReportsAnUncertainCommit(t *testing.T) {
	withDamagedTemplateStore(t, func(passphrase []byte, _ string, _ *bytes.Buffer) {
		paths := keystorePaths()
		before, err := crypto.ReadStoreRootExact(paths.ProductDir())
		if err != nil {
			t.Fatal(err)
		}
		fsutil.TestHook = func(op fsutil.HookOp, path string) error {
			if op == fsutil.OpDirSync && path == paths.ProductDir() {
				if visible, err := crypto.ReadStoreRootExact(paths.ProductDir()); err == nil && !bytes.Equal(visible, before) {
					return errors.New("simulated identity-directory sync failure")
				}
			}
			return nil
		}
		t.Cleanup(func() { fsutil.TestHook = nil })
		_, err = runTemplateCommand(t, string(passphrase)+"\n",
			"repair", "repin", repairEdited, "drop", repairOrphan, "--confirm")
		fsutil.TestHook = nil
		if !genstore.RootCommitUncertain(err) || !strings.Contains(err.Error(), "template repair may have committed as generation") ||
			!strings.Contains(err.Error(), "start apsigner and unlock it to check") {
			t.Fatalf("template repair error = %v, want the may-have-committed error", err)
		}
	})
}

func TestTemplateRepairUsage(t *testing.T) {
	for name, args := range map[string][]string{
		"no subcommand":           {},
		"unknown subcommand":      {"fix"},
		"key type before a verb":  {"repair", repairEdited, "repin", repairOrphan},
		"key type named twice":    {"repair", "repin", repairEdited, "drop", strings.ToUpper(repairEdited)},
		"verb given twice":        {"repair", "drop", repairEdited, "drop", repairOrphan},
		"verb with no key type":   {"repair", "repin", "drop", repairOrphan},
		"--confirm alone":         {"repair", "--confirm"},
		"--confirm twice":         {"repair", "drop", repairOrphan, "--confirm", "--confirm"},
		"unknown option":          {"repair", "drop", repairOrphan, "--yes"},
		"malformed key type name": {"repair", "drop", "bad/key"},
	} {
		_, err := parseTemplateCommand(args)
		if got := exitCodeForError(err); got != apstoreExitUsage {
			t.Fatalf("%s: parseTemplateCommand(%v) = %v (exit %d), want a usage error", name, args, err, got)
		}
	}
}

// A malformed command line is a usage error even while a running signer
// holds the store: dispatch parses it before the execution-mode check and
// the store lock.
func TestTemplateRepairUsageErrorBeforeTheStoreLock(t *testing.T) {
	oldDataDirectory := dataDirectory
	t.Cleanup(func() { dataDirectory = oldDataDirectory })
	dataDirectory = t.TempDir()
	guard, err := storelock.AcquireShared(dataDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = guard.Close() }()
	code, logged := dispatchUntilExit(t, []string{"template", "bogus"})
	if code != apstoreExitUsage || !strings.Contains(logged, templateRepairUsage) {
		t.Fatalf("dispatch(template bogus) = exit %d, logged %q; want the usage error", code, logged)
	}
}

// apstore template repair, a preview included, refuses a store a running
// signer holds.
func TestTemplateRepairNeedsTheExclusiveStoreLock(t *testing.T) {
	dataDir := t.TempDir()
	guard, err := storelock.AcquireShared(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = guard.Close() }()
	for _, args := range [][]string{{"template", "repair"}, {"template", "repair", "drop", repairOrphan, "--confirm"}} {
		release, err := acquireOfflineMutationLockForArgs(args, dataDir)
		if err == nil {
			release()
			t.Fatalf("acquireOfflineMutationLockForArgs(%v) took the lock a signer holds", args)
		}
		if !strings.Contains(err.Error(), "while apsigner or another apstore mutation holds the store lock") {
			t.Fatalf("acquireOfflineMutationLockForArgs(%v) error = %v", args, err)
		}
	}
}

func currentGenerationForTest(t *testing.T, passphrase []byte) storepaths.GenPaths {
	t.Helper()
	active, kr, err := genstore.ResolveStoreRoot(keystorePaths(), passphrase)
	if err != nil {
		t.Fatal(err)
	}
	kr.Zero()
	return active
}

func apstoreStoreDigest(t *testing.T) string {
	t.Helper()
	paths := keystorePaths()
	root, err := crypto.ReadStoreRootExact(paths.ProductDir())
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	hash.Write(root)
	err = filepath.WalkDir(paths.GenerationsDir(), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		hash.Write([]byte(path + "\x00"))
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		hash.Write(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func apstoreRepairYAML(keyType string) []byte {
	family := strings.TrimSuffix(strings.TrimPrefix(keyType, "test."), ".v1")
	return []byte(`schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: ` + family + `
version: 1
display_name: "Apstore Repair"
valid_rekey_target: false
max_opcode_cost: 20000
teal: |
  #pragma version 10
  int 1
  return
`)
}
