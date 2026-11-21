// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templaterepair_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/lsigsalt/lsigsalttest"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"
	"github.com/aplane-algo/aplane/internal/signerapp/templaterepair"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatelibrary"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/lsig/clientreg"
)

const (
	healthy        = "test.repair-healthy.v1"
	editedGeneric  = "test.repair-edited-generic.v1"
	editedComposed = "test.repair-edited-composed.v1"
	orphanGeneric  = "test.repair-orphan-generic.v1"
	orphanComposed = "test.repair-orphan-composed.v1"
	orphanDisabled = "test.repair-orphan-disabled.v1"

	editedFingerprint = "1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	otherFingerprint  = "1:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	activatedAt       = "2026-01-02T03:04:05Z"
)

type fixture struct {
	t          *testing.T
	paths      storepaths.Paths
	passphrase []byte
	opts       templaterepair.Options
	// installed is the fingerprint each install recorded.
	installed map[string]string
	keyCount  int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	clientreg.RegisterClient()
	root := t.TempDir()
	paths := storepaths.NewPaths(root)
	passphrase := []byte("template-repair-test-passphrase")
	if _, err := storeinit.Initialize(passphrase, storeinit.Options{ValidateCandidate: storevalidate.FirstGeneration,
		DataDir: root, Paths: paths, Role: noderole.RoleSigner,
	}); err != nil {
		t.Fatal(err)
	}
	cfg := serverconfig.DefaultServerConfig()
	f := &fixture{
		t: t, paths: paths, passphrase: passphrase, installed: map[string]string{},
		opts: templaterepair.Options{Paths: paths, Role: noderole.RoleSigner, DataDir: root, Config: &cfg},
	}
	f.reopen()
	return f
}

// reopen resolves the store root fresh, as apstore does on each run.
func (f *fixture) reopen() {
	f.t.Helper()
	active, kr, err := genstore.ResolveStoreRoot(f.paths, f.passphrase)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(kr.Zero)
	f.opts.Current, f.opts.Keyring = active, kr
}

func (f *fixture) install(yaml []byte) {
	f.t.Helper()
	parsed, err := templatelibrary.ParseYAML("source.yaml", yaml)
	if err != nil {
		f.t.Fatal(err)
	}
	bound := genstoretest.BindActive(f.t, f.paths, f.opts.Current)
	if _, err := templatelibrary.InstallParsed(bound, parsed, f.opts.Keyring); err != nil {
		f.t.Fatalf("InstallParsed(%s) error = %v", parsed.KeyType, err)
	}
	rec := f.record(parsed.KeyType)
	f.installed[parsed.KeyType] = rec.Fingerprint
	rec.ActivatedAt = activatedAt
	f.put(rec)
}

func (f *fixture) record(keyType string) keytypestate.Record {
	f.t.Helper()
	rec, ok, err := keytypestate.GetActive(f.opts.Current, keyType)
	if err != nil || !ok {
		f.t.Fatalf("GetActive(%s) = %v, %v", keyType, ok, err)
	}
	return rec
}

func (f *fixture) put(rec keytypestate.Record) {
	f.t.Helper()
	if err := keytypestate.PutActive(f.opts.Current, rec); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) editRecord(keyType string) {
	f.t.Helper()
	rec := f.record(keyType)
	rec.Fingerprint = editedFingerprint
	f.put(rec)
}

// orphan installs yaml and removes its template file, leaving the record
// with state.
func (f *fixture) orphan(yaml []byte, keyType string, state keytypestate.State) {
	f.t.Helper()
	f.install(yaml)
	rec := f.record(keyType)
	rec.State = state
	f.put(rec)
	if err := os.Remove(f.opts.Current.KeyTypeTemplate(keyType)); err != nil {
		f.t.Fatal(err)
	}
}

// addKey writes a generic LogicSig aplane key of keyType whose provenance
// names templateFingerprint.
func (f *fixture) addKey(keyType, templateFingerprint string) {
	f.t.Helper()
	f.keyCount++
	program := lsigsalttest.OffCurve(f.t, []byte{0x06, 0x81, byte(f.keyCount), 0x00}, 3)
	payload := keys.NewGenericLSigPayload(keyType, nil, program.Bytecode, "", nil, templateFingerprint)
	if err := payload.SetLogicSigOpcodeProfile(lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling), false); err != nil {
		f.t.Fatal(err)
	}
	if _, err := keys.SaveNewPayloadActive(f.opts.Current, payload, false, f.opts.Keyring); err != nil {
		f.t.Fatalf("SaveNewPayloadActive() error = %v", err)
	}
}

// damagedStore holds one of each template record defect beside a healthy
// template, and keys of the edited generic key type.
func damagedStore(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	f.install(genericYAML("repair-healthy"))
	f.install(genericYAML("repair-edited-generic"))
	f.install(composedYAML("repair-edited-composed"))
	f.editRecord(editedGeneric)
	f.editRecord(editedComposed)
	f.orphan(genericYAML("repair-orphan-generic"), orphanGeneric, keytypestate.StateEnabled)
	f.orphan(composedYAML("repair-orphan-composed"), orphanComposed, keytypestate.StateEnabled)
	f.orphan(genericYAML("repair-orphan-disabled"), orphanDisabled, keytypestate.StateDisabled)
	f.addKey(editedGeneric, f.installed[editedGeneric])
	f.addKey(editedGeneric, otherFingerprint)
	f.addKey(editedGeneric, "")
	f.addKey(healthy, f.installed[healthy])
	return f
}

// The defects a store holds are what an unlock refuses it for.
func requireRecovery(t *testing.T, f *fixture) {
	t.Helper()
	opts := storevalidate.Options{
		Paths: f.paths, Candidate: f.opts.Current, Keyring: f.opts.Keyring,
		ExpectedRole: f.opts.Role, DataDir: f.opts.DataDir, Config: f.opts.Config,
	}
	if err := storevalidate.Candidate(opts); err == nil || !strings.Contains(err.Error(), "template/key-type content defect") {
		t.Fatalf("Candidate() error = %v, want a template record defect", err)
	}
}

func TestInspectClassifiesEveryRecordDefect(t *testing.T) {
	f := damagedStore(t)
	requireRecovery(t, f)
	preview, err := templaterepair.Inspect(f.opts)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if preview.GenerationID != f.opts.Current.GenerationID() || preview.OtherDamage != nil {
		t.Fatalf("Inspect() = generation %s, other damage %v; want %s and none", preview.GenerationID, preview.OtherDamage, f.opts.Current.GenerationID())
	}
	want := []templaterepair.Defect{
		{KeyType: orphanGeneric, Kind: signertemplates.RecordOrphaned, TemplateType: templatestore.TemplateTypeGeneric,
			DefaultAction: templaterepair.ActionDrop, RecordedFingerprint: f.installed[orphanGeneric]},
		{KeyType: orphanComposed, Kind: signertemplates.RecordOrphaned, TemplateType: templatestore.TemplateTypeComposed,
			DefaultAction: templaterepair.ActionDrop, RecordedFingerprint: f.installed[orphanComposed]},
		{KeyType: editedGeneric, Kind: signertemplates.RecordExternalEdit, TemplateType: templatestore.TemplateTypeGeneric,
			DefaultAction: templaterepair.ActionRepin, Keys: 3, ConflictAfterRepin: 1,
			RecordedFingerprint: editedFingerprint, TemplateFingerprint: f.installed[editedGeneric]},
		{KeyType: editedComposed, Kind: signertemplates.RecordExternalEdit, TemplateType: templatestore.TemplateTypeComposed,
			DefaultAction:       templaterepair.ActionRepin,
			RecordedFingerprint: editedFingerprint, TemplateFingerprint: f.installed[editedComposed]},
		{KeyType: orphanDisabled, Kind: signertemplates.RecordDisabledOrphaned,
			DefaultAction: templaterepair.ActionDrop, RecordedFingerprint: f.installed[orphanDisabled]},
	}
	if !reflect.DeepEqual(preview.Defects, want) {
		t.Fatalf("Inspect().Defects =\n%+v\nwant\n%+v", preview.Defects, want)
	}
}

func TestInspectOfAHealthyStoreFindsNothing(t *testing.T) {
	f := newFixture(t)
	f.install(genericYAML("repair-healthy"))
	preview, err := templaterepair.Inspect(f.opts)
	if err != nil || len(preview.Defects) != 0 || preview.OtherDamage != nil {
		t.Fatalf("Inspect() = %+v, %v; want nothing", preview, err)
	}
}

func TestRepairCommitsAGenerationThatValidates(t *testing.T) {
	for _, tc := range []struct {
		name    string
		actions map[string]templaterepair.Action
	}{
		{"repin the edits", map[string]templaterepair.Action{
			editedGeneric: templaterepair.ActionRepin, editedComposed: templaterepair.ActionRepin,
			orphanGeneric: templaterepair.ActionDrop, orphanComposed: templaterepair.ActionDrop, orphanDisabled: templaterepair.ActionDrop,
		}},
		{"drop everything", map[string]templaterepair.Action{
			editedGeneric: templaterepair.ActionDrop, editedComposed: templaterepair.ActionDrop,
			orphanGeneric: templaterepair.ActionDrop, orphanComposed: templaterepair.ActionDrop, orphanDisabled: templaterepair.ActionDrop,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := damagedStore(t)
			damaged := f.opts.Current
			keysBefore := treeDigest(t, damaged.KeysDir())
			healthyBefore := f.record(healthy)

			result, err := templaterepair.Repair(f.opts, tc.actions)
			if err != nil {
				t.Fatalf("Repair() error = %v", err)
			}
			if result.Parent != damaged.GenerationID() || result.GenerationID == damaged.GenerationID() || result.CommitUncertain {
				t.Fatalf("Repair() = %+v, want a new generation over %s", result, damaged.GenerationID())
			}
			f.reopen()
			repaired := f.opts.Current
			if repaired.GenerationID() != result.GenerationID {
				t.Fatalf("store root selects %s, want %s", repaired.GenerationID(), result.GenerationID)
			}
			manifest, err := genstore.ReadManifest(repaired)
			if err != nil {
				t.Fatal(err)
			}
			if manifest.Operation != templaterepair.Operation || manifest.ParentID != damaged.GenerationID() {
				t.Fatalf("manifest = operation %q parent %q, want %q over %s", manifest.Operation, manifest.ParentID, templaterepair.Operation, damaged.GenerationID())
			}
			// The damaged generation is kept, sealed, as the rollback parent.
			if err := genstore.ValidateSealed(damaged, f.opts.Keyring); err != nil {
				t.Fatalf("damaged generation after the repair: %v", err)
			}
			if got := treeDigest(t, repaired.KeysDir()); got != keysBefore {
				t.Fatal("the repair changed a key file")
			}
			if got := f.record(healthy); got != healthyBefore {
				t.Fatalf("healthy record after the repair = %+v, want %+v", got, healthyBefore)
			}

			for _, entry := range result.Entries {
				if entry.Action != tc.actions[entry.KeyType] {
					t.Fatalf("entry %s action = %s, want %s", entry.KeyType, entry.Action, tc.actions[entry.KeyType])
				}
				requireRepaired(t, f, entry)
			}
			if len(result.Entries) != len(tc.actions) {
				t.Fatalf("Repair() reported %d entries, want %d", len(result.Entries), len(tc.actions))
			}

			// What an unlock checks: the full candidate validation and the
			// reload's template registration.
			if err := storevalidate.Candidate(storevalidate.Options{
				Paths: f.paths, Candidate: repaired, Keyring: f.opts.Keyring,
				ExpectedRole: f.opts.Role, DataDir: f.opts.DataDir, Config: f.opts.Config,
			}); err != nil {
				t.Fatalf("Candidate(repaired) error = %v", err)
			}
			manager := signertemplates.NewManager(f.paths)
			manager.ActivePaths = repaired
			report, err := manager.RegisterKeystoreTemplates(f.opts.Keyring)
			for _, keyType := range []string{healthy, editedGeneric, editedComposed} {
				t.Cleanup(func() { signertemplates.UnregisterProductProvider(keyType) })
			}
			if err != nil || len(report.ContentDefectKeyTypes()) != 0 || len(report.Warnings()) != 0 {
				t.Fatalf("RegisterKeystoreTemplates(repaired) = %v, warnings %q, %v", report.ContentDefectKeyTypes(), report.Warnings(), err)
			}
		})
	}
}

func requireRepaired(t *testing.T, f *fixture, entry templaterepair.Entry) {
	t.Helper()
	repaired := f.opts.Current
	rec, ok, err := keytypestate.GetActive(repaired, entry.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	switch entry.Action {
	case templaterepair.ActionRepin:
		want := keytypestate.Record{
			KeyType: entry.KeyType, Source: rec.Source, State: keytypestate.StateEnabled,
			Fingerprint: f.installed[entry.KeyType], ActivatedAt: activatedAt,
		}
		if !ok || rec != want {
			t.Fatalf("re-pinned record %s = %+v, want %+v", entry.KeyType, rec, want)
		}
	case templaterepair.ActionDrop:
		if ok {
			t.Fatalf("dropped record %s is still there: %+v", entry.KeyType, rec)
		}
		archive := repaired.DeletedKeyTypeTemplate(entry.KeyType)
		_, statErr := os.Stat(archive)
		if entry.Kind == signertemplates.RecordExternalEdit {
			if statErr != nil || entry.Archived != archive {
				t.Fatalf("dropped edit %s: archived %q (%v), want %q", entry.KeyType, entry.Archived, statErr, archive)
			}
			if _, err := os.Stat(repaired.KeyTypeTemplate(entry.KeyType)); !os.IsNotExist(err) {
				t.Fatalf("dropped edit %s still has its template file: %v", entry.KeyType, err)
			}
		} else if !os.IsNotExist(statErr) || entry.Archived != "" {
			t.Fatalf("dropped orphan %s: archived %q (%v), want nothing", entry.KeyType, entry.Archived, statErr)
		}
	}
}

// Every refusal is decided before anything is staged: the store root, the
// generations and the selected generation's content stay exactly as they
// were.
func TestRepairRefusalsChangeNothing(t *testing.T) {
	all := func(overrides map[string]templaterepair.Action) map[string]templaterepair.Action {
		actions := map[string]templaterepair.Action{
			editedGeneric: templaterepair.ActionRepin, editedComposed: templaterepair.ActionRepin,
			orphanGeneric: templaterepair.ActionDrop, orphanComposed: templaterepair.ActionDrop, orphanDisabled: templaterepair.ActionDrop,
		}
		for keyType, action := range overrides {
			if action == "" {
				delete(actions, keyType)
				continue
			}
			actions[keyType] = action
		}
		return actions
	}
	for _, tc := range []struct {
		name    string
		damage  func(t *testing.T, f *fixture)
		actions map[string]templaterepair.Action
		want    error
		detail  string
	}{
		{name: "a healthy key type", actions: all(map[string]templaterepair.Action{healthy: templaterepair.ActionDrop}),
			want: templaterepair.ErrNotDefective, detail: healthy},
		{name: "a key type the store does not have", actions: all(map[string]templaterepair.Action{"test.absent.v1": templaterepair.ActionDrop}),
			want: templaterepair.ErrNotDefective, detail: "test.absent.v1"},
		{name: "a re-pin of an orphaned record", actions: all(map[string]templaterepair.Action{orphanComposed: templaterepair.ActionRepin}),
			want: templaterepair.ErrRepinRefused, detail: orphanComposed},
		{name: "a re-pin of a disabled record without template", actions: all(map[string]templaterepair.Action{orphanDisabled: templaterepair.ActionRepin}),
			want: templaterepair.ErrRepinRefused, detail: orphanDisabled},
		{name: "a defect left out", actions: all(map[string]templaterepair.Action{orphanGeneric: ""}),
			want: templaterepair.ErrUnnamedDefect, detail: orphanGeneric},
		{name: "nothing named", actions: map[string]templaterepair.Action{}, want: templaterepair.ErrNothingNamed},
		{name: "a damaged key file", actions: all(nil), want: templaterepair.ErrOtherDamage, detail: "credential content defect",
			damage: func(t *testing.T, f *fixture) {
				if err := os.WriteFile(filepath.Join(f.opts.Current.KeysDir(), "DAMAGED.key"), []byte("damaged"), 0o600); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "a damaged policy", actions: all(nil), want: templaterepair.ErrOtherDamage, detail: "policy",
			damage: func(t *testing.T, f *fixture) {
				if err := os.WriteFile(f.opts.Current.DefaultPolicyIntegritySidecar(), []byte("damaged"), 0o600); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "an invalid template beside the defects", actions: all(nil), want: templaterepair.ErrOtherDamage, detail: healthy,
			damage: func(t *testing.T, f *fixture) {
				if err := os.WriteFile(f.opts.Current.KeyTypeTemplate(healthy), []byte("damaged"), 0o600); err != nil {
					t.Fatal(err)
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := damagedStore(t)
			if tc.damage != nil {
				tc.damage(t, f)
			}
			before := storeDigest(t, f)
			_, err := templaterepair.Repair(f.opts, tc.actions)
			if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.detail) {
				t.Fatalf("Repair() error = %v, want %v naming %q", err, tc.want, tc.detail)
			}
			if after := storeDigest(t, f); after != before {
				t.Fatal("a refused repair changed the store")
			}
		})
	}
}

// A commit whose store root cannot be confirmed durable is reported as one
// that may have landed, with the generation it would select.
func TestRepairReportsAnUncertainCommit(t *testing.T) {
	f := damagedStore(t)
	parent := f.opts.Current.GenerationID()
	before, err := crypto.ReadStoreRootExact(f.paths.ProductDir())
	if err != nil {
		t.Fatal(err)
	}
	// Fail the directory sync that follows the new root's rename.
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && path == f.paths.ProductDir() {
			if visible, err := crypto.ReadStoreRootExact(f.paths.ProductDir()); err == nil && !bytes.Equal(visible, before) {
				return errors.New("simulated identity-directory sync failure")
			}
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })
	result, err := templaterepair.Repair(f.opts, map[string]templaterepair.Action{
		editedGeneric: templaterepair.ActionRepin, editedComposed: templaterepair.ActionRepin,
		orphanGeneric: templaterepair.ActionDrop, orphanComposed: templaterepair.ActionDrop, orphanDisabled: templaterepair.ActionDrop,
	})
	fsutil.TestHook = nil
	if !genstore.RootCommitUncertain(err) || !result.CommitUncertain || result.Parent != parent ||
		!strings.Contains(err.Error(), "template repair may have committed as generation "+result.GenerationID) {
		t.Fatalf("Repair() = %+v, %v; want an uncertain commit", result, err)
	}
	f.reopen()
	if f.opts.Current.GenerationID() != result.GenerationID {
		t.Fatalf("store root selects %s, want the uncertain %s", f.opts.Current.GenerationID(), result.GenerationID)
	}
}

// A mint that fails before the root moves leaves the damaged generation
// selected and says nothing was committed.
func TestRepairFailureBeforeTheRootMovesCommitsNothing(t *testing.T) {
	f := damagedStore(t)
	before, err := crypto.ReadStoreRootExact(f.paths.ProductDir())
	if err != nil {
		t.Fatal(err)
	}
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpRename && path == f.paths.StoreRootPath() {
			return errors.New("simulated store root rename failure")
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })
	result, err := templaterepair.Repair(f.opts, map[string]templaterepair.Action{
		editedGeneric: templaterepair.ActionDrop, editedComposed: templaterepair.ActionDrop,
		orphanGeneric: templaterepair.ActionDrop, orphanComposed: templaterepair.ActionDrop, orphanDisabled: templaterepair.ActionDrop,
	})
	fsutil.TestHook = nil
	if err == nil || genstore.RootCommitUncertain(err) || result.CommitUncertain ||
		!strings.Contains(err.Error(), "nothing was committed") {
		t.Fatalf("Repair() = %+v, %v; want a failure before commit", result, err)
	}
	after, err := crypto.ReadStoreRootExact(f.paths.ProductDir())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("store root after a failed repair changed (%v)", err)
	}
}

// storeDigest covers the store root and every generation's content.
func storeDigest(t *testing.T, f *fixture) string {
	t.Helper()
	root, err := crypto.ReadStoreRootExact(f.paths.ProductDir())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(root)
	return hex.EncodeToString(sum[:]) + treeDigest(t, f.paths.GenerationsDir())
}

func treeDigest(t *testing.T, dir string) string {
	t.Helper()
	hash := sha256.New()
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		hash.Write([]byte(relative + "\x00"))
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

func genericYAML(family string) []byte {
	return []byte(`schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: ` + family + `
version: 1
display_name: "Repair Generic"
valid_rekey_target: false
max_opcode_cost: 20000
teal: |
  #pragma version 10
  int 1
  return
`)
}

func composedYAML(family string) []byte {
	return []byte(`schema_version: 1
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: generated
publisher: test
family: ` + family + `
version: 1
display_name: "Repair Composed"
valid_rekey_target: true
max_opcode_cost: 20000
teal: |
  int 1
  assert
`)
}
