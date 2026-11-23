// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storevalidate_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/asasetstore"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/lsig/clientreg"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

func TestRecoveryDestinationRefusesDamageOutsideSelectedCredential(t *testing.T) {
	clientreg.RegisterClient()
	tests := map[string]func(t *testing.T, active storepaths.GenPaths){
		"policy sidecar": func(t *testing.T, active storepaths.GenPaths) {
			writeDamage(t, active.DefaultPolicyIntegritySidecar())
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
		"asa set sidecar without its set": func(t *testing.T, active storepaths.GenPaths) {
			writeDamage(t, active.ASASetIntegritySidecar())
		},
		"unauthenticated asa set": func(t *testing.T, active storepaths.GenPaths) {
			writeDamage(t, active.ASASetPath())
			writeDamage(t, active.ASASetIntegritySidecar())
		},
	}
	for name, damage := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			paths := storepaths.NewPaths(root)
			passphrase := []byte("storevalidate-test-passphrase")
			if _, err := storeinit.Initialize(passphrase, storeinit.Options{ValidateCandidate: storevalidate.FirstGeneration,
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

// A valid ASA set passes candidate validation; the same store with the set's
// sidecar damaged does not.
func TestCandidateAuthenticatesTheASASet(t *testing.T) {
	clientreg.RegisterClient()
	root := t.TempDir()
	paths := storepaths.NewPaths(root)
	passphrase := []byte("storevalidate-test-passphrase")
	if _, err := storeinit.Initialize(passphrase, storeinit.Options{ValidateCandidate: storevalidate.FirstGeneration,
		DataDir: root, Paths: paths, Role: noderole.RoleSigner,
	}); err != nil {
		t.Fatal(err)
	}
	active, kr, err := genstore.ResolveStoreRoot(paths, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	set, err := asaset.New([]asaset.Entry{{
		Identity:              asaset.Identity{Genesis: asaset.GenesisHash{1}, AssetID: 7},
		UnitName:              "XYZ",
		Decimals:              2,
		Creator:               types.Address{3}.String(),
		ConfirmedAt:           time.Unix(1_785_200_000, 0),
		NetworkAtConfirmation: "private-dev",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := asasetstore.Write(active, set, kr, time.Unix(1_785_200_000, 0)); err != nil {
		t.Fatal(err)
	}
	opts := storevalidate.Options{
		Paths: paths, Candidate: active, Keyring: kr,
		ExpectedRole: noderole.RoleSigner, DataDir: root,
		Config: &serverconfig.ServerConfig{},
	}
	if err := storevalidate.Candidate(opts); err != nil {
		t.Fatalf("Candidate() with a valid asa set error = %v", err)
	}
	writeDamage(t, active.ASASetIntegritySidecar())
	if err := storevalidate.Candidate(opts); err == nil || !strings.Contains(err.Error(), "asa set") {
		t.Fatalf("Candidate() with a damaged asa set sidecar error = %v", err)
	}
}

// Admission is for submitted documents only: a generation whose stored
// default names an unknown network and an asset outside the set, as one
// written before admission was enforced might, still validates, so restore,
// rollback and rotation keep it.
func TestCandidateKeepsDocumentsTheNodeWouldNotAdmit(t *testing.T) {
	clientreg.RegisterClient()
	root := t.TempDir()
	paths := storepaths.NewPaths(root)
	passphrase := []byte("storevalidate-test-passphrase")
	if _, err := storeinit.Initialize(passphrase, storeinit.Options{ValidateCandidate: storevalidate.FirstGeneration,
		DataDir: root, Paths: paths, Role: noderole.RoleSigner,
	}); err != nil {
		t.Fatal(err)
	}
	active, kr, err := genstore.ResolveStoreRoot(paths, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	legacy := policytest.MustDocument(noderole.RoleSigner, policy.DefaultKey,
		`{"limits": {"mainet": {"algo": {"reject_above": "1"}}, "mainnet": {"asa:999999": {"reject_above": "1"}}}}`)
	if err := policy.WriteDefault(active, noderole.RoleSigner, []byte(legacy), kr, time.Unix(1_785_200_000, 0)); err != nil {
		t.Fatal(err)
	}
	if err := storevalidate.Candidate(storevalidate.Options{
		Paths: paths, Candidate: active, Keyring: kr,
		ExpectedRole: noderole.RoleSigner, DataDir: root, Config: &serverconfig.ServerConfig{},
	}); err != nil {
		t.Fatalf("Candidate() with a legacy document = %v, want it valid", err)
	}
}

// A template repair is refused for any damage it does not repair: the
// template record defects of the key types it names are all it may skip.
func TestTemplateRepairDestinationSkipsOnlyTheRepairedRecords(t *testing.T) {
	clientreg.RegisterClient()
	const orphan, other = "test.repair-orphan.v1", "test.repair-other.v1"
	setup := func(t *testing.T) (storevalidate.Options, func()) {
		t.Helper()
		root := t.TempDir()
		paths := storepaths.NewPaths(root)
		passphrase := []byte("storevalidate-test-passphrase")
		if _, err := storeinit.Initialize(passphrase, storeinit.Options{ValidateCandidate: storevalidate.FirstGeneration,
			DataDir: root, Paths: paths, Role: noderole.RoleSigner,
		}); err != nil {
			t.Fatal(err)
		}
		active, kr, err := genstore.ResolveStoreRoot(paths, passphrase)
		if err != nil {
			t.Fatal(err)
		}
		// An enabled record with no template file: an orphaned record.
		if err := keytypestate.PutActive(active, keytypestate.Record{
			KeyType: orphan, Source: keytypestate.SourceYAMLGeneric, State: keytypestate.StateEnabled,
		}); err != nil {
			t.Fatal(err)
		}
		return storevalidate.Options{
			Paths: paths, Candidate: active, Keyring: kr,
			ExpectedRole: noderole.RoleSigner, DataDir: root,
			Config: &serverconfig.ServerConfig{},
		}, kr.Zero
	}

	opts, done := setup(t)
	defer done()
	if err := storevalidate.Candidate(opts); err == nil || !strings.Contains(err.Error(), orphan) {
		t.Fatalf("Candidate() error = %v, want the orphaned record", err)
	}
	if scan, err := storevalidate.TemplateRepairDestination(opts, map[string]bool{orphan: true}); err != nil || scan == nil {
		t.Fatalf("TemplateRepairDestination(the orphan) = %v, %v; want the scan and no error", scan, err)
	}
	if _, err := storevalidate.TemplateRepairDestination(opts, map[string]bool{other: true}); err == nil || !strings.Contains(err.Error(), orphan) {
		t.Fatalf("TemplateRepairDestination(another key type) error = %v, want the orphaned record", err)
	}
	if _, err := storevalidate.TemplateRepairDestination(opts, nil); err == nil {
		t.Fatal("TemplateRepairDestination(nothing) accepted a repair that names no key type")
	}

	damage := map[string]func(t *testing.T, active storepaths.GenPaths){
		"policy sidecar": func(t *testing.T, active storepaths.GenPaths) {
			writeDamage(t, active.DefaultPolicyIntegritySidecar())
		},
		"credential": func(t *testing.T, active storepaths.GenPaths) {
			writeDamage(t, filepath.Join(active.KeysDir(), "DAMAGED.key"))
		},
		"another template record": func(t *testing.T, active storepaths.GenPaths) {
			if err := keytypestate.PutActive(active, keytypestate.Record{
				KeyType: other, Source: keytypestate.SourceYAMLComposed, State: keytypestate.StateDisabled,
			}); err != nil {
				t.Fatal(err)
			}
		},
		"key-type namespace": func(t *testing.T, active storepaths.GenPaths) {
			writeDamage(t, filepath.Join(active.KeyTypeRecordsDir(), "notes.txt"))
		},
	}
	for name, damage := range damage {
		t.Run(name, func(t *testing.T) {
			opts, done := setup(t)
			defer done()
			damage(t, opts.Candidate)
			if _, err := storevalidate.TemplateRepairDestination(opts, map[string]bool{orphan: true}); err == nil {
				t.Fatal("TemplateRepairDestination() accepted damage the repair does not cover")
			}
		})
	}

	// Unlock never opens a deleted-archive member, so the gate leaves a
	// damaged one to CommitOnlyDamage, which every commit's Candidate check
	// also refuses, and names the member.
	t.Run("deleted archive member", func(t *testing.T) {
		opts, done := setup(t)
		defer done()
		const member = "deleted/keytypes/test.repair-archived.v1.template"
		writeDamage(t, filepath.Join(opts.Candidate.Dir(), filepath.FromSlash(member)))
		scan, err := storevalidate.TemplateRepairDestination(opts, map[string]bool{orphan: true})
		if err != nil {
			t.Fatalf("TemplateRepairDestination() error = %v, want the archive member left to commit validation", err)
		}
		var damaged *storevalidate.DeletedArchiveMemberError
		if err := storevalidate.CommitOnlyDamage(opts, scan); !errors.As(err, &damaged) || damaged.Path != member {
			t.Fatalf("CommitOnlyDamage() error = %v, want the member %s", err, member)
		}
		if err := storevalidate.Candidate(opts); !errors.As(err, &damaged) || damaged.Path != member {
			t.Fatalf("Candidate() error = %v, want the member %s", err, member)
		}
		if !reflect.DeepEqual(damaged.Prune, []string{member}) {
			t.Fatalf("member prune selection = %q, want %q", damaged.Prune, member)
		}
	})
	// An archived policy document is pruned together with its sidecar.
	t.Run("archived policy document", func(t *testing.T) {
		opts, done := setup(t)
		defer done()
		const document = "deleted/policies/K.json"
		writeDamage(t, filepath.Join(opts.Candidate.Dir(), filepath.FromSlash(document)))
		writeDamage(t, filepath.Join(opts.Candidate.Dir(), filepath.FromSlash(document+".hmac")))
		var damaged *storevalidate.DeletedArchiveMemberError
		err := storevalidate.Candidate(opts)
		if !errors.As(err, &damaged) || !reflect.DeepEqual(damaged.Prune, []string{document, document + ".hmac"}) {
			t.Fatalf("Candidate() error = %v (%+v), want the document and its sidecar to prune", err, damaged)
		}
	})
	// A file whose name no member takes is not prunable, and says so by type.
	t.Run("stray file", func(t *testing.T) {
		opts, done := setup(t)
		defer done()
		const stray = "deleted/keys/notes.txt"
		writeDamage(t, filepath.Join(opts.Candidate.Dir(), filepath.FromSlash(stray)))
		scan, err := storevalidate.TemplateRepairDestination(opts, map[string]bool{orphan: true})
		if err != nil {
			t.Fatal(err)
		}
		var strayErr *storevalidate.DeletedArchiveStrayError
		if err := storevalidate.CommitOnlyDamage(opts, scan); !errors.As(err, &strayErr) || strayErr.Path != stray ||
			err.Error() != `deleted archive: unsupported deleted credential "`+stray+`"` {
			t.Fatalf("CommitOnlyDamage() error = %v, want the stray %s", err, stray)
		}
	})
}

// Candidate (and therefore apstore verify and generation commits) must reject
// a disabled YAML template whose stored file no longer matches its recorded
// compatibility fingerprint.
func TestCandidateRejectsDisabledTemplateWithMismatchedFingerprint(t *testing.T) {
	clientreg.RegisterClient()
	root := t.TempDir()
	paths := storepaths.NewPaths(root)
	passphrase := []byte("storevalidate-test-passphrase")
	if _, err := storeinit.Initialize(passphrase, storeinit.Options{
		ValidateCandidate: storevalidate.FirstGeneration,
		DataDir:           root,
		Paths:             paths,
		Role:              noderole.RoleSigner,
	}); err != nil {
		t.Fatal(err)
	}
	active, kr, err := genstore.ResolveStoreRoot(paths, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()

	const keyType = "test.disabled-verify.v1"
	yamlV1 := []byte(`schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: disabled-verify
version: 1
display_name: "Disabled Verify"
valid_rekey_target: false
description: "Disabled fingerprint test"
max_opcode_cost: 20000
parameters: []
runtime_args: []
teal: |
  #pragma version 8
  int 1
  return
`)
	yamlV2 := []byte(`schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: disabled-verify
version: 1
display_name: "Disabled Verify"
valid_rekey_target: false
description: "Disabled fingerprint test"
max_opcode_cost: 20000
parameters: []
runtime_args: []
teal: |
  #pragma version 8
  int 2
  return
`)
	fpV1, err := generictemplate.SemanticFingerprint(yamlV1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := templatestore.SaveTemplateActive(active, yamlV1, keyType, templatestore.TemplateTypeGeneric, kr); err != nil {
		t.Fatal(err)
	}
	if err := keytypestate.PutActive(active, keytypestate.Record{
		KeyType:     keyType,
		Source:      keytypestate.SourceYAMLGeneric,
		State:       keytypestate.StateDisabled,
		Fingerprint: fpV1,
	}); err != nil {
		t.Fatal(err)
	}

	opts := storevalidate.Options{
		Paths: paths, Candidate: active, Keyring: kr,
		ExpectedRole: noderole.RoleSigner, DataDir: root,
		Config: &serverconfig.ServerConfig{},
	}
	if err := storevalidate.Candidate(opts); err != nil {
		t.Fatalf("Candidate() with matching disabled template fingerprint error = %v", err)
	}

	// Replace the disabled template file with different valid YAML without
	// updating the state record's fingerprint.
	if _, err := templatestore.SaveTemplateActive(active, yamlV2, keyType, templatestore.TemplateTypeGeneric, kr); err != nil {
		t.Fatal(err)
	}
	var defectErr *storevalidate.TemplateContentDefectError
	err = storevalidate.Candidate(opts)
	if !errors.As(err, &defectErr) {
		t.Fatalf("Candidate() error = %v, want *TemplateContentDefectError", err)
	}
	if filepath.Base(defectErr.Path) != keyType+".template" || !strings.Contains(defectErr.Defect, "fingerprint") {
		t.Fatalf("TemplateContentDefectError = %+v, want fingerprint defect on %s.template", defectErr, keyType)
	}
}
