// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	"github.com/aplane-algo/aplane/internal/policyexport"
	"github.com/aplane-algo/aplane/internal/protocol"
)

const privateDevHash = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="

// exportedSession is a cosigner node with key A's own document, exported
// into dir.
func exportedSession(t *testing.T) (*fakeOnlineSession, string) {
	t.Helper()
	onlineEnv(t)
	session := newFakeSession("cosigner", protocol.PolicyDocumentWire{Key: testKeyA, Document: testCosignerDoc(testKeyA)})
	session.makeReal(t, map[string]string{"private-dev": privateDevHash})
	dir := filepath.Join(t.TempDir(), "export")
	var stdout bytes.Buffer
	if err := (OnlineRunner{Session: session}).Run(context.Background(), Command{Verb: VerbExport, ExportDir: dir}, Streams{Stdout: &stdout}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "exported 2 policy document(s) and the node context to "+dir) {
		t.Fatalf("stdout = %q", stdout.String())
	}
	return session, dir
}

// editedCosignerDoc is key A's document with an operator's edit.
func editedCosignerDoc() string {
	return policytest.MustDocument(noderole.RoleCosigner, testKeyA, `{"reject_clawback": true}`)
}

func TestExportAllWritesTheDocumentsAndTheContext(t *testing.T) {
	session, dir := exportedSession(t)
	for key, want := range session.bodies {
		data, err := os.ReadFile(filepath.Join(dir, key+".json"))
		if err != nil || string(data) != want {
			t.Fatalf("%s.json = %q, %v", key, data, err)
		}
	}
	selected, err := policyexport.Discover([]string{filepath.Join(dir, policy.DefaultKey+".json")}, "")
	if err != nil || selected == nil || selected.Export.Baseline.SnapshotSHA256 != session.snapshot {
		t.Fatalf("export context = %+v, %v; want the node's snapshot", selected, err)
	}
	if _, ok := selected.Export.Context.Chain("private-dev"); !ok {
		t.Fatal("the export lacks the node's custom network")
	}
}

// The documents are fetched against the snapshot the export read; a node
// that moves during the export is refused, and nothing is written.
func TestExportAllStopsWhenTheNodeMoves(t *testing.T) {
	onlineEnv(t)
	session := newFakeSession("cosigner")
	session.makeReal(t, nil)
	moving := &movingSession{fakeOnlineSession: session}
	dir := filepath.Join(t.TempDir(), "export")
	err := (OnlineRunner{Session: moving}).Run(context.Background(), Command{Verb: VerbExport, ExportDir: dir}, Streams{})
	if err == nil || !strings.Contains(err.Error(), "changed since the snapshot") {
		t.Fatalf("export = %v, want the moved node refused", err)
	}
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Fatal("a refused export created its directory")
	}
}

func TestApplyFromACurrentExport(t *testing.T) {
	session, dir := exportedSession(t)
	edited := filepath.Join(dir, testKeyA+".json")
	if err := os.WriteFile(edited, []byte(editedCosignerDoc()), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := (OnlineRunner{Session: session}).Run(context.Background(), Command{Verb: VerbApply, Args: []string{edited}, Yes: true},
		Streams{Stdout: &stdout, Stderr: &stderr}); err != nil {
		t.Fatal(err)
	}
	if len(session.applies) != 1 || session.applies[0].ExpectedSnapshotSHA256 != session.snapshot {
		t.Fatalf("applies = %+v", session.applies)
	}
	if strings.Contains(stderr.String(), "no export baseline") {
		t.Fatalf("an apply from an export said it had no baseline: %q", stderr.String())
	}
}

func TestStaleExportIsRefusedBeforeReview(t *testing.T) {
	for name, move := range map[string]func(t *testing.T, s *fakeOnlineSession){
		"the policy changed": func(t *testing.T, s *fakeOnlineSession) {
			s.bodies[testKeyB] = testCosignerDoc(testKeyB)
			s.policy.Documents = append(s.policy.Documents, protocol.PolicyDocumentInfoWire{
				Key: testKeyB, SHA256: policy.PolicySHA256([]byte(s.bodies[testKeyB])), Size: len(s.bodies[testKeyB]),
			})
			s.makeReal(t, map[string]string{"private-dev": privateDevHash})
		},
		"the context changed": func(t *testing.T, s *fakeOnlineSession) {
			s.makeReal(t, map[string]string{"private-dev": privateDevHash, "lab": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="})
		},
	} {
		t.Run(name, func(t *testing.T) {
			session, dir := exportedSession(t)
			move(t, session)
			file := filepath.Join(dir, testKeyA+".json")
			if err := os.WriteFile(file, []byte(editedCosignerDoc()), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, verb := range []Verb{VerbCheck, VerbDiff, VerbApply} {
				var stdout bytes.Buffer
				err := (OnlineRunner{Session: session}).Run(context.Background(), Command{Verb: verb, Args: []string{file}, Yes: verb == VerbApply},
					Streams{Stdout: &stdout, Stderr: &bytes.Buffer{}})
				if err == nil || !strings.Contains(err.Error(), "policy_export_stale") || !strings.Contains(err.Error(), "export again") {
					t.Fatalf("%s from a stale export = %v", verb, err)
				}
				want := "policy changed"
				if name == "the context changed" {
					want = "ASA set, network map or role changed"
				}
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("%s: %v, want it to say the node's %s", verb, err, want)
				}
			}
			if len(session.checks) != 0 || len(session.applies) != 0 {
				t.Fatalf("a stale export reached the node: %d checks, %d applies", len(session.checks), len(session.applies))
			}

			// Choosing no context applies against the node as it is now, and
			// says there is no baseline.
			var stderr bytes.Buffer
			err := (OnlineRunner{Session: session}).Run(context.Background(), Command{Verb: VerbApply, Args: []string{file}, Yes: true, NoNodeContext: true},
				Streams{Stdout: &bytes.Buffer{}, Stderr: &stderr})
			if err != nil || len(session.applies) != 1 || !strings.Contains(stderr.String(), "no export baseline") {
				t.Fatalf("--no-node-context apply = %v, %d applies, stderr %q", err, len(session.applies), stderr.String())
			}
		})
	}
}

func TestADraftNotFromAnExportSaysItHasNoBaseline(t *testing.T) {
	onlineEnv(t)
	session := newFakeSession("cosigner")
	draft := writePolicyFile(t, "a.json", testCosignerDoc(testKeyA))
	var stderr bytes.Buffer
	if err := (OnlineRunner{Session: session}).Run(context.Background(), Command{Verb: VerbApply, Args: []string{draft}, Yes: true},
		Streams{Stdout: &bytes.Buffer{}, Stderr: &stderr}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "not from an export") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestExportFlagsValidate(t *testing.T) {
	for _, bad := range []Command{
		{Verb: VerbStatus, ExportDir: "d"},
		{Verb: VerbExport, ExportDir: "d", Key: testKeyA},
		{Verb: VerbExport, NodeContext: "n"},
		{Verb: VerbRemove, Args: []string{testKeyA}, NoNodeContext: true},
		{Verb: VerbApply, Args: []string{"a"}, NodeContext: "n", NoNodeContext: true},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("Validate(%+v) accepted it", bad)
		}
	}
}
