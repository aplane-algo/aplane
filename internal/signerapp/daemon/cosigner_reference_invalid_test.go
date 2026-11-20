// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	"github.com/aplane-algo/aplane/internal/witness"
)

// A cosigner reference file that is not a valid reference never breaks a
// listing. The admin list reports it beside the valid references, with
// whether removing it by name clears it; list_key_types leaves it out and
// still answers. Removal clears one named for a reference name; a file with
// any other name stays reported until it is deleted by hand.
func TestInvalidCosignerReferencesAreReportedAndLeftOut(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	svc := server.adminServices()

	publicBytes := make([]byte, witnessPublicKeySizeForTest(t))
	for i := range publicBytes {
		publicBytes[i] = 0xab
	}
	witnessKeyID, err := witness.ID(witness.Falcon1024V1, publicBytes)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := cosignerrefs.NewExportEnvelope(witnessKeyID, witness.Falcon1024V1, strings.Repeat("ab", len(publicBytes)))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if imported := svc.ImportCosignerReference(adminproto.ImportCosignerReferenceRequest{Name: "lab", EnvelopeJSON: string(raw)}); !imported.Success {
		t.Fatalf("ImportCosignerReference() = %#v", imported)
	}
	paths := server.productRuntime().KeyPaths()
	if err := os.WriteFile(paths.CosignerRefPath("bad"), []byte(`{"schema":"wrong"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	unreachable := filepath.Join(paths.CosignerRefsDir(), "Lab.json")
	if err := os.WriteFile(unreachable, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	listed := svc.ListCosignerReferences()
	if listed.Error != "" || len(listed.References) != 1 || listed.References[0].Name != "lab" {
		t.Fatalf("ListCosignerReferences() = %#v, want the valid reference listed", listed)
	}
	want := []adminproto.InvalidCosignerReference{
		{Path: unreachable, Name: "Lab", Reason: `"Lab" is not a reference name`},
		{Path: paths.CosignerRefPath("bad"), Name: "bad", Reason: `unsupported schema "wrong"`, Removable: true},
	}
	if !reflect.DeepEqual(listed.Invalid, want) {
		t.Fatalf("ListCosignerReferences() invalid = %+v\nwant %+v", listed.Invalid, want)
	}
	if keyTypes := svc.templateServices().ListKeyTypes(); keyTypes.Error != "" || len(keyTypes.KeyTypes) == 0 {
		t.Fatalf("ListKeyTypes() = %q %q with %d key types, want an answer", keyTypes.Code, keyTypes.Error, len(keyTypes.KeyTypes))
	}

	// Remove takes the name exactly as listed: "Lab" would reach lab.json, the
	// valid reference, so it is refused and both files stay.
	refused := svc.RemoveCosignerReference(adminproto.RemoveCosignerReferenceRequest{Name: "Lab"})
	if refused.Success || refused.Code != "remove_failed" || !strings.HasPrefix(refused.Error, "remove takes a reference name exactly as listed") {
		t.Fatalf("RemoveCosignerReference(Lab) = %#v, want it refused", refused)
	}
	for _, path := range []string{unreachable, paths.CosignerRefPath("lab")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("a refused remove deleted %s: %v", path, err)
		}
	}

	removed := svc.RemoveCosignerReference(adminproto.RemoveCosignerReferenceRequest{Name: "bad"})
	if !removed.Success || !removed.Removed || removed.ComponentKey != "" || removed.Path != paths.CosignerRefPath("bad") {
		t.Fatalf("RemoveCosignerReference(bad) = %#v, want it removed", removed)
	}
	listed = svc.ListCosignerReferences()
	if listed.Error != "" || len(listed.References) != 1 || !reflect.DeepEqual(listed.Invalid, want[:1]) {
		t.Fatalf("ListCosignerReferences() after removal = %#v, want only the hand-deleted file reported", listed)
	}
}

// Key type lists leave invalid reference entries out on every call, but log
// them only when they change: an entry that is new or reported differently is
// warned about once, and one that is no longer left out is noted once.
func TestKeyTypeListsLogLeftOutReferencesOnlyWhenTheyChange(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	logs := &syncBuffer{}
	appLogger.SetOutput(logs)
	t.Cleanup(func() { appLogger.SetOutput(os.Stderr) })
	svc := server.adminServices().templateServices()
	paths := server.productRuntime().KeyPaths()
	if err := os.MkdirAll(paths.CosignerRefsDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(paths.CosignerRefPath(name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	list := func() {
		t.Helper()
		if result := svc.ListKeyTypes(); result.Error != "" {
			t.Fatalf("ListKeyTypes() error = %s", result.Error)
		}
	}
	leftOut := func(name string) int {
		return strings.Count(logs.String(), fmt.Sprintf("left out of the key type list: %q", paths.CosignerRefPath(name)))
	}
	back := func(name string) int {
		return strings.Count(logs.String(), fmt.Sprintf("cosigner reference file %q is no longer left out", paths.CosignerRefPath(name)))
	}

	write("bad", `{"schema":"wrong"}`)
	list()
	list()
	if leftOut("bad") != 1 {
		t.Fatalf("bad.json logged %d times over two lists, want once:\n%s", leftOut("bad"), logs.String())
	}
	write("other", `{"schema":"wrong"}`)
	list()
	if leftOut("bad") != 1 || leftOut("other") != 1 {
		t.Fatalf("after a new entry, bad.json logged %d times and other.json %d, want once each:\n%s", leftOut("bad"), leftOut("other"), logs.String())
	}
	write("bad", `{"schema":"still wrong"}`)
	list()
	if leftOut("bad") != 2 || leftOut("other") != 1 {
		t.Fatalf("after a changed entry, bad.json logged %d times and other.json %d, want 2 and 1:\n%s", leftOut("bad"), leftOut("other"), logs.String())
	}
	if err := os.Remove(paths.CosignerRefPath("bad")); err != nil {
		t.Fatal(err)
	}
	list()
	list()
	if back("bad") != 1 || back("other") != 0 || leftOut("other") != 1 {
		t.Fatalf("after bad.json went, it was noted %d times, want once:\n%s", back("bad"), logs.String())
	}
}
