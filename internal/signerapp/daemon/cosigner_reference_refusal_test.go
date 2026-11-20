// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	"github.com/aplane-algo/aplane/internal/witness"
)

// A cosigner reference that does not parse is not hidden: listing the
// references refuses, naming it, and so does /keytypes, whose generation
// choices they are. Removing it by name is how the operator clears it.
func TestAnInvalidCosignerReferenceIsRefusedUntilRemoved(t *testing.T) {
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

	listed := svc.ListCosignerReferences()
	if listed.Code != "list_failed" || !strings.HasPrefix(listed.Error, "invalid cosigner reference bad: ") || len(listed.References) != 0 {
		t.Fatalf("ListCosignerReferences() = %#v, want the invalid record refused", listed)
	}
	keyTypes := svc.templateServices().ListKeyTypes()
	if keyTypes.Code != "list_failed" || keyTypes.Error != "failed to read key type activations or cosigner references" {
		t.Fatalf("ListKeyTypes() = %q %q, want the invalid record refused", keyTypes.Code, keyTypes.Error)
	}

	removed := svc.RemoveCosignerReference(adminproto.RemoveCosignerReferenceRequest{Name: "bad"})
	if !removed.Success || !removed.Removed || removed.ComponentKey != "" {
		t.Fatalf("RemoveCosignerReference(bad) = %#v, want it removed", removed)
	}
	listed = svc.ListCosignerReferences()
	if listed.Error != "" || len(listed.References) != 1 || listed.References[0].Name != "lab" {
		t.Fatalf("ListCosignerReferences() after removal = %#v", listed)
	}
	if keyTypes := svc.templateServices().ListKeyTypes(); keyTypes.Error != "" {
		t.Fatalf("ListKeyTypes() after removal: %s", keyTypes.Error)
	}
}
