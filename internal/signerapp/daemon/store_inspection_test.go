// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/sentry/sentryrefs"
	"github.com/aplane-algo/aplane/internal/witness"
)

func TestSignerAdminServicesOwnSentryReferenceLifecycle(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	svc := server.adminServices()

	publicKey := strings.Repeat("ab", witnessPublicKeySizeForTest(t))
	publicBytes := make([]byte, witnessPublicKeySizeForTest(t))
	for i := range publicBytes {
		publicBytes[i] = 0xab
	}
	witnessKeyID, err := witness.ID(witness.Falcon1024V1, publicBytes)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := sentryrefs.NewExportEnvelope(witnessKeyID, witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}

	imported := svc.ImportSentryReference(adminproto.ImportSentryReferenceRequest{Name: "lab", EnvelopeJSON: string(raw)})
	if !imported.Success || imported.Reference.Name != "lab" {
		t.Fatalf("ImportSentryReference() = %#v", imported)
	}
	listed := svc.ListSentryReferences()
	if listed.Error != "" || len(listed.References) != 1 || listed.References[0].ComponentKey != witnessKeyID {
		t.Fatalf("ListSentryReferences() = %#v", listed)
	}
	got := svc.GetSentryReference(adminproto.GetSentryReferenceRequest{Name: "lab"})
	if !got.Success || got.Reference.PublicKeyHex != publicKey {
		t.Fatalf("GetSentryReference() = %#v", got)
	}
	removed := svc.RemoveSentryReference(adminproto.RemoveSentryReferenceRequest{Name: "lab"})
	if !removed.Success || !removed.Removed || removed.ComponentKey != witnessKeyID {
		t.Fatalf("RemoveSentryReference() = %#v", removed)
	}
}

func TestSignerAdminServicesExportsSentryPublicFromAuthenticatedGeneration(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	publicBytes := make([]byte, witnessPublicKeySizeForTest(t))
	for i := range publicBytes {
		publicBytes[i] = 0xab
	}
	witnessKeyID, err := witness.ID(witness.Falcon1024V1, publicBytes)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := sentryrefs.NewExportEnvelope(witnessKeyID, witness.Falcon1024V1, strings.Repeat("ab", len(publicBytes)))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	active, err := server.productRuntime().ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(apkeys.WitnessPublicMetadataPathActive(active, witnessKeyID), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	result := server.adminServices().ExportSentryPublic(adminproto.ExportSentryPublicRequest{WitnessKeyID: witnessKeyID})
	if !result.Success || result.WitnessKeyID != witnessKeyID {
		t.Fatalf("ExportSentryPublic() = %#v", result)
	}
	var got witness.PublicReference
	if err := json.Unmarshal([]byte(result.EnvelopeJSON), &got); err != nil {
		t.Fatalf("ExportSentryPublic() returned invalid JSON: %v", err)
	}
	if got != *envelope {
		t.Fatalf("ExportSentryPublic() envelope = %#v, want %#v", got, *envelope)
	}
}

func TestSignerAdminServicesListsGenerationInventoryReadOnly(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	result := server.adminServices().ListGenerations()
	if result.Error != "" || result.Current == "" {
		t.Fatalf("ListGenerations() = %#v", result)
	}
}

func TestSignerAdminServicesInspectionReturnsBusyDuringMutation(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- server.withStoreMutation(func() error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	defer func() {
		close(release)
		if err := <-done; err != nil {
			t.Errorf("withStoreMutation() error = %v", err)
		}
	}()

	result := server.adminServices().ListGenerations()
	if result.Code != protocol.ResultCodeStoreBusy || !strings.Contains(result.Error, "mutation is in progress") {
		t.Fatalf("ListGenerations() = %#v, want immediate store_busy result", result)
	}
}

func witnessPublicKeySizeForTest(t *testing.T) int {
	t.Helper()
	size, ok := witness.PublicKeySize(witness.Falcon1024V1)
	if !ok {
		t.Fatal("missing witness public key size")
	}
	return size
}
