// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/cosigner/enrollment"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestPrepareCosignerSetupUsesCombinedEndpointAndOverrides(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)
	document, reference := testCosignerEnrollmentDocument(t, &endpointrefs.Envelope{
		Schema: endpointrefs.Schema, URL: "ssh://bundle.example:2223", SignerPort: 12270,
	})

	plan, err := app.PrepareCosignerSetup(CosignerSetupRequest{
		Document: document, Alias: "field", URL: "ssh://override.example:2224", SignerPort: 13270,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Created || plan.ReplacementRequired || !plan.BundledEndpoint {
		t.Fatalf("plan = %#v, want new bundled route", plan)
	}
	if plan.Witness != reference {
		t.Fatalf("witness = %#v, want %#v", plan.Witness, reference)
	}
	if plan.Endpoint.URL != "ssh://override.example:2224" || plan.Endpoint.SignerPort != 13270 || plan.Endpoint.LocalPort != 0 {
		t.Fatalf("endpoint = %#v, want explicit URL/port", plan.Endpoint)
	}
}

func TestPrepareCosignerSetupRejectsBundledLocalPort(t *testing.T) {
	document, _ := testCosignerEnrollmentDocument(t, &endpointrefs.Envelope{
		Schema: endpointrefs.Schema, URL: "ssh://bundle.example:2223", SignerPort: 12270, LocalPort: 12271,
	})
	_, err := newEndpointTestApp(t, t.TempDir()).PrepareCosignerSetup(CosignerSetupRequest{
		Document: document, Alias: "field",
	})
	if err == nil || !strings.Contains(err.Error(), "local_port is not supported for cosigner endpoints") {
		t.Fatalf("PrepareCosignerSetup() error = %v, want cosigner local_port rejection", err)
	}
}

func TestPrepareCosignerSetupReusesUnchangedCustomEndpoint(t *testing.T) {
	dataDir := t.TempDir()
	want := config.ClientEndpointConfig{
		Role: config.ClientEndpointRoleCosigner, URL: "ssh://cosigner.example:2223",
		SignerPort: 12270, IdentityFile: "/custom/id",
		KnownHostsPath: "/custom/known_hosts", TokenFile: "/custom/token",
	}
	if _, err := config.UpsertStoredClientEndpoint(dataDir, "field", want, true); err != nil {
		t.Fatal(err)
	}
	app := newEndpointTestApp(t, dataDir)
	document, _ := testCosignerEnrollmentDocument(t, nil)
	plan, err := app.PrepareCosignerSetup(CosignerSetupRequest{
		Document: document, Alias: "field",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Created || plan.Updated || plan.ReplacementRequired || plan.DestinationChanged {
		t.Fatalf("plan = %#v, want unchanged reuse", plan)
	}
	if plan.Endpoint != want {
		t.Fatalf("endpoint = %#v, want custom endpoint %#v", plan.Endpoint, want)
	}
	endpointPath := config.GetClientEndpointsPath(dataDir)
	past := time.Unix(1_600_000_000, 0)
	if err := os.Chtimes(endpointPath, past, past); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ApplyCosignerSetupEndpoint(plan, false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(endpointPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(past) {
		t.Fatalf("unchanged setup rewrote endpoints.yaml: modtime = %v, want %v", info.ModTime(), past)
	}
}

func TestPrepareCosignerSetupMarksDestinationReplacement(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := config.UpsertStoredClientEndpoint(dataDir, "field", config.ClientEndpointConfig{
		Role: config.ClientEndpointRoleCosigner, URL: "ssh://old.example:22",
	}, true); err != nil {
		t.Fatal(err)
	}
	document, _ := testCosignerEnrollmentDocument(t, nil)
	plan, err := newEndpointTestApp(t, dataDir).PrepareCosignerSetup(CosignerSetupRequest{
		Document: document, Alias: "field", URL: "ssh://new.example:22",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Updated || !plan.ReplacementRequired || !plan.DestinationChanged {
		t.Fatalf("plan = %#v, want destination replacement", plan)
	}
}

func TestPrepareCosignerSetupTreatsChangedSSHRESTPortAsDestinationChange(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := config.UpsertStoredClientEndpoint(dataDir, "field", config.ClientEndpointConfig{
		Role: config.ClientEndpointRoleCosigner, URL: "ssh://cosigner.example", SignerPort: 11270,
	}, true); err != nil {
		t.Fatal(err)
	}
	document, _ := testCosignerEnrollmentDocument(t, nil)
	plan, err := newEndpointTestApp(t, dataDir).PrepareCosignerSetup(CosignerSetupRequest{
		Document: document, Alias: "field", SignerPort: 12270,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.DestinationChanged || !plan.ReplacementRequired {
		t.Fatalf("plan = %#v, want signer REST port destination replacement", plan)
	}
}

func TestPrepareCosignerSetupRejectsMissingRouteSelfAndSignerAlias(t *testing.T) {
	document, _ := testCosignerEnrollmentDocument(t, nil)
	tests := []struct {
		name    string
		prepare func(*testing.T) (*App, CosignerSetupRequest)
		want    string
	}{
		{
			name: "missing route",
			prepare: func(t *testing.T) (*App, CosignerSetupRequest) {
				return newEndpointTestApp(t, t.TempDir()), CosignerSetupRequest{Document: document, Alias: "field"}
			},
			want: "endpoint URL is required",
		},
		{
			name: "self",
			prepare: func(t *testing.T) (*App, CosignerSetupRequest) {
				return newEndpointTestApp(t, t.TempDir()), CosignerSetupRequest{Document: document, Alias: "field", URL: "self"}
			},
			want: `url "self" is not supported`,
		},
		{
			name: "signer alias",
			prepare: func(t *testing.T) (*App, CosignerSetupRequest) {
				dataDir := t.TempDir()
				if _, err := config.UpsertStoredClientEndpoint(dataDir, "primary", config.ClientEndpointConfig{Role: config.ClientEndpointRoleSigner, URL: "ssh://signer.example"}, true); err != nil {
					t.Fatal(err)
				}
				return newEndpointTestApp(t, dataDir), CosignerSetupRequest{Document: document, Alias: "primary", URL: "ssh://cosigner.example"}
			},
			want: "has role \"signer\"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, req := tt.prepare(t)
			_, err := app.PrepareCosignerSetup(req)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("PrepareCosignerSetup() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestPrepareCosignerSetupClassifiesMissingEndpointURL(t *testing.T) {
	document, _ := testCosignerEnrollmentDocument(t, nil)
	_, err := newEndpointTestApp(t, t.TempDir()).PrepareCosignerSetup(CosignerSetupRequest{
		Document: document,
		Alias:    "field",
	})
	if !errors.Is(err, ErrCosignerEndpointURLRequired) {
		t.Fatalf("PrepareCosignerSetup() error = %v, want ErrCosignerEndpointURLRequired", err)
	}
}

func TestPrepareCosignerSetupSurfacesCosignerEndpointLimit(t *testing.T) {
	dataDir := t.TempDir()
	for i := 0; i < config.MaxClientCosignerEndpoints; i++ {
		alias := fmt.Sprintf("cosigner-%02d", i)
		if _, err := config.UpsertStoredClientEndpoint(dataDir, alias, config.ClientEndpointConfig{
			Role: config.ClientEndpointRoleCosigner, URL: fmt.Sprintf("ssh://cosigner-%02d.example", i),
		}, true); err != nil {
			t.Fatal(err)
		}
	}
	document, _ := testCosignerEnrollmentDocument(t, nil)
	_, err := newEndpointTestApp(t, dataDir).PrepareCosignerSetup(CosignerSetupRequest{
		Document: document, Alias: "one-too-many", URL: "ssh://extra.example",
	})
	if err == nil || !strings.Contains(err.Error(), "maximum is 12") {
		t.Fatalf("PrepareCosignerSetup() error = %v, want cosigner endpoint limit", err)
	}
}

func TestApplyCosignerSetupRejectsStaleReviewedAlias(t *testing.T) {
	dataDir := t.TempDir()
	app := newEndpointTestApp(t, dataDir)
	document, _ := testCosignerEnrollmentDocument(t, nil)
	plan, err := app.PrepareCosignerSetup(CosignerSetupRequest{
		Document: document, Alias: "field", URL: "ssh://reviewed.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.UpsertStoredClientEndpoint(dataDir, "field", config.ClientEndpointConfig{
		Role: config.ClientEndpointRoleCosigner, URL: "ssh://concurrent.example",
	}, true); err != nil {
		t.Fatal(err)
	}
	_, err = app.ApplyCosignerSetupEndpoint(plan, true)
	if err == nil || !strings.Contains(err.Error(), "changed after review") {
		t.Fatalf("ApplyCosignerSetupEndpoint() error = %v, want stale-review rejection", err)
	}
	registry, _, err := config.LoadStoredClientEndpointRegistry(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := registry.Endpoint("field"); got.URL != "ssh://concurrent.example" {
		t.Fatalf("endpoint = %#v, concurrent update was overwritten", got)
	}
}

func TestApplyCosignerSetupDryRunDoesNotWrite(t *testing.T) {
	dataDir := t.TempDir()
	document, _ := testCosignerEnrollmentDocument(t, nil)
	app := newEndpointTestApp(t, dataDir)
	plan, err := app.PrepareCosignerSetup(CosignerSetupRequest{
		Document: document, Alias: "field", URL: "ssh://cosigner.example", DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.ApplyCosignerSetupEndpoint(plan, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(config.GetClientEndpointsPath(dataDir)); !os.IsNotExist(err) {
		t.Fatalf("endpoints.yaml stat error = %v, want absent", err)
	}
}

func TestCompleteCosignerSetupVerifiesExactWitness(t *testing.T) {
	dataDir := t.TempDir()
	document, reference := testCosignerEnrollmentDocument(t, nil)
	otherPublicKey := strings.Repeat("cd", witness.Falcon1024PublicKeySize)
	otherID := testComponentSelector(t, witness.Falcon1024V1, otherPublicKey)
	expected := signerapi.KeyInfo{
		Address: reference.WitnessKeyID, PublicKeyHex: reference.PublicKeyHex,
		KeyType: reference.KeyType, IsWitnessKey: true,
	}
	server := newEndpointKeysServer(t, "cosigner-token", []signerapi.KeyInfo{
		expected,
		expected, // Identical repeated advertisements are deduplicated.
		{Address: otherID, PublicKeyHex: otherPublicKey, KeyType: witness.Falcon1024V1, IsWitnessKey: true},
	})
	writeLiveCosignerEndpoint(t, dataDir, "field", server.URL, "cosigner-token")
	app := newEndpointTestApp(t, dataDir)
	plan, err := app.PrepareCosignerSetup(CosignerSetupRequest{Document: document, Alias: "field"})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := app.ApplyCosignerSetupEndpoint(plan, false)
	if err != nil {
		t.Fatal(err)
	}
	result, err := app.CompleteCosignerSetup(context.Background(), plan, endpoint, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Verified || result.TokenIssued || result.WitnessKeyID != reference.WitnessKeyID {
		t.Fatalf("result = %#v, want existing-token exact verification", result)
	}
}

func TestCompleteCosignerSetupReportsLockedCosigner(t *testing.T) {
	dataDir := t.TempDir()
	document, _ := testCosignerEnrollmentDocument(t, nil)
	server := newEndpointKeysStatusServer(t, "cosigner-token", 403, `{"error":"signer is locked"}`)
	writeLiveCosignerEndpoint(t, dataDir, "field", server.URL, "cosigner-token")
	app := newEndpointTestApp(t, dataDir)
	plan, err := app.PrepareCosignerSetup(CosignerSetupRequest{Document: document, Alias: "field"})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := app.ApplyCosignerSetupEndpoint(plan, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = app.CompleteCosignerSetup(context.Background(), plan, endpoint, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "unlock it in apadmin and rerun") {
		t.Fatalf("CompleteCosignerSetup() error = %v, want unlock guidance", err)
	}
}

func TestCompleteCosignerSetupRequiresExistingTokenForDirectEndpoint(t *testing.T) {
	dataDir := t.TempDir()
	document, _ := testCosignerEnrollmentDocument(t, nil)
	app := newEndpointTestApp(t, dataDir)
	plan, err := app.PrepareCosignerSetup(CosignerSetupRequest{
		Document: document, Alias: "field", URL: "https://cosigner.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := app.ApplyCosignerSetupEndpoint(plan, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = app.CompleteCosignerSetup(context.Background(), plan, endpoint, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "automatic enrollment requires ssh://") {
		t.Fatalf("CompleteCosignerSetup() error = %v, want direct-endpoint token guidance", err)
	}
}

func testCosignerEnrollmentDocument(t *testing.T, endpoint *endpointrefs.Envelope) ([]byte, witness.PublicReference) {
	t.Helper()
	publicKeyHex := testCosignerPublicKeyHex()
	reference, err := witness.NewPublicReference(
		witness.Falcon1024V1,
		testComponentSelector(t, witness.Falcon1024V1, publicKeyHex),
		publicKeyHex,
	)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint == nil {
		data, err := enrollment.MarshalWitness(reference)
		if err != nil {
			t.Fatal(err)
		}
		return data, reference
	}
	data, err := enrollment.Marshal(enrollment.Envelope{
		Schema: enrollment.Schema, Witness: reference, Endpoint: endpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	return data, reference
}

func TestCosignerSetupUsesResolvedEndpointTokenPath(t *testing.T) {
	dataDir := t.TempDir()
	document, _ := testCosignerEnrollmentDocument(t, nil)
	app := newEndpointTestApp(t, dataDir)
	plan, err := app.PrepareCosignerSetup(CosignerSetupRequest{
		Document: document, Alias: "field", URL: "ssh://cosigner.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := app.ApplyCosignerSetupEndpoint(plan, false)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dataDir, "tokens", "field.token")
	if endpoint.TokenFile != want {
		t.Fatalf("token path = %q, want %q", endpoint.TokenFile, want)
	}
}
