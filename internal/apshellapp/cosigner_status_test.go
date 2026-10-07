// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestCosignerStatusObservesLiveRoutesWithoutMutation(t *testing.T) {
	dir := t.TempDir()
	public := testCosignerPublicKeyHex()
	id := testComponentSelector(t, witness.Falcon1024V1, public)
	cosigner := newEndpointKeysServer(t, []signerapi.KeyInfo{{Address: id, PublicKeyHex: public, KeyType: witness.Falcon1024V1, IsWitnessKey: true}})
	writeLiveCosignerEndpoint(t, dir, "cosigner", cosigner)
	signer := newEndpointKeysServerHTTP(t, []signerapi.KeyInfo{
		{Address: "guarded", SigningFlow: signerapi.SigningFlowCosigner1, CosignerComponentKeyType: witness.Falcon1024V1, Parameters: map[string]string{"cosigner_public_key": public}},
		{Address: "bounded", SigningFlow: signerapi.SigningFlowBoundedCosigner1, CosignerComponentKeyType: witness.Falcon1024V1, BoundedAuthorization: &signerapi.BoundedAuthorizationInfo{Cosigner: &signerapi.BoundedCosignerAuthorizationInfo{PublicKeyHex: public}}},
	})
	app := newEndpointTestApp(t, dir)
	client := signerclient.NewSignerClient(signer.URL)
	app.eng.Connection.SignerClient = client
	cfgBefore := app.Config
	registryBefore := app.eng.EndpointRegistry.Clone()
	cacheBefore, _ := json.Marshal(app.eng.SignerCache)
	filesBefore := snapshotStatusFiles(t, dir)
	result, err := app.CosignerStatus(t.Context(), CosignerStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if result.AccountInventory != "available" || len(result.Accounts) != 2 || len(result.Connections) != 1 {
		t.Fatalf("result=%+v", result)
	}
	for _, account := range result.Accounts {
		if account.State != "cosigner route available" || account.WitnessKeyID != id {
			t.Fatalf("account=%+v", account)
		}
	}
	joined := strings.Join(result.RenderLines, "\n")
	if !strings.Contains(joined, "Witness Key ID: "+witness.GroupedID(id)) || strings.Contains(joined, "Witness Key ID: "+id) {
		t.Fatalf("status did not group the display ID: %s", joined)
	}
	cacheAfter, _ := json.Marshal(app.eng.SignerCache)
	if string(cacheBefore) != string(cacheAfter) || !reflect.DeepEqual(cfgBefore, app.Config) || !reflect.DeepEqual(registryBefore, app.eng.EndpointRegistry) || app.eng.Connection.SignerClient != client || !reflect.DeepEqual(filesBefore, snapshotStatusFiles(t, dir)) {
		t.Fatal("status mutated client state")
	}
	data, err := json.Marshal(result)
	if err != nil || strings.Contains(string(data), public) || strings.Contains(string(data), "RenderLines") {
		t.Fatalf("unexpected projection: %s, %v", data, err)
	}
}

func TestCosignerStatusUnavailableSignerAndPartialEndpoints(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"disconnected", 0, ""},
		{"locked", http.StatusLocked, `{"code":"locked","error":"locked"}`},
		{"unauthorized", http.StatusUnauthorized, `{"error":"unauthorized"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			app := newEndpointTestApp(t, dir)
			server := newEndpointKeysServer(t, nil)
			writeLiveCosignerEndpoint(t, dir, "healthy", server)
			bad := newUnenrolledEndpointKeysServer(t, nil)
			writeLiveCosignerEndpoint(t, dir, "unauthorized", bad)
			if tc.status != 0 {
				primary := newEndpointKeysStatusServer(t, tc.status, tc.body)
				app.eng.Connection.SignerClient = signerclient.NewSignerClient(primary.URL)
			}
			result, err := app.CosignerStatus(t.Context(), CosignerStatusRequest{})
			if err != nil {
				t.Fatal(err)
			}
			if result.AccountInventory != "unavailable" || result.InventoryError == "" || len(result.Connections) != 2 || result.Connections[0].State != "reachable; authenticated" || result.Connections[1].Error == "" {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestCosignerStatusEmptyRegistryAndDuplicateWitness(t *testing.T) {
	dir := t.TempDir()
	app := newEndpointTestApp(t, dir)
	result, err := app.CosignerStatus(t.Context(), CosignerStatusRequest{})
	if err != nil || len(result.Connections) != 0 || result.AccountInventory != "unavailable" {
		t.Fatalf("empty=%+v %v", result, err)
	}
	public := testCosignerPublicKeyHex()
	id := testComponentSelector(t, witness.Falcon1024V1, public)
	for _, alias := range []string{"a", "b"} {
		server := newEndpointKeysServer(t, []signerapi.KeyInfo{{Address: id, PublicKeyHex: public, KeyType: witness.Falcon1024V1, IsWitnessKey: true}})
		writeLiveCosignerEndpoint(t, dir, alias, server)
	}
	result, err = app.CosignerStatus(t.Context(), CosignerStatusRequest{})
	if err != nil || len(result.DuplicateRoutes[id]) != 2 {
		t.Fatalf("duplicate=%+v %v", result, err)
	}
}

func snapshotStatusFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		result[path] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
