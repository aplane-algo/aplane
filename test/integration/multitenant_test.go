// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/internal/tokenfile"
	"github.com/aplane-algo/aplane/internal/transport"
	"github.com/aplane-algo/aplane/test/integration/harness"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestMultitenantHTTPRoutesByAuthenticatedIdentity(t *testing.T) {
	lockOnDisconnect := false
	env := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})

	aliceToken, aliceTemplateKeyType := createIntegrationIdentityWithTemplate(t, env, "alice")

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	aliceAdmin := unlockIdentityOverSSHAdmin(t, "alice", aliceToken)
	t.Cleanup(aliceAdmin.Close)

	defaultToken := readSignerToken(t, signerd)
	defaultClient := signerclient.NewSignerClientWithToken(signerd.GetURL(), defaultToken)
	aliceClient := signerclient.NewSignerClientWithToken(signerd.GetURL(), aliceToken)

	aliceKeyTypes, err := aliceClient.GetKeyTypes()
	if err != nil {
		t.Fatalf("alice /keytypes failed: %v", err)
	}
	if !keyTypesContain(aliceKeyTypes.KeyTypes, aliceTemplateKeyType) {
		t.Fatalf("alice /keytypes missing identity-local template %q", aliceTemplateKeyType)
	}

	defaultKeyTypes, err := defaultClient.GetKeyTypes()
	if err != nil {
		t.Fatalf("default /keytypes failed: %v", err)
	}
	if keyTypesContain(defaultKeyTypes.KeyTypes, aliceTemplateKeyType) {
		t.Fatalf("default /keytypes included alice-only template %q", aliceTemplateKeyType)
	}

	generated, err := aliceClient.AdminGenerate("ed25519", nil)
	if err != nil {
		t.Fatalf("alice AdminGenerate(ed25519) failed: %v", err)
	}
	t.Cleanup(func() {
		if _, err := aliceClient.AdminDeleteKey(generated.Address); err != nil {
			t.Logf("cleanup: alice AdminDeleteKey(%s) failed: %v", generated.Address, err)
		}
	})

	if !waitForKey(t, signerd.GetURL(), aliceToken, generated.Address, 10*time.Second) {
		t.Fatalf("alice /keys did not show generated key %s", generated.Address)
	}
	if !waitForKeyMissing(t, signerd.GetURL(), defaultToken, generated.Address, 10*time.Second) {
		t.Fatalf("default /keys showed alice generated key %s", generated.Address)
	}

	signReq := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: generated.Address,
			TxnBytesHex: mustUnsignedPaymentTxnHex(t, integrationSuggestedParams(), generated.Address, integrationBurnAddress, 0, "mt-identity-routing"),
		}},
	}

	defaultStatus, defaultBody := postSignRequest(t, signerd.GetURL(), "aplane "+defaultToken, signReq)
	if defaultStatus != http.StatusBadRequest {
		t.Fatalf("default token signing alice key = %d: %s, want 400", defaultStatus, string(defaultBody))
	}

	aliceStatus, aliceBody := postSignRequest(t, signerd.GetURL(), "aplane "+aliceToken, signReq)
	if aliceStatus != http.StatusOK {
		t.Fatalf("alice token signing alice key = %d: %s, want 200", aliceStatus, string(aliceBody))
	}
	var signResp signerapi.GroupSignResponse
	if err := json.Unmarshal(aliceBody, &signResp); err != nil {
		t.Fatalf("decode alice sign response: %v", err)
	}
	if signResp.Error != "" {
		t.Fatalf("alice sign response error = %q", signResp.Error)
	}
	if len(signResp.Signed) != 1 || strings.TrimSpace(signResp.Signed[0]) == "" {
		t.Fatalf("alice sign response signed = %#v, want one signed txn", signResp.Signed)
	}
}

func createIntegrationIdentityWithTemplate(t *testing.T, env *harness.TestEnvClone, identityID string) (string, string) {
	t.Helper()

	paths := storepaths.NewPaths(env.SignerDataDir)
	passphrase := []byte(mustReadPassphrase(t, env.SignerDataDir))
	defer apcrypto.ZeroBytes(passphrase)
	identityDir := paths.IdentityDir(identityID)
	genstoretest.MintFirst(t, paths, identityID)
	masterKeyRing, err := apcrypto.CreateKeyringStore(paths.KeystoreMetadataDir(identityID), passphrase)
	if err != nil {
		t.Fatalf("failed to create %s keystore metadata: %v", identityID, err)
	}
	t.Cleanup(masterKeyRing.Zero)

	_, roleBytes, err := noderole.Load(paths)
	if err != nil {
		t.Fatalf("failed to load node role for %s: %v", identityID, err)
	}
	if err := noderole.SaveIdentitySidecarWithKeyring(paths, identityID, roleBytes, masterKeyRing, time.Now()); err != nil {
		t.Fatalf("failed to create %s node role sidecar: %v", identityID, err)
	}

	if err := policy.SaveStoredConfigWithKeyring(paths.Root(), identityID, &policy.StoredConfig{}, masterKeyRing, time.Now()); err != nil {
		t.Fatalf("failed to create signed %s policy: %v", identityID, err)
	}

	token, err := tokenfile.GenerateToken()
	if err != nil {
		t.Fatalf("failed to generate %s token: %v", identityID, err)
	}
	if err := tokenfile.WriteToken(tokenfile.GetAPlaneTokenPathForRoot(paths.Root(), identityID), token); err != nil {
		t.Fatalf("failed to write %s token: %v", identityID, err)
	}

	sshDir := filepath.Join(identityDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("failed to create %s ssh dir: %v", identityID, err)
	}
	clientPubKey, err := os.ReadFile(filepath.Join(env.ClientDataDir, ".ssh", "id_ed25519.pub"))
	if err != nil {
		t.Fatalf("failed to read client public key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "authorized_keys"), clientPubKey, 0o600); err != nil {
		t.Fatalf("failed to write %s authorized_keys: %v", identityID, err)
	}

	family := fmt.Sprintf("integration-%s-template-%d", identityID, time.Now().UnixNano())
	keyType := integrationTemplateKeyType(family)
	if _, err := templatestore.SaveTemplateForPaths(paths, identityID, integrationGenericTemplateYAML(family), keyType, templatestore.TemplateTypeGeneric, masterKeyRing); err != nil {
		t.Fatalf("failed to save %s template %s: %v", identityID, keyType, err)
	}
	if err := keytypestate.Put(paths, identityID, keytypestate.Record{
		KeyType: keyType,
		Source:  keytypestate.SourceYAMLGeneric,
		State:   keytypestate.StateEnabled,
	}); err != nil {
		t.Fatalf("failed to write %s template state %s: %v", identityID, keyType, err)
	}

	return token, keyType
}

func unlockIdentityOverSSHAdmin(t *testing.T, identityID, token string) *transport.SSHAdminClient {
	t.Helper()

	sshCfg := mustLoadClientSSHConfig(t)
	client := transport.NewSSHAdminForIdentity(sshCfg.Host, sshCfg.Port, identityID, token, sshCfg.IdentityFile, sshCfg.KnownHostsPath)
	if err := client.Dial(); err != nil {
		t.Fatalf("failed to connect SSH admin session: %v", err)
	}
	if err := client.Authenticate(mustReadPassphrase(t, os.Getenv("APSIGNER_DATA")), 10*time.Second); err != nil {
		client.Close()
		t.Fatalf("failed to authenticate SSH admin session: %v", err)
	}
	status, err := client.WaitForStatus(10 * time.Second)
	if err != nil {
		client.Close()
		t.Fatalf("failed to read SSH admin status: %v", err)
	}
	if status.State != "unlocked" {
		client.Close()
		t.Fatalf("SSH admin status = %q, want unlocked", status.State)
	}
	return client
}

func integrationSuggestedParams() types.SuggestedParams {
	return types.SuggestedParams{
		Fee:             types.MicroAlgos(1000),
		GenesisHash:     integrationTestnetGenesisHash(),
		GenesisID:       "testnet-v1.0",
		FirstRoundValid: 100,
		LastRoundValid:  200,
		FlatFee:         true,
	}
}

func integrationTestnetGenesisHash() []byte {
	decoded, err := base64.StdEncoding.DecodeString(apconfig.AlgorandTestnetGenesisHash)
	if err != nil {
		panic(err)
	}
	return decoded
}

func integrationGenericTemplateYAML(family string) []byte {
	return []byte(fmt.Sprintf(`schema_version: 1
derivation_version: 3
template_type: generic
template_mode: generated
publisher: %s
family: %s
version: 1
display_name: "Integration Identity Scoped"
description: "Integration test template for identity-scoped inventory"
max_opcode_cost: 20000
parameters: []
runtime_args: []
teal: |
  #pragma version 13
  int 1
  return
`, integrationTemplatePublisher, family))
}

func keyTypesContain(items []signerapi.KeyTypeInfo, keyType string) bool {
	for _, item := range items {
		if item.KeyType == keyType {
			return true
		}
	}
	return false
}
