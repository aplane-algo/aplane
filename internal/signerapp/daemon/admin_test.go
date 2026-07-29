// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/witness"

	"github.com/aplane-algo/aplane/internal/addressderive"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	utilkeys "github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/generictemplate"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// testPassphrase is a fixed passphrase for test keystore creation.
var testPassphrase = []byte("test-passphrase-for-unit-tests!")

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

// setupTestSigner creates a Signer with a working keystore and unlocked runtime,
// and identity context ready for handler testing.
// Returns the signer and a cleanup function. The caller should defer cleanup().
func setupTestSigner(t *testing.T) (*Signer, func()) {
	t.Helper()

	tmpDir := t.TempDir()

	// Create identity-scoped keys directory
	keysDir := filepath.Join(tmpDir, "identities", "default", "keys")
	if err := os.MkdirAll(keysDir, 0750); err != nil {
		t.Fatalf("Failed to create keys dir: %v", err)
	}

	keyPaths := utilkeys.NewPaths(tmpDir)

	// Create keystore metadata (.keystore file in identity directory)
	userDir := filepath.Join(tmpDir, "identities", "default")
	masterKeyRing, err := crypto.CreateKeyringStore(userDir, testPassphrase)
	if err != nil {
		t.Fatalf("Failed to create keystore metadata: %v", err)
	}
	masterKey, err := masterKeyRing.CurrentTermKey()
	if err != nil {
		t.Fatalf("CurrentTermKey(): %v", err)
	}
	if err := policy.SaveStoredConfigWithKeyring(tmpDir, auth.DefaultIdentityID, &policy.StoredConfig{}, cryptotest.Keyring(t, masterKey), time.Now()); err != nil {
		crypto.ZeroBytes(masterKey)
		t.Fatalf("Failed to create policy baseline: %v", err)
	}
	roleBytes, _, err := noderole.SaveInitial(keyPaths, noderole.RoleSigner, time.Now())
	if err != nil {
		crypto.ZeroBytes(masterKey)
		t.Fatalf("Failed to create node role: %v", err)
	}
	if err := noderole.SaveIdentitySidecarWithKeyring(keyPaths, auth.DefaultIdentityID, roleBytes, cryptotest.Keyring(t, masterKey), time.Now()); err != nil {
		crypto.ZeroBytes(masterKey)
		t.Fatalf("Failed to create node role sidecar: %v", err)
	}
	initialPolicy, err := policyruntime.LoadVerified(tmpDir, auth.DefaultIdentityID, serverConfigForTest(), cryptotest.Keyring(t, masterKey))
	if err != nil {
		crypto.ZeroBytes(masterKey)
		t.Fatalf("Failed to verify policy baseline: %v", err)
	}
	crypto.ZeroBytes(masterKey)

	// Initialize FileKeyStore and derive master key
	ks := keystore.NewFileKeyStoreForPaths(keyPaths, auth.DefaultIdentityID)
	err = ks.Unlock(testPassphrase)
	if err != nil {
		t.Fatalf("Failed to initialize master key: %v", err)
	}

	// A real audit logger, as production always has: the durable
	// activation-intent gate fails closed without one.
	auditLog, err := NewAuditLogger(filepath.Join(tmpDir, "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })
	server := &Signer{
		registry: identity.NewRegistry(),
		config:   serverConfigForTest(),
		keyPaths: keyPaths,
		dataDir:  tmpDir,
		auditLog: auditLog,
	}

	ir := identity.New(identity.Config{
		Authenticator: auth.NewTokenAuthenticator("test-token"),
		ID:            auth.DefaultIdentityID,
		KeyStore:      ks,
		KeyPaths:      keyPaths,
		NodeRole:      noderole.RoleSigner,
	})
	_ = server.registry.Register(ir)
	// All stores are generational in this release: mint the first
	// generation the way initialize does before any test writes keys.
	convertTestSignerToGenerational(t, server)
	signerstartup.WireReloadFunc(ir, testIdentityBuildOptions(server), server.identityBuildHooks())
	signerstartup.WireApprovalCoordinator(ir, server.identityBuildHooks())
	ir.SetPolicy(initialPolicy)
	ir.SetUnlocked()

	cleanup := func() {}

	return server, cleanup
}

func serverConfigForTest() *serverconfig.ServerConfig {
	cfg := serverconfig.DefaultServerConfig()
	cfg.Theme = "auto"
	return &cfg
}

// requestWithIdentity creates an HTTP request with an authenticated identity in the context.
func requestWithIdentity(method, url string, body []byte) *http.Request {
	return requestWithIdentityID(method, url, body, auth.CurrentProductIdentityID())
}

func requestWithIdentityID(method, url string, body []byte, identityID string) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, url, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, url, nil)
	}
	identity := &auth.Identity{ID: identityID, Type: "service", Method: "test"}
	ctx := auth.ContextWithIdentity(r.Context(), identity)
	return r.WithContext(ctx)
}

// decodeResponse decodes the JSON response body into the given target.
func decodeResponse(t *testing.T, w *httptest.ResponseRecorder, target interface{}) {
	t.Helper()
	if err := json.NewDecoder(w.Body).Decode(target); err != nil {
		t.Fatalf("Failed to decode response: %v (body: %s)", err, w.Body.String())
	}
}

// configureMockAlgod sets up a mock algod on the signer and DSA providers.
// Returns a cleanup function that should be deferred.
func configureMockAlgod(t *testing.T, server *Signer) (cleanup func()) {
	t.Helper()
	server.config.Algod = config.AlgodConfig{
		"testnet": &config.AlgodNetworkConfig{
			Server: "http://mock-algod",
			Token:  "",
		},
	}

	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/v2/teal/compile" {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"message":"not found"}`)),
				Request:    req,
			}, nil
		}
		source, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		bytecode := compiledPushbytesSaltBytecode(0)
		isTrailingBytecblockSalt := strings.HasSuffix(strings.TrimSpace(string(source)), "bytecblock 0x00")
		if isTrailingBytecblockSalt {
			bytecode = []byte{0x0c, 0x81, 0x01, 0x43, 0x26, 0x01, 0x01, 0x00}
		} else if bytes.Contains(source, []byte("bytecblock 0x00")) {
			bytecode = []byte{
				0x0c,
				0x26, 0x01, 0x01, 0x00,
				0x31, 0x17,
				0x2d,
				0x81, 0x01,
			}
		}
		if !isTrailingBytecblockSalt {
			bytecode = append(bytecode, make([]byte, 32)...)
		}
		body, err := json.Marshal(map[string]interface{}{
			"hash":   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
			"result": base64.StdEncoding.EncodeToString(bytecode),
		})
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(body)),
			Request:    req,
		}, nil
	})

	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, transport)
	if err != nil {
		t.Fatalf("Failed to create mock algod client: %v", err)
	}
	logicsigdsa.ConfigureAlgodClient(client)
	server.makeAlgod = func(serverURL, token string) (*algod.Client, error) {
		return algod.MakeClientWithTransport(serverURL, token, nil, transport)
	}

	return func() {}
}

func compiledPushbytesSaltBytecode(counter byte) []byte {
	marker := lsigsalt.PushbytesSaltMarker(counter)
	bytecode := []byte{0x0c, 0x80, byte(len(marker))}
	bytecode = append(bytecode, marker...)
	bytecode = append(bytecode, 0x48, 0x81, 0x01)
	return bytecode
}

func registerLibraryGenericTemplateForTest(t *testing.T, filename string) {
	t.Helper()

	_, spec := loadLibraryGenericTemplateForTest(t, filename)
	genericlsig.RegisterIfAbsent(generictemplate.NewYAMLTemplate(spec))
}

func installLibraryGenericTemplateForTest(t *testing.T, server *Signer, filename string) {
	t.Helper()

	data, spec := loadLibraryGenericTemplateForTest(t, filename)
	saveGenericTemplateForTest(t, server, spec.KeyType(), data)
}

func loadLibraryGenericTemplateForTest(t *testing.T, filename string) ([]byte, *generictemplate.TemplateSpec) {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "..", "library", "templates", filename))
	if err != nil {
		t.Fatalf("read template library file %s: %v", filename, err)
	}
	spec, err := generictemplate.ParseTemplateSpec(data)
	if err != nil {
		t.Fatalf("parse template library file %s: %v", filename, err)
	}
	if err := generictemplate.ValidateSpec(spec); err != nil {
		t.Fatalf("validate template library file %s: %v", filename, err)
	}
	return data, spec
}

func registerLibraryFalconTemplateForTest(t *testing.T, filename string) {
	t.Helper()
	RegisterProviders()

	data, err := os.ReadFile(filepath.Join("..", "..", "..", "library", "templates", filename))
	if err != nil {
		t.Fatalf("read template library file %s: %v", filename, err)
	}
	spec, err := composeddsa.ParseTemplateSpec(data)
	if err != nil {
		t.Fatalf("parse template library file %s: %v", filename, err)
	}
	if err := composeddsa.ValidateTemplateSpec(spec); err != nil {
		t.Fatalf("validate template library file %s: %v", filename, err)
	}
	keytypecatalog.Register(keytypecatalog.Entry{
		KeyType:      spec.KeyType(),
		Family:       spec.Family,
		Availability: keytypecatalog.AvailabilityDefaultEnabled,
	})
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("create provider from %s: %v", filename, err)
	}
	if logicsigdsa.RegisterIfAbsent(provider) {
		base, ok := composeddsa.LookupBase(spec.BaseKeyType)
		if !ok {
			t.Fatalf("base key type %s was not registered", spec.BaseKeyType)
		}
		addressderive.Register(provider.KeyType(), base.NewAddressDeriver(provider.KeyType()))
	}
}

// --- Generate tests ---

func TestAdminGenerateEd25519(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	reqBody, _ := json.Marshal(AdminGenerateRequest{
		KeyType: "ed25519",
	})

	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", reqBody)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)

	if resp.Error != "" {
		t.Fatalf("Unexpected error: %s", resp.Error)
	}
	if resp.Address == "" {
		t.Fatal("Expected non-empty address")
	}
	if resp.KeyType != "ed25519" {
		t.Errorf("Expected key_type ed25519, got %s", resp.KeyType)
	}
	// Verify address is a valid 58-char Algorand address
	if len(resp.Address) != 58 {
		t.Errorf("Expected 58-char Algorand address, got %d chars", len(resp.Address))
	}
}

func TestAdminGenerateFalcon1024(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	algodCleanup := configureMockAlgod(t, server)
	defer algodCleanup()

	reqBody, _ := json.Marshal(AdminGenerateRequest{
		KeyType: "aplane.falcon1024.v1",
	})

	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", reqBody)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)

	if resp.Error != "" {
		t.Fatalf("Unexpected error: %s", resp.Error)
	}
	if resp.Address == "" {
		t.Fatal("Expected non-empty address")
	}
	if resp.KeyType != "aplane.falcon1024.v1" {
		t.Errorf("Expected key_type aplane.falcon1024.v1, got %s", resp.KeyType)
	}
	if len(resp.Address) != 58 {
		t.Errorf("Expected 58-char Algorand address, got %d chars", len(resp.Address))
	}
}

func TestAdminGenerateDoesNotInferPublisher(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	algodCleanup := configureMockAlgod(t, server)
	defer algodCleanup()

	reqBody, _ := json.Marshal(AdminGenerateRequest{
		KeyType: "falcon1024.v1",
	})

	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", reqBody)
	server.handleAdminGenerate(w, r)

	if w.Code == http.StatusOK {
		t.Fatalf("Expected failure for unqualified key type, got 200: %s", w.Body.String())
	}

	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)
	if resp.Error == "" {
		t.Fatal("Expected error for unqualified key type")
	}
}

func TestAdminGenerateEd25519IsImmediatelyVisibleInKeyCache(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	reqBody, _ := json.Marshal(AdminGenerateRequest{KeyType: "ed25519"})
	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", reqBody)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)

	ir := server.registry.Get(auth.DefaultIdentityID)
	keyFile, err := ir.FindKeyFile(resp.Address)
	if err != nil {
		t.Fatalf("generated address %s not present in key cache immediately after generate: %v", resp.Address, err)
	}
	if keyFile == "" {
		t.Fatalf("generated address %s has empty key path in cache", resp.Address)
	}
}

func TestAdminGenerateFalconAllowlistIsImmediatelyVisibleInKeyCache(t *testing.T) {
	registerLibraryFalconTemplateForTest(t, "aplane.falcon1024-allowlist.v1.yaml")

	server, cleanup := setupTestSigner(t)
	defer cleanup()

	algodCleanup := configureMockAlgod(t, server)
	defer algodCleanup()

	reqBody, _ := json.Marshal(AdminGenerateRequest{
		KeyType: "aplane.falcon1024-allowlist.v1",
		Parameters: map[string]string{
			"recipients": "M75L3PBI5EFTOXBQ6QLRQMQ3VIHBBTPP6SWOLT3WTZN4XF7DBL5662BBRM",
		},
	})
	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", reqBody)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)

	ir := server.registry.Get(auth.DefaultIdentityID)
	keyFile, err := ir.FindKeyFile(resp.Address)
	if err != nil {
		t.Fatalf("generated address %s not present in key cache immediately after generate: %v", resp.Address, err)
	}
	if keyFile == "" {
		t.Fatalf("generated address %s has empty key path in cache", resp.Address)
	}
}

func TestAdminGenerateHTLCV1(t *testing.T) {
	registerLibraryGenericTemplateForTest(t, "aplane.htlc.v1.yaml")

	server, cleanup := setupTestSigner(t)
	defer cleanup()
	installLibraryGenericTemplateForTest(t, server, "aplane.htlc.v1.yaml")

	algodCleanup := configureMockAlgod(t, server)
	defer algodCleanup()

	// aplane.htlc.v1 requires a digest, recipient, refund address, and timeout.
	reqBody, _ := json.Marshal(AdminGenerateRequest{
		KeyType: "aplane.htlc.v1",
		Parameters: map[string]string{
			"hash":           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"recipient":      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
			"refund_address": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
			"timeout_round":  "1000000",
		},
	})

	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", reqBody)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)

	if resp.Error != "" {
		t.Fatalf("Unexpected error: %s", resp.Error)
	}
	if resp.Address == "" {
		t.Fatal("Expected non-empty address")
	}
	if resp.KeyType != "aplane.htlc.v1" {
		t.Errorf("Expected key_type aplane.htlc.v1, got %s", resp.KeyType)
	}
	// Verify parameters are echoed back
	if resp.Parameters["timeout_round"] == "" {
		t.Error("Expected parameters to include timeout_round")
	}
}

func TestAdminSyncSentriesNotifiesAdminKeyTypesChanged(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	hub := &recordingAdminHub{}
	server.hub = hub

	publicKeyBytes := bytes.Repeat([]byte{0xab}, witness.Falcon1024PublicKeySize)
	componentKey, err := witness.ID(witness.Falcon1024V1, publicKeyBytes)
	if err != nil {
		t.Fatalf("witness.ID() error = %v", err)
	}
	reqBody, _ := json.Marshal(signerapi.AdminSyncSentryReferencesRequest{
		Candidates: []signerapi.SentryReferenceCandidate{{
			EndpointAlias: "sentry-local",
			ComponentKey:  componentKey,
			KeyType:       witness.Falcon1024V1,
			PublicKeyHex:  strings.Repeat("ab", witness.Falcon1024PublicKeySize),
		}},
	})

	w := httptest.NewRecorder()
	server.handleAdminSyncSentries(w, requestWithIdentity(http.MethodPost, "/admin/sentries/sync", reqBody))
	if w.Code != http.StatusOK {
		t.Fatalf("handleAdminSyncSentries status = %d: %s", w.Code, w.Body.String())
	}
	var resp signerapi.AdminSyncSentryReferencesResponse
	decodeResponse(t, w, &resp)
	if resp.Added != 1 {
		t.Fatalf("Added = %d, want 1", resp.Added)
	}
	if hub.keysIdentity != auth.CurrentProductIdentityID() {
		t.Fatalf("NotifyKeysChanged identity = %q, want %q", hub.keysIdentity, auth.CurrentProductIdentityID())
	}
}

// --- Delete tests ---

func TestAdminDeleteEd25519(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	// First generate a key
	genBody, _ := json.Marshal(AdminGenerateRequest{KeyType: "ed25519"})
	genW := httptest.NewRecorder()
	genR := requestWithIdentity(http.MethodPost, "/admin/generate", genBody)
	server.handleAdminGenerate(genW, genR)

	if genW.Code != http.StatusOK {
		t.Fatalf("Generate failed: %d: %s", genW.Code, genW.Body.String())
	}

	var genResp AdminGenerateResponse
	decodeResponse(t, genW, &genResp)
	address := genResp.Address

	// Reload keys so the signer knows about the new key
	if err := reloadKeysForTest(server); err != nil {
		t.Fatalf("Failed to reload keys: %v", err)
	}

	// Now delete it
	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodDelete, "/admin/keys?address="+address, nil)
	server.handleAdminDelete(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp AdminDeleteResponse
	decodeResponse(t, w, &resp)

	if !resp.Success {
		t.Fatalf("Expected success=true, got error: %s", resp.Error)
	}
}

func TestAdminDeleteFalcon1024(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	algodCleanup := configureMockAlgod(t, server)
	defer algodCleanup()

	// Generate a aplane.falcon1024.v1 key
	genBody, _ := json.Marshal(AdminGenerateRequest{KeyType: "aplane.falcon1024.v1"})
	genW := httptest.NewRecorder()
	genR := requestWithIdentity(http.MethodPost, "/admin/generate", genBody)
	server.handleAdminGenerate(genW, genR)

	if genW.Code != http.StatusOK {
		t.Fatalf("Generate failed: %d: %s", genW.Code, genW.Body.String())
	}

	var genResp AdminGenerateResponse
	decodeResponse(t, genW, &genResp)
	address := genResp.Address

	// Reload keys
	if err := reloadKeysForTest(server); err != nil {
		t.Fatalf("Failed to reload keys: %v", err)
	}

	// Delete it
	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodDelete, "/admin/keys?address="+address, nil)
	server.handleAdminDelete(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp AdminDeleteResponse
	decodeResponse(t, w, &resp)

	if !resp.Success {
		t.Fatalf("Expected success=true, got error: %s", resp.Error)
	}
}

func TestAdminDeleteHTLCV1(t *testing.T) {
	registerLibraryGenericTemplateForTest(t, "aplane.htlc.v1.yaml")

	server, cleanup := setupTestSigner(t)
	defer cleanup()
	installLibraryGenericTemplateForTest(t, server, "aplane.htlc.v1.yaml")

	algodCleanup := configureMockAlgod(t, server)
	defer algodCleanup()

	// Generate an aplane.htlc.v1 key.
	genBody, _ := json.Marshal(AdminGenerateRequest{
		KeyType: "aplane.htlc.v1",
		Parameters: map[string]string{
			"hash":           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"recipient":      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
			"refund_address": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
			"timeout_round":  "1000000",
		},
	})
	genW := httptest.NewRecorder()
	genR := requestWithIdentity(http.MethodPost, "/admin/generate", genBody)
	server.handleAdminGenerate(genW, genR)

	if genW.Code != http.StatusOK {
		t.Fatalf("Generate failed: %d: %s", genW.Code, genW.Body.String())
	}

	var genResp AdminGenerateResponse
	decodeResponse(t, genW, &genResp)
	address := genResp.Address

	// Reload keys
	if err := reloadKeysForTest(server); err != nil {
		t.Fatalf("Failed to reload keys: %v", err)
	}

	// Delete it
	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodDelete, "/admin/keys?address="+address, nil)
	server.handleAdminDelete(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp AdminDeleteResponse
	decodeResponse(t, w, &resp)

	if !resp.Success {
		t.Fatalf("Expected success=true, got error: %s", resp.Error)
	}
}

// --- Error case tests ---

func TestAdminGenerateMethodNotAllowed(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodGet, "/admin/generate", nil)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestAdminGenerateLockedSigner(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	// Lock the signer
	server.lock()

	reqBody, _ := json.Marshal(AdminGenerateRequest{KeyType: "ed25519"})
	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", reqBody)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", w.Code)
	}

	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)
	if !strings.Contains(resp.Error, "locked") {
		t.Errorf("Expected 'locked' in error, got %q", resp.Error)
	}
}

func TestAdminGenerateNoIdentity(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	reqBody, _ := json.Marshal(AdminGenerateRequest{KeyType: "ed25519"})
	w := httptest.NewRecorder()
	// No identity in context
	r := httptest.NewRequest(http.MethodPost, "/admin/generate", bytes.NewReader(reqBody))
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestAdminGenerateEmptyKeyType(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	reqBody, _ := json.Marshal(AdminGenerateRequest{KeyType: ""})
	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", reqBody)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestAdminGenerateInvalidKeyType(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	reqBody, _ := json.Marshal(AdminGenerateRequest{KeyType: "nonexistent-type"})
	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", reqBody)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}

	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)
	if !strings.Contains(resp.Error, "invalid key type") {
		t.Errorf("Expected 'invalid key type' in error, got %q", resp.Error)
	}
}

func TestAdminGenerateRejectsGloballyRegisteredGenericTemplateNotInstalledForIdentity(t *testing.T) {
	family := fmt.Sprintf("admin-uninstalled-generic-%d", time.Now().UnixNano())
	keyType := family + "-v1"
	registerGenericTemplateProviderForTest(t, renderGenericTemplateYAML(family, 1, "Admin Uninstalled Generic", "global registry only"))

	server, cleanup := setupTestSigner(t)
	defer cleanup()

	reqBody, _ := json.Marshal(AdminGenerateRequest{KeyType: keyType})
	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", reqBody)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)
	if !strings.Contains(resp.Error, "invalid key type") {
		t.Fatalf("Expected invalid key type error, got %q", resp.Error)
	}
}

func TestAdminGenerateRejectsUnavailableAuthenticatedIdentity(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	reqBody, _ := json.Marshal(AdminGenerateRequest{KeyType: "ed25519"})
	w := httptest.NewRecorder()
	r := requestWithIdentityID(http.MethodPost, "/admin/generate", reqBody, "other-identity")
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d", w.Code)
	}

	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)
	if !strings.Contains(resp.Error, "identity not available: other-identity") {
		t.Fatalf("Expected identity not available error, got %q", resp.Error)
	}
}

func TestAdminGenerateInvalidJSON(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", []byte("not json"))
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestAdminGenerateHTLCMissingAlgod(t *testing.T) {
	registerLibraryGenericTemplateForTest(t, "aplane.htlc.v1.yaml")

	server, cleanup := setupTestSigner(t)
	defer cleanup()
	installLibraryGenericTemplateForTest(t, server, "aplane.htlc.v1.yaml")

	// No algod configured
	server.config.Algod = nil

	reqBody, _ := json.Marshal(AdminGenerateRequest{
		KeyType: "aplane.htlc.v1",
		Parameters: map[string]string{
			"hash":           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"recipient":      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
			"refund_address": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
			"timeout_round":  "1000000",
		},
	})
	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", reqBody)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", w.Code)
	}

	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)
	if resp.Error != "key generation failed" {
		t.Errorf("Expected generic key generation error, got %q", resp.Error)
	}
}

func TestAdminGenerateHTLCInvalidParams(t *testing.T) {
	registerLibraryGenericTemplateForTest(t, "aplane.htlc.v1.yaml")

	server, cleanup := setupTestSigner(t)
	defer cleanup()
	installLibraryGenericTemplateForTest(t, server, "aplane.htlc.v1.yaml")

	algodCleanup := configureMockAlgod(t, server)
	defer algodCleanup()

	// Missing required params
	reqBody, _ := json.Marshal(AdminGenerateRequest{
		KeyType:    "aplane.htlc.v1",
		Parameters: map[string]string{}, // Missing all required params
	})
	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", reqBody)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)
	if !strings.Contains(resp.Error, "parameter validation failed") {
		t.Errorf("Expected param validation error, got %q", resp.Error)
	}
}

func TestAdminGenerateFalconAllowlistInvalidParams(t *testing.T) {
	registerLibraryFalconTemplateForTest(t, "aplane.falcon1024-allowlist.v1.yaml")

	server, cleanup := setupTestSigner(t)
	defer cleanup()

	algodCleanup := configureMockAlgod(t, server)
	defer algodCleanup()

	reqBody, _ := json.Marshal(AdminGenerateRequest{
		KeyType: "aplane.falcon1024-allowlist.v1",
		Parameters: map[string]string{
			"recipient": "M75L3PBI5EFTOXBQ6QLRQMQ3VIHBBTPP6SWOLT3WTZN4XF7DBL5662BBRM",
		},
	})
	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", reqBody)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)
	if !strings.Contains(resp.Error, "parameter validation failed") {
		t.Fatalf("expected parameter validation error, got %q", resp.Error)
	}
}

func TestAdminDeleteMethodNotAllowed(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/keys?address=TEST", nil)
	server.handleAdminDelete(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestAdminDeleteLockedSigner(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	server.lock()

	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodDelete, "/admin/keys?address=TEST", nil)
	server.handleAdminDelete(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", w.Code)
	}
}

func TestAdminDeleteNoAddress(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodDelete, "/admin/keys", nil)
	server.handleAdminDelete(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}

	var resp AdminDeleteResponse
	decodeResponse(t, w, &resp)
	if !strings.Contains(resp.Error, "address") {
		t.Errorf("Expected 'address' in error, got %q", resp.Error)
	}
}

func TestAdminDeleteNotFound(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodDelete, "/admin/keys?address=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ", nil)
	server.handleAdminDelete(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}

	var resp AdminDeleteResponse
	decodeResponse(t, w, &resp)
	if !strings.Contains(resp.Error, "not found") {
		t.Errorf("Expected 'not found' in error, got %q", resp.Error)
	}
}

func TestAdminDeleteNoIdentity(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/admin/keys?address=TEST", nil)
	server.handleAdminDelete(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

// --- Round-trip tests (generate then delete) ---

func TestAdminGenerateThenDeleteEd25519(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	// Generate
	genBody, _ := json.Marshal(AdminGenerateRequest{KeyType: "ed25519"})
	genW := httptest.NewRecorder()
	server.handleAdminGenerate(genW, requestWithIdentity(http.MethodPost, "/admin/generate", genBody))

	if genW.Code != http.StatusOK {
		t.Fatalf("Generate failed: %d: %s", genW.Code, genW.Body.String())
	}
	var genResp AdminGenerateResponse
	decodeResponse(t, genW, &genResp)
	address := genResp.Address

	// Reload keys to populate the in-memory maps
	if err := reloadKeysForTest(server); err != nil {
		t.Fatalf("Failed to reload keys: %v", err)
	}

	// Delete
	delW := httptest.NewRecorder()
	server.handleAdminDelete(delW, requestWithIdentity(http.MethodDelete, "/admin/keys?address="+address, nil))

	if delW.Code != http.StatusOK {
		t.Fatalf("Delete failed: %d: %s", delW.Code, delW.Body.String())
	}
	var delResp AdminDeleteResponse
	decodeResponse(t, delW, &delResp)
	if !delResp.Success {
		t.Fatalf("Delete not successful: %s", delResp.Error)
	}

	// Reload keys again to reflect deletion
	if err := reloadKeysForTest(server); err != nil {
		t.Fatalf("Failed to reload keys after delete: %v", err)
	}

	// Verify key is gone
	ir := server.registry.Get(auth.DefaultIdentityID)
	_, err := ir.FindKeyFile(address)
	if err == nil {
		t.Error("Key should not exist after deletion")
	}
}

func TestAdminGenerateMultipleEd25519(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	addresses := make(map[string]bool)
	for i := 0; i < 3; i++ {
		genBody, _ := json.Marshal(AdminGenerateRequest{KeyType: "ed25519"})
		w := httptest.NewRecorder()
		server.handleAdminGenerate(w, requestWithIdentity(http.MethodPost, "/admin/generate", genBody))

		if w.Code != http.StatusOK {
			t.Fatalf("Generate %d failed: %d: %s", i, w.Code, w.Body.String())
		}
		var resp AdminGenerateResponse
		decodeResponse(t, w, &resp)

		if addresses[resp.Address] {
			t.Errorf("Duplicate address generated: %s", resp.Address)
		}
		addresses[resp.Address] = true
	}

	if len(addresses) != 3 {
		t.Errorf("Expected 3 unique addresses, got %d", len(addresses))
	}
}

// reloadKeysForTest rescans the keys directory to update in-memory maps.
// This simulates what the file watcher does in production.
func reloadKeysForTest(server *Signer) error {
	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		return fmt.Errorf("identity not found")
	}

	ks := ir.KeyStore()
	if err := ks.Scan(testPassphrase); err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	ir.PublishSnapshot(ks.GetCache(), ks.GetKeyTypes(), ks.GetLsigSizes())
	return nil
}
