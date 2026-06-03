// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/signerapp/keyadmin"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	ed25519 "github.com/aplane-algo/aplane/internal/signing/ed25519"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
	lsigsignerreg "github.com/aplane-algo/aplane/lsig/signerreg"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

var restTestPassphrase = []byte("test-passphrase-for-unit-tests!")

const restGenericErrorKeyType = "test.generic-rest-error.v1"

func restTestMasterKey() []byte {
	return bytes.Repeat([]byte{9}, 32)
}

func writeTemplateStateForRestTest(t *testing.T, paths storepaths.Paths, identityID, keyType string, templateType templatestore.TemplateType, state keytypestate.State) {
	t.Helper()
	var source keytypestate.Source
	switch templateType {
	case templatestore.TemplateTypeGeneric:
		source = keytypestate.SourceYAMLGeneric
	case templatestore.TemplateTypeComposed:
		source = keytypestate.SourceYAMLComposed
	default:
		t.Fatalf("unsupported template type in test: %q", templateType)
	}
	if err := keytypestate.Put(paths, identityID, keytypestate.Record{
		KeyType: keyType,
		Source:  source,
		State:   state,
	}); err != nil {
		t.Fatalf("keytypestate.Put() error = %v", err)
	}
}

func init() {
	lsigsignerreg.RegisterSigner()
	ed25519.RegisterSigner()
}

type stubSigningService struct {
	gotIdentityID string
	gotReq        signerapi.GroupSignRequest
	gotSession    *keystore.KeySession
	gotCtx        context.Context
	result        *signersigning.SignGroupResult
	err           *signersigning.ServiceError
}

type testContextKey string

func (s *stubSigningService) SignGroupWithContext(ctx context.Context, identityID string, req signerapi.GroupSignRequest, session *keystore.KeySession) (*signersigning.SignGroupResult, *signersigning.ServiceError) {
	s.gotCtx = ctx
	s.gotIdentityID = identityID
	s.gotReq = req
	s.gotSession = session
	return s.result, s.err
}

func (s *stubSigningService) SignGroupForSimulationWithContext(ctx context.Context, identityID string, req signerapi.GroupSignRequest, session *keystore.KeySession) (*signersigning.SignGroupResult, *signersigning.ServiceError) {
	s.gotCtx = ctx
	s.gotIdentityID = identityID
	s.gotReq = req
	s.gotSession = session
	return s.result, s.err
}

func rejectAllSimulateDeps(t *testing.T) Dependencies {
	t.Helper()
	return Dependencies{
		NewSigningService: func(*identity.Runtime) SigningService {
			t.Fatal("NewSigningService should not be called")
			return nil
		},
		EncodeTxnHex: func(types.Transaction) string {
			t.Fatal("EncodeTxnHex should not be called")
			return ""
		},
		SimulateSignedGroup: func(context.Context, []types.SignedTxn) ([]string, string, bool, *signersigning.ServiceError) {
			t.Fatal("SimulateSignedGroup should not be called")
			return nil, "", false, nil
		},
	}
}

func setupIdentityRuntime(t *testing.T, unlocked bool) *identity.Runtime {
	t.Helper()

	tmpDir := t.TempDir()
	keyPaths := storepaths.NewPaths(tmpDir)
	userDir := filepath.Join(tmpDir, "identities", auth.DefaultIdentityID)
	keysDir := keyPaths.KeysDir(auth.DefaultIdentityID)
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(keysDir): %v", err)
	}
	if _, _, err := crypto.CreateKeystoreMetadata(userDir, restTestPassphrase); err != nil {
		t.Fatalf("CreateKeystoreMetadata(): %v", err)
	}

	ks := keystore.NewFileKeyStoreForPaths(keyPaths, auth.DefaultIdentityID)
	if _, err := ks.InitializeMasterKey(restTestPassphrase); err != nil {
		t.Fatalf("InitializeMasterKey(): %v", err)
	}

	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		KeyStore:      ks,
		KeyPaths:      keyPaths,
		Authenticator: auth.NewTokenAuthenticator("test-token"),
	})
	ir.SetReloadFunc(func(identityID string, passphrase []byte, session *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		return nil, reloadKeysForTest(ir, keyPaths)
	})
	if unlocked {
		ir.SetUnlocked()
	}
	return ir
}

func reloadKeysForTest(ir *identity.Runtime, _ storepaths.Paths) error {
	ks := ir.KeyStore()
	if err := ks.Scan(nil); err != nil {
		return err
	}
	ir.PublishSnapshot(ks.GetCache(), ks.GetKeyTypes(), ks.GetLsigSizes())
	return nil
}

func TestServiceSignGroupDelegates(t *testing.T) {
	ir := setupIdentityRuntime(t, true)
	stub := &stubSigningService{
		result: &signersigning.SignGroupResult{
			Signed: []string{"abc123"},
			Mutations: &signerapi.MutationReport{
				OriginalCount: 1,
				FinalCount:    1,
			},
		},
	}
	svc := Service{
		Deps: Dependencies{
			NewSigningService: func(got *identity.Runtime) SigningService {
				if got != ir {
					t.Fatalf("runtime = %p, want %p", got, ir)
				}
				return stub
			},
		},
	}

	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: "ADDR"}}}
	ctx := context.WithValue(context.Background(), testContextKey("sign"), "ctx")
	resp, err := svc.SignGroup(ctx, ir, req)
	if err != nil {
		t.Fatalf("SignGroup() error = %v", err)
	}
	if stub.gotIdentityID != ir.ID() {
		t.Fatalf("identityID = %q, want %q", stub.gotIdentityID, ir.ID())
	}
	if len(resp.Signed) != 1 || resp.Signed[0] != "abc123" {
		t.Fatalf("Signed = %#v, want [abc123]", resp.Signed)
	}
	if resp.Mutations == nil || resp.Mutations.OriginalCount != 1 {
		t.Fatalf("Mutations = %#v, want populated report", resp.Mutations)
	}
	if stub.gotSession == nil {
		t.Fatal("SignGroup() passed nil session")
	}
	if stub.gotCtx != ctx {
		t.Fatal("SignGroup() did not pass caller context to signing service")
	}
}

func TestServicePlanShapesResponse(t *testing.T) {
	ir := setupIdentityRuntime(t, true)
	svc := Service{
		Deps: Dependencies{
			PlanGroup: func(identityID string, req signerapi.GroupSignRequest) (*signersigning.PlanResult, *signersigning.ServiceError) {
				if identityID != ir.ID() {
					t.Fatalf("identityID = %q, want %q", identityID, ir.ID())
				}
				return &signersigning.PlanResult{
					AllTxns:        []types.Transaction{{Header: types.Header{Fee: 1000}}, {Header: types.Header{Fee: 2000}}},
					DummiesNeeded:  1,
					LsigIndices:    []int{0},
					FeeInfo:        signersigning.DummyFeeInfo{TotalFees: 1000},
					NeedsRegroup:   true,
					ForeignIndices: map[int]bool{},
				}, nil
			},
			EncodeTxnHex: func(txn types.Transaction) string {
				return fmt.Sprintf("fee-%d", txn.Fee)
			},
		},
	}

	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: "ADDR"}}}
	resp, err := svc.Plan(ir, req)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(resp.Transactions) != 2 {
		t.Fatalf("Transactions len = %d, want 2", len(resp.Transactions))
	}
	if resp.Mutations == nil || resp.Mutations.DummiesAdded != 1 || !resp.Mutations.GroupIDChanged {
		t.Fatalf("Mutations = %#v, want dummy/group mutation report", resp.Mutations)
	}
}

func TestServiceSimulateSignsInternallyAndOmitsSignedBytes(t *testing.T) {
	ir := setupIdentityRuntime(t, true)
	txn := types.Transaction{Header: types.Header{Sender: types.Address{1}, Fee: 1000}}
	stub := &stubSigningService{
		result: &signersigning.SignGroupResult{
			Signed: []string{hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txn}))},
			Mutations: &signerapi.MutationReport{
				OriginalCount: 1,
				FinalCount:    1,
			},
		},
	}
	svc := Service{
		Deps: Dependencies{
			NewSigningService: func(got *identity.Runtime) SigningService {
				if got != ir {
					t.Fatalf("runtime = %p, want %p", got, ir)
				}
				return stub
			},
			EncodeTxnHex: func(got types.Transaction) string {
				if got.Fee != txn.Fee {
					t.Fatalf("encoded txn fee = %d, want %d", got.Fee, txn.Fee)
				}
				return "TXfinal"
			},
			SimulateSignedGroup: func(ctx context.Context, got []types.SignedTxn) ([]string, string, bool, *signersigning.ServiceError) {
				if len(got) != 1 || got[0].Txn.Fee != txn.Fee {
					t.Fatalf("signed group = %#v, want signed txn fee %d", got, txn.Fee)
				}
				return []string{"TXID"}, "simulation output\n", false, nil
			},
		},
	}

	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: "ADDR"}}}
	ctx := context.WithValue(context.Background(), testContextKey("simulate"), "ctx")
	resp, err := svc.Simulate(ctx, ir, req)
	if err != nil {
		t.Fatalf("Simulate() error = %v", err)
	}
	if stub.gotSession == nil {
		t.Fatal("Simulate() passed nil session")
	}
	if stub.gotCtx != ctx {
		t.Fatal("Simulate() did not pass caller context to signing service")
	}
	if len(resp.TxIDs) != 1 || resp.TxIDs[0] != "TXID" {
		t.Fatalf("TxIDs = %#v, want [TXID]", resp.TxIDs)
	}
	if len(resp.Transactions) != 1 || resp.Transactions[0] != "TXfinal" {
		t.Fatalf("Transactions = %#v, want [TXfinal]", resp.Transactions)
	}
	if resp.Output != "simulation output\n" {
		t.Fatalf("Output = %q, want simulation output", resp.Output)
	}
	if resp.Mutations == nil || resp.Mutations.FinalCount != 1 {
		t.Fatalf("Mutations = %#v, want populated report", resp.Mutations)
	}
}

func TestServiceSimulateRejectsDecommissionedRuntime(t *testing.T) {
	ir := setupIdentityRuntime(t, true)
	if err := ir.Decommission(); err != nil {
		t.Fatalf("Decommission() error = %v", err)
	}
	svc := Service{Deps: rejectAllSimulateDeps(t)}

	_, err := svc.Simulate(context.Background(), ir, signerapi.GroupSignRequest{})
	if err == nil || err.Kind != signersigning.ErrorForbidden {
		t.Fatalf("Simulate() error = %#v, want forbidden", err)
	}
	if !strings.Contains(err.Message, "decommissioned") {
		t.Fatalf("Simulate() error message = %q, want decommissioned reason", err.Message)
	}
}

func TestServiceSimulateRejectsLockedRuntime(t *testing.T) {
	ir := setupIdentityRuntime(t, false)
	svc := Service{Deps: rejectAllSimulateDeps(t)}

	_, err := svc.Simulate(context.Background(), ir, signerapi.GroupSignRequest{})
	if err == nil || err.Kind != signersigning.ErrorForbidden {
		t.Fatalf("Simulate() error = %#v, want forbidden", err)
	}
	if err.Message != "signer is locked" {
		t.Fatalf("Simulate() error message = %q, want signer is locked", err.Message)
	}
}

func TestServiceSimulateRejectsForeignPlaceholders(t *testing.T) {
	ir := setupIdentityRuntime(t, true)
	stub := &stubSigningService{
		result: &signersigning.SignGroupResult{
			Signed: []string{""},
			Mutations: &signerapi.MutationReport{
				ForeignCount: 1,
			},
		},
	}
	svc := Service{
		Deps: Dependencies{
			NewSigningService: func(got *identity.Runtime) SigningService { return stub },
			EncodeTxnHex:      func(txn types.Transaction) string { return "TXfinal" },
			SimulateSignedGroup: func(ctx context.Context, got []types.SignedTxn) ([]string, string, bool, *signersigning.ServiceError) {
				t.Fatal("SimulateSignedGroup called for foreign placeholder")
				return nil, "", false, nil
			},
		},
	}

	_, err := svc.Simulate(context.Background(), ir, signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: "ADDR"}}})
	if err == nil {
		t.Fatal("Simulate() error = nil, want foreign placeholder rejection")
	}
	if err.Kind != signersigning.ErrorBadRequest || !strings.Contains(err.Message, "foreign placeholder") {
		t.Fatalf("Simulate() error = %#v, want foreign placeholder bad request", err)
	}
}

func TestServiceKeysAndAdminMutations(t *testing.T) {
	ir := setupIdentityRuntime(t, true)
	svc := Service{Deps: Dependencies{KeyAdmin: keyadmin.Service{}}}

	status, genResp := svc.AdminGenerate(context.Background(), ir, signerapi.AdminGenerateRequest{KeyType: "ed25519"})
	if status != 200 {
		t.Fatalf("AdminGenerate status = %d, want 200", status)
	}
	if genResp.Address == "" {
		t.Fatal("AdminGenerate() returned empty address")
	}

	keysResp, err := svc.Keys(ir)
	if err != nil {
		t.Fatalf("Keys() error = %v", err)
	}
	if keysResp.Count != 1 {
		t.Fatalf("Keys count = %d, want 1", keysResp.Count)
	}
	if keysResp.Keys[0].Address != genResp.Address {
		t.Fatalf("Keys address = %q, want %q", keysResp.Keys[0].Address, genResp.Address)
	}

	status, delResp := svc.AdminDelete(ir, genResp.Address)
	if status != 200 {
		t.Fatalf("AdminDelete status = %d, want 200", status)
	}
	if !delResp.Success {
		t.Fatalf("AdminDelete response = %#v, want success", delResp)
	}
}

func TestServiceComponentKeyGenerateAndInventoryProjection(t *testing.T) {
	ir := setupIdentityRuntime(t, true)
	svc := Service{Deps: Dependencies{KeyAdmin: keyadmin.Service{}}}

	status, genResp := svc.AdminGenerate(context.Background(), ir, signerapi.AdminGenerateRequest{KeyType: keytypes.AttestorComponentEd25519V1})
	if status != 200 {
		t.Fatalf("AdminGenerate(component) status = %d, want 200: %#v", status, genResp)
	}
	if !strings.HasPrefix(genResp.Address, keytypes.ComponentKeyIDPrefix) {
		t.Fatalf("AdminGenerate address = %q, want component key ID", genResp.Address)
	}
	if genResp.ComponentKeyID != genResp.Address {
		t.Fatalf("ComponentKeyID = %q, want address %q", genResp.ComponentKeyID, genResp.Address)
	}
	if genResp.PublicKeyHex == "" {
		t.Fatal("AdminGenerate public key is empty")
	}
	if !genResp.IsComponentKey {
		t.Fatal("AdminGenerate is_component_key = false, want true")
	}
	if genResp.IsSpendingAccount == nil || *genResp.IsSpendingAccount {
		t.Fatalf("AdminGenerate is_spending_account = %#v, want false pointer", genResp.IsSpendingAccount)
	}

	keysResp, err := svc.Keys(ir)
	if err != nil {
		t.Fatalf("Keys() error = %v", err)
	}
	if keysResp.Count != 1 {
		t.Fatalf("Keys count = %d, want 1", keysResp.Count)
	}
	row := keysResp.Keys[0]
	if row.Address != genResp.Address || row.ComponentKeyID != genResp.ComponentKeyID {
		t.Fatalf("component row handles = (%q, %q), want %q", row.Address, row.ComponentKeyID, genResp.Address)
	}
	if row.PublicKeyHex != genResp.PublicKeyHex {
		t.Fatalf("component row public key = %q, want %q", row.PublicKeyHex, genResp.PublicKeyHex)
	}
	if !row.IsComponentKey {
		t.Fatal("component row is_component_key = false, want true")
	}
	if row.IsSpendingAccount == nil || *row.IsSpendingAccount {
		t.Fatalf("component row is_spending_account = %#v, want false pointer", row.IsSpendingAccount)
	}
}

func TestServiceKeyTypesIncludesEd25519(t *testing.T) {
	resp := Service{}.KeyTypes()
	if resp == nil || len(resp.KeyTypes) == 0 {
		t.Fatal("KeyTypes() returned no key types")
	}

	foundEd25519 := false
	foundComponent := false
	for _, keyType := range resp.KeyTypes {
		if keyType.KeyType == "ed25519" {
			foundEd25519 = true
		}
		if keyType.KeyType == keytypes.AttestorComponentEd25519V1 {
			foundComponent = true
			if keyType.Family != "attestor-ed25519" || keyType.MnemonicImport {
				t.Fatalf("component key type info = %#v, want attestor component metadata", keyType)
			}
		}
	}
	if !foundEd25519 {
		t.Fatal("KeyTypes() did not include ed25519")
	}
	if !foundComponent {
		t.Fatalf("KeyTypes() did not include %s", keytypes.AttestorComponentEd25519V1)
	}
}

func TestServiceKeyTypesHidesLibraryOnlyCompiledProvider(t *testing.T) {
	resp := Service{}.KeyTypes()
	for _, keyType := range resp.KeyTypes {
		if keyType.KeyType == "aplane.falcon1024_ed25519.v1" {
			t.Fatal("KeyTypes() included library-only provider before identity activation")
		}
	}
}

func TestServiceKeyTypesIncludesActivatedCompiledProvider(t *testing.T) {
	ir := setupIdentityRuntime(t, false)
	if err := keytypestate.Put(ir.KeyPaths(), ir.ID(), keytypestate.Record{
		KeyType: "aplane.falcon1024_ed25519.v1",
		Source:  keytypestate.SourceCompiled,
		State:   keytypestate.StateEnabled,
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	resp, svcErr := Service{}.KeyTypesForIdentity(ir)
	if svcErr != nil {
		t.Fatalf("KeyTypesForIdentity() error = %v", svcErr)
	}
	found := false
	for _, keyType := range resp.KeyTypes {
		if keyType.KeyType == "aplane.falcon1024_ed25519.v1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("KeyTypesForIdentity() did not include activated compiled provider")
	}
}

func TestServiceKeyTypesIncludesEnabledYAMLComposedProvider(t *testing.T) {
	ir := setupIdentityRuntime(t, false)
	keyType := "rest-composed-enabled-v1"
	logicsigdsa.RegisterIfAbsent(restTestDSAProvider{keyType: keyType})

	if err := keytypestate.Put(ir.KeyPaths(), ir.ID(), keytypestate.Record{
		KeyType: keyType,
		Source:  keytypestate.SourceYAMLComposed,
		State:   keytypestate.StateEnabled,
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	resp, svcErr := Service{}.KeyTypesForIdentity(ir)
	if svcErr != nil {
		t.Fatalf("KeyTypesForIdentity() error = %v", svcErr)
	}
	if !keyTypesResponseContains(resp.KeyTypes, keyType) {
		t.Fatalf("KeyTypesForIdentity() did not include enabled composed provider %q", keyType)
	}
}

func TestServiceKeyTypesForIdentityReportsCorruptStateRecord(t *testing.T) {
	ir := setupIdentityRuntime(t, false)
	path := ir.KeyPaths().KeyTypeRecord(ir.ID(), "bad-rest-state-v1")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(`{bad`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	resp, svcErr := Service{}.KeyTypesForIdentity(ir)
	if resp != nil {
		t.Fatalf("KeyTypesForIdentity() response = %#v, want nil", resp)
	}
	if svcErr == nil || svcErr.Kind != signersigning.ErrorInternal {
		t.Fatalf("KeyTypesForIdentity() error = %#v, want internal state error", svcErr)
	}
}

func TestServiceKeyTypesHidesDisabledInstalledTemplate(t *testing.T) {
	ir := setupIdentityRuntime(t, true)
	keyType := "test.generic-rest-disabled.v1"
	yamlData := []byte(`schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: generic-rest-disabled
version: 1
display_name: Generic Rest Disabled
description: Test disabled template
parameters: []
runtime_args: []
teal: |
  #pragma version 8
  int 1
  return
`)
	spec, err := generictemplate.ParseTemplateSpec(yamlData)
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	if err := generictemplate.ValidateSpec(spec); err != nil {
		t.Fatalf("ValidateSpec() error = %v", err)
	}
	genericlsig.RegisterIfAbsent(generictemplate.NewYAMLTemplate(spec))
	if err := ir.WithMasterKey(func(mk []byte) error {
		_, saveErr := templatestore.SaveTemplateForPaths(ir.KeyPaths(), ir.ID(), yamlData, keyType, templatestore.TemplateTypeGeneric, mk)
		return saveErr
	}); err != nil {
		t.Fatalf("SaveTemplateForPaths() error = %v", err)
	}
	writeTemplateStateForRestTest(t, ir.KeyPaths(), ir.ID(), keyType, templatestore.TemplateTypeGeneric, keytypestate.StateEnabled)
	if err := keytypestate.SetState(ir.KeyPaths(), ir.ID(), keyType, keytypestate.StateDisabled); err != nil {
		t.Fatalf("SetState() error = %v", err)
	}

	resp, svcErr := Service{}.KeyTypesForIdentity(ir)
	if svcErr != nil {
		t.Fatalf("KeyTypesForIdentity() error = %v", svcErr)
	}
	for _, keyTypeInfo := range resp.KeyTypes {
		if keyTypeInfo.KeyType == keyType {
			t.Fatal("KeyTypesForIdentity() included disabled installed template")
		}
	}
}

func TestServiceKeyTypesForIdentityHidesTemplateInstalledForOtherIdentity(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	keyType := "test.generic-rest-identity-scoped.v1"
	yamlData := []byte(`schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: generic-rest-identity-scoped
version: 1
display_name: Generic Rest Identity Scoped
description: Test identity-scoped template
parameters: []
runtime_args: []
teal: |
  #pragma version 8
  int 1
  return
`)
	spec, err := generictemplate.ParseTemplateSpec(yamlData)
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	if err := generictemplate.ValidateSpec(spec); err != nil {
		t.Fatalf("ValidateSpec() error = %v", err)
	}
	genericlsig.RegisterIfAbsent(generictemplate.NewYAMLTemplate(spec))

	if _, err := templatestore.SaveTemplateForPaths(paths, "alice", yamlData, keyType, templatestore.TemplateTypeGeneric, restTestMasterKey()); err != nil {
		t.Fatalf("SaveTemplateForPaths(alice) error = %v", err)
	}
	writeTemplateStateForRestTest(t, paths, "alice", keyType, templatestore.TemplateTypeGeneric, keytypestate.StateEnabled)

	alice := identity.New(identity.Config{
		ID:            "alice",
		KeyPaths:      paths,
		Authenticator: auth.NewTokenAuthenticator("alice-token"),
	})
	bob := identity.New(identity.Config{
		ID:            "bob",
		KeyPaths:      paths,
		Authenticator: auth.NewTokenAuthenticator("bob-token"),
	})

	aliceResp, svcErr := Service{}.KeyTypesForIdentity(alice)
	if svcErr != nil {
		t.Fatalf("KeyTypesForIdentity(alice) error = %v", svcErr)
	}
	if !keyTypesResponseContains(aliceResp.KeyTypes, keyType) {
		t.Fatalf("KeyTypesForIdentity(alice) did not include installed template %q", keyType)
	}

	bobResp, svcErr := Service{}.KeyTypesForIdentity(bob)
	if svcErr != nil {
		t.Fatalf("KeyTypesForIdentity(bob) error = %v", svcErr)
	}
	if keyTypesResponseContains(bobResp.KeyTypes, keyType) {
		t.Fatalf("KeyTypesForIdentity(bob) included template %q installed only for alice", keyType)
	}
}

func TestServiceKeyTypesForIdentityLifecycleMatrix(t *testing.T) {
	type matrixCase struct {
		name        string
		keyType     string
		setup       func(t *testing.T, paths storepaths.Paths) *identity.Runtime
		wantVisible bool
	}

	tests := []matrixCase{
		{
			name:    "library-only compiled provider is hidden",
			keyType: "aplane.falcon1024_ed25519.v1",
			setup: func(t *testing.T, paths storepaths.Paths) *identity.Runtime {
				t.Helper()
				return restMatrixIdentity(paths, auth.DefaultIdentityID)
			},
		},
		{
			name:    "activated compiled provider is visible",
			keyType: "aplane.falcon1024_ed25519.v1",
			setup: func(t *testing.T, paths storepaths.Paths) *identity.Runtime {
				t.Helper()
				if err := keytypestate.Put(paths, auth.DefaultIdentityID, keytypestate.Record{
					KeyType: "aplane.falcon1024_ed25519.v1",
					Source:  keytypestate.SourceCompiled,
					State:   keytypestate.StateEnabled,
				}); err != nil {
					t.Fatalf("Put() error = %v", err)
				}
				return restMatrixIdentity(paths, auth.DefaultIdentityID)
			},
			wantVisible: true,
		},
		{
			name:    "enabled generic template is visible",
			keyType: "test.generic-rest-matrix-enabled.v1",
			setup: func(t *testing.T, paths storepaths.Paths) *identity.Runtime {
				t.Helper()
				keyType := "test.generic-rest-matrix-enabled.v1"
				yamlData := restGenericMatrixTemplateYAML("generic-rest-matrix-enabled", "Generic Rest Matrix Enabled")
				registerRestGenericTemplateYAML(t, yamlData)
				if _, err := templatestore.SaveTemplateForPaths(paths, auth.DefaultIdentityID, yamlData, keyType, templatestore.TemplateTypeGeneric, restTestMasterKey()); err != nil {
					t.Fatalf("SaveTemplateForPaths() error = %v", err)
				}
				writeTemplateStateForRestTest(t, paths, auth.DefaultIdentityID, keyType, templatestore.TemplateTypeGeneric, keytypestate.StateEnabled)
				return restMatrixIdentity(paths, auth.DefaultIdentityID)
			},
			wantVisible: true,
		},
		{
			name:    "disabled generic template is hidden",
			keyType: "test.generic-rest-matrix-disabled.v1",
			setup: func(t *testing.T, paths storepaths.Paths) *identity.Runtime {
				t.Helper()
				keyType := "test.generic-rest-matrix-disabled.v1"
				yamlData := restGenericMatrixTemplateYAML("generic-rest-matrix-disabled", "Generic Rest Matrix Disabled")
				registerRestGenericTemplateYAML(t, yamlData)
				if _, err := templatestore.SaveTemplateForPaths(paths, auth.DefaultIdentityID, yamlData, keyType, templatestore.TemplateTypeGeneric, restTestMasterKey()); err != nil {
					t.Fatalf("SaveTemplateForPaths() error = %v", err)
				}
				writeTemplateStateForRestTest(t, paths, auth.DefaultIdentityID, keyType, templatestore.TemplateTypeGeneric, keytypestate.StateEnabled)
				if err := keytypestate.SetState(paths, auth.DefaultIdentityID, keyType, keytypestate.StateDisabled); err != nil {
					t.Fatalf("SetState() error = %v", err)
				}
				return restMatrixIdentity(paths, auth.DefaultIdentityID)
			},
		},
		{
			name:    "enabled composed provider is visible",
			keyType: "test.composed-rest-matrix-enabled.v1",
			setup: func(t *testing.T, paths storepaths.Paths) *identity.Runtime {
				t.Helper()
				keyType := "test.composed-rest-matrix-enabled.v1"
				logicsigdsa.RegisterIfAbsent(restTestDSAProvider{keyType: keyType})
				if err := keytypestate.Put(paths, auth.DefaultIdentityID, keytypestate.Record{
					KeyType: keyType,
					Source:  keytypestate.SourceYAMLComposed,
					State:   keytypestate.StateEnabled,
				}); err != nil {
					t.Fatalf("Put() error = %v", err)
				}
				return restMatrixIdentity(paths, auth.DefaultIdentityID)
			},
			wantVisible: true,
		},
		{
			name:    "disabled composed provider is hidden",
			keyType: "test.composed-rest-matrix-disabled.v1",
			setup: func(t *testing.T, paths storepaths.Paths) *identity.Runtime {
				t.Helper()
				keyType := "test.composed-rest-matrix-disabled.v1"
				logicsigdsa.RegisterIfAbsent(restTestDSAProvider{keyType: keyType})
				if err := keytypestate.Put(paths, auth.DefaultIdentityID, keytypestate.Record{
					KeyType: keyType,
					Source:  keytypestate.SourceYAMLComposed,
					State:   keytypestate.StateDisabled,
				}); err != nil {
					t.Fatalf("Put() error = %v", err)
				}
				return restMatrixIdentity(paths, auth.DefaultIdentityID)
			},
		},
		{
			name:    "template installed for another identity is hidden",
			keyType: "test.generic-rest-matrix-other-identity.v1",
			setup: func(t *testing.T, paths storepaths.Paths) *identity.Runtime {
				t.Helper()
				keyType := "test.generic-rest-matrix-other-identity.v1"
				yamlData := restGenericMatrixTemplateYAML("generic-rest-matrix-other-identity", "Generic Rest Matrix Other Identity")
				registerRestGenericTemplateYAML(t, yamlData)
				if _, err := templatestore.SaveTemplateForPaths(paths, "alice", yamlData, keyType, templatestore.TemplateTypeGeneric, restTestMasterKey()); err != nil {
					t.Fatalf("SaveTemplateForPaths(alice) error = %v", err)
				}
				writeTemplateStateForRestTest(t, paths, "alice", keyType, templatestore.TemplateTypeGeneric, keytypestate.StateEnabled)
				return restMatrixIdentity(paths, "bob")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := storepaths.NewPaths(t.TempDir())
			ir := tt.setup(t, paths)

			resp, svcErr := Service{}.KeyTypesForIdentity(ir)
			if svcErr != nil {
				t.Fatalf("KeyTypesForIdentity() error = %v", svcErr)
			}
			if got := keyTypesResponseContains(resp.KeyTypes, tt.keyType); got != tt.wantVisible {
				t.Fatalf("KeyTypesForIdentity() contains %q = %v, want %v", tt.keyType, got, tt.wantVisible)
			}
		})
	}
}

func keyTypesResponseContains(items []signerapi.KeyTypeInfo, keyType string) bool {
	for _, item := range items {
		if item.KeyType == keyType {
			return true
		}
	}
	return false
}

func restMatrixIdentity(paths storepaths.Paths, identityID string) *identity.Runtime {
	return identity.New(identity.Config{
		ID:            identityID,
		KeyPaths:      paths,
		Authenticator: auth.NewTokenAuthenticator(identityID + "-token"),
	})
}

func registerRestGenericTemplateYAML(t *testing.T, yamlData []byte) {
	t.Helper()
	spec, err := generictemplate.ParseTemplateSpec(yamlData)
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	if err := generictemplate.ValidateSpec(spec); err != nil {
		t.Fatalf("ValidateSpec() error = %v", err)
	}
	genericlsig.RegisterIfAbsent(generictemplate.NewYAMLTemplate(spec))
}

func restGenericMatrixTemplateYAML(family, displayName string) []byte {
	return []byte(`schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: ` + family + `
version: 1
display_name: ` + displayName + `
description: Test generic template
parameters: []
runtime_args: []
teal: |
  #pragma version 8
  int 1
  return
`)
}

type restTestDSAProvider struct {
	keyType string
}

func (p restTestDSAProvider) KeyType() string { return p.keyType }
func (p restTestDSAProvider) Family() string {
	return strings.TrimSuffix(p.keyType, "-v1")
}
func (p restTestDSAProvider) Version() int                                { return 1 }
func (p restTestDSAProvider) Category() string                            { return lsigprovider.CategoryDSALsig }
func (p restTestDSAProvider) DisplayName() string                         { return "REST Test DSA" }
func (p restTestDSAProvider) Description() string                         { return "Test provider" }
func (p restTestDSAProvider) DisplayColor() string                        { return "" }
func (p restTestDSAProvider) CreationParams() []lsigprovider.ParameterDef { return nil }
func (p restTestDSAProvider) ValidateCreationParams(map[string]string) error {
	return nil
}
func (p restTestDSAProvider) RuntimeArgs() []lsigprovider.RuntimeArgDef { return nil }
func (p restTestDSAProvider) BuildArgs([]byte, map[string][]byte) ([][]byte, error) {
	return nil, nil
}
func (p restTestDSAProvider) CryptoSignatureSize() int { return 0 }
func (p restTestDSAProvider) MnemonicScheme() string   { return "bip39" }
func (p restTestDSAProvider) MnemonicWordCount() int   { return 24 }
func (p restTestDSAProvider) DeriveLsig(context.Context, []byte, map[string]string) ([]byte, string, error) {
	return nil, "", nil
}

func TestServiceHealthShapesRuntimeState(t *testing.T) {
	locked := setupIdentityRuntime(t, false)
	resp := (Service{}).Health(locked, true, false)
	if resp.Status != "healthy" {
		t.Fatalf("Status = %q, want healthy", resp.Status)
	}
	if !resp.SignerLocked {
		t.Fatal("SignerLocked = false, want true")
	}
	if resp.ReadyForSigning {
		t.Fatal("ReadyForSigning = true, want false")
	}
	if !resp.SSHEnabled || resp.IPCEnabled {
		t.Fatalf("transport flags = %#v, want ssh true ipc false", resp)
	}

	unlocked := setupIdentityRuntime(t, true)
	resp = (Service{}).Health(unlocked, false, true)
	if resp.SignerLocked {
		t.Fatal("SignerLocked = true, want false")
	}
	if !resp.ReadyForSigning {
		t.Fatal("ReadyForSigning = false, want true")
	}
}

func TestServiceHealthDegradedWithoutIdentity(t *testing.T) {
	resp := (Service{}).Health(nil, false, false)
	if resp.Status != "degraded" {
		t.Fatalf("Status = %q, want degraded", resp.Status)
	}
	if resp.ReadyForSigning {
		t.Fatal("ReadyForSigning = true, want false")
	}
}

func TestServiceLockedAndInternalErrors(t *testing.T) {
	locked := setupIdentityRuntime(t, false)
	if _, err := (Service{}).SignGroup(context.Background(), locked, signerapi.GroupSignRequest{}); err == nil || err.HTTPStatus() != 403 {
		t.Fatalf("SignGroup(locked) error = %#v, want forbidden", err)
	}
	if _, err := (Service{}).Keys(locked); err == nil || err.HTTPStatus() != 403 {
		t.Fatalf("Keys(locked) error = %#v, want forbidden", err)
	}

	decommissioned := setupIdentityRuntime(t, true)
	if err := decommissioned.Decommission(); err != nil {
		t.Fatalf("Decommission() error = %v", err)
	}
	if _, err := (Service{}).SignGroup(context.Background(), decommissioned, signerapi.GroupSignRequest{}); err == nil || err.HTTPStatus() != 403 {
		t.Fatalf("SignGroup(decommissioned) error = %#v, want forbidden", err)
	}
	if _, err := (Service{}).Plan(decommissioned, signerapi.GroupSignRequest{}); err == nil || err.HTTPStatus() != 403 {
		t.Fatalf("Plan(decommissioned) error = %#v, want forbidden", err)
	}

	ir := setupIdentityRuntime(t, true)
	svc := Service{
		Deps: Dependencies{
			NewSigningService: func(*identity.Runtime) SigningService {
				return &stubSigningService{
					err: &signersigning.ServiceError{Kind: signersigning.ErrorUnavailable, Message: "no approver"},
				}
			},
		},
	}
	if _, err := svc.SignGroup(context.Background(), ir, signerapi.GroupSignRequest{}); err == nil || err.HTTPStatus() != 503 {
		t.Fatalf("SignGroup(service error) = %#v, want unavailable", err)
	}

	svc = Service{
		Deps: Dependencies{
			KeyAdmin: keyadmin.Service{},
			GenerateGenericLSig: func(context.Context, *identity.Runtime, string, map[string]string) (string, error) {
				return "", errors.New("boom")
			},
		},
	}
	registerRestGenericTemplate(t)
	if err := ir.WithMasterKey(func(mk []byte) error {
		_, saveErr := templatestore.SaveTemplateForPaths(ir.KeyPaths(), ir.ID(), restGenericTemplateYAML(), restGenericErrorKeyType, templatestore.TemplateTypeGeneric, mk)
		return saveErr
	}); err != nil {
		t.Fatalf("SaveTemplateForPaths(rest generic template) error = %v", err)
	}
	writeTemplateStateForRestTest(t, ir.KeyPaths(), ir.ID(), restGenericErrorKeyType, templatestore.TemplateTypeGeneric, keytypestate.StateEnabled)
	status, resp := svc.AdminGenerate(context.Background(), ir, signerapi.AdminGenerateRequest{KeyType: restGenericErrorKeyType})
	if status != 500 || resp.Error != "key generation failed" {
		t.Fatalf("AdminGenerate(internal) = (%d, %#v), want 500 key generation failed", status, resp)
	}
}

func registerRestGenericTemplate(t *testing.T) {
	t.Helper()
	spec := &generictemplate.TemplateSpec{
		BaseTemplateSpec: templatestore.BaseTemplateSpec{
			Publisher:   "test",
			Family:      "generic-rest-error",
			Version:     1,
			DisplayName: "Generic Rest Error",
		},
		TEAL: "#pragma version 8\nint 1\nreturn",
	}
	if err := generictemplate.ValidateSpec(spec); err != nil {
		t.Fatalf("ValidateSpec(rest generic template) error = %v", err)
	}
	genericlsig.RegisterIfAbsent(generictemplate.NewYAMLTemplate(spec))
}

func restGenericTemplateYAML() []byte {
	return []byte(`schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: generic-rest-error
version: 1
display_name: Generic Rest Error
description: Test generic rest template
parameters: []
runtime_args: []
teal: |
  #pragma version 8
  int 1
  return
`)
}
