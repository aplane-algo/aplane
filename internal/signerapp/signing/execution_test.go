// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

type testBaseSignatureProvider struct {
	keyType string
	family  string
}

func (p *testBaseSignatureProvider) KeyType() string       { return p.keyType }
func (p *testBaseSignatureProvider) RoutingFamily() string { return p.family }
func (p *testBaseSignatureProvider) Version() int          { return 1 }
func (p *testBaseSignatureProvider) Category() string      { return lsigprovider.CategoryDSALsig }
func (p *testBaseSignatureProvider) DisplayName() string   { return p.keyType }
func (p *testBaseSignatureProvider) Description() string   { return "" }
func (p *testBaseSignatureProvider) DisplayColor() string  { return "" }
func (p *testBaseSignatureProvider) CreationParams() []lsigprovider.ParameterDef {
	return nil
}
func (p *testBaseSignatureProvider) ValidateCreationParams(map[string]string) error {
	return nil
}
func (p *testBaseSignatureProvider) RuntimeArgs() []lsigprovider.RuntimeArgDef {
	return nil
}
func (p *testBaseSignatureProvider) BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error) {
	if signature == nil {
		return nil, fmt.Errorf("signature required")
	}
	return [][]byte{signature}, nil
}

type testNativeSigningProvider struct {
	family string
}

func (p *testNativeSigningProvider) RoutingFamily() string { return p.family }
func (p *testNativeSigningProvider) LoadKeyMaterial(_ coresigning.ProviderKey) (*coresigning.KeyMaterial, error) {
	return nil, fmt.Errorf("not implemented")
}
func (p *testNativeSigningProvider) SignMessage(key *coresigning.KeyMaterial, message []byte) ([]byte, error) {
	return bytes.Repeat([]byte{0x11}, 64), nil
}
func (p *testNativeSigningProvider) ZeroKey(key *coresigning.KeyMaterial) {
	if key == nil {
		return
	}
	if privateKey, ok := key.Value.([]byte); ok {
		for i := range privateKey {
			privateKey[i] = 0
		}
	}
	key.Type = ""
	key.Value = nil
}

type unexpectedTransactionAuthorizerProvider struct {
	testNativeSigningProvider
	called bool
}

func (p *unexpectedTransactionAuthorizerProvider) AuthorizeTransaction(_ *coresigning.KeyMaterial, txn types.Transaction, _ types.Address) (types.SignedTxn, error) {
	p.called = true
	return types.SignedTxn{Txn: txn}, nil
}

var testApprovalProgram = []byte{0x06, 0x81, 0x01}

type cancelAfterGetKeyStore struct {
	key   *coresigning.KeyMaterial
	after func()
}

func (s cancelAfterGetKeyStore) Get(context.Context, string) (*coresigning.KeyMaterial, error) {
	if s.after != nil {
		s.after()
	}
	return s.key, nil
}

func TestExecutorExecuteGroupSigningHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	exec := &Executor{}
	_, err := exec.ExecuteGroupSigning(ctx, &PlanResult{
		AllTxns:            []types.Transaction{{}},
		PassthroughIndices: map[int]bool{},
		ForeignIndices:     map[int]bool{},
	}, signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{AuthAddress: "AUTHADDR"}},
	}, nil)
	if err == nil {
		t.Fatal("ExecuteGroupSigning() error = nil, want cancellation")
		return
	}
	if err.Kind != ErrorUnavailable {
		t.Fatalf("error kind = %q, want %q", err.Kind, ErrorUnavailable)
	}
	if err.Message != "sign request canceled: context canceled" {
		t.Fatalf("error message = %q, want context canceled", err.Message)
	}
}

func TestExecutorSignSingleTransactionZeroesKeyAfterPostLoadCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	privateKey := []byte{1, 2, 3}
	keyMaterial := &coresigning.KeyMaterial{
		Type:  "unsupported-v1",
		Value: privateKey,
	}
	session := keystore.NewKeySession(cancelAfterGetKeyStore{
		key:   keyMaterial,
		after: cancel,
	})
	session.InitializeSession()

	exec := &Executor{}
	_, _, err := exec.signSingleTransaction(types.Transaction{}, "AUTHADDR", "", nil, nil, session, ctx)
	if err == nil {
		t.Fatal("signSingleTransaction() error = nil, want cancellation")
		return
	}
	if err.Kind != ErrorUnavailable {
		t.Fatalf("error kind = %q, want %q", err.Kind, ErrorUnavailable)
	}
	if privateKey[0] != 0 || privateKey[1] != 0 || privateKey[2] != 0 {
		t.Fatalf("private key bytes = %v, want zeroed", privateKey)
	}
	if keyMaterial.Value != nil || keyMaterial.Type != "" {
		t.Fatalf("key material after cancel = %#v, want cleared wrapper", keyMaterial)
	}
}

func TestExecutorSignCryptoKeyRejectsUnsupportedKeyType(t *testing.T) {
	exec := &Executor{}
	keyMaterial := &coresigning.KeyMaterial{
		Type:  "unsupported-v1",
		Value: []byte{1, 2, 3},
	}

	_, keyType, err := exec.signCryptoKey(
		types.Transaction{},
		"AUTHADDR",
		"",
		nil,
		nil,
		keyMaterial,
	)
	if err == nil {
		t.Fatal("signCryptoKey() error = nil, want unsupported key type")
		return
	}
	if keyType != "unsupported-v1" {
		t.Fatalf("keyType = %q, want unsupported-v1", keyType)
	}
	if err.Kind != ErrorInternal {
		t.Fatalf("error kind = %q, want %q", err.Kind, ErrorInternal)
	}
	if err.Message != "unsupported key type: unsupported-v1" {
		t.Fatalf("error message = %q, want unsupported key type message", err.Message)
	}
	// signSingleTransaction zeroes the key it loaded on this exit
	// (TestExecutorSignSingleTransactionZeroesTheLoadedKeyOnEveryExit).
}

func TestExecutorRejectsCosignerKeyTypesBeforeSessionLoad(t *testing.T) {
	tests := []struct {
		name    string
		keyType string
	}{
		{name: "Falcon witness key", keyType: witness.Falcon1024V1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := &Executor{}
			plan := &PlanResult{
				AllTxns:            []types.Transaction{{}},
				PassthroughIndices: map[int]bool{},
				ForeignIndices:     map[int]bool{},
				AuthKeyTypes:       []string{tt.keyType},
			}
			req := signerapi.GroupSignRequest{
				Requests: []signerapi.SignRequest{{
					AuthAddress: "AUTHADDR",
					TxnBytesHex: "deadbeef",
				}},
			}

			_, err := exec.ExecuteGroupSigning(context.Background(), plan, req, nil)
			if err == nil {
				t.Fatal("ExecuteGroupSigning() error = nil, want cosigner key type rejection")
				return
			}
			if err.Kind != ErrorBadRequest {
				t.Fatalf("error kind = %q, want %q", err.Kind, ErrorBadRequest)
			}
			if !strings.Contains(err.Message, cosignerComponentSignRejectMessage) {
				t.Fatalf("error message = %q, want %q", err.Message, cosignerComponentSignRejectMessage)
			}
		})
	}
}

// A key that loads as a witness key is refused before any provider is
// looked up, and zeroed.
func TestExecutorSignSingleTransactionRejectsLoadedCosignerKeyTypes(t *testing.T) {
	for _, keyType := range []string{witness.Falcon1024V1, witness.Ed25519V1} {
		t.Run(keyType, func(t *testing.T) {
			privateKey := []byte{1, 2, 3}
			keyMaterial := &coresigning.KeyMaterial{
				Type:        keyType,
				BaseKeyType: "ed25519",
				Value:       privateKey,
			}
			session := keystore.NewKeySession(cancelAfterGetKeyStore{key: keyMaterial})
			session.InitializeSession()

			_, gotKeyType, err := (&Executor{}).signSingleTransaction(types.Transaction{}, "AUTHADDR", "", nil, nil, session, context.Background())
			if err == nil {
				t.Fatal("signSingleTransaction() error = nil, want cosigner key type rejection")
				return
			}
			if gotKeyType != keyType {
				t.Fatalf("keyType = %q, want %q", gotKeyType, keyType)
			}
			if err.Kind != ErrorBadRequest {
				t.Fatalf("error kind = %q, want %q", err.Kind, ErrorBadRequest)
			}
			if !strings.Contains(err.Message, cosignerComponentSignRejectMessage) {
				t.Fatalf("error message = %q, want %q", err.Message, cosignerComponentSignRejectMessage)
			}
			if keyMaterial.Value != nil {
				t.Fatalf("keyMaterial.Value = %#v, want nil after cleanup", keyMaterial.Value)
			}
			if !bytes.Equal(privateKey, []byte{0, 0, 0}) {
				t.Fatalf("private key bytes = %v, want zeroed", privateKey)
			}
		})
	}
}

func TestExecutorSignCryptoKeyRejectsInvalidAuthAddress(t *testing.T) {
	keyType := uniqueSigningTestFamily("test-native-auth-decode")
	coresigning.Register(&testNativeSigningProvider{family: keyType})
	exec := &Executor{}

	_, gotKeyType, err := exec.signCryptoKey(
		types.Transaction{},
		"not-an-address",
		types.Address{1}.String(),
		nil,
		nil,
		&coresigning.KeyMaterial{
			Type:  keyType,
			Value: []byte{1},
		},
	)
	if err == nil {
		t.Fatal("signCryptoKey() error = nil, want invalid auth address")
		return
	}
	if gotKeyType != keyType {
		t.Fatalf("keyType = %q, want %q", gotKeyType, keyType)
	}
	if err.Kind != ErrorBadRequest {
		t.Fatalf("error kind = %q, want %q", err.Kind, ErrorBadRequest)
	}
	if !strings.Contains(err.Message, "invalid auth address") {
		t.Fatalf("error message = %q, want invalid auth address", err.Message)
	}
}

func TestExecutorRejectsUnexpectedTransactionAuthorizerBeforeInvocation(t *testing.T) {
	keyType := uniqueSigningTestFamily("test-unexpected-transaction-authorizer")
	provider := &unexpectedTransactionAuthorizerProvider{
		testNativeSigningProvider: testNativeSigningProvider{family: keyType},
	}
	coresigning.Register(provider)
	privateKey := []byte{1, 2, 3}
	session := keystore.NewKeySession(cancelAfterGetKeyStore{key: &coresigning.KeyMaterial{Type: keyType, Value: privateKey}})
	session.InitializeSession()

	_, gotKeyType, err := (&Executor{}).signSingleTransaction(
		types.Transaction{},
		types.Address{1}.String(),
		types.Address{1}.String(),
		nil,
		nil,
		session,
		context.Background(),
	)
	if err == nil || !strings.Contains(err.Message, "unexpectedly implements structured transaction authorization") {
		t.Fatalf("signSingleTransaction() error = %#v, want unexpected transaction authorizer rejection", err)
	}
	if gotKeyType != keyType {
		t.Fatalf("keyType = %q, want %q", gotKeyType, keyType)
	}
	if provider.called {
		t.Fatal("unexpected transaction authorizer was invoked before its key type was rejected")
	}
	if !bytes.Equal(privateKey, []byte{0, 0, 0}) {
		t.Fatalf("private key bytes = %v, want zeroed", privateKey)
	}
}

func TestExecutorSignGenericLSigRejectsMissingRequiredRuntimeArg(t *testing.T) {
	keyType := "test-required-runtime-v1"

	exec := &Executor{}

	_, gotKeyType, err := exec.signGenericLSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		nil,
		&coresigning.KeyMaterial{
			Type:     keyType,
			Category: keys.CategoryGenericLsig,
			Bytecode: []byte{1},
			SigningArgs: []lsigprovider.RuntimeArgDef{{
				Name:     "secret",
				Type:     "bytes",
				Required: true,
			}},
		},
	)
	if err == nil {
		t.Fatal("signGenericLSig() error = nil, want missing runtime arg rejection")
		return
	}
	if gotKeyType != keyType {
		t.Fatalf("keyType = %q, want %q", gotKeyType, keyType)
	}
	if err.Kind != ErrorBadRequest {
		t.Fatalf("error kind = %q, want %q", err.Kind, ErrorBadRequest)
	}
	if err.Message != "missing required arg: secret" {
		t.Fatalf("error message = %q, want missing required arg", err.Message)
	}
}

func TestExecutorSignGenericLSigRejectsMalformedRuntimeArgs(t *testing.T) {
	keyType := "test-malformed-runtime-v1"

	exec := &Executor{}

	_, gotKeyType, err := exec.signGenericLSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		map[string]string{"secret": "xyz"},
		&coresigning.KeyMaterial{
			Type:     keyType,
			Category: keys.CategoryGenericLsig,
			Bytecode: []byte{1},
			SigningArgs: []lsigprovider.RuntimeArgDef{{
				Name:     "secret",
				Type:     "bytes",
				Required: true,
			}},
		},
	)
	if err == nil {
		t.Fatal("signGenericLSig() error = nil, want runtime arg decode rejection")
		return
	}
	if gotKeyType != keyType {
		t.Fatalf("keyType = %q, want %q", gotKeyType, keyType)
	}
	if err.Kind != ErrorBadRequest {
		t.Fatalf("error kind = %q, want %q", err.Kind, ErrorBadRequest)
	}
	if err.Message != "invalid hex for arg secret: encoding/hex: invalid byte: U+0078 'x'" {
		t.Fatalf("error message = %q, want runtime arg decode failure", err.Message)
	}
}

func TestExecutorSignGenericLSigUsesStoredSigningArgsWithoutProvider(t *testing.T) {
	keyType := "test-standalone-generic-runtime-v1"

	exec := &Executor{}

	_, gotKeyType, err := exec.signGenericLSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		nil,
		&coresigning.KeyMaterial{
			Type:     keyType,
			Category: keys.CategoryGenericLsig,
			Bytecode: []byte{1},
			SigningArgs: []lsigprovider.RuntimeArgDef{{
				Name:     "secret",
				Type:     "bytes",
				Required: true,
			}},
		},
	)
	if err == nil {
		t.Fatal("signGenericLSig() error = nil, want missing runtime arg rejection")
		return
	}
	if gotKeyType != keyType {
		t.Fatalf("keyType = %q, want %q", gotKeyType, keyType)
	}
	if err.Kind != ErrorBadRequest {
		t.Fatalf("error kind = %q, want %q", err.Kind, ErrorBadRequest)
	}
	if err.Message != "missing required arg: secret" {
		t.Fatalf("error message = %q, want missing required secret", err.Message)
	}
}

func TestExecutorSignGenericLSigOrdersStoredSigningArgsOnSuccess(t *testing.T) {
	keyType := "test-standalone-generic-runtime-success-v1"

	exec := &Executor{}

	signedBytes, gotKeyType, err := exec.signGenericLSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		map[string]string{"first": "01", "second": "02"},
		&coresigning.KeyMaterial{
			Type:     keyType,
			Category: keys.CategoryGenericLsig,
			Bytecode: append([]byte(nil), testApprovalProgram...),
			SigningArgs: []lsigprovider.RuntimeArgDef{
				{Name: "second", Type: "bytes", Required: true},
				{Name: "first", Type: "bytes", Required: true},
			},
		},
	)
	if err != nil {
		t.Fatalf("signGenericLSig() error = %v", err)
	}
	if gotKeyType != keyType {
		t.Fatalf("keyType = %q, want %q", gotKeyType, keyType)
	}
	assertLogicSigArgs(t, signedBytes, [][]byte{{0x02}, {0x01}})
}

func TestExecutorSignGenericLSigIgnoresLiveTemplateMetadata(t *testing.T) {
	keyType := "test-standalone-generic-live-metadata-v1"
	lsigprovider.RegisterIfAbsent(&testTemplateMetadataProvider{
		keyType: keyType,
		runtimeArgs: []lsigprovider.RuntimeArgDef{{
			Name:     "live",
			Type:     "bytes",
			Required: true,
		}},
	})

	exec := &Executor{}

	signedBytes, gotKeyType, err := exec.signGenericLSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		map[string]string{"stored": "7a"},
		&coresigning.KeyMaterial{
			Type:     keyType,
			Category: keys.CategoryGenericLsig,
			Bytecode: append([]byte(nil), testApprovalProgram...),
			SigningArgs: []lsigprovider.RuntimeArgDef{{
				Name:     "stored",
				Type:     "bytes",
				Required: true,
			}},
		},
	)
	if err != nil {
		t.Fatalf("signGenericLSig() error = %v", err)
	}
	if gotKeyType != keyType {
		t.Fatalf("keyType = %q, want %q", gotKeyType, keyType)
	}
	assertLogicSigArgs(t, signedBytes, [][]byte{{0x7a}})
}

func TestExecutorAssembleDSALogicSigRejectsMissingRequiredRuntimeArg(t *testing.T) {
	baseKeyType := "test-dsa-required-runtime-base-v1"
	keyType := "test-dsa-required-runtime-composed-v1"
	lsigprovider.RegisterIfAbsent(&testBaseSignatureProvider{
		keyType: baseKeyType,
		family:  "test-dsa-required-runtime-base",
	})

	exec := &Executor{}

	_, gotKeyType, err := exec.assembleDSALogicSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		nil,
		nil,
		&coresigning.KeyMaterial{
			Type:        keyType,
			Category:    keys.CategoryDSALsig,
			BaseKeyType: baseKeyType,
			Bytecode:    []byte{1},
			SigningArgs: []lsigprovider.RuntimeArgDef{{
				Name:     "secret",
				Type:     "bytes",
				Required: true,
			}},
		},
		[]byte{1, 2, 3},
		keyType,
	)
	if err == nil {
		t.Fatal("assembleDSALogicSig() error = nil, want missing runtime arg rejection")
		return
	}
	if gotKeyType != keyType {
		t.Fatalf("keyType = %q, want %q", gotKeyType, keyType)
	}
	if err.Kind != ErrorBadRequest {
		t.Fatalf("error kind = %q, want %q", err.Kind, ErrorBadRequest)
	}
	if err.Message != "missing required arg: secret" {
		t.Fatalf("error message = %q, want missing required secret", err.Message)
	}
}

func TestExecutorAssembleDSALogicSigUsesStoredSigningArgsWithoutComposedProvider(t *testing.T) {
	baseKeyType := "test-standalone-base-dsa-v1"
	keyType := "test-standalone-composed-dsa-v1"
	lsigprovider.RegisterIfAbsent(&testBaseSignatureProvider{
		keyType: baseKeyType,
		family:  "test-standalone-base-dsa",
	})

	exec := &Executor{}

	_, gotKeyType, err := exec.assembleDSALogicSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		nil,
		nil,
		&coresigning.KeyMaterial{
			Type:        keyType,
			Category:    keys.CategoryDSALsig,
			BaseKeyType: baseKeyType,
			Bytecode:    []byte{1},
			SigningArgs: []lsigprovider.RuntimeArgDef{{
				Name:     "secret",
				Type:     "bytes",
				Required: true,
			}},
		},
		[]byte{1, 2, 3},
		keyType,
	)
	if err == nil {
		t.Fatal("assembleDSALogicSig() error = nil, want missing runtime arg rejection")
		return
	}
	if gotKeyType != keyType {
		t.Fatalf("keyType = %q, want %q", gotKeyType, keyType)
	}
	if err.Kind != ErrorBadRequest {
		t.Fatalf("error kind = %q, want %q", err.Kind, ErrorBadRequest)
	}
	if err.Message != "missing required arg: secret" {
		t.Fatalf("error message = %q, want missing required secret", err.Message)
	}
}

func TestExecutorAssembleDSALogicSigOrdersStoredSigningArgsOnSuccess(t *testing.T) {
	baseKeyType := "test-standalone-base-dsa-success-v1"
	keyType := "test-standalone-composed-dsa-success-v1"
	lsigprovider.RegisterIfAbsent(&testBaseSignatureProvider{
		keyType: baseKeyType,
		family:  "test-standalone-base-dsa-success",
	})

	exec := &Executor{}
	signature := []byte{0x99, 0x88}

	signedBytes, gotKeyType, err := exec.assembleDSALogicSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		map[string]string{"alpha": "0a", "beta": "0b"},
		nil,
		&coresigning.KeyMaterial{
			Type:        keyType,
			Category:    keys.CategoryDSALsig,
			BaseKeyType: baseKeyType,
			Bytecode:    append([]byte(nil), testApprovalProgram...),
			SigningArgs: []lsigprovider.RuntimeArgDef{
				{Name: "beta", Type: "bytes", Required: true},
				{Name: "alpha", Type: "bytes", Required: true},
			},
		},
		signature,
		keyType,
	)
	if err != nil {
		t.Fatalf("assembleDSALogicSig() error = %v", err)
	}
	if gotKeyType != keyType {
		t.Fatalf("keyType = %q, want %q", gotKeyType, keyType)
	}
	assertLogicSigArgs(t, signedBytes, [][]byte{signature, {0x0b}, {0x0a}})
}

func TestExecutorAssembleBoundedSpendingRekeyUsesExactBaseArgs(t *testing.T) {
	baseKeyType := "test-bounded-base-dsa-v1"
	keyType := "test-bounded-composed-dsa-v1"
	lsigprovider.RegisterIfAbsent(&testBaseSignatureProvider{keyType: baseKeyType, family: baseKeyType})
	signature := []byte{0x99, 0x88}

	signedBytes, gotKeyType, err := (&Executor{}).assembleDSALogicSig(
		testBoundedRekey(),
		types.Address{1}.String(),
		types.Address{1}.String(),
		nil,
		&boundedPlanItem{Path: boundedPathSpendingKeyRekey, Metadata: testBoundedMetadata(t, boundedmeta.RekeySpendingKey)},
		&coresigning.KeyMaterial{
			Type:                 keyType,
			Category:             keys.CategoryDSALsig,
			BaseKeyType:          baseKeyType,
			Bytecode:             append([]byte(nil), testApprovalProgram...),
			BoundedAuthorization: testBoundedMetadata(t, boundedmeta.RekeySpendingKey),
		},
		signature,
		keyType,
	)
	if err != nil {
		t.Fatalf("assembleDSALogicSig() error = %v", err)
	}
	if gotKeyType != keyType {
		t.Fatalf("keyType = %q, want %q", gotKeyType, keyType)
	}
	assertLogicSigArgs(t, signedBytes, [][]byte{signature})
}

// TestResolveBoundedPlanItemsRejectsUndeclaredCallerArgs pins the caller-owned
// slot boundary; the executor consumes only runtime args accepted into the plan.
func TestResolveBoundedPlanItemsRejectsUndeclaredCallerArgs(t *testing.T) {
	authAddr := types.Address{1}.String()
	snapshot := PlannerRuntimeSnapshot{
		KeyMetadata: map[string]PlannerKeyMetadata{authAddr: {
			PublicKeyHex:         "aabb",
			BoundedAuthorization: testBoundedMetadata(t, boundedmeta.RekeySpendingKey),
		}},
	}
	requests := []signerapi.SignRequest{{
		AuthAddress: authAddr,
		TxnBytesHex: "00",
		LsigArgs:    map[string]string{"base_signature_0": "00"},
	}}

	_, err := resolveBoundedPlanItems(snapshot, requests, []types.Transaction{testBoundedPayment()}, map[int]bool{}, map[int]bool{})
	if err == nil || err.Kind != ErrorBadRequest || !strings.Contains(err.Message, "not a declared runtime slot") {
		t.Fatalf("resolveBoundedPlanItems() error = %#v, want caller-args rejection", err)
	}
}

func TestResolveBoundedPlanItemsAcceptsDeclaredRuntimeArgs(t *testing.T) {
	authAddr := types.Address{1}.String()
	metadata := testBoundedMetadata(t, boundedmeta.RekeyRefused)
	metadata.RuntimeArgs = []boundedmeta.RuntimeArg{{Name: "preimage", Type: "bytes", Required: true, ByteLength: 2, MaxSize: 2}}
	metadata.ArgumentLayout = append(metadata.ArgumentLayout, boundedmeta.ArgumentSlot{
		Index: 1, Name: "preimage", Source: boundedmeta.ArgSourceRuntime, MaxSize: 2,
		Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: boundedmeta.ArgForbidden, ListedRekey: boundedmeta.ArgForbidden},
	})
	if err := metadata.Validate(); err != nil {
		t.Fatalf("runtime metadata invalid: %v", err)
	}
	snapshot := PlannerRuntimeSnapshot{KeyMetadata: map[string]PlannerKeyMetadata{authAddr: {
		PublicKeyHex: "aabb", BoundedAuthorization: metadata,
	}}}
	requests := []signerapi.SignRequest{{AuthAddress: authAddr, LsigArgs: map[string]string{"preimage": "aabb"}}}
	items, err := resolveBoundedPlanItems(snapshot, requests, []types.Transaction{testBoundedPayment()}, map[int]bool{}, map[int]bool{})
	if err != nil {
		t.Fatalf("resolveBoundedPlanItems() error = %v", err)
	}
	if len(items) != 1 || items[0] == nil || !bytes.Equal(items[0].RuntimeArgs["preimage"], []byte{0xaa, 0xbb}) {
		t.Fatalf("planned runtime args = %#v", items)
	}

	requests[0].LsigArgs = nil
	if _, err := resolveBoundedPlanItems(snapshot, requests, []types.Transaction{testBoundedPayment()}, map[int]bool{}, map[int]bool{}); err == nil || !strings.Contains(err.Message, "missing required") {
		t.Fatalf("missing runtime arg error = %#v", err)
	}
}

// An account stored before the network's argument limit was enforced can declare
// a runtime argument maximum above it. It still loads, and signing refuses a
// supplied value the network would refuse. Only a supplied value is checked, so
// a rekey, which carries no runtime argument, is unaffected.
func TestResolveBoundedPlanItemsCapsASuppliedRuntimeArgAtTheNetworkLimit(t *testing.T) {
	authAddr := types.Address{1}.String()
	metadata := testBoundedMetadata(t, boundedmeta.RekeySpendingKey)
	metadata.RuntimeArgs = []boundedmeta.RuntimeArg{{Name: "blob", Type: "bytes", Required: true, MaxSize: 5000}}
	metadata.ArgumentLayout = append(metadata.ArgumentLayout, boundedmeta.ArgumentSlot{
		Index: 1, Name: "blob", Source: boundedmeta.ArgSourceRuntime, MaxSize: 5000,
		Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: boundedmeta.ArgForbidden, ListedRekey: boundedmeta.ArgForbidden},
	})
	// Durable validation, which a stored key gets on load, accepts it. The
	// generation-time check does not, so the metadata is built by hand.
	if err := metadata.Validate(); err != nil {
		t.Fatalf("stored metadata invalid: %v", err)
	}
	if err := metadata.ValidateNetworkLimits(); err == nil || !strings.Contains(err.Error(), "(blob) is 5000 bytes: a LogicSig argument is at most 4096") {
		t.Fatalf("ValidateNetworkLimits() error = %v, want the fixture past the limit", err)
	}
	snapshot := PlannerRuntimeSnapshot{KeyMetadata: map[string]PlannerKeyMetadata{authAddr: {
		PublicKeyHex: "aabb", BoundedAuthorization: metadata,
	}}}
	resolve := func(txn types.Transaction, lsigArgs map[string]string) ([]*boundedPlanItem, *ServiceError) {
		return resolveBoundedPlanItems(snapshot, []signerapi.SignRequest{{AuthAddress: authAddr, LsigArgs: lsigArgs}},
			[]types.Transaction{txn}, map[int]bool{}, map[int]bool{})
	}
	blob := func(size int) map[string]string {
		return map[string]string{"blob": hex.EncodeToString(bytes.Repeat([]byte{0xab}, size))}
	}

	// One byte past the network's limit, inside the account's own maximum.
	_, err := resolve(testBoundedPayment(), blob(lsigresource.MaxLogicSigArgBytes+1))
	if err == nil || err.Kind != ErrorBadRequest ||
		!strings.Contains(err.Message, `bounded runtime argument "blob" is 4097 bytes, and a LogicSig argument is at most 4096`) {
		t.Fatalf("4097-byte argument: error = %#v, want the network limit refusal", err)
	}
	// At the limit.
	items, err := resolve(testBoundedPayment(), blob(lsigresource.MaxLogicSigArgBytes))
	if err != nil {
		t.Fatalf("4096-byte argument: error = %v", err)
	}
	if len(items) != 1 || items[0] == nil || items[0].Path != boundedPathPureSpend || len(items[0].RuntimeArgs["blob"]) != lsigresource.MaxLogicSigArgBytes {
		t.Fatalf("4096-byte argument: planned items = %#v", items)
	}
	// Past the account's own maximum, the account's refusal comes first.
	if _, err := resolve(testBoundedPayment(), blob(5001)); err == nil || !strings.Contains(err.Message, "exceeds 5000-byte maximum") {
		t.Fatalf("5001-byte argument: error = %#v, want the account's own maximum", err)
	}
	// A rekey omits the argument, so the oversized declaration doesn't stop it.
	items, err = resolve(testBoundedRekey(), nil)
	if err != nil {
		t.Fatalf("rekey without the argument: error = %v", err)
	}
	if len(items) != 1 || items[0] == nil || items[0].Path != boundedPathSpendingKeyRekey || len(items[0].RuntimeArgs) != 0 {
		t.Fatalf("rekey without the argument: planned items = %#v", items)
	}
}

func TestAssembleBoundedArgsPreservesInteriorEmptySlots(t *testing.T) {
	metadata := &boundedmeta.Metadata{ArgumentLayout: []boundedmeta.ArgumentSlot{
		{Index: 0, Name: "base_signature_0", Source: boundedmeta.ArgSourceBaseSignature, MaxSize: 4, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired}},
		{Index: 1, Name: "proof", Source: boundedmeta.ArgSourceDerived, MaxSize: boundedmeta.MerkleProofSize, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgOptional}},
		{Index: 2, Name: "preimage", Source: boundedmeta.ArgSourceRuntime, MaxSize: 4, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired}},
		{Index: 3, Name: "memo", Source: boundedmeta.ArgSourceRuntime, MaxSize: 4, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgOptional}},
	}}
	item := &boundedPlanItem{Path: boundedPathPureSpend, RuntimeArgs: map[string][]byte{"preimage": {0xaa}}}
	args, err := assembleBoundedArgs(metadata, item, [][]byte{{0x99}}, map[string][]byte{"proof": nil})
	if err != nil {
		t.Fatalf("assembleBoundedArgs() error = %v", err)
	}
	if len(args) != 3 || !bytes.Equal(args[0], []byte{0x99}) || args[1] == nil || len(args[1]) != 0 || !bytes.Equal(args[2], []byte{0xaa}) {
		t.Fatalf("assembled args = %#v, want base/empty/runtime with the trailing empty slot omitted", args)
	}
}

// Each derived value goes to the layout slot of its own name, whatever order
// the metadata declares the derived arguments in.
func TestAssembleBoundedArgsPlacesDerivedArgsByName(t *testing.T) {
	listed := boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgOptional, SpendingRekey: boundedmeta.ArgOptional, ListedRekey: boundedmeta.ArgOptional}
	metadata := &boundedmeta.Metadata{
		DerivedArgs: []boundedmeta.DerivedArg{{Name: "first"}, {Name: "second"}},
		ArgumentLayout: []boundedmeta.ArgumentSlot{
			{Index: 0, Name: "base_signature_0", Source: boundedmeta.ArgSourceBaseSignature, MaxSize: 4, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired}},
			{Index: 1, Name: "second", Source: boundedmeta.ArgSourceDerived, MaxSize: 4, Paths: listed},
			{Index: 2, Name: "first", Source: boundedmeta.ArgSourceDerived, MaxSize: 4, Paths: listed},
		},
	}
	item := &boundedPlanItem{Path: boundedPathPureSpend}
	args, err := assembleBoundedArgs(metadata, item, [][]byte{{0x99}}, map[string][]byte{"first": {0x01}, "second": {0x02}})
	if err != nil {
		t.Fatalf("assembleBoundedArgs() error = %v", err)
	}
	if len(args) != 3 || !bytes.Equal(args[1], []byte{0x02}) || !bytes.Equal(args[2], []byte{0x01}) {
		t.Fatalf("assembled args = %x, want second's value in slot 1 and first's in slot 2", args)
	}

	if _, err := assembleBoundedArgs(metadata, item, [][]byte{{0x99}}, map[string][]byte{"first": {0x01}}); err == nil || !strings.Contains(err.Message, `bounded derived slot "second" has no derived argument`) {
		t.Fatalf("slot without a derived value: error = %+v", err)
	}
	if _, err := assembleBoundedArgs(metadata, item, [][]byte{{0x99}}, map[string][]byte{"first": {0x01}, "second": {0x02}, "third": nil}); err == nil || !strings.Contains(err.Message, "not fully consumed") {
		t.Fatalf("derived value without a slot: error = %+v", err)
	}
}

// TestVerifyBoundedPlanIntegrity pins the executor's single bounded recheck:
// the loaded key must still match the planned classification.
func TestVerifyBoundedPlanIntegrity(t *testing.T) {
	metadata := testBoundedMetadata(t, boundedmeta.RekeySpendingKey)
	item := &boundedPlanItem{Path: boundedPathSpendingKeyRekey, Metadata: boundedmeta.Clone(metadata)}
	loaded := &coresigning.KeyMaterial{
		BoundedAuthorization: boundedmeta.Clone(metadata),
	}

	if err := verifyBoundedPlanIntegrity(item, loaded); err != nil {
		t.Fatalf("matching metadata: unexpected error %v", err)
	}
	if err := verifyBoundedPlanIntegrity(nil, &coresigning.KeyMaterial{}); err != nil {
		t.Fatalf("plain key without plan item: unexpected error %v", err)
	}

	if err := verifyBoundedPlanIntegrity(nil, loaded); err == nil || err.Kind != ErrorInternal {
		t.Fatalf("key gained bounded metadata: error = %#v, want internal", err)
	}
	if err := verifyBoundedPlanIntegrity(item, &coresigning.KeyMaterial{}); err == nil || err.Kind != ErrorInternal {
		t.Fatalf("key lost bounded metadata: error = %#v, want internal", err)
	}

	drifted := boundedmeta.Clone(metadata)
	drifted.MaxFee = new(*drifted.MaxFee - 1)
	changed := &coresigning.KeyMaterial{
		BoundedAuthorization: drifted,
	}
	if err := verifyBoundedPlanIntegrity(item, changed); err == nil || err.Kind != ErrorInternal {
		t.Fatalf("metadata drift: error = %#v, want internal", err)
	}

	rekeyChanged := boundedmeta.Clone(metadata)
	rekeyChanged.Rekey = boundedmeta.RekeyRefused
	if err := verifyBoundedPlanIntegrity(item, &coresigning.KeyMaterial{
		BoundedAuthorization: rekeyChanged,
	}); err == nil || err.Kind != ErrorInternal {
		t.Fatalf("rekey setting drift: error = %#v, want internal", err)
	}
}

func TestExecutorAssembleDSALogicSigIgnoresLiveComposedProviderMetadata(t *testing.T) {
	baseKeyType := "test-standalone-base-dsa-live-metadata-v1"
	keyType := "test-standalone-composed-dsa-live-metadata-v1"
	lsigprovider.RegisterIfAbsent(&testBaseSignatureProvider{
		keyType: baseKeyType,
		family:  "test-standalone-base-dsa-live-metadata",
	})
	lsigprovider.RegisterIfAbsent(&testTemplateMetadataProvider{
		keyType: keyType,
		runtimeArgs: []lsigprovider.RuntimeArgDef{{
			Name:     "live",
			Type:     "bytes",
			Required: true,
		}},
	})

	exec := &Executor{}
	signature := []byte{0x99, 0x88}

	signedBytes, gotKeyType, err := exec.assembleDSALogicSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		map[string]string{"stored": "55"},
		nil,
		&coresigning.KeyMaterial{
			Type:        keyType,
			Category:    keys.CategoryDSALsig,
			BaseKeyType: baseKeyType,
			Bytecode:    append([]byte(nil), testApprovalProgram...),
			SigningArgs: []lsigprovider.RuntimeArgDef{{
				Name:     "stored",
				Type:     "bytes",
				Required: true,
			}},
		},
		signature,
		keyType,
	)
	if err != nil {
		t.Fatalf("assembleDSALogicSig() error = %v", err)
	}
	if gotKeyType != keyType {
		t.Fatalf("keyType = %q, want %q", gotKeyType, keyType)
	}
	assertLogicSigArgs(t, signedBytes, [][]byte{signature, {0x55}})
}

func TestExecutorAssembleDSALogicSigRejectsMissingStoredBaseProvider(t *testing.T) {
	baseKeyType := "test-missing-base-dsa-v1"
	keyType := "test-missing-base-composed-dsa-v1"
	lsigprovider.RegisterIfAbsent(&testBaseSignatureProvider{
		keyType: keyType,
		family:  "test-missing-base-composed-dsa",
	})

	exec := &Executor{}

	_, gotKeyType, err := exec.assembleDSALogicSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		nil,
		nil,
		&coresigning.KeyMaterial{
			Type:        keyType,
			Category:    keys.CategoryDSALsig,
			BaseKeyType: baseKeyType,
			Bytecode:    []byte{0x06, 0x81, 0x01},
		},
		[]byte{1, 2, 3},
		keyType,
	)
	if err == nil {
		t.Fatal("assembleDSALogicSig() error = nil, want missing base provider rejection")
		return
	}
	if gotKeyType != keyType {
		t.Fatalf("keyType = %q, want %q", gotKeyType, keyType)
	}
	if err.Kind != ErrorInternal {
		t.Fatalf("error kind = %q, want %q", err.Kind, ErrorInternal)
	}
	want := "provider not found for base key type " + baseKeyType
	if err.Message != want {
		t.Fatalf("error message = %q, want %q", err.Message, want)
	}
}

type testTemplateMetadataProvider struct {
	keyType     string
	runtimeArgs []lsigprovider.RuntimeArgDef
}

func (p *testTemplateMetadataProvider) KeyType() string                             { return p.keyType }
func (p *testTemplateMetadataProvider) RoutingFamily() string                       { return p.keyType }
func (p *testTemplateMetadataProvider) Version() int                                { return 1 }
func (p *testTemplateMetadataProvider) Category() string                            { return lsigprovider.CategoryGenericLsig }
func (p *testTemplateMetadataProvider) DisplayName() string                         { return p.keyType }
func (p *testTemplateMetadataProvider) Description() string                         { return "live metadata should be ignored" }
func (p *testTemplateMetadataProvider) DisplayColor() string                        { return "" }
func (p *testTemplateMetadataProvider) CreationParams() []lsigprovider.ParameterDef { return nil }
func (p *testTemplateMetadataProvider) ValidateCreationParams(map[string]string) error {
	return nil
}
func (p *testTemplateMetadataProvider) RuntimeArgs() []lsigprovider.RuntimeArgDef {
	return p.runtimeArgs
}
func (p *testTemplateMetadataProvider) BuildArgs(signature []byte, _ map[string][]byte) ([][]byte, error) {
	return [][]byte{append([]byte("live:"), signature...)}, nil
}
func (p *testTemplateMetadataProvider) CompatibilityFingerprint() string {
	return "live-fingerprint"
}

func assertLogicSigArgs(t *testing.T, signedBytes []byte, want [][]byte) {
	t.Helper()
	var stxn types.SignedTxn
	if err := msgpack.Decode(signedBytes, &stxn); err != nil {
		t.Fatalf("signed txn msgpack decode error = %v", err)
	}
	if !bytes.Equal(stxn.Lsig.Logic, testApprovalProgram) {
		t.Fatalf("LogicSig logic = %x, want %x", stxn.Lsig.Logic, testApprovalProgram)
	}
	if len(stxn.Lsig.Args) != len(want) {
		t.Fatalf("LogicSig arg count = %d, want %d (%x)", len(stxn.Lsig.Args), len(want), stxn.Lsig.Args)
	}
	for i := range want {
		if !bytes.Equal(stxn.Lsig.Args[i], want[i]) {
			t.Fatalf("LogicSig arg %d = %x, want %x", i, stxn.Lsig.Args[i], want[i])
		}
	}
}

// Every way out of signSingleTransaction after the key loads zeroes the
// loaded key, the refusals before signing and the signatures alike, and
// returns the loaded key's type.
func TestExecutorSignSingleTransactionZeroesTheLoadedKeyOnEveryExit(t *testing.T) {
	nativeType := uniqueSigningTestFamily("test-native-zeroing")
	coresigning.Register(&testNativeSigningProvider{family: nativeType})
	baseType := uniqueSigningTestFamily("test-dsa-zeroing-base")
	coresigning.Register(&testNativeSigningProvider{family: baseType})
	lsigprovider.RegisterIfAbsent(&testBaseSignatureProvider{keyType: baseType, family: baseType})
	cosigned := boundedCosignerTestMetadata(t, bytes.Repeat([]byte{0x52}, boundedmeta.DefaultCosignerPublicKeySize))
	sender := types.Address{1}.String()
	txn := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{1}, Fee: 1_000, FirstValid: 1, LastValid: 2}}

	cases := []struct {
		name    string
		key     func(private []byte) *coresigning.KeyMaterial
		item    *boundedPlanItem
		wantErr string
		want    func(t *testing.T, signed []byte)
	}{
		{name: "witness key", wantErr: cosignerComponentSignRejectMessage,
			key: func(private []byte) *coresigning.KeyMaterial {
				return &coresigning.KeyMaterial{Type: witness.Falcon1024V1, Value: private}
			}},
		{name: "rotating key", wantErr: "rotating",
			key: func(private []byte) *coresigning.KeyMaterial {
				return &coresigning.KeyMaterial{Type: rotatingkey.RotatingTripleSlhdsaV1, Value: private}
			}},
		{name: "bounded metadata the plan lacks", wantErr: "key gained bounded metadata after planning",
			key: func(private []byte) *coresigning.KeyMaterial {
				return &coresigning.KeyMaterial{Type: nativeType, Value: private, BoundedAuthorization: boundedmeta.Clone(cosigned)}
			}},
		{name: "cosigned bounded account", item: &boundedPlanItem{Path: boundedPathPureSpend, Metadata: boundedmeta.Clone(cosigned)}, wantErr: "cosign",
			key: func(private []byte) *coresigning.KeyMaterial {
				return &coresigning.KeyMaterial{Type: nativeType, Value: private, BoundedAuthorization: boundedmeta.Clone(cosigned)}
			}},
		{name: "unsupported key type", wantErr: "unsupported key type: test-unsupported-zeroing-v1",
			key: func(private []byte) *coresigning.KeyMaterial {
				return &coresigning.KeyMaterial{Type: "test-unsupported-zeroing-v1", Value: private}
			}},
		{name: "native signature",
			key: func(private []byte) *coresigning.KeyMaterial {
				return &coresigning.KeyMaterial{Type: nativeType, Value: private}
			},
			want: func(t *testing.T, signed []byte) {
				var sig types.Signature
				copy(sig[:], bytes.Repeat([]byte{0x11}, 64))
				if !bytes.Equal(signed, msgpack.Encode(types.SignedTxn{Txn: txn, Sig: sig})) {
					t.Fatal("native signed bytes differ from the transaction with its signature")
				}
			}},
		{name: "DSA LogicSig signature",
			key: func(private []byte) *coresigning.KeyMaterial {
				return &coresigning.KeyMaterial{
					Type: "test-dsa-zeroing-v1", BaseKeyType: baseType, Category: keys.CategoryDSALsig, Value: private,
					Bytecode: append([]byte(nil), testApprovalProgram...),
				}
			},
			want: func(t *testing.T, signed []byte) {
				assertLogicSigArgs(t, signed, [][]byte{bytes.Repeat([]byte{0x11}, 64)})
			}},
		{name: "generic LogicSig",
			key: func(private []byte) *coresigning.KeyMaterial {
				return &coresigning.KeyMaterial{
					Type: "test-generic-zeroing-v1", Category: keys.CategoryGenericLsig, Value: private,
					Bytecode: append([]byte(nil), testApprovalProgram...),
				}
			},
			want: func(t *testing.T, signed []byte) {
				assertLogicSigArgs(t, signed, nil)
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			private := []byte{1, 2, 3}
			key := tc.key(private)
			wantType, bytecode := key.Type, key.Bytecode
			session := keystore.NewKeySession(cancelAfterGetKeyStore{key: key})
			session.InitializeSession()

			signed, keyType, err := (&Executor{}).signSingleTransaction(txn, sender, sender, nil, tc.item, session, context.Background())
			if keyType != wantType {
				t.Fatalf("keyType = %q, want the loaded key's %q", keyType, wantType)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Message, tc.wantErr) {
					t.Fatalf("err = %#v, want %q", err, tc.wantErr)
				}
			} else {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				tc.want(t, signed)
			}
			if !bytes.Equal(private, []byte{0, 0, 0}) {
				t.Fatalf("private key bytes = %v, want zeroed", private)
			}
			if len(bytecode) > 0 && !bytes.Equal(bytecode, make([]byte, len(bytecode))) {
				t.Fatalf("bytecode = %x, want zeroed", bytecode)
			}
		})
	}
}

// Both bounded paths check base signature arguments against the stored
// layout with the same rule and the same text.
func TestCheckBaseSignatureLayout(t *testing.T) {
	layout := boundedmeta.SignatureArgLayout{Count: 2, MaxSizes: []int{3, 2}}
	cases := []struct {
		args [][]byte
		want string
	}{
		{[][]byte{{1}, {2}}, ""},
		{[][]byte{{1, 2, 3}, {4, 5}}, ""},
		{[][]byte{{1}}, "base provider emitted 1 signature args, stored bounded layout requires 2"},
		{[][]byte{{1}, {}}, "base signature arg 1 length 0 violates stored bounded maximum 2"},
		{[][]byte{{1, 2, 3, 4}, {1}}, "base signature arg 0 length 4 violates stored bounded maximum 3"},
	}
	for _, tc := range cases {
		err := checkBaseSignatureLayout(layout, tc.args)
		if tc.want == "" {
			if err != nil {
				t.Fatalf("checkBaseSignatureLayout(%v) = %v, want nil", tc.args, err)
			}
			continue
		}
		if err == nil || err.Kind != ErrorInternal || err.Message != tc.want {
			t.Fatalf("checkBaseSignatureLayout(%v) = %#v, want internal %q", tc.args, err, tc.want)
		}
	}
}
