// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/signerapi"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/witness"

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

func (s cancelAfterGetKeyStore) List(context.Context) ([]keystore.KeyMetadata, error) {
	return nil, nil
}
func (s cancelAfterGetKeyStore) Get(context.Context, string) (*coresigning.KeyMaterial, error) {
	if s.after != nil {
		s.after()
	}
	return s.key, nil
}
func (s cancelAfterGetKeyStore) GetMetadata(context.Context, string) (*keystore.KeyMetadata, error) {
	return nil, nil
}
func (s cancelAfterGetKeyStore) Delete(context.Context, string) error { return nil }
func (s cancelAfterGetKeyStore) WithKeyring(func([]byte) error) error {
	return nil
}
func (s cancelAfterGetKeyStore) Type() string { return "test" }

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
	privateKey := []byte{1, 2, 3}
	keyMaterial := &coresigning.KeyMaterial{
		Type:  "unsupported-v1",
		Value: privateKey,
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
	if keyMaterial.Value != nil {
		t.Fatalf("keyMaterial.Value = %#v, want nil after cleanup", keyMaterial.Value)
	}
	if !bytes.Equal(privateKey, []byte{0, 0, 0}) {
		t.Fatalf("private key bytes = %v, want zeroed", privateKey)
	}
}

func TestExecutorRejectsSentryKeyTypesBeforeSessionLoad(t *testing.T) {
	tests := []struct {
		name    string
		keyType string
	}{
		{name: "Falcon guarded Falcon sentry", keyType: keytypes.GuardedFalcon1024Sentry1024V1},
		{name: "falcon guarded falcon sentry", keyType: keytypes.GuardedFalcon1024Sentry1024V1},
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
				t.Fatal("ExecuteGroupSigning() error = nil, want sentry key type rejection")
				return
			}
			if err.Kind != ErrorBadRequest {
				t.Fatalf("error kind = %q, want %q", err.Kind, ErrorBadRequest)
			}
			if !strings.Contains(err.Message, guardedAccountSignRejectMessage) {
				t.Fatalf("error message = %q, want %q", err.Message, guardedAccountSignRejectMessage)
			}
		})
	}
}

func TestExecutorSignCryptoKeyRejectsSentryKeyTypesBeforeProviderLookup(t *testing.T) {
	tests := []struct {
		name    string
		keyType string
		want    string
	}{
		{name: "ed25519 component", keyType: witness.Falcon1024V1, want: sentryComponentSignRejectMessage},
		{name: "falcon component", keyType: witness.Falcon1024V1, want: sentryComponentSignRejectMessage},
		{name: "guarded Falcon sentry", keyType: keytypes.GuardedFalcon1024Sentry1024V1, want: guardedAccountSignRejectMessage},
		{name: "guarded falcon sentry", keyType: keytypes.GuardedFalcon1024Sentry1024V1, want: guardedAccountSignRejectMessage},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey := []byte{1, 2, 3}
			keyMaterial := &coresigning.KeyMaterial{
				Type:        tt.keyType,
				BaseKeyType: "ed25519",
				Value:       privateKey,
			}

			_, keyType, err := (&Executor{}).signCryptoKey(
				types.Transaction{},
				"AUTHADDR",
				"",
				nil,
				nil,
				keyMaterial,
			)
			if err == nil {
				t.Fatal("signCryptoKey() error = nil, want sentry key type rejection")
				return
			}
			if keyType != tt.keyType {
				t.Fatalf("keyType = %q, want %q", keyType, tt.keyType)
			}
			if err.Kind != ErrorBadRequest {
				t.Fatalf("error kind = %q, want %q", err.Kind, ErrorBadRequest)
			}
			if !strings.Contains(err.Message, tt.want) {
				t.Fatalf("error message = %q, want %q", err.Message, tt.want)
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
	keyType := "test-native-auth-decode"
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
	keyType := "test-unexpected-transaction-authorizer"
	provider := &unexpectedTransactionAuthorizerProvider{
		testNativeSigningProvider: testNativeSigningProvider{family: keyType},
	}
	coresigning.Register(provider)
	privateKey := []byte{1, 2, 3}

	_, gotKeyType, err := (&Executor{}).signCryptoKey(
		types.Transaction{},
		types.Address{1}.String(),
		types.Address{1}.String(),
		nil,
		nil,
		&coresigning.KeyMaterial{Type: keyType, Value: privateKey},
	)
	if err == nil || !strings.Contains(err.Message, "unexpectedly implements structured transaction authorization") {
		t.Fatalf("signCryptoKey() error = %#v, want unexpected transaction authorizer rejection", err)
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

	exec := &Executor{
		DecodeRuntimeArgs: func(lsigArgs map[string]string) (map[string][]byte, error) {
			return map[string][]byte{}, nil
		},
	}

	_, gotKeyType, err := exec.signGenericLSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		nil,
		&coresigning.KeyMaterial{
			Type:                   keyType,
			Category:               keys.CategoryGenericLsig,
			Bytecode:               []byte{1},
			SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
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

	exec := &Executor{
		DecodeRuntimeArgs: func(lsigArgs map[string]string) (map[string][]byte, error) {
			return nil, fmt.Errorf("arg secret: invalid hex")
		},
	}

	_, gotKeyType, err := exec.signGenericLSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		map[string]string{"secret": "xyz"},
		&coresigning.KeyMaterial{
			Type:                   keyType,
			Category:               keys.CategoryGenericLsig,
			Bytecode:               []byte{1},
			SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
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
	if err.Message != "arg secret: invalid hex" {
		t.Fatalf("error message = %q, want runtime arg decode failure", err.Message)
	}
}

func TestExecutorSignGenericLSigRejectsMissingSigningMetadata(t *testing.T) {
	keyType := "test-generic-missing-signing-metadata-v1"

	exec := &Executor{
		DecodeRuntimeArgs: func(lsigArgs map[string]string) (map[string][]byte, error) {
			return map[string][]byte{}, nil
		},
	}

	_, gotKeyType, err := exec.signGenericLSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		nil,
		&coresigning.KeyMaterial{
			Type:     keyType,
			Category: keys.CategoryGenericLsig,
			Bytecode: []byte{1},
		},
	)
	if err == nil {
		t.Fatal("signGenericLSig() error = nil, want missing signing metadata rejection")
		return
	}
	if gotKeyType != keyType {
		t.Fatalf("keyType = %q, want %q", gotKeyType, keyType)
	}
	if err.Kind != ErrorInternal {
		t.Fatalf("error kind = %q, want %q", err.Kind, ErrorInternal)
	}
	want := "logic sig key " + keyType + " is missing signing metadata; regenerate the key or restore from a current-format backup"
	if err.Message != want {
		t.Fatalf("error message = %q, want %q", err.Message, want)
	}
}

func TestExecutorSignGenericLSigUsesStoredSigningArgsWithoutProvider(t *testing.T) {
	keyType := "test-standalone-generic-runtime-v1"

	exec := &Executor{
		DecodeRuntimeArgs: func(lsigArgs map[string]string) (map[string][]byte, error) {
			return map[string][]byte{}, nil
		},
	}

	_, gotKeyType, err := exec.signGenericLSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		nil,
		&coresigning.KeyMaterial{
			Type:                   keyType,
			Category:               keys.CategoryGenericLsig,
			Bytecode:               []byte{1},
			SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
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

	exec := &Executor{
		DecodeRuntimeArgs: func(lsigArgs map[string]string) (map[string][]byte, error) {
			return map[string][]byte{
				"first":  {0x01},
				"second": {0x02},
			}, nil
		},
	}

	signedBytes, gotKeyType, err := exec.signGenericLSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		map[string]string{"first": "ignored", "second": "ignored"},
		&coresigning.KeyMaterial{
			Type:                   keyType,
			Category:               keys.CategoryGenericLsig,
			Bytecode:               append([]byte(nil), testApprovalProgram...),
			SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
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

	exec := &Executor{
		DecodeRuntimeArgs: func(lsigArgs map[string]string) (map[string][]byte, error) {
			return map[string][]byte{"stored": {0x7a}}, nil
		},
	}

	signedBytes, gotKeyType, err := exec.signGenericLSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		map[string]string{"stored": "ignored"},
		&coresigning.KeyMaterial{
			Type:                   keyType,
			Category:               keys.CategoryGenericLsig,
			Bytecode:               append([]byte(nil), testApprovalProgram...),
			SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
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

	exec := &Executor{
		DecodeRuntimeArgs: func(lsigArgs map[string]string) (map[string][]byte, error) {
			return map[string][]byte{}, nil
		},
	}

	_, gotKeyType, err := exec.assembleDSALogicSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		nil,
		nil,
		&coresigning.KeyMaterial{
			Type:                   keyType,
			Category:               keys.CategoryDSALsig,
			BaseKeyType:            baseKeyType,
			Bytecode:               []byte{1},
			SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
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

func TestExecutorAssembleDSALogicSigRejectsMissingSigningMetadata(t *testing.T) {
	keyType := "test-dsa-missing-signing-metadata-v1"

	exec := &Executor{
		DecodeRuntimeArgs: func(lsigArgs map[string]string) (map[string][]byte, error) {
			return map[string][]byte{}, nil
		},
	}

	_, gotKeyType, err := exec.assembleDSALogicSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		nil,
		nil,
		&coresigning.KeyMaterial{
			Type:     keyType,
			Category: keys.CategoryDSALsig,
			Bytecode: []byte{1},
		},
		[]byte{1, 2, 3},
		keyType,
	)
	if err == nil {
		t.Fatal("assembleDSALogicSig() error = nil, want missing signing metadata rejection")
		return
	}
	if gotKeyType != keyType {
		t.Fatalf("keyType = %q, want %q", gotKeyType, keyType)
	}
	if err.Kind != ErrorInternal {
		t.Fatalf("error kind = %q, want %q", err.Kind, ErrorInternal)
	}
	want := "logic sig key " + keyType + " is missing signing metadata; regenerate the key or restore from a current-format backup"
	if err.Message != want {
		t.Fatalf("error message = %q, want %q", err.Message, want)
	}
}

func TestExecutorAssembleDSALogicSigUsesStoredSigningArgsWithoutComposedProvider(t *testing.T) {
	baseKeyType := "test-standalone-base-dsa-v1"
	keyType := "test-standalone-composed-dsa-v1"
	lsigprovider.RegisterIfAbsent(&testBaseSignatureProvider{
		keyType: baseKeyType,
		family:  "test-standalone-base-dsa",
	})

	exec := &Executor{
		DecodeRuntimeArgs: func(lsigArgs map[string]string) (map[string][]byte, error) {
			return map[string][]byte{}, nil
		},
	}

	_, gotKeyType, err := exec.assembleDSALogicSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		nil,
		nil,
		&coresigning.KeyMaterial{
			Type:                   keyType,
			Category:               keys.CategoryDSALsig,
			BaseKeyType:            baseKeyType,
			Bytecode:               []byte{1},
			SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
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

	exec := &Executor{
		DecodeRuntimeArgs: func(lsigArgs map[string]string) (map[string][]byte, error) {
			return map[string][]byte{
				"alpha": {0x0a},
				"beta":  {0x0b},
			}, nil
		},
	}
	signature := []byte{0x99, 0x88}

	signedBytes, gotKeyType, err := exec.assembleDSALogicSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		map[string]string{"alpha": "ignored", "beta": "ignored"},
		nil,
		&coresigning.KeyMaterial{
			Type:                   keyType,
			Category:               keys.CategoryDSALsig,
			BaseKeyType:            baseKeyType,
			Bytecode:               append([]byte(nil), testApprovalProgram...),
			SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
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
		&boundedPlanItem{Path: boundedPathSpendingKeyRekey, Metadata: testBoundedMetadata(t, boundedmeta.AdminAuthorizationSpend)},
		&coresigning.KeyMaterial{
			Type:                   keyType,
			Category:               keys.CategoryDSALsig,
			BaseKeyType:            baseKeyType,
			Bytecode:               append([]byte(nil), testApprovalProgram...),
			SigningMetadataVersion: keys.BoundedSigningMetadataVersion,
			BoundedAuthorization:   testBoundedMetadata(t, boundedmeta.AdminAuthorizationSpend),
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
	snapshot := PlannerIdentitySnapshot{
		KeyMetadata: map[string]PlannerKeyMetadata{authAddr: {
			PublicKeyHex:         "aabb",
			BoundedAuthorization: testBoundedMetadata(t, boundedmeta.AdminAuthorizationSpend),
		}},
	}
	requests := []signerapi.SignRequest{{
		AuthAddress: authAddr,
		TxnBytesHex: "00",
		LsigArgs:    map[string]string{"admin_signature": "00"},
	}}

	_, err := resolveBoundedPlanItems(snapshot, requests, []types.Transaction{testBoundedPayment()}, map[int]bool{}, map[int]bool{})
	if err == nil || err.Kind != ErrorBadRequest || !strings.Contains(err.Message, "not a declared runtime slot") {
		t.Fatalf("resolveBoundedPlanItems() error = %#v, want caller-args rejection", err)
	}
}

func TestResolveBoundedPlanItemsAcceptsDeclaredRuntimeArgs(t *testing.T) {
	authAddr := types.Address{1}.String()
	metadata := testBoundedMetadata(t, "")
	metadata.RuntimeArgs = []boundedmeta.RuntimeArg{{Name: "preimage", Type: "bytes", Required: true, ByteLength: 2, MaxSize: 2}}
	metadata.ArgumentLayout = append(metadata.ArgumentLayout, boundedmeta.ArgumentSlot{
		Index: 1, Name: "preimage", Source: boundedmeta.ArgSourceRuntime, MaxSize: 2,
		Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: boundedmeta.ArgForbidden, AdminRekey: boundedmeta.ArgForbidden},
	})
	if err := metadata.Validate(); err != nil {
		t.Fatalf("runtime metadata invalid: %v", err)
	}
	snapshot := PlannerIdentitySnapshot{KeyMetadata: map[string]PlannerKeyMetadata{authAddr: {
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

func TestAssembleBoundedArgsPreservesInteriorEmptySlots(t *testing.T) {
	metadata := &boundedmeta.Metadata{ArgumentLayout: []boundedmeta.ArgumentSlot{
		{Index: 0, Name: "base_signature_0", Source: boundedmeta.ArgSourceBaseSignature, MaxSize: 4, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired}},
		{Index: 1, Name: "proof", Source: boundedmeta.ArgSourceDerived, MaxSize: boundedmeta.MerkleProofSize, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgOptional}},
		{Index: 2, Name: "preimage", Source: boundedmeta.ArgSourceRuntime, MaxSize: 4, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired}},
		{Index: 3, Name: "admin_signature", Source: boundedmeta.ArgSourceAdmin, MaxSize: boundedmeta.FalconAdminSignatureSize, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgForbidden}},
	}}
	item := &boundedPlanItem{Path: boundedPathPureSpend, RuntimeArgs: map[string][]byte{"preimage": {0xaa}}}
	args, err := assembleBoundedArgs(metadata, item, [][]byte{{0x99}}, [][]byte{nil})
	if err != nil {
		t.Fatalf("assembleBoundedArgs() error = %v", err)
	}
	if len(args) != 3 || !bytes.Equal(args[0], []byte{0x99}) || args[1] == nil || len(args[1]) != 0 || !bytes.Equal(args[2], []byte{0xaa}) {
		t.Fatalf("assembled args = %#v, want base/empty/runtime with trailing admin omitted", args)
	}
}

// TestVerifyBoundedPlanIntegrity pins the executor's single bounded recheck:
// the loaded key must still match the planned classification.
func TestVerifyBoundedPlanIntegrity(t *testing.T) {
	metadata := testBoundedMetadata(t, boundedmeta.AdminAuthorizationSpend)
	item := &boundedPlanItem{Path: boundedPathSpendingKeyRekey, Metadata: boundedmeta.Clone(metadata)}
	loaded := &coresigning.KeyMaterial{
		SigningMetadataVersion: keys.BoundedSigningMetadataVersion,
		BoundedAuthorization:   boundedmeta.Clone(metadata),
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

	wrongVersion := &coresigning.KeyMaterial{
		SigningMetadataVersion: keys.BoundedSigningMetadataVersion - 1,
		BoundedAuthorization:   boundedmeta.Clone(metadata),
	}
	if err := verifyBoundedPlanIntegrity(item, wrongVersion); err == nil || err.Kind != ErrorInternal {
		t.Fatalf("wrong signing metadata version: error = %#v, want internal", err)
	}

	drifted := boundedmeta.Clone(metadata)
	drifted.MaxFee--
	changed := &coresigning.KeyMaterial{
		SigningMetadataVersion: keys.BoundedSigningMetadataVersion,
		BoundedAuthorization:   drifted,
	}
	if err := verifyBoundedPlanIntegrity(item, changed); err == nil || err.Kind != ErrorInternal {
		t.Fatalf("metadata drift: error = %#v, want internal", err)
	}
}

// TestExecutorSignCryptoKeyRejectsAdminRekeyFromPlanItem pins the executor's
// defense-in-depth admin-path check, driven by the plan item rather than a
// re-derived classification.
func TestExecutorSignCryptoKeyRejectsAdminRekeyFromPlanItem(t *testing.T) {
	metadata := testBoundedMetadata(t, boundedmeta.AdminAuthorizationAdmin)
	item := &boundedPlanItem{Path: boundedPathAdminKeyRekey, Metadata: boundedmeta.Clone(metadata)}
	keyMaterial := &coresigning.KeyMaterial{
		Type:                   "test-bounded-admin-reject-v1",
		Category:               keys.CategoryDSALsig,
		SigningMetadataVersion: keys.BoundedSigningMetadataVersion,
		BoundedAuthorization:   boundedmeta.Clone(metadata),
	}

	_, _, err := (&Executor{}).signCryptoKey(
		testBoundedRekey(),
		types.Address{1}.String(),
		types.Address{1}.String(),
		nil,
		item,
		keyMaterial,
	)
	if err == nil || err.Kind != ErrorBoundedAdminRequired {
		t.Fatalf("signCryptoKey() error = %#v, want bounded_admin_required", err)
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

	exec := &Executor{
		DecodeRuntimeArgs: func(lsigArgs map[string]string) (map[string][]byte, error) {
			return map[string][]byte{"stored": {0x55}}, nil
		},
	}
	signature := []byte{0x99, 0x88}

	signedBytes, gotKeyType, err := exec.assembleDSALogicSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		map[string]string{"stored": "ignored"},
		nil,
		&coresigning.KeyMaterial{
			Type:                   keyType,
			Category:               keys.CategoryDSALsig,
			BaseKeyType:            baseKeyType,
			Bytecode:               append([]byte(nil), testApprovalProgram...),
			SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
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

	exec := &Executor{
		DecodeRuntimeArgs: func(lsigArgs map[string]string) (map[string][]byte, error) {
			return map[string][]byte{}, nil
		},
	}

	_, gotKeyType, err := exec.assembleDSALogicSig(
		types.Transaction{},
		"AUTHADDR",
		"",
		nil,
		nil,
		&coresigning.KeyMaterial{
			Type:                   keyType,
			Category:               keys.CategoryDSALsig,
			BaseKeyType:            baseKeyType,
			Bytecode:               []byte{0x06, 0x81, 0x01},
			SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
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
