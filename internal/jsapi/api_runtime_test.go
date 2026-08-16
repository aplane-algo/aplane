// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	algoCrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/dop251/goja"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func jsonResponse(req *http.Request, status int, payload any) (*http.Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}, nil
}

type stubPluginExecutor struct {
	success      bool
	message      string
	data         interface{}
	presentation interface{}
	err          error
	last         struct {
		name string
		args []string
	}
}

func (s *stubPluginExecutor) ExecutePlugin(name string, args []string) (bool, string, interface{}, interface{}, error) {
	s.last.name = name
	s.last.args = append([]string(nil), args...)
	return s.success, s.message, s.data, s.presentation, s.err
}

func newTestAPI(t *testing.T) (*engine.Engine, *goja.Runtime, *API) {
	t.Helper()

	eng := newTempStoreEngine(t)
	vm := goja.New()
	api := NewAPI(eng, false, nil)
	if err := api.RegisterAll(vm); err != nil {
		t.Fatalf("RegisterAll() error = %v", err)
	}

	return eng, vm, api
}

func newTempStoreEngine(t *testing.T) *engine.Engine {
	t.Helper()

	cacheStore := cache.NewStore(t.TempDir())
	eng, err := engine.NewEngine("testnet",
		engine.WithCacheStore(cacheStore),
		engine.WithAliasCache(cache.LoadAliasCacheFromStore(cacheStore)),
		engine.WithSetCache(cache.LoadSetCacheFromStore(cacheStore)),
		engine.WithSignerCache(cache.LoadSignerCacheFromStore(cacheStore)),
		engine.WithAuthCache(cache.LoadAuthCacheFromStore(cacheStore, "testnet")),
	)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return eng
}

func TestRegisterAllExposesCoreFunctions(t *testing.T) {
	_, vm, _ := newTestAPI(t)

	functions := []string{
		"algo", "microalgos", "print", "log", "network", "status", "connected",
		"plugin", "balance", "accounts", "alias", "createSet", "assetInfo",
		"appCall", "send", "close", "sign", "plan", "keyTypes",
		"generateKey", "deleteKey", "atomicSend",
	}

	for _, name := range functions {
		t.Run(name, func(t *testing.T) {
			value := vm.Get(name)
			if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
				t.Fatalf("%s was not registered", name)
			}
			if _, ok := goja.AssertFunction(value); !ok {
				t.Fatalf("%s is not a JS function", name)
			}
		})
	}
}

func TestPrintLogAndModeHelpers(t *testing.T) {
	eng, _, api := newTestAPI(t)

	var output []string
	api.output = func(msg string) {
		output = append(output, msg)
	}

	api.jsPrint(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue("hello"), api.runtime.ToValue(7)}})
	if got := strings.Join(output, "\n"); !strings.Contains(got, "hello7") {
		t.Fatalf("print output = %q, want concatenated message", got)
	}

	api.jsLog(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue("hidden")}})
	if len(output) != 1 {
		t.Fatalf("log output count = %d, want 1 while verbose disabled", len(output))
	}

	api.jsSetVerbose(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue(true)}})
	api.jsLog(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue("visible")}})
	if got := output[len(output)-1]; got != "[debug] visible" {
		t.Fatalf("verbose log output = %q, want debug prefix", got)
	}
	if !eng.Verbose {
		t.Fatal("engine verbose flag was not enabled")
	}

	api.jsSetWriteMode(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue(true)}})
	if !eng.GetWriteMode() {
		t.Fatal("write mode was not enabled")
	}
	if got := api.jsWriteMode(goja.FunctionCall{}).Export(); got != true {
		t.Fatalf("writeMode() = %v, want true", got)
	}

	api.jsSetSimulate(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue(true)}})
	if !eng.GetSimulate() {
		t.Fatal("simulate mode was not enabled")
	}
	if got := api.jsSimulate(goja.FunctionCall{}).Export(); got != true {
		t.Fatalf("simulate() = %v, want true", got)
	}
}

func TestPluginExecutionPaths(t *testing.T) {
	_, _, api := newTestAPI(t)

	t.Run("missing executor", func(t *testing.T) {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic")
			}
			if got := r.(goja.Value).String(); !strings.Contains(got, "no plugin executor configured") {
				t.Fatalf("panic = %q, want plugin executor error", got)
			}
		}()
		api.jsPlugin(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue("echo")}})
	})

	t.Run("success", func(t *testing.T) {
		exec := &stubPluginExecutor{
			success:      true,
			message:      "ok",
			data:         map[string]interface{}{"value": float64(3)},
			presentation: map[string]interface{}{"title": "Echo"},
		}
		api.SetPluginExecutor(exec)

		got := api.jsPlugin(goja.FunctionCall{Arguments: []goja.Value{
			api.runtime.ToValue("echo"),
			api.runtime.ToValue("a"),
			api.runtime.ToValue("b"),
		}}).Export().(map[string]interface{})

		if exec.last.name != "echo" {
			t.Fatalf("plugin name = %q, want echo", exec.last.name)
		}
		if strings.Join(exec.last.args, ",") != "a,b" {
			t.Fatalf("plugin args = %v, want [a b]", exec.last.args)
		}
		if got["success"] != true || got["message"] != "ok" {
			t.Fatalf("plugin result = %#v, want success payload", got)
		}
		if presentation, ok := got["presentation"].(map[string]interface{}); !ok || presentation["title"] != "Echo" {
			t.Fatalf("plugin presentation = %#v, want Echo title", got["presentation"])
		}
	})

	t.Run("executor error", func(t *testing.T) {
		api.SetPluginExecutor(&stubPluginExecutor{err: errors.New("boom")})
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic")
			}
			if got := r.(goja.Value).String(); !strings.Contains(got, "plugin() error: boom") {
				t.Fatalf("panic = %q, want wrapped plugin error", got)
			}
		}()
		api.jsPlugin(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue("echo")}})
	})
}

func TestPluginExecutorCanBeSwappedConcurrently(t *testing.T) {
	_, _, api := newTestAPI(t)

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			api.SetPluginExecutor(&stubPluginExecutor{success: true, message: "ok"})
		}()
		go func() {
			defer wg.Done()
			_ = api.getPluginExecutor()
		}()
	}
	wg.Wait()
}

func TestAccountAliasSetAndSignerHelpers(t *testing.T) {
	eng, _, api := newTestAPI(t)

	addr1 := algoCrypto.GenerateAccount().Address.String()
	addr2 := algoCrypto.GenerateAccount().Address.String()

	added := api.jsAddAlias(goja.FunctionCall{Arguments: []goja.Value{
		api.runtime.ToValue("alice"),
		api.runtime.ToValue(addr1),
	}}).Export().(map[string]interface{})
	if added["created"] != true {
		t.Fatalf("addAlias created = %v, want true", added["created"])
	}
	if got := api.jsAlias(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue("alice")}}).Export(); got != addr1 {
		t.Fatalf("alias() = %v, want %s", got, addr1)
	}

	aliases := api.jsAliases(goja.FunctionCall{}).Export().(map[string]interface{})
	if aliases["alice"] != addr1 {
		t.Fatalf("aliases() = %#v, want alice alias", aliases)
	}

	createdSet := api.jsCreateSet(goja.FunctionCall{Arguments: []goja.Value{
		api.runtime.ToValue("crew"),
		api.runtime.ToValue([]string{addr1}),
	}}).Export().(map[string]interface{})
	if got := toUint64Value(api.runtime, createdSet["count"]); got != 1 {
		t.Fatalf("createSet count = %v, want 1", createdSet["count"])
	}

	api.jsAddToSet(goja.FunctionCall{Arguments: []goja.Value{
		api.runtime.ToValue("crew"),
		api.runtime.ToValue([]string{addr2}),
	}})
	setValues := api.jsSet(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue("crew")}}).Export().([]interface{})
	if len(setValues) != 2 {
		t.Fatalf("set() len = %d, want 2", len(setValues))
	}

	api.jsRemoveFromSet(goja.FunctionCall{Arguments: []goja.Value{
		api.runtime.ToValue("crew"),
		api.runtime.ToValue([]string{addr2}),
	}})
	setNames := api.jsSets(goja.FunctionCall{}).Export().([]interface{})
	if len(setNames) != 1 || setNames[0] != "crew" {
		t.Fatalf("sets() = %#v, want crew", setNames)
	}

	deleted := api.jsDeleteSet(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue("crew")}}).Export().(map[string]interface{})
	if got := toUint64Value(api.runtime, deleted["deleted"]); got != 1 {
		t.Fatalf("deleteSet deleted = %v, want 1", deleted["deleted"])
	}

	if got := api.jsSigners(goja.FunctionCall{}).Export().(map[string]interface{}); len(got) != 0 {
		t.Fatalf("signers() = %#v, want empty map", got)
	}
	filtered := api.jsSigners(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue([]string{addr1, addr2})}}).Export().([]interface{})
	if len(filtered) != 0 {
		t.Fatalf("signers(filter) = %#v, want empty list", filtered)
	}

	if got := api.jsSignableAddresses(goja.FunctionCall{}).Export().([]interface{}); len(got) != 0 {
		t.Fatalf("signableAddresses() = %#v, want empty list", got)
	}

	if got := api.jsSet(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue("missing")}}); !goja.IsNull(got) {
		t.Fatal("missing set should return null")
	}

	if got := api.jsAlias(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue("missing")}}); !goja.IsNull(got) {
		t.Fatal("missing alias should return null")
	}

	eng.SignerCache.Keys = map[string]string{addr1: "ed25519"}
	accounts := api.jsAccounts(goja.FunctionCall{}).Export().([]interface{})
	if len(accounts) != 1 {
		t.Fatalf("accounts() len = %d, want 1", len(accounts))
	}
}

func TestJSAliasAndAccountHelpersMatchMCPProjectionSemantics(t *testing.T) {
	eng, _, api := newTestAPI(t)

	addr := algoCrypto.GenerateAccount().Address.String()
	api.jsAddAlias(goja.FunctionCall{Arguments: []goja.Value{
		api.runtime.ToValue("alice"),
		api.runtime.ToValue(addr),
	}})
	eng.SignerCache.Keys = map[string]string{addr: "ed25519"}

	jsAliases := api.jsAliases(goja.FunctionCall{}).Export().(map[string]interface{})
	if jsAliases["alice"] != addr {
		t.Fatalf("aliases() = %#v, want alice -> %s", jsAliases, addr)
	}

	aliasList := eng.ListAliases()
	mcpAliasInput := make([]appresult.AliasView, len(aliasList.Aliases))
	for i, alias := range aliasList.Aliases {
		mcpAliasInput[i] = appresult.AliasView{
			Name:       alias.Name,
			Address:    alias.Address,
			IsSignable: alias.IsSignable,
			KeyType:    alias.KeyType,
		}
	}
	mcpAliases := appresult.AliasesToMCP(mcpAliasInput)
	if len(mcpAliases) != 1 {
		t.Fatalf("len(mcpAliases) = %d, want 1", len(mcpAliases))
	}
	if mcpAliases[0].Name != "alice" || mcpAliases[0].Address != addr {
		t.Fatalf("mcpAliases[0] = %#v, want alice/%s", mcpAliases[0], addr)
	}

	jsAccounts := api.jsAccounts(goja.FunctionCall{}).Export().([]interface{})
	if len(jsAccounts) != 1 {
		t.Fatalf("accounts() len = %d, want 1", len(jsAccounts))
	}
	jsAccount := jsAccounts[0].(map[string]interface{})
	if jsAccount["address"] != addr {
		t.Fatalf("accounts()[0].address = %#v, want %s", jsAccount["address"], addr)
	}
	if jsAccount["alias"] != "alice" {
		t.Fatalf("accounts()[0].alias = %#v, want alice", jsAccount["alias"])
	}
	if jsAccount["keyType"] != "ed25519" {
		t.Fatalf("accounts()[0].keyType = %#v, want ed25519", jsAccount["keyType"])
	}
	if jsAccount["isSignable"] != true {
		t.Fatalf("accounts()[0].isSignable = %#v, want true", jsAccount["isSignable"])
	}

	accounts, err := eng.ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts() error = %v", err)
	}
	mcpAccountInput := make([]appresult.AccountView, len(accounts))
	for i, account := range accounts {
		mcpAccountInput[i] = appresult.AccountView{
			Address:    account.Address,
			Alias:      account.Alias,
			Source:     account.Source,
			IsSignable: account.IsSignable,
			KeyType:    account.KeyType,
		}
	}
	mcpAccounts := appresult.AccountsToMCP(mcpAccountInput)
	if len(mcpAccounts) != 1 {
		t.Fatalf("len(mcpAccounts) = %d, want 1", len(mcpAccounts))
	}
	if mcpAccounts[0].Address != addr {
		t.Fatalf("mcpAccounts[0].address = %q, want %s", mcpAccounts[0].Address, addr)
	}
	if mcpAccounts[0].Alias != "alice" {
		t.Fatalf("mcpAccounts[0].alias = %q, want alice", mcpAccounts[0].Alias)
	}
	if mcpAccounts[0].KeyType != "ed25519" {
		t.Fatalf("mcpAccounts[0].key_type = %q, want ed25519", mcpAccounts[0].KeyType)
	}
	if !mcpAccounts[0].IsSignable {
		t.Fatal("mcpAccounts[0].is_signable = false, want true")
	}
}

func TestPlanValidationAndRequestMapping(t *testing.T) {
	t.Run("non-array input", func(t *testing.T) {
		_, _, api := newTestAPI(t)

		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic")
			}
			if got := r.(goja.Value).String(); !strings.Contains(got, "plan() argument must be an array") {
				t.Fatalf("panic = %q, want array validation error", got)
			}
		}()

		api.jsPlan(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue("nope")}})
	})

	t.Run("invalid lsig args", func(t *testing.T) {
		_, _, api := newTestAPI(t)

		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic")
			}
			if got := r.(goja.Value).String(); !strings.Contains(got, `lsigArgs["arg"] must be a hex string`) {
				t.Fatalf("panic = %q, want lsigArgs validation error", got)
			}
		}()

		api.jsPlan(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue([]interface{}{
			map[string]interface{}{
				"txnBytesHex": "5458",
				"lsigArgs":    map[string]interface{}{"arg": float64(7)},
			},
		})}})
	})

	t.Run("invalid LogicSig resource", func(t *testing.T) {
		_, _, api := newTestAPI(t)

		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic")
			}
			if got := r.(goja.Value).String(); !strings.Contains(got, "invalid lsigResources.programBytes") {
				t.Fatalf("panic = %q, want LogicSig resource error", got)
			}
		}()

		api.jsPlan(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue([]interface{}{
			map[string]interface{}{
				"txnBytesHex": "5458",
				"lsigResources": map[string]interface{}{
					"programBytes":  -1,
					"argumentBytes": 0,
					"maxOpcodeCost": 1,
				},
			},
		})}})
	})

	t.Run("invalid pq scheme type", func(t *testing.T) {
		_, _, api := newTestAPI(t)

		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic")
			}
			if got := r.(goja.Value).String(); !strings.Contains(got, "pqScheme must be a non-empty string") {
				t.Fatalf("panic = %q, want pqScheme validation error", got)
			}
		}()

		api.jsPlan(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue([]interface{}{
			map[string]interface{}{"txnBytesHex": "5458", "pqScheme": float64(1)},
		})}})
	})

	t.Run("maps request and response", func(t *testing.T) {
		eng, _, api := newTestAPI(t)
		algodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v2/transactions/params" {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
				ConsensusVersion: string(protocol.ConsensusV42),
			})
		}))
		defer algodServer.Close()
		algodClient, err := algod.MakeClient(algodServer.URL, "")
		if err != nil {
			t.Fatalf("algod.MakeClient() error = %v", err)
		}
		eng.AlgodClient = algodClient

		var gotReq signerapi.GroupSignRequest
		signerClient := signerclient.NewSignerClientWithToken("http://signer.test", "test-token")
		signerClient.Client = &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path != "/plan" {
				t.Fatalf("path = %s, want /plan", r.URL.Path)
			}
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s, want POST", r.Method)
			}
			if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			return jsonResponse(r, http.StatusOK, signerapi.GroupPlanResponse{
				Transactions: []string{"TXabc", "TXdef", "TXghi"},
				Mutations: &signerapi.MutationReport{
					DummiesAdded:     1,
					GroupIDChanged:   true,
					FeesModified:     []int{0, 2},
					TotalFeesDelta:   3000,
					OriginalCount:    3,
					FinalCount:       4,
					PassthroughCount: 0,
					ForeignCount:     2,
					Reason:           "lsig_budget",
				},
			})
		})}

		eng.Connection.SignerClient = signerClient

		value := api.jsPlan(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue([]interface{}{
			map[string]interface{}{
				"authAddress": "AUTHADDR",
				"txnSender":   "SENDERADDR",
				"txnBytesHex": "5458abcd",
				"lsigArgs": map[string]interface{}{
					"alpha": "00ff",
					"beta":  "01",
				},
			},
			map[string]interface{}{
				"txnBytesHex": "5458beef",
				"lsigResources": map[string]interface{}{
					"programBytes":  float64(123),
					"argumentBytes": float64(45),
					"maxOpcodeCost": float64(6_789),
				},
			},
			map[string]interface{}{
				"txnBytesHex": "5458cafe",
				"pqScheme":    signerapi.PQSchemeFalcon1024,
			},
		})}})

		got := value.Export().(map[string]interface{})
		if !reflect.DeepEqual(gotReq.Requests, []signerapi.SignRequest{
			{
				AuthAddress: "AUTHADDR",
				TxnSender:   "SENDERADDR",
				TxnBytesHex: "5458abcd",
				LsigArgs: map[string]string{
					"alpha": "00ff",
					"beta":  "01",
				},
			},
			{
				TxnBytesHex: "5458beef",
				LsigResources: &signerapi.LogicSigResourceUsage{
					ProgramBytes: 123, ArgumentBytes: 45, MaxOpcodeCost: 6_789,
				},
			},
			{
				TxnBytesHex: "5458cafe",
				PQScheme:    signerapi.PQSchemeFalcon1024,
			},
		}) {
			t.Fatalf("request = %#v, want mapped sign requests", gotReq.Requests)
		}

		if !reflect.DeepEqual(toStringArrayValue(got["transactions"]), []string{"TXabc", "TXdef", "TXghi"}) {
			t.Fatalf("transactions = %#v, want planned transactions", got["transactions"])
		}

		mutations, ok := got["mutations"].(map[string]interface{})
		if !ok {
			t.Fatalf("mutations = %#v, want object", got["mutations"])
		}
		if toUint64Value(api.runtime, mutations["dummiesAdded"]) != 1 || mutations["groupIDChanged"] != true {
			t.Fatalf("mutations = %#v, want mapped mutation fields", mutations)
		}
		if !reflect.DeepEqual(toInterfaceSliceValue(mutations["feesModified"]), []interface{}{float64(0), float64(2)}) &&
			!reflect.DeepEqual(mutations["feesModified"], []int{0, 2}) {
			t.Fatalf("feesModified = %#v, want [0 2]", mutations["feesModified"])
		}
		if toUint64Value(api.runtime, mutations["totalFeesDelta"]) != 3000 || mutations["reason"] != "lsig_budget" {
			t.Fatalf("mutations = %#v, want fee delta and reason", mutations)
		}
	})
}

func TestKeyTypesMapsFullMetadata(t *testing.T) {
	eng, _, api := newTestAPI(t)

	signerClient := signerclient.NewSignerClientWithToken("http://signer.test", "test-token")
	signerClient.Client = &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/keytypes" {
			t.Fatalf("path = %s, want /keytypes", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		return jsonResponse(r, http.StatusOK, signerapi.KeyTypesResponse{
			KeyTypes: []signerapi.KeyTypeInfo{
				{
					KeyType:           "generic-lsig",
					Family:            "logic",
					DisplayName:       "Generic LSig",
					Description:       "scripted signer",
					AuthorizationKind: "logic_sig",
					RequiresLogicSig:  true,
					MnemonicWordCount: 25,
					MnemonicImport:    true,
					MnemonicScheme:    "bip39",
					CreationParams: []signerapi.CreationParamInfo{
						{
							Name:        "owner",
							Label:       "Owner",
							Description: "owner address",
							Type:        "address",
							Required:    true,
							Example:     "ALICE",
							Placeholder: "ADDR",
							Default:     "ADDR1",
						},
					},
					RuntimeArgs: []signerapi.RuntimeArgInfo{
						{
							Name:        "preimage",
							Label:       "Preimage",
							Description: "unlock bytes",
							Type:        "bytes",
							Required:    true,
							ByteLength:  32,
						},
					},
				},
			},
		})
	})}

	eng.Connection.SignerClient = signerClient

	result := api.jsKeyTypes(goja.FunctionCall{}).Export()
	var entry map[string]interface{}
	switch items := result.(type) {
	case []map[string]interface{}:
		if len(items) != 1 {
			t.Fatalf("keyTypes() len = %d, want 1", len(items))
		}
		entry = items[0]
	case []interface{}:
		if len(items) != 1 {
			t.Fatalf("keyTypes() len = %d, want 1", len(items))
		}
		var ok bool
		entry, ok = items[0].(map[string]interface{})
		if !ok {
			t.Fatalf("keyTypes()[0] = %#v, want object", items[0])
		}
	default:
		t.Fatalf("keyTypes() = %#v, want slice", result)
	}
	if entry["keyType"] != "generic-lsig" || entry["family"] != "logic" || entry["authorizationKind"] != "logic_sig" || entry["requiresLogicSig"] != true || entry["mnemonicImport"] != true {
		t.Fatalf("keyTypes()[0] = %#v, want top-level metadata", entry)
	}

	var param map[string]interface{}
	switch creationParams := entry["creationParams"].(type) {
	case []map[string]interface{}:
		if len(creationParams) != 1 {
			t.Fatalf("creationParams = %#v, want one entry", entry["creationParams"])
		}
		param = creationParams[0]
	case []interface{}:
		if len(creationParams) != 1 {
			t.Fatalf("creationParams = %#v, want one entry", entry["creationParams"])
		}
		var ok bool
		param, ok = creationParams[0].(map[string]interface{})
		if !ok {
			t.Fatalf("creationParams[0] = %#v, want object", creationParams[0])
		}
	default:
		t.Fatalf("creationParams = %#v, want slice", entry["creationParams"])
	}
	if param["label"] != "Owner" || param["type"] != "address" || param["example"] != "ALICE" || param["placeholder"] != "ADDR" {
		t.Fatalf("creationParams[0] = %#v, want full param metadata", param)
	}

	var runtimeArg map[string]interface{}
	switch runtimeArgs := entry["runtimeArgs"].(type) {
	case []map[string]interface{}:
		if len(runtimeArgs) != 1 {
			t.Fatalf("runtimeArgs = %#v, want one entry", entry["runtimeArgs"])
		}
		runtimeArg = runtimeArgs[0]
	case []interface{}:
		if len(runtimeArgs) != 1 {
			t.Fatalf("runtimeArgs = %#v, want one entry", entry["runtimeArgs"])
		}
		var ok bool
		runtimeArg, ok = runtimeArgs[0].(map[string]interface{})
		if !ok {
			t.Fatalf("runtimeArgs[0] = %#v, want object", runtimeArgs[0])
		}
	default:
		t.Fatalf("runtimeArgs = %#v, want slice", entry["runtimeArgs"])
	}
	if runtimeArg["name"] != "preimage" || runtimeArg["type"] != "bytes" || toUint64Value(api.runtime, runtimeArg["byteLength"]) != 32 {
		t.Fatalf("runtimeArgs[0] = %#v, want runtime arg metadata", runtimeArg)
	}
}

func TestAssetAndKeyManagementHelpers(t *testing.T) {
	eng, _, api := newTestAPI(t)

	if got := api.jsCachedAssets(goja.FunctionCall{}).Export().([]interface{}); len(got) != 0 {
		t.Fatalf("cachedAssets() = %#v, want empty list", got)
	}
	if got := api.jsClearAssetCache(goja.FunctionCall{}).Export(); got != int64(0) {
		t.Fatalf("clearAssetCache() = %v, want 0", got)
	}
	if got := api.jsGetAsaId(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue("USDC")}}).Export(); got != int64(10458941) {
		t.Fatalf("getAsaId(USDC) = %v, want testnet USDC", got)
	}
	eng.AsaCache.Assets = map[uint64]cache.ASAInfo{
		900001: {Name: "Local Asset", UnitName: "LOCAL", Decimals: 3},
	}
	if got := api.jsGetAsaId(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue("local")}}).Export(); got != int64(900001) {
		t.Fatalf("getAsaId(local) = %v, want cached local asset", got)
	}
	if got := api.jsGetAsaId(goja.FunctionCall{Arguments: []goja.Value{
		api.runtime.ToValue("usdc"),
		api.runtime.ToValue("unknownnet"),
	}}); !goja.IsNull(got) {
		t.Fatal("unknown network asset lookup should return null")
	}

	t.Run("asset info requires client", func(t *testing.T) {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic")
			}
			if got := r.(goja.Value).String(); !strings.Contains(got, "assetInfo() error") {
				t.Fatalf("panic = %q, want assetInfo error", got)
			}
		}()
		api.jsAssetInfo(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue(1)}})
	})

	t.Run("cache asset requires client", func(t *testing.T) {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic")
			}
			if got := r.(goja.Value).String(); !strings.Contains(got, "cacheAsset() error") {
				t.Fatalf("panic = %q, want cacheAsset error", got)
			}
		}()
		api.jsCacheAsset(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue(1)}})
	})

	t.Run("keyTypes requires signer", func(t *testing.T) {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic")
			}
			if got := r.(goja.Value).String(); !strings.Contains(got, "keyTypes() error") {
				t.Fatalf("panic = %q, want keyTypes error", got)
			}
		}()
		api.jsKeyTypes(goja.FunctionCall{})
	})

	t.Run("generateKey requires signer", func(t *testing.T) {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic")
			}
			if got := r.(goja.Value).String(); !strings.Contains(got, "generateKey() error") {
				t.Fatalf("panic = %q, want generateKey error", got)
			}
		}()
		api.jsGenerateKey(goja.FunctionCall{Arguments: []goja.Value{
			api.runtime.ToValue("ed25519"),
			api.runtime.ToValue(map[string]interface{}{"name": "alice"}),
		}})
	})

	t.Run("generateKey invalid options type", func(t *testing.T) {
		defer expectJSPanicContaining(t, "generateKey() options must be an object")()
		api.jsGenerateKey(goja.FunctionCall{Arguments: []goja.Value{
			api.runtime.ToValue("ed25519"),
			api.runtime.ToValue("oops"),
		}})
	})

	t.Run("deleteKey resolve failure", func(t *testing.T) {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic")
			}
			if got := r.(goja.Value).String(); !strings.Contains(got, "deleteKey() error resolving address") {
				t.Fatalf("panic = %q, want deleteKey resolve error", got)
			}
		}()
		api.jsDeleteKey(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue("not-an-address")}})
	})

	t.Run("keys requires signer", func(t *testing.T) {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic")
			}
			if got := r.(goja.Value).String(); !strings.Contains(got, "keys() error") {
				t.Fatalf("panic = %q, want keys error", got)
			}
		}()
		api.jsKeys(goja.FunctionCall{})
	})
}

func TestAtomicAndAppHelpers(t *testing.T) {
	_, _, api := newTestAPI(t)
	addr1 := algoCrypto.GenerateAccount().Address.String()
	addr2 := algoCrypto.GenerateAccount().Address.String()

	t.Run("atomicSend empty", func(t *testing.T) {
		defer expectJSPanicContaining(t, "atomicSend() requires at least one payment")()
		api.jsAtomicSend(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue([]interface{}{})}})
	})

	t.Run("atomicSend invalid amount", func(t *testing.T) {
		defer expectJSPanicContaining(t, "atomicSend() payment 1: invalid amount")()
		api.jsAtomicSend(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue([]interface{}{
			map[string]interface{}{"from": addr1, "to": addr2, "amount": "x"},
		})}})
	})

	t.Run("atomicSend requires array", func(t *testing.T) {
		defer expectJSPanicContaining(t, "atomicSend() requires a payments array")()
		api.jsAtomicSend(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue("not-an-array")}})
	})

	t.Run("atomicSend requires object items", func(t *testing.T) {
		defer expectJSPanicContaining(t, "atomicSend() payment 1: must be an object")()
		api.jsAtomicSend(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue([]interface{}{"not-an-object"})}})
	})

	t.Run("atomicSendAsset missing field", func(t *testing.T) {
		defer expectJSPanicContaining(t, "atomicSendAsset() transfer 1: missing assetId field")()
		api.jsAtomicSendAsset(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue([]interface{}{
			map[string]interface{}{"from": addr1, "to": addr2, "amount": int64(5)},
		})}})
	})

	t.Run("atomicSendAsset requires array", func(t *testing.T) {
		defer expectJSPanicContaining(t, "atomicSendAsset() requires a transfers array")()
		api.jsAtomicSendAsset(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue("not-an-array")}})
	})

	t.Run("atomicSendAsset requires object items", func(t *testing.T) {
		defer expectJSPanicContaining(t, "atomicSendAsset() transfer 1: must be an object")()
		api.jsAtomicSendAsset(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue([]interface{}{"not-an-object"})}})
	})

	t.Run("resolve missing throws", func(t *testing.T) {
		defer expectJSPanicContaining(t, "resolve() error:")()
		api.jsResolve(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue("not-found")}})
	})

	callOpts := goja.FunctionCall{Arguments: []goja.Value{
		api.runtime.ToValue(uint64(7)),
		api.runtime.ToValue("from"),
		api.runtime.ToValue([]interface{}{"arg"}),
		api.runtime.ToValue(map[string]interface{}{
			"pay":          int64(9),
			"accounts":     []string{"a", "b"},
			"apps":         []interface{}{int64(1), "2"},
			"assets":       []interface{}{int64(3), "4"},
			"boxes":        []interface{}{"str:box", map[string]interface{}{"appId": int64(8), "name": []interface{}{float64(1), float64(2)}}},
			"onCompletion": "optin",
			"fee":          int64(1000),
			"wait":         false,
			"note":         "memo",
		}),
	}}
	opts := api.parseAppCallOptions(callOpts, 3, "appCallRaw()", 7)
	if opts.PayAmount != 9 || opts.Wait || opts.Note != "memo" {
		t.Fatalf("parseAppCallOptions() = %#v, want pay/wait/note parsed", opts)
	}
	if len(opts.Accounts) != 2 || len(opts.ForeignApps) != 2 || len(opts.ForeignAssets) != 2 || len(opts.ForeignBoxes) != 2 {
		t.Fatalf("parseAppCallOptions() missing arrays: %#v", opts)
	}
	if opts.OnCompletion != types.OptInOC {
		t.Fatalf("OnCompletion = %v, want OptInOC", opts.OnCompletion)
	}

	deployOpts := api.parseAppDeployOptions(goja.FunctionCall{Arguments: []goja.Value{
		api.runtime.ToValue("from"),
		api.runtime.ToValue("approval.teal"),
		api.runtime.ToValue("clear.teal"),
		api.runtime.ToValue(map[string]interface{}{
			"approvalCompiled": true,
			"clearCompiled":    true,
			"globalUint":       int64(1),
			"globalBytes":      int64(2),
			"localUint":        int64(3),
			"localBytes":       int64(4),
			"extraPages":       int64(5),
		}),
	}}, 3, "appDeploy()")
	if !deployOpts.ApprovalCompiled || !deployOpts.ClearCompiled || deployOpts.ExtraPages != 5 {
		t.Fatalf("parseAppDeployOptions() = %#v, want compiled flags and extra pages", deployOpts)
	}

	t.Run("parseAppDeployOptions invalid bool type", func(t *testing.T) {
		defer expectJSPanicContaining(t, "appDeploy() invalid approvalCompiled: expected boolean")()
		api.parseAppDeployOptions(goja.FunctionCall{Arguments: []goja.Value{
			api.runtime.ToValue("from"),
			api.runtime.ToValue("approval.teal"),
			api.runtime.ToValue("clear.teal"),
			api.runtime.ToValue(map[string]interface{}{
				"approvalCompiled": "yes",
			}),
		}}, 3, "appDeploy()")
	})

	fromAddr, accounts, err := api.resolveAppAccounts(addr1, []string{addr2}, "appCallRaw()")
	if err != nil {
		t.Fatalf("resolveAppAccounts() error = %v", err)
	}
	if fromAddr != addr1 || len(accounts) != 1 || accounts[0] != addr2 {
		t.Fatalf("resolveAppAccounts() = %q %#v", fromAddr, accounts)
	}

	submit := api.submitResultValue(&engine.SubmitResult{TxID: "TX1", Confirmed: true}, "increment(uint64)void").Export().(map[string]interface{})
	if submit["txid"] != "TX1" || submit["confirmed"] != true {
		t.Fatalf("submitResultValue() = %#v, want txid/confirmed", submit)
	}
	if submit["method"] != "increment(uint64)void" {
		t.Fatalf("submitResultValue() method = %#v, want increment(uint64)void", submit["method"])
	}

	group := api.preparedGroupResultValue(&engine.PreparedGroupSubmitResult{TxIDs: []string{"A", "B"}, Confirmed: false}, "increment(uint64)void").Export().(map[string]interface{})
	if group["grouped"] != true {
		t.Fatalf("preparedGroupResultValue() = %#v, want grouped flag", group)
	}
	if group["method"] != "increment(uint64)void" {
		t.Fatalf("preparedGroupResultValue() method = %#v, want increment(uint64)void", group["method"])
	}

	t.Run("appInfo without algod", func(t *testing.T) {
		defer expectJSPanicContaining(t, "appInfo() error")()
		api.jsAppInfo(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue(1)}})
	})
}

func TestStandaloneHelperConversions(t *testing.T) {
	_, _, api := newTestAPI(t)

	jsObj := api.toJSObject(struct {
		Name string `json:"name"`
	}{Name: "alice"}).Export().(map[string]interface{})
	if jsObj["name"] != "alice" {
		t.Fatalf("toJSObject() = %#v, want marshaled object", jsObj)
	}

	if got := toUint64Value(api.runtime, int64(9)); got != 9 {
		t.Fatalf("toUint64Value() = %d, want 9", got)
	}
	if got := toBoolValue(api.runtime, true); !got {
		t.Fatal("toBoolValue(true) = false, want true")
	}
	if bytes, err := parseJSByteString([]interface{}{int64(1), float64(2)}); err != nil || len(bytes) != 2 || bytes[1] != 2 {
		t.Fatalf("parseJSByteString(slice) = %v, %v", bytes, err)
	}
	if values, err := toUint64SliceValue([]interface{}{int64(1), "2"}); err != nil || len(values) != 2 || values[1] != 2 {
		t.Fatalf("toUint64SliceValue() = %v, %v", values, err)
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic from invalid bool conversion")
		}
		if got := r.(goja.Value).String(); !strings.Contains(got, "unsupported type for bool conversion") {
			t.Fatalf("panic = %q, want JS conversion error", got)
		}
	}()
	_ = toBoolValue(api.runtime, "bad")
}

func TestAdditionalErrorPaths(t *testing.T) {
	eng, _, api := newTestAPI(t)
	addr1 := algoCrypto.GenerateAccount().Address.String()
	addr2 := algoCrypto.GenerateAccount().Address.String()

	t.Run("waitForTx without algod", func(t *testing.T) {
		defer expectJSPanicContaining(t, "waitForTx() error")()
		api.jsWaitForTx(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue("TXID")}})
	})

	t.Run("holders without algod", func(t *testing.T) {
		if eng.AliasCache.Aliases == nil {
			eng.AliasCache.Aliases = make(map[string]string)
		}
		eng.AliasCache.Aliases["alice"] = addr1
		defer expectJSPanicContaining(t, "holders() error")()
		api.jsHolders(goja.FunctionCall{Arguments: []goja.Value{
			api.runtime.ToValue([]string{addr1, addr2}),
			api.runtime.ToValue("algo"),
		}})
	})

	t.Run("canSignFor returns signer state", func(t *testing.T) {
		if eng.AliasCache.Aliases == nil {
			eng.AliasCache.Aliases = make(map[string]string)
		}
		eng.AliasCache.Aliases["alice"] = addr1
		eng.SignerCache.Keys = map[string]string{addr1: "ed25519"}

		got := api.jsCanSignFor(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue("alice")}}).Export().(map[string]interface{})
		if got["canSign"] != true || got["isLsig"] != false {
			t.Fatalf("canSignFor() = %#v, want signer state", got)
		}
	})

	t.Run("close resolve failure", func(t *testing.T) {
		defer expectJSPanicContaining(t, "close() error resolving from address")()
		api.jsClose(goja.FunctionCall{Arguments: []goja.Value{
			api.runtime.ToValue("bad-address"),
			api.runtime.ToValue(addr2),
		}})
	})

	t.Run("close invalid lsig args", func(t *testing.T) {
		defer expectJSPanicContaining(t, `close() invalid lsigArgs["preimage"]`)()
		api.jsClose(goja.FunctionCall{Arguments: []goja.Value{
			api.runtime.ToValue(addr1),
			api.runtime.ToValue(addr2),
			api.runtime.ToValue(map[string]interface{}{
				"lsigArgs": map[string]interface{}{
					"preimage": map[string]interface{}{"bad": "value"},
				},
			}),
		}})
	})

	t.Run("close invalid options type", func(t *testing.T) {
		defer expectJSPanicContaining(t, "close() options must be an object")()
		api.jsClose(goja.FunctionCall{Arguments: []goja.Value{
			api.runtime.ToValue(addr1),
			api.runtime.ToValue(addr2),
			api.runtime.ToValue("oops"),
		}})
	})

	t.Run("parseCloseOptions parses lsig args", func(t *testing.T) {
		opts := api.parseCloseOptions(goja.FunctionCall{Arguments: []goja.Value{
			api.runtime.ToValue(addr1),
			api.runtime.ToValue(addr2),
			api.runtime.ToValue(map[string]interface{}{
				"fee":  float64(1000),
				"wait": false,
				"lsigArgs": map[string]interface{}{
					"preimage": "text:open-sesame",
					"bytes":    []interface{}{float64(1), float64(2), float64(3)},
				},
			}),
		}})

		if opts.Fee != 1000 || opts.Wait != false {
			t.Fatalf("parseCloseOptions() = %#v, want fee/wait parsed", opts)
		}
		if string(opts.LsigArgs["preimage"]) != "open-sesame" {
			t.Fatalf("preimage = %q, want open-sesame", string(opts.LsigArgs["preimage"]))
		}
		if !reflect.DeepEqual(opts.LsigArgs["bytes"], []byte{1, 2, 3}) {
			t.Fatalf("bytes = %v, want [1 2 3]", opts.LsigArgs["bytes"])
		}
	})

	t.Run("sign parse failure", func(t *testing.T) {
		defer expectJSPanicContaining(t, "sign() error parsing file")()
		api.jsSign(goja.FunctionCall{Arguments: []goja.Value{api.runtime.ToValue("missing.txn")}})
	})

	t.Run("sign invalid options type", func(t *testing.T) {
		defer expectJSPanicContaining(t, "sign() options must be an object")()
		api.jsSign(goja.FunctionCall{Arguments: []goja.Value{
			api.runtime.ToValue("missing.txn"),
			api.runtime.ToValue("oops"),
		}})
	})

	t.Run("keyreg invalid options type", func(t *testing.T) {
		defer expectJSPanicContaining(t, "keyreg() options must be an object")()
		api.jsKeyreg(goja.FunctionCall{Arguments: []goja.Value{
			api.runtime.ToValue(addr1),
			api.runtime.ToValue("online"),
			api.runtime.ToValue("oops"),
		}})
	})
}

func expectJSPanicContaining(t *testing.T, want string) func() {
	t.Helper()
	return func() {
		t.Helper()
		r := recover()
		if r == nil {
			t.Fatal("expected panic")
		}
		v, ok := r.(goja.Value)
		if !ok {
			t.Fatalf("panic type = %T, want goja.Value", r)
		}
		if got := v.String(); !strings.Contains(got, want) {
			t.Fatalf("panic = %q, want containing %q", got, want)
		}
	}
}

// Test-only goja value converters.
func toUint64Value(vm *goja.Runtime, v interface{}) uint64 {
	out, err := toUint64Interface(v)
	if err != nil {
		panic(vm.ToValue(err.Error()))
	}
	return out
}

func toBoolValue(vm *goja.Runtime, v interface{}) bool {
	b, ok := v.(bool)
	if !ok {
		panic(vm.ToValue(fmt.Sprintf("unsupported type for bool conversion: %T", v)))
	}
	return b
}
