// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// A submission that fails at or after algod's submit call reaches an MCP
// caller with its transaction IDs and how far it got, through every
// submitting command's wrapping. These tests run each command family against
// a test signer that signs with real ed25519 keys and a test node whose
// answer to the submission is chosen per test.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

const submitTestAsset = 77
const submitTestApp = 123

// How the test node answers the submit call.
const (
	nodeDropsSubmit   = "drop"   // closes the connection: the answer is lost
	nodeAcceptsSubmit = "accept" // accepts; the confirmation wait then times out
	nodeRefusesSubmit = "refuse" // HTTP 400
	nodeHasTheGroup   = "ledger" // HTTP 400: the transaction is already in the ledger
	nodeUnavailable   = "503"    // HTTP 503
	nodePoolError     = "pool"   // accepts; the pending transaction then reports a pool error
	nodeConfirms      = "confirm"
)

// submitFixture is a shell in MCP's mode (AutoConfirm) on testnet, with a
// test signer holding the ed25519 keys of a, b and c, and a test node on
// which every account holds 5 ALGO, a holds asset 77 at zero, and r is
// rekeyed to a. The signer records the IDs of the transactions it signed.
type submitFixture struct {
	state   *REPLState
	eng     *engine.Engine
	a, b, c crypto.Account
	r       types.Address
	genesis []byte
	mode    string
	mu      sync.Mutex
	signed  [][]string
}

func newSubmitFixture(t *testing.T, mode string) *submitFixture {
	t.Helper()
	f := &submitFixture{a: crypto.GenerateAccount(), b: crypto.GenerateAccount(), c: crypto.GenerateAccount(),
		r: crypto.GenerateAccount().Address, mode: mode}
	var err error
	if f.genesis, err = base64.StdEncoding.DecodeString(config.AlgorandTestnetGenesisHash); err != nil {
		t.Fatal(err)
	}
	keys := map[string]crypto.Account{f.a.Address.String(): f.a, f.b.Address.String(): f.b, f.c.Address.String(): f.c}
	signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/keys":
			var infos []signerapi.KeyInfo
			for _, account := range []crypto.Account{f.a, f.b, f.c} {
				infos = append(infos, signerapi.KeyInfo{Address: account.Address.String(), KeyType: "ed25519", ValidRekeyTarget: true})
			}
			_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Count: len(infos), Keys: infos})
		case r.Method == http.MethodGet && r.URL.Path == "/status":
			_ = json.NewEncoder(w).Encode(signerapi.StatusResponse{State: "unlocked", ReadyForSigning: true, KeyCount: 3})
		case r.Method == http.MethodPost && r.URL.Path == "/sign":
			var req signerapi.GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode /sign request: %v", err)
			}
			_ = json.NewEncoder(w).Encode(f.sign(t, keys, req.Requests))
		default:
			t.Errorf("unexpected signer request %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	t.Cleanup(signer.Close)
	node := httptest.NewServer(http.HandlerFunc(f.serveNode(t)))
	t.Cleanup(node.Close)
	client, err := algod.MakeClient(node.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	eng, err := newIsolatedTestEngine(t, "testnet")
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.SetNetwork("testnet", client); err != nil {
		t.Fatal(err)
	}
	eng.Connection.SignerClient = signerclient.NewSignerClient(signer.URL)
	if _, err := eng.RefreshKeys(context.Background()); err != nil {
		t.Fatalf("RefreshKeys() error = %v", err)
	}
	f.eng = eng
	f.state = &REPLState{App: apshellapp.New(eng, config.DefaultConfig(), t.TempDir()), AutoConfirm: true, DataDir: t.TempDir()}
	f.state.SetOutput(&bytes.Buffer{})
	f.state.CommandRegistry = f.state.initCommandRegistry()
	return f
}

// sign signs each request with the key its auth address names, grouping a
// group the client left ungrouped, as the signer does.
func (f *submitFixture) sign(t *testing.T, keys map[string]crypto.Account, requests []signerapi.SignRequest) signerapi.GroupSignResponse {
	txns := make([]types.Transaction, len(requests))
	for i, req := range requests {
		txn, err := txnutil.DecodePrefixedHex(req.TxnBytesHex)
		if err != nil {
			t.Errorf("decode /sign transaction: %v", err)
			return signerapi.GroupSignResponse{}
		}
		txns[i] = txn
	}
	var mutations *signerapi.MutationReport
	if len(txns) > 1 && txns[0].Group == (types.Digest{}) {
		gid, err := crypto.ComputeGroupID(txns)
		if err != nil {
			t.Errorf("compute group ID: %v", err)
		}
		for i := range txns {
			txns[i].Group = gid
		}
		mutations = &signerapi.MutationReport{OriginalCount: len(txns), FinalCount: len(txns), GroupIDChanged: true}
	}
	resp := signerapi.GroupSignResponse{Mutations: mutations}
	var ids []string
	for i, txn := range txns {
		key, ok := keys[requests[i].AuthAddress]
		if !ok {
			t.Errorf("/sign asked for %s, which the signer holds no key for", requests[i].AuthAddress)
			return signerapi.GroupSignResponse{}
		}
		id, raw, err := signing.SignTransactionWithKey(key.PrivateKey, txn)
		if err != nil {
			t.Errorf("sign: %v", err)
		}
		if key.Address != txn.Sender {
			var stx types.SignedTxn
			if err := msgpack.Decode(raw, &stx); err != nil {
				t.Errorf("decode signed: %v", err)
			}
			stx.AuthAddr = key.Address
			raw = msgpack.Encode(stx)
		}
		ids = append(ids, id)
		resp.Signed = append(resp.Signed, hex.EncodeToString(raw))
	}
	f.mu.Lock()
	f.signed = append(f.signed, ids)
	f.mu.Unlock()
	return resp
}

func (f *submitFixture) signedIDs() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.signed...)
}

func (f *submitFixture) serveNode(t *testing.T) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		switch {
		case path == "/v2/transactions/params":
			_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
				ConsensusVersion: string(protocol.ConsensusV43), MinFee: 1000, LastRound: 1000,
				GenesisId: "testnet-v1.0", GenesisHash: f.genesis,
			})
		case path == "/v2/transactions" && r.Method == http.MethodPost:
			_, _ = io.Copy(io.Discard, r.Body)
			switch f.mode {
			case nodeDropsSubmit:
				if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
					_ = conn.Close()
				}
			case nodeRefusesSubmit:
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": "TransactionPool.Remember: transaction X: overspend"})
			case nodeHasTheGroup:
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": "TransactionPool.Remember: transaction X: transaction already in ledger"})
			case nodeUnavailable:
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": "node is catching up"})
			default:
				_ = json.NewEncoder(w).Encode(map[string]string{"txId": "accepted"})
			}
		case path == "/v2/status" || strings.HasPrefix(path, "/v2/status/wait-for-block-after/"):
			_ = json.NewEncoder(w).Encode(models.NodeStatus{LastRound: 1000})
		case strings.HasPrefix(path, "/v2/transactions/pending/"):
			info := models.PendingTransactionInfoResponse{}
			switch f.mode {
			case nodeConfirms:
				info.ConfirmedRound = 1001
			case nodePoolError:
				info.PoolError = "TransactionPool.Remember: transaction X: overspend"
			}
			w.Header().Set("Content-Type", "application/msgpack")
			_, _ = w.Write(msgpack.Encode(info))
		case strings.HasPrefix(path, "/v2/accounts/"):
			address := strings.Split(strings.TrimPrefix(path, "/v2/accounts/"), "/")[0]
			if strings.Contains(strings.TrimPrefix(path, "/v2/accounts/"), "/assets/") {
				_ = json.NewEncoder(w).Encode(models.AccountAssetResponse{AssetHolding: models.AssetHolding{AssetId: submitTestAsset}})
				return
			}
			account := models.Account{Address: address, Amount: 5_000_000, AmountWithoutPendingRewards: 5_000_000,
				MinBalance: 100_000, Status: "Offline"}
			if address == f.a.Address.String() {
				account.Assets = []models.AssetHolding{{AssetId: submitTestAsset}}
			}
			if address == f.r.String() {
				account.AuthAddr = f.a.Address.String()
			}
			_ = json.NewEncoder(w).Encode(account)
		case path == fmt.Sprintf("/v2/assets/%d", submitTestAsset):
			_ = json.NewEncoder(w).Encode(models.Asset{Index: submitTestAsset, Params: models.AssetParams{
				Creator: f.b.Address.String(), Name: "Test", UnitName: "TST", Total: 1000,
			}})
		case path == fmt.Sprintf("/v2/applications/%d", submitTestApp):
			_ = json.NewEncoder(w).Encode(models.Application{Id: submitTestApp, Params: models.ApplicationParams{Creator: f.b.Address.String()}})
		default:
			t.Errorf("unexpected node request %s %s", r.Method, path)
			http.Error(w, "not found", http.StatusNotFound)
		}
	}
}

// signFile writes two ungrouped payments from a into a transaction file.
func (f *submitFixture) signFile(t *testing.T) string {
	t.Helper()
	var raw []byte
	for i := 0; i < 2; i++ {
		txn, err := transaction.MakePaymentTxn(f.a.Address.String(), f.b.Address.String(), 1000, []byte(fmt.Sprint(i)), "", types.SuggestedParams{
			Fee: 1000, FirstRoundValid: 1000, LastRoundValid: 1900, GenesisHash: f.genesis, GenesisID: "testnet-v1.0", FlatFee: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, msgpack.Encode(txn)...)
	}
	path := filepath.Join(t.TempDir(), "group.txn")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(raw)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func (f *submitFixture) approvalBin(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "program.bin")
	// #pragma version 8; int 1
	if err := os.WriteFile(path, []byte{0x08, 0x81, 0x01}, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// mcpErrorParts returns an MCP error result's text and its structured
// content, failing unless it is an error result with both.
func mcpErrorParts(t *testing.T, result *mcp.CallToolResult) (string, mcpErrorJSON) {
	t.Helper()
	if !result.IsError || len(result.Content) != 2 {
		t.Fatalf("result = %+v, want an error result with text and structured content", result)
	}
	text, ok1 := result.Content[0].(mcp.TextContent)
	data, ok2 := result.Content[1].(mcp.TextContent)
	if !ok1 || !ok2 {
		t.Fatalf("content = %#v, want two text contents", result.Content)
	}
	var structured mcpErrorJSON
	if err := json.Unmarshal([]byte(data.Text), &structured); err != nil {
		t.Fatalf("structured content %q: %v", data.Text, err)
	}
	return text.Text, structured
}

// Every submitting command family reaches the MCP caller with its outcome
// through its own wrapping. The node closes the connection on the submit
// call, so nothing in the error text names a transaction: the IDs the result
// carries are those the signer signed, from the error's structure, and the
// state is "unknown".
func TestMCPSubmittingCommandsReportALostSubmission(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command func(f *submitFixture, t *testing.T) string
	}{
		{"sign-file", func(f *submitFixture, t *testing.T) string { return "sign " + f.signFile(t) }},
		{"atomic send", func(f *submitFixture, t *testing.T) string {
			return fmt.Sprintf("send 0.001 algo from %s to [%s %s] atomic", f.a.Address, f.b.Address, f.c.Address)
		}},
		{"app call raw", func(f *submitFixture, t *testing.T) string {
			return fmt.Sprintf("app call raw %d from %s", submitTestApp, f.a.Address)
		}},
		{"app call raw grouped", func(f *submitFixture, t *testing.T) string {
			return fmt.Sprintf("app call raw %d from %s --pay 100000", submitTestApp, f.a.Address)
		}},
		{"app deploy", func(f *submitFixture, t *testing.T) string {
			bin := f.approvalBin(t)
			return fmt.Sprintf("app deploy from %s approval-bin=%s clear-bin=%s global-uint=0 global-bytes=0 local-uint=0 local-bytes=0", f.a.Address, bin, bin)
		}},
		{"opt-in", func(f *submitFixture, t *testing.T) string {
			return fmt.Sprintf("optin %d for %s", submitTestAsset, f.a.Address)
		}},
		{"opt-out", func(f *submitFixture, t *testing.T) string {
			return fmt.Sprintf("optout %d from %s", submitTestAsset, f.a.Address)
		}},
		{"keyreg", func(f *submitFixture, t *testing.T) string { return fmt.Sprintf("keyreg %s offline", f.a.Address) }},
		{"rekey", func(f *submitFixture, t *testing.T) string {
			return fmt.Sprintf("rekey %s to %s", f.a.Address, f.b.Address)
		}},
		{"unrekey", func(f *submitFixture, t *testing.T) string { return fmt.Sprintf("unrekey %s", f.r) }},
		{"close", func(f *submitFixture, t *testing.T) string {
			return fmt.Sprintf("close %s to %s", f.c.Address, f.b.Address)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSubmitFixture(t, nodeDropsSubmit)
			cmd, err := parseShellCommand(tc.command(f, t))
			if err != nil {
				t.Fatal(err)
			}
			text, structured := mcpErrorParts(t, mcpExecuteCommand(f.state, cmd))
			signed := f.signedIDs()
			if len(signed) != 1 {
				t.Fatalf("signed %d group(s), want 1 (error %q)", len(signed), text)
			}
			if len(structured.Submissions) != 1 {
				t.Fatalf("submissions = %+v, want one", structured.Submissions)
			}
			got := structured.Submissions[0]
			if got.State != "unknown" || got.Submitted || !reflect.DeepEqual(got.TxIDs, signed[0]) {
				t.Fatalf("submission = %+v, want unknown with IDs %v", got, signed[0])
			}
			for _, id := range signed[0] {
				if strings.Contains(structured.Error, id) {
					t.Fatalf("the error text %q names %s: the test proves nothing", structured.Error, id)
				}
				if !strings.Contains(text, id) {
					t.Fatalf("text %q does not name %s", text, id)
				}
			}
			if !strings.HasPrefix(text, structured.Error+"\n") || !strings.Contains(text, got.Message) ||
				!strings.Contains(text, "Check these IDs on the network before retrying.") {
				t.Fatalf("text = %q, want the error, then the outcome in words", text)
			}
		})
	}
}

// The states and success, through one command: an accepted submission whose
// confirmation wait timed out or ended with the pool error algod reported, a
// lost submit response, an HTTP answer other than 400, algod's 400 answer,
// and a confirmed send. Each sentence says what happened, with what algod or
// the wait answered as given. Only a failed submission adds structured
// content; the error text is the one the REPL prints.
func TestMCPSubmissionOutcomeStates(t *testing.T) {
	for _, tc := range []struct {
		mode      string
		state     string
		submitted bool
		message   func(ids []string) string
	}{
		{nodeAcceptsSubmit, "submitted", true, func(ids []string) string {
			return "Submitted: algod accepted transaction(s) " + strings.Join(ids, ", ") +
				", and waiting for their confirmation ended with: wait for transaction id " + ids[0] + " timed out. Check these IDs on the network before retrying."
		}},
		{nodePoolError, "submitted", true, func(ids []string) string {
			return "Submitted: algod accepted transaction(s) " + strings.Join(ids, ", ") +
				", and waiting for their confirmation ended with: transaction rejected: TransactionPool.Remember: transaction X: overspend. Check these IDs on the network before retrying."
		}},
		{nodeDropsSubmit, "unknown", false, func(ids []string) string {
			return "Submission outcome unknown: the submit request for transaction(s) " + strings.Join(ids, ", ") +
				" got no answer from algod, so they may have been accepted. Check these IDs on the network before retrying."
		}},
		{nodeUnavailable, "unknown", false, func(ids []string) string {
			return "Submission outcome unknown: algod answered the submit request for transaction(s) " + strings.Join(ids, ", ") +
				` with HTTP 503: {"message":"node is catching up"}. Check these IDs on the network before retrying.`
		}},
		{nodeRefusesSubmit, "rejected", false, func(ids []string) string {
			return "algod answered the submit request for transaction(s) " + strings.Join(ids, ", ") +
				" with an error. Read the reason before retrying: a transaction already in the ledger is answered this way too."
		}},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			f := newSubmitFixture(t, tc.mode)
			cmd, err := parseShellCommand(fmt.Sprintf("send 0.001 algo from %s to [%s %s] atomic", f.a.Address, f.b.Address, f.c.Address))
			if err != nil {
				t.Fatal(err)
			}
			text, structured := mcpErrorParts(t, mcpExecuteCommand(f.state, cmd))
			ids := f.signedIDs()[0]
			want := appresult.Submission{State: tc.state, Submitted: tc.submitted, TxIDs: ids,
				Message: tc.message(ids)}
			got := structured.Submissions[0]
			want.Error = got.Error
			if !reflect.DeepEqual(got, want) || got.Error == "" || !strings.Contains(structured.Error, got.Error) {
				t.Fatalf("submission = %+v, want %+v", got, want)
			}
			if text != structured.Error+"\n"+want.Message {
				t.Fatalf("text = %q", text)
			}
		})
	}
	t.Run("confirmed", func(t *testing.T) {
		f := newSubmitFixture(t, nodeConfirms)
		cmd, err := parseShellCommand(fmt.Sprintf("send 0.001 algo from %s to [%s %s] atomic", f.a.Address, f.b.Address, f.c.Address))
		if err != nil {
			t.Fatal(err)
		}
		result := mcpExecuteCommand(f.state, cmd)
		if result.IsError {
			t.Fatalf("result = %+v, want success", result)
		}
		var got struct {
			TxIDs     []string `json:"tx_ids"`
			Confirmed bool     `json:"confirmed"`
		}
		if err := json.Unmarshal([]byte(mcpResultText(t, result)), &got); err != nil {
			t.Fatal(err)
		}
		if !got.Confirmed || !reflect.DeepEqual(got.TxIDs, f.signedIDs()[0]) {
			t.Fatalf("result = %+v, want the confirmed group", got)
		}
	})
}

// An error that carries no submission is the error text alone, as before.
func TestMCPErrorWithoutASubmissionIsItsText(t *testing.T) {
	f := newSubmitFixture(t, nodeDropsSubmit)
	cmd, err := parseShellCommand("optin 77 for nobody")
	if err != nil {
		t.Fatal(err)
	}
	result := mcpExecuteCommand(f.state, cmd)
	if !result.IsError || len(result.Content) != 1 || len(f.signedIDs()) != 0 {
		t.Fatalf("result = %+v, want the error text alone", result)
	}
}

// A sweep in which every item failed reports each item's outcome once: in
// the error result's submissions, in order. The result is not attached, so
// no outcome appears twice, and the error text is the REPL's.
func TestMCPSweepWhoseItemsAllFailed(t *testing.T) {
	f := newSubmitFixture(t, nodeDropsSubmit)
	cmd, err := parseShellCommand(fmt.Sprintf("sweep algo from [%s %s] to %s", f.a.Address, f.c.Address, f.b.Address))
	if err != nil {
		t.Fatal(err)
	}
	result := mcpExecuteCommand(f.state, cmd)
	text, structured := mcpErrorParts(t, result)
	signed := f.signedIDs()
	if structured.Error != "all 2 transaction(s) failed" || len(signed) != 2 || len(structured.Submissions) != 2 {
		t.Fatalf("error %q, submissions %+v, signed %v", structured.Error, structured.Submissions, signed)
	}
	for i, submission := range structured.Submissions {
		if submission.State != "unknown" || !reflect.DeepEqual(submission.TxIDs, signed[i]) {
			t.Fatalf("submission %d = %+v, want unknown for %v", i, submission, signed[i])
		}
		if !strings.Contains(text, submission.Message) {
			t.Fatalf("text %q lacks item %d's outcome", text, i)
		}
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal([]byte(result.Content[1].(mcp.TextContent).Text), &keys); err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys["error"] == nil || keys["submissions"] == nil {
		t.Fatalf("structured content has %v, want error and submissions only", keys)
	}
}

// The error of a sweep in which every item failed is the sweep's own: no
// item's error is reachable through it, so no item's sentinel matches it,
// while the outcomes of the items whose submission failed are still read
// from it. One whose items carry no outcome is the error text alone, as
// before, though the sweep returned its result with it.
func TestSweepWhoseItemsAllFailedMatchesNoItemError(t *testing.T) {
	sweep := func(t *testing.T, f *submitFixture) Command {
		t.Helper()
		cmd, err := parseShellCommand(fmt.Sprintf("sweep algo from [%s %s] to %s", f.a.Address, f.c.Address, f.b.Address))
		if err != nil {
			t.Fatal(err)
		}
		return cmd
	}
	t.Run("refused before signing", func(t *testing.T) {
		f := newSubmitFixture(t, nodeDropsSubmit)
		f.eng.Connection.SignerClient = nil
		result, err := f.state.executeCommandResult(sweep(t, f))
		if result == nil || err == nil || err.Error() != "all 2 transaction(s) failed" || errors.Is(err, engine.ErrNotConnected) {
			t.Fatalf("result returned %v, error %v: want the sweep's result and its own error, matching no item's", result != nil, err)
		}
		if mcpResult := mcpExecuteCommand(f.state, sweep(t, f)); !mcpResult.IsError || len(mcpResult.Content) != 1 ||
			mcpResultText(t, mcpResult) != "all 2 transaction(s) failed" {
			t.Fatalf("MCP result = %+v, want the error text alone", mcpResult)
		}
	})
	t.Run("lost submissions", func(t *testing.T) {
		f := newSubmitFixture(t, nodeDropsSubmit)
		_, err := f.state.executeCommandResult(sweep(t, f))
		var failure *signing.SubmissionError
		if err == nil || errors.Is(err, io.EOF) || errors.As(err, &failure) {
			t.Fatalf("error %v reaches an item's error", err)
		}
		if got := appresult.SubmissionsFromError(err); len(got) != 2 {
			t.Fatalf("submissions = %+v, want both items'", got)
		}
	})
}

// JS sign() through the MCP js tool: the uncaught error keeps its text, and
// the result carries the outcome.
func TestMCPJSSignReportsASubmission(t *testing.T) {
	f := newSubmitFixture(t, nodeAcceptsSubmit)
	file := f.signFile(t)
	text, structured := mcpErrorParts(t, mcpJSExecutionResult(context.Background(), f.state, fmt.Sprintf("sign(%q)", file)))
	ids := f.signedIDs()[0]
	if len(structured.Submissions) != 1 || structured.Submissions[0].State != "submitted" ||
		!reflect.DeepEqual(structured.Submissions[0].TxIDs, ids) {
		t.Fatalf("submissions = %+v, want submitted %v", structured.Submissions, ids)
	}
	if !strings.HasPrefix(structured.Error, "sign() error: confirmation failed: wait for transaction id "+ids[0]+" timed out\n") ||
		!strings.HasPrefix(text, structured.Error) {
		t.Fatalf("error %q, text %q", structured.Error, text)
	}
}

// The MCP js tool reports every submission failure the script's functions
// threw, including those the script caught: on a successful result, and with
// a later uncaught one on the error result. The caught Error names the
// submission for the script.
func TestMCPJSReportsCaughtSubmissions(t *testing.T) {
	send := func(f *submitFixture) string { return fmt.Sprintf("send(%q, %q, 1000)", f.a.Address, f.b.Address) }
	t.Run("caught", func(t *testing.T) {
		f := newSubmitFixture(t, nodeDropsSubmit)
		result := mcpJSExecutionResult(context.Background(), f.state,
			`var seen; try { `+send(f)+` } catch (e) { seen = e.submission + " " + e.txids.join(",") } seen`)
		if result.IsError {
			t.Fatalf("result = %+v, want success", result)
		}
		var got mcpJSResult
		if err := json.Unmarshal([]byte(mcpResultText(t, result)), &got); err != nil {
			t.Fatal(err)
		}
		ids := f.signedIDs()[0]
		if got.Value != "unknown "+strings.Join(ids, ",") {
			t.Fatalf("the script read %v from the error, want its state and IDs %v", got.Value, ids)
		}
		if len(got.Submissions) != 1 || got.Submissions[0].State != "unknown" || !reflect.DeepEqual(got.Submissions[0].TxIDs, ids) {
			t.Fatalf("submissions = %+v, want the caught one for %v", got.Submissions, ids)
		}
	})
	t.Run("caught, then uncaught", func(t *testing.T) {
		f := newSubmitFixture(t, nodeDropsSubmit)
		text, structured := mcpErrorParts(t, mcpJSExecutionResult(context.Background(), f.state,
			`try { `+send(f)+` } catch (e) {} `+send(f)))
		wantJSSubmissions(t, f, text, structured, 2)
	})
}

// The REPL is unchanged: it returns the error text it printed before, and
// prints the submission output that lists the IDs, never the MCP sentence.
func TestREPLSubmissionFailureOutputIsUnchanged(t *testing.T) {
	f := newSubmitFixture(t, nodeDropsSubmit)
	var out bytes.Buffer
	f.state.SetOutput(&out)
	cmd, err := parseShellCommand(fmt.Sprintf("send 0.001 algo from %s to [%s %s] atomic", f.a.Address, f.b.Address, f.c.Address))
	if err != nil {
		t.Fatal(err)
	}
	err = f.state.executeCommand(cmd)
	if err == nil || !strings.HasPrefix(err.Error(), "atomic transaction group failed: failed to sign and submit atomic group: failed to submit transaction group: ") {
		t.Fatalf("executeCommand() error = %v", err)
	}
	ids := f.signedIDs()[0]
	if strings.Contains(err.Error(), ids[0]) || strings.Contains(out.String(), "Check these IDs") ||
		strings.Contains(out.String(), "Submission outcome") {
		t.Fatalf("REPL error %q, output %q: the REPL changed", err, out.String())
	}
}

// A plugin's default draft, which apsigner signs, under MCP: the plugin
// result stays a result (success false), and carries the failed step's
// outcome in submissions.
func TestMCPPluginDraftReportsASubmission(t *testing.T) {
	f := newSubmitFixture(t, nodeDropsSubmit)
	txn, err := transaction.MakePaymentTxn(f.a.Address.String(), f.b.Address.String(), 1000, nil, "", types.SuggestedParams{
		Fee: 1000, FirstRoundValid: 1000, LastRoundValid: 1900, GenesisHash: f.genesis, GenesisID: "testnet-v1.0", FlatFee: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	state, _ := scriptedPluginShellOnEngine(t, f.eng, map[string]any{
		"success": true, "message": "pay",
		"transactions": []map[string]any{{"type": "raw", "encoded": base64.StdEncoding.EncodeToString(msgpack.Encode(txn))}},
	})
	result := mcpExecuteCommand(state, Command{Name: "wf", Args: []string{"start"}})
	if result.IsError {
		t.Fatalf("result = %+v, want a plugin result", result)
	}
	var got appresult.Plugin
	if err := json.Unmarshal([]byte(mcpResultText(t, result)), &got); err != nil {
		t.Fatal(err)
	}
	signed := f.signedIDs()
	if got.Success || len(signed) != 1 || len(got.Submissions) != 1 || got.Submissions[0].State != "unknown" ||
		!reflect.DeepEqual(got.Submissions[0].TxIDs, signed[0]) {
		t.Fatalf("plugin result = %+v, want the step's unknown outcome for %v", got, signed)
	}
}

// Every JS function that submits throws its submission failure through one
// helper (jsapi's throwSubmitError), so the MCP js tool reports the outcome
// for each. A function that threw a string instead would leave the result
// without structured content.
func TestMCPJSSubmittersReportALostSubmission(t *testing.T) {
	abi := filepath.Join(t.TempDir(), "contract.json")
	if err := os.WriteFile(abi, []byte(`{"name":"t","methods":[{"name":"ping","args":[],"returns":{"type":"void"}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		code   func(f *submitFixture, t *testing.T) string
		groups int
	}{
		{name: "validate", code: func(f *submitFixture, t *testing.T) string { return fmt.Sprintf("validate(%q)", f.a.Address) }},
		{name: "send", code: func(f *submitFixture, t *testing.T) string {
			return fmt.Sprintf("send(%q, %q, 1000)", f.a.Address, f.b.Address)
		}},
		{name: "sweep", groups: 2, code: func(f *submitFixture, t *testing.T) string {
			return fmt.Sprintf("sweep([%q, %q], %q)", f.a.Address, f.c.Address, f.b.Address)
		}},
		{name: "sendAsset", code: func(f *submitFixture, t *testing.T) string {
			return fmt.Sprintf("sendAsset(%q, %q, %d, 0)", f.a.Address, f.a.Address, submitTestAsset)
		}},
		{name: "optIn", code: func(f *submitFixture, t *testing.T) string {
			return fmt.Sprintf("optIn(%q, %d)", f.a.Address, submitTestAsset)
		}},
		{name: "optOut", code: func(f *submitFixture, t *testing.T) string {
			return fmt.Sprintf("optOut(%q, %d)", f.a.Address, submitTestAsset)
		}},
		{name: "keyreg", code: func(f *submitFixture, t *testing.T) string {
			return fmt.Sprintf("keyreg(%q, \"offline\")", f.a.Address)
		}},
		{name: "rekey", code: func(f *submitFixture, t *testing.T) string {
			return fmt.Sprintf("rekey(%q, %q)", f.a.Address, f.b.Address)
		}},
		{name: "unrekey", code: func(f *submitFixture, t *testing.T) string { return fmt.Sprintf("unrekey(%q)", f.r) }},
		{name: "close", code: func(f *submitFixture, t *testing.T) string {
			return fmt.Sprintf("close(%q, %q)", f.c.Address, f.b.Address)
		}},
		{name: "sign", code: func(f *submitFixture, t *testing.T) string { return fmt.Sprintf("sign(%q)", f.signFile(t)) }},
		{name: "atomicSend", code: func(f *submitFixture, t *testing.T) string {
			return fmt.Sprintf("atomicSend([{from: %q, to: %q, amount: 1000}, {from: %q, to: %q, amount: 1000}])", f.a.Address, f.b.Address, f.c.Address, f.b.Address)
		}},
		{name: "atomicSendAsset", code: func(f *submitFixture, t *testing.T) string {
			return fmt.Sprintf("atomicSendAsset([{from: %q, to: %q, assetId: %d, amount: 0, note: \"1\"}, {from: %q, to: %q, assetId: %d, amount: 0, note: \"2\"}])",
				f.a.Address, f.a.Address, submitTestAsset, f.a.Address, f.a.Address, submitTestAsset)
		}},
		{name: "appDeploy", code: func(f *submitFixture, t *testing.T) string {
			bin := f.approvalBin(t)
			return fmt.Sprintf("appDeploy(%q, %q, %q, {approvalCompiled: true, clearCompiled: true})", f.a.Address, bin, bin)
		}},
		{name: "appCallRaw", code: func(f *submitFixture, t *testing.T) string {
			return fmt.Sprintf("appCallRaw(%d, %q, [])", submitTestApp, f.a.Address)
		}},
		{name: "appCallRaw grouped", code: func(f *submitFixture, t *testing.T) string {
			return fmt.Sprintf("appCallRaw(%d, %q, [], {pay: 100000})", submitTestApp, f.a.Address)
		}},
		{name: "appCall", code: func(f *submitFixture, t *testing.T) string {
			return fmt.Sprintf("appCall(%d, \"ping()void\", %q, %q, [])", submitTestApp, abi, f.a.Address)
		}},
		{name: "appCall grouped", code: func(f *submitFixture, t *testing.T) string {
			return fmt.Sprintf("appCall(%d, \"ping()void\", %q, %q, [], {pay: 100000})", submitTestApp, abi, f.a.Address)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSubmitFixture(t, nodeDropsSubmit)
			text, structured := mcpErrorParts(t, mcpJSExecutionResult(context.Background(), f.state, tc.code(f, t)))
			wantJSSubmissions(t, f, text, structured, max(tc.groups, 1))
		})
	}
	t.Run("plugin", func(t *testing.T) {
		f := newSubmitFixture(t, nodeDropsSubmit)
		txn, err := transaction.MakePaymentTxn(f.a.Address.String(), f.b.Address.String(), 1000, nil, "", types.SuggestedParams{
			Fee: 1000, FirstRoundValid: 1000, LastRoundValid: 1900, GenesisHash: f.genesis, GenesisID: "testnet-v1.0", FlatFee: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		state, _ := scriptedPluginShellOnEngine(t, f.eng, map[string]any{
			"success": true, "message": "pay",
			"transactions": []map[string]any{{"type": "raw", "encoded": base64.StdEncoding.EncodeToString(msgpack.Encode(txn))}},
		})
		text, structured := mcpErrorParts(t, mcpJSExecutionResult(context.Background(), state, `plugin("wf", "start")`))
		wantJSSubmissions(t, f, text, structured, 1)
	})
}

func wantJSSubmissions(t *testing.T, f *submitFixture, text string, structured mcpErrorJSON, groups int) {
	t.Helper()
	signed := f.signedIDs()
	if len(signed) != groups || len(structured.Submissions) != groups {
		t.Fatalf("signed %v, submissions %+v, want %d (error %q)", signed, structured.Submissions, groups, structured.Error)
	}
	for i, submission := range structured.Submissions {
		if submission.State != "unknown" || !reflect.DeepEqual(submission.TxIDs, signed[i]) || !strings.Contains(text, submission.Message) {
			t.Fatalf("submission %d = %+v, want unknown for %v, in the text %q", i, submission, signed[i], text)
		}
	}
	if strings.Contains(structured.Error, "GoError") {
		t.Fatalf("error text %q changed", structured.Error)
	}
}

// A 400 for a transaction already in the ledger, as a resubmission of the
// same signed file after an unknown outcome gets, is "rejected": algod
// answered with an error. Nothing says the transactions are not on the
// network, and algod's reason is handed over as it is.
func TestMCPRejectedSubmissionDoesNotClaimNotSubmitted(t *testing.T) {
	f := newSubmitFixture(t, nodeHasTheGroup)
	cmd, err := parseShellCommand("sign " + f.signFile(t))
	if err != nil {
		t.Fatal(err)
	}
	text, structured := mcpErrorParts(t, mcpExecuteCommand(f.state, cmd))
	got := structured.Submissions[0]
	if got.State != "rejected" || got.Submitted || !reflect.DeepEqual(got.TxIDs, f.signedIDs()[0]) ||
		!strings.Contains(got.Error, "transaction already in ledger") {
		t.Fatalf("submission = %+v, want rejected with algod's reason", got)
	}
	for _, claim := range []string{"not submitted", "refused"} {
		if strings.Contains(strings.ToLower(got.Message), claim) || strings.Contains(strings.ToLower(text), claim) {
			t.Fatalf("message %q / text %q claims %q", got.Message, text, claim)
		}
	}
}
