// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	pluginmanager "github.com/aplane-algo/aplane/internal/plugin/manager"
	"github.com/aplane-algo/aplane/internal/plugin/manifest"
	"github.com/aplane-algo/aplane/internal/signing"
)

// scriptedPlugin answers each execute call with the next of its results and
// records the parameters it was called with.
type scriptedPlugin struct {
	mu      sync.Mutex
	results []map[string]any
	calls   []jsonrpc.ExecuteParams
}

func (p *scriptedPlugin) executeCalls() []jsonrpc.ExecuteParams {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]jsonrpc.ExecuteParams(nil), p.calls...)
}

func (p *scriptedPlugin) instance(t *testing.T, plugin *discovery.Plugin) *pluginmanager.Instance {
	t.Helper()
	cmd := exec.Command("sh", "-c", "cat >/dev/null")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe() error = %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe() error = %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("StderrPipe() error = %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start() error = %v", err)
	}
	serverToClientReader, serverToClientWriter := io.Pipe()
	clientToServerReader, clientToServerWriter := io.Pipe()
	client := jsonrpc.NewClient(serverToClientReader, clientToServerWriter)
	client.Start()

	go func() {
		dec := json.NewDecoder(clientToServerReader)
		enc := json.NewEncoder(serverToClientWriter)
		for {
			var req struct {
				ID     any             `json:"id"`
				Method string          `json:"method"`
				Params json.RawMessage `json:"params"`
			}
			if err := dec.Decode(&req); err != nil {
				_ = clientToServerReader.Close()
				_ = serverToClientWriter.Close()
				return
			}
			result := map[string]any{"success": true, "version": "1.0.0"}
			if req.Method == jsonrpc.MethodExecute {
				var params jsonrpc.ExecuteParams
				_ = json.Unmarshal(req.Params, &params)
				p.mu.Lock()
				n := len(p.calls)
				p.calls = append(p.calls, params)
				p.mu.Unlock()
				result = map[string]any{"success": false, "message": "no scripted result left"}
				if n < len(p.results) {
					result = p.results[n]
				}
			}
			_ = enc.Encode(map[string]any{"jsonrpc": jsonrpc.Version, "id": req.ID, "result": result})
			if req.Method == jsonrpc.MethodShutdown {
				return
			}
		}
	}()
	return pluginmanager.NewTestInstanceForHooks(plugin, cmd, client, stdin, stdout, stderr, time.Now())
}

// scriptedPluginShell is a shell with one plugin, "workflow", whose command
// "wf" answers with results in order.
func scriptedPluginShell(t *testing.T, results ...map[string]any) (*REPLState, *scriptedPlugin) {
	t.Helper()
	return scriptedPluginShellWithAlgod(t, nil, results...)
}

// scriptedPluginShellWithAlgod is scriptedPluginShell on an algod.
func scriptedPluginShellWithAlgod(t *testing.T, client *algod.Client, results ...map[string]any) (*REPLState, *scriptedPlugin) {
	t.Helper()
	eng, err := newIsolatedTestEngine(t, "testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.AlgodClient = client
	scripted := &scriptedPlugin{results: results}
	pm := pluginmanager.NewManager()
	var started []*pluginmanager.Instance
	pm.SetCachedPluginsForTest([]*discovery.Plugin{{
		Manifest: &manifest.Manifest{
			Name:     "workflow",
			Commands: []manifest.Command{{Name: "wf", Description: "a multi-step workflow"}},
			Timeout:  5,
		},
	}})
	pm.SetTestHooks(pluginmanager.TestHooks{
		StartPluginInstance: func(plugin *discovery.Plugin) (*pluginmanager.Instance, error) {
			inst := scripted.instance(t, plugin)
			started = append(started, inst)
			return inst, nil
		},
		InitializePlugin: func(*pluginmanager.Instance) error { return nil },
	})
	t.Cleanup(func() {
		for _, inst := range started {
			inst.Stop()
		}
	})
	state := &REPLState{
		App:             apshellapp.New(eng, config.DefaultConfig(), t.TempDir()),
		CommandRegistry: command.NewRegistry(),
		AutoConfirm:     true,
		Out:             &bytes.Buffer{},
	}
	state.App.Plugins = pm
	return state, scripted
}

func runScript(t *testing.T, state *REPLState, code string) (string, error) {
	t.Helper()
	state.ensureJSRunner()
	result, err := state.Scripts.Runner.RunWithContext(context.Background(), code)
	if err != nil {
		return "", err
	}
	value, _ := result.Value.(string)
	return value, nil
}

// plugin() follows a plugin's continuation, as the REPL and MCP do, and
// returns only after the last step, with that step's result. The
// continuation's command, arguments and context reach the plugin.
func TestJSPluginFollowsContinuations(t *testing.T) {
	state, scripted := scriptedPluginShell(t,
		map[string]any{
			"success": true, "message": "step 1",
			"continuation": map[string]any{"command": "wf", "args": []string{"_step2", "x"}, "context": map[string]any{"escrow": "E"}},
		},
		map[string]any{
			"success": true, "message": "step 2",
			"continuation": map[string]any{"command": "wf", "args": []string{"_step3"}},
		},
		map[string]any{"success": true, "message": "done", "data": map[string]any{"result": "ok"}},
	)

	out, err := runScript(t, state, `JSON.stringify(plugin("wf", "start"))`)
	if err != nil {
		t.Fatalf("plugin() error = %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("plugin() returned %q: %v", out, err)
	}
	if got["success"] != true || got["message"] != "done" || !reflect.DeepEqual(got["data"], map[string]any{"result": "ok"}) {
		t.Fatalf("plugin() = %v, want the last step's result (message done, data {result: ok})", got)
	}
	calls := scripted.executeCalls()
	if len(calls) != 3 {
		t.Fatalf("plugin executed %d step(s), want 3", len(calls))
	}
	if calls[1].Command != "wf" || !reflect.DeepEqual(calls[1].Args, []string{"_step2", "x"}) ||
		!reflect.DeepEqual(calls[1].Context.Continuation, map[string]any{"escrow": "E"}) {
		t.Fatalf("second step called with %+v, want the continuation's command, args and context", calls[1])
	}
	if calls[2].Command != "wf" || !reflect.DeepEqual(calls[2].Args, []string{"_step3"}) {
		t.Fatalf("third step called with %+v", calls[2])
	}
}

// An error in a step after the first is an error from plugin(), not a
// success that reports the first step.
func TestJSPluginErrorInALaterStepIsAnError(t *testing.T) {
	for name, step2 := range map[string]map[string]any{
		"invalid continuation": {"success": true, "continuation": map[string]any{"command": ""}},
		"transactions with success=false": {
			"success": false, "transactions": []map[string]any{{"type": "raw", "encoded": "AA=="}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			state, scripted := scriptedPluginShell(t,
				map[string]any{"success": true, "message": "step 1", "continuation": map[string]any{"command": "wf", "args": []string{"_step2"}}},
				step2,
			)
			_, err := runScript(t, state, `JSON.stringify(plugin("wf", "start"))`)
			if err == nil || !strings.Contains(err.Error(), "plugin() error") {
				t.Fatalf("plugin() error = %v, want the later step's failure as an error", err)
			}
			if got := len(scripted.executeCalls()); got != 2 {
				t.Fatalf("plugin executed %d step(s), want 2", got)
			}
		})
	}
}

// pluginTestGenesis is the network the confirmation-test algod serves.
var pluginTestGenesis = bytes.Repeat([]byte{7}, 32)

// pregroupedStep is a plugin step returning a signed, grouped pair of
// self-payments for the test network, and the pair's transaction IDs.
func pregroupedStep(t *testing.T, note string, continuation map[string]any) (map[string]any, []string) {
	t.Helper()
	acct := crypto.GenerateAccount()
	sp := types.SuggestedParams{Fee: 1000, FirstRoundValid: 1, LastRoundValid: 1001,
		GenesisHash: pluginTestGenesis, GenesisID: "plugin-test", FlatFee: true}
	txns := make([]types.Transaction, 2)
	for i := range txns {
		txn, err := transaction.MakePaymentTxn(acct.Address.String(), acct.Address.String(), 0, []byte(note+string(rune('a'+i))), "", sp)
		if err != nil {
			t.Fatalf("make txn: %v", err)
		}
		txns[i] = txn
	}
	gid, err := crypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatalf("compute group id: %v", err)
	}
	intents := make([]map[string]any, len(txns))
	ids := make([]string, len(txns))
	for i := range txns {
		txns[i].Group = gid
		_, raw, err := signing.SignTransactionWithKey(acct.PrivateKey, txns[i])
		if err != nil {
			t.Fatalf("sign txn: %v", err)
		}
		intents[i] = map[string]any{"type": "signed", "encoded": base64.StdEncoding.EncodeToString(raw)}
		ids[i] = crypto.GetTxID(txns[i])
	}
	step := map[string]any{"success": true, "message": note, "groupMode": "pregrouped-signed", "transactions": intents}
	if continuation != nil {
		step["continuation"] = continuation
	}
	return step, ids
}

// confirmationFailingAlgod accepts every group and confirms the first
// confirmedGroups of them; for every later group the wait for confirmation
// fails, after the group was accepted. It counts the groups sent.
func confirmationFailingAlgod(t *testing.T, confirmedGroups int32) (*algod.Client, *atomic.Int32) {
	t.Helper()
	var sent atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/transactions/params":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
				ConsensusVersion: string(protocol.ConsensusV42), MinFee: 1000, LastRound: 10,
				GenesisHash: pluginTestGenesis, GenesisId: "plugin-test",
			})
		case r.URL.Path == "/v2/transactions" && r.Method == http.MethodPost:
			sent.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"txId": "accepted"})
		case r.URL.Path == "/v2/status":
			if sent.Load() > confirmedGroups {
				http.Error(w, "status unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(models.NodeStatus{LastRound: 10})
		case strings.HasPrefix(r.URL.Path, "/v2/transactions/pending/"):
			w.Header().Set("Content-Type", "application/msgpack")
			_, _ = w.Write(msgpack.Encode(models.PendingTransactionInfoResponse{ConfirmedRound: 11}))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client, err := algod.MakeClient(server.URL, "")
	if err != nil {
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	return client, &sent
}

// After a failure, plugin() lists every transaction ID the run produced, the
// failing step's included when its submission returned IDs with its error, in
// one list, and says to look them up. It says nothing of what became of them.
func TestJSPluginListsTheRunsTransactionIDsAfterAFailure(t *testing.T) {
	const lookUp = ": look them up before running it again"
	t.Run("first step", func(t *testing.T) {
		step, ids := pregroupedStep(t, "fund", nil)
		client, sent := confirmationFailingAlgod(t, 0)
		state, _ := scriptedPluginShellWithAlgod(t, client, step)
		state.AutoConfirm, state.LineReader = false, func() (string, error) { return "y", nil }

		_, err := runScript(t, state, `plugin("wf", "start")`)
		if sent.Load() != 1 {
			t.Fatalf("groups sent = %d, want 1", sent.Load())
		}
		if err == nil || !strings.Contains(err.Error(), "confirmation failed") ||
			!strings.Contains(err.Error(), "; this run produced transaction(s) "+strings.Join(ids, ", ")+lookUp) {
			t.Fatalf("plugin() error = %v, want the failure listing %v", err, ids)
		}
	})
	t.Run("later step", func(t *testing.T) {
		second, secondIDs := pregroupedStep(t, "claim", nil)
		first, firstIDs := pregroupedStep(t, "fund", map[string]any{"command": "wf", "args": []string{"_claim"}})
		client, sent := confirmationFailingAlgod(t, 1)
		state, _ := scriptedPluginShellWithAlgod(t, client, first, second)
		state.AutoConfirm, state.LineReader = false, func() (string, error) { return "y", nil }

		_, err := runScript(t, state, `plugin("wf", "start")`)
		if sent.Load() != 2 {
			t.Fatalf("groups sent = %d, want 2", sent.Load())
		}
		all := strings.Join(append(append([]string(nil), firstIDs...), secondIDs...), ", ")
		if err == nil || !strings.Contains(err.Error(), "; this run produced transaction(s) "+all+lookUp) {
			t.Fatalf("plugin() error = %v, want both steps' IDs in one list (%s)", err, all)
		}
	})
}

// The REPL and MCP record a failed run as main does: the steps that completed
// their submission, and nothing of the failing step, whose IDs come back with
// its error. A run of one step is reported at the top level only when it
// completes.
func TestPluginRunRecordOfAFailedRunIsUnchanged(t *testing.T) {
	project := func(t *testing.T, pr *PluginResult) map[string]any {
		t.Helper()
		var got map[string]any
		if err := json.Unmarshal(appresult.Marshal(projectPluginResult(pr)), &got); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		return got
	}
	t.Run("one step", func(t *testing.T) {
		step, _ := pregroupedStep(t, "fund", nil)
		client, _ := confirmationFailingAlgod(t, 0)
		state, _ := scriptedPluginShellWithAlgod(t, client, step)
		state.AutoConfirm, state.LineReader = false, func() (string, error) { return "y", nil }

		pr, _ := execPlugin(state, "wf", []string{"start"})
		got := project(t, pr)
		want := map[string]any{"plugin": "workflow", "success": false, "message": pr.Message}
		if !reflect.DeepEqual(got, want) || !strings.Contains(pr.Message, "confirmation failed") {
			t.Fatalf("MCP result = %v, want %v", got, want)
		}
	})
	t.Run("later step", func(t *testing.T) {
		second, _ := pregroupedStep(t, "claim", nil)
		first, firstIDs := pregroupedStep(t, "fund", map[string]any{"command": "wf", "args": []string{"_claim"}})
		client, _ := confirmationFailingAlgod(t, 1)
		state, _ := scriptedPluginShellWithAlgod(t, client, first, second)
		state.AutoConfirm, state.LineReader = false, func() (string, error) { return "y", nil }

		pr, _ := execPlugin(state, "wf", []string{"start"})
		got := project(t, pr)
		ids := make([]any, len(firstIDs))
		for i, id := range firstIDs {
			ids[i] = id
		}
		want := map[string]any{"plugin": "workflow", "success": false, "message": pr.Message,
			"steps": []any{map[string]any{"message": "fund", "txids": ids}}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("MCP result = %v, want %v", got, want)
		}
	})
}

// simulationFailingAlgod simulates the first okGroups groups and fails every
// later simulation; it counts the simulations and anything sent for real.
func simulationFailingAlgod(t *testing.T, okGroups int32) (*algod.Client, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var simulated, sent atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2/transactions/params":
			_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
				ConsensusVersion: string(protocol.ConsensusV42), MinFee: 1000, LastRound: 10,
				GenesisHash: pluginTestGenesis, GenesisId: "plugin-test",
			})
		case "/v2/transactions/simulate":
			group := models.SimulateTransactionGroupResult{TxnResults: make([]models.SimulateTransactionResult, 2)}
			if simulated.Add(1) > okGroups {
				group.FailureMessage = "logic eval error"
			}
			_ = json.NewEncoder(w).Encode(models.SimulateResponse{LastRound: 10, TxnGroups: []models.SimulateTransactionGroupResult{group}})
		case "/v2/transactions":
			sent.Add(1)
			http.Error(w, "nothing may be sent in simulate mode", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client, err := algod.MakeClient(server.URL, "")
	if err != nil {
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	return client, &simulated, &sent
}

// In simulate mode nothing is sent. plugin() names the transactions of the
// steps simulated as simulated, not sent, and does not list a failed
// simulation's own IDs; the REPL and MCP record no step for it.
func TestJSPluginInSimulateMode(t *testing.T) {
	t.Run("one step", func(t *testing.T) {
		step, ids := pregroupedStep(t, "fund", nil)
		client, simulated, sent := simulationFailingAlgod(t, 0)
		state, _ := scriptedPluginShellWithAlgod(t, client, step, step)
		state.App.SetSimulateMode(true)
		state.AutoConfirm, state.LineReader = false, func() (string, error) { return "y", nil }

		_, err := runScript(t, state, `plugin("wf", "start")`)
		if err == nil || strings.Contains(err.Error(), ids[0]) || strings.Contains(err.Error(), "this run") {
			t.Fatalf("plugin() error = %v, want the simulation failure with no IDs listed", err)
		}
		pr, _ := execPlugin(state, "wf", []string{"start"})
		if pr.Success || pr.TxIDs != nil || pr.Steps != nil {
			t.Fatalf("result = %+v, want a failure that records no step", pr.Plugin)
		}
		if simulated.Load() != 2 || sent.Load() != 0 {
			t.Fatalf("simulations = %d, sent = %d, want 2 and 0", simulated.Load(), sent.Load())
		}
	})
	t.Run("later step", func(t *testing.T) {
		second, secondIDs := pregroupedStep(t, "claim", nil)
		first, firstIDs := pregroupedStep(t, "fund", map[string]any{"command": "wf", "args": []string{"_claim"}})
		client, _, sent := simulationFailingAlgod(t, 1)
		state, _ := scriptedPluginShellWithAlgod(t, client, first, second)
		state.App.SetSimulateMode(true)
		state.AutoConfirm, state.LineReader = false, func() (string, error) { return "y", nil }

		_, err := runScript(t, state, `plugin("wf", "start")`)
		if sent.Load() != 0 {
			t.Fatalf("sent = %d, want 0", sent.Load())
		}
		if err == nil || !strings.Contains(err.Error(), "; this run simulated transaction(s) "+strings.Join(firstIDs, ", ")+", which were not sent") ||
			strings.Contains(err.Error(), secondIDs[0]) {
			t.Fatalf("plugin() error = %v, want only %v named, as simulated", err, firstIDs)
		}
	})
}

// A completed run's data.steps entries are exactly { message, txids }, as
// USER_JSAPI.md documents, and data.txids lists every ID in order.
func TestJSPluginDataStepsHoldOnlyMessageAndTxIDs(t *testing.T) {
	second, secondIDs := pregroupedStep(t, "claim", nil)
	first, firstIDs := pregroupedStep(t, "fund", map[string]any{"command": "wf", "args": []string{"_claim"}})
	client, _ := confirmationFailingAlgod(t, 2)
	state, _ := scriptedPluginShellWithAlgod(t, client, first, second)
	state.AutoConfirm, state.LineReader = false, func() (string, error) { return "y", nil }

	out, err := runScript(t, state, `
		let r = plugin("wf", "start")
		JSON.stringify({keys: r.data.steps.map(s => Object.keys(s).sort()), txids: r.data.txids})`)
	if err != nil {
		t.Fatalf("plugin() error = %v", err)
	}
	var got struct {
		Keys  [][]string `json:"keys"`
		TxIDs []string   `json:"txids"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("plugin() returned %q: %v", out, err)
	}
	if !reflect.DeepEqual(got.Keys, [][]string{{"message", "txids"}, {"message", "txids"}}) {
		t.Fatalf("data.steps keys = %v, want [message txids] for each step", got.Keys)
	}
	if want := append(append([]string(nil), firstIDs...), secondIDs...); !reflect.DeepEqual(got.TxIDs, want) {
		t.Fatalf("data.txids = %v, want %v", got.TxIDs, want)
	}
}

// A read-only plugin command that returns an empty data object hands the
// script an empty object, not undefined: only localSigners is removed.
func TestJSPluginKeepsAnEmptyDataObject(t *testing.T) {
	state, _ := scriptedPluginShell(t,
		map[string]any{"success": true, "message": "status", "data": map[string]any{}},
		map[string]any{"success": true, "message": "status", "data": map[string]any{"localSigners": []any{"X"}}},
	)
	for i := 0; i < 2; i++ {
		out, err := runScript(t, state, `JSON.stringify(plugin("wf", "status").data)`)
		if err != nil {
			t.Fatalf("run %d: plugin() error = %v", i, err)
		}
		if out != "{}" {
			t.Fatalf("run %d: plugin().data = %s, want {}", i, out)
		}
	}
}

// Once the run has produced transaction IDs, a step that fails, is cancelled
// or reports failure is an error that lists them in one list and says to look
// them up, the failing step's own IDs included; in simulate mode the
// simulated ones are named as not sent and a failed simulation's own IDs are
// not listed. Before any IDs, a cancel or the plugin's failure is still a
// {success: false} result. A finished run reports every ID. A plugin's data
// never carries localSigners, and an object stays an object.
func TestJSPluginOutcome(t *testing.T) {
	twoSteps := []appresult.PluginStep{{Message: "fund", TxIDs: []string{"T1"}}, {Message: "claim", TxIDs: []string{"T2", "T3"}}}
	later := errors.New("continuation failed: plugin crashed")
	const lookUp = ": look them up before running it again"
	tests := []struct {
		name        string
		pr          PluginResult
		runErr      error
		simulated   bool
		wantErr     string // the whole error
		wantSuccess bool
		wantMessage string
		wantData    any // compared when set or when wantNoData
		wantNoData  bool
	}{
		{name: "later step fails", pr: PluginResult{Plugin: appresult.Plugin{Steps: twoSteps[:1]}}, runErr: later,
			wantErr: "continuation failed: plugin crashed; this run produced transaction(s) T1" + lookUp},
		{name: "failing step returned IDs", pr: PluginResult{Plugin: appresult.Plugin{Steps: twoSteps[:1]}, failedStepTxIDs: []string{"T2", "T3"}},
			runErr:  errors.New("confirmation failed: timed out"),
			wantErr: "confirmation failed: timed out; this run produced transaction(s) T1, T2, T3" + lookUp},
		{name: "first step returned IDs", pr: PluginResult{failedStepTxIDs: []string{"T1"}},
			runErr:  errors.New("confirmation failed: timed out"),
			wantErr: "confirmation failed: timed out; this run produced transaction(s) T1" + lookUp},
		{name: "later step fails, simulated", pr: PluginResult{Plugin: appresult.Plugin{Steps: twoSteps[:1]}, failedStepTxIDs: []string{"T2"}},
			runErr: later, simulated: true,
			wantErr: "continuation failed: plugin crashed; this run simulated transaction(s) T1, which were not sent"},
		{name: "first simulation fails", pr: PluginResult{failedStepTxIDs: []string{"T1"}}, runErr: errors.New("simulation failed"),
			simulated: true, wantErr: "simulation failed"},
		{name: "later step cancelled", pr: PluginResult{Plugin: appresult.Plugin{Steps: twoSteps[:1]}}, runErr: errPluginTransactionCancelled,
			wantErr: "transaction cancelled by user; this run produced transaction(s) T1" + lookUp},
		{name: "last step reports failure", pr: PluginResult{Plugin: appresult.Plugin{Success: false, Message: "no counterparty", TxIDs: []string{"T1"}}},
			wantErr: "plugin reported failure: no counterparty; this run produced transaction(s) T1" + lookUp},
		{name: "first step cancelled", runErr: errPluginTransactionCancelled,
			wantMessage: "Transaction cancelled by user"},
		{name: "first step fails", runErr: errors.New("not connected to signer"), wantErr: "not connected to signer"},
		{name: "plugin's own failure, nothing produced", pr: PluginResult{Plugin: appresult.Plugin{Success: false, Message: "bad input"}},
			wantMessage: "bad input"},
		{name: "nothing produced, data filtered", pr: PluginResult{Plugin: appresult.Plugin{Success: true, Message: "status",
			Data: map[string]any{"amount": 1, "localSigners": []any{"X"}}}},
			wantSuccess: true, wantMessage: "status", wantData: map[string]any{"amount": 1}},
		{name: "nothing produced, only localSigners", pr: PluginResult{Plugin: appresult.Plugin{Success: true, Message: "status",
			Data: map[string]any{"localSigners": []any{"X"}}}},
			wantSuccess: true, wantMessage: "status", wantData: map[string]any{}},
		{name: "nothing produced, empty data", pr: PluginResult{Plugin: appresult.Plugin{Success: true, Message: "status",
			Data: map[string]any{}}},
			wantSuccess: true, wantMessage: "status", wantData: map[string]any{}},
		{name: "nothing produced, no data", pr: PluginResult{Plugin: appresult.Plugin{Success: true, Message: "status"}},
			wantSuccess: true, wantMessage: "status", wantNoData: true},
		{name: "nothing produced, data not an object", pr: PluginResult{Plugin: appresult.Plugin{Success: true, Message: "status",
			Data: "plain"}},
			wantSuccess: true, wantMessage: "status", wantData: "plain"},
		{name: "one step", pr: PluginResult{Plugin: appresult.Plugin{Success: true, Message: "ok", TxIDs: []string{"T1"},
			Data: map[string]any{"escrow": "E", "txids": "forged", "localSigners": []any{"X"}}}},
			wantSuccess: true, wantMessage: "ok", wantData: map[string]any{"escrow": "E", "txids": []string{"T1"}}},
		{name: "two steps", pr: PluginResult{Plugin: appresult.Plugin{Success: true, Message: "claimed", Steps: twoSteps}},
			wantSuccess: true, wantMessage: "claimed", wantData: map[string]any{"txids": []string{"T1", "T2", "T3"}, "steps": twoSteps}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			success, message, data, _, err := jsPluginOutcome(&tt.pr, tt.runErr, tt.simulated)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("outcome = (%v, %q, %v, %v), want the error %q", success, message, data, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			if success != tt.wantSuccess || message != tt.wantMessage {
				t.Fatalf("outcome = (%v, %q), want (%v, %q)", success, message, tt.wantSuccess, tt.wantMessage)
			}
			if (tt.wantData != nil || tt.wantNoData) && !reflect.DeepEqual(data, tt.wantData) {
				t.Fatalf("data = %#v, want %#v", data, tt.wantData)
			}
		})
	}
}
