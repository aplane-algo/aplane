// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package signing

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// ErrSimulationFailed indicates the simulate endpoint reported a transaction failure.
// Details are already printed to the console by SimulateTransactions.
var ErrSimulationFailed = errors.New("simulation failed")

// SimulateTransactions simulates signed transactions via the algod simulate endpoint
// instead of submitting them to the network. This allows dry-run testing of the full
// signing flow without affecting on-chain state.
//
// Returns transaction IDs and an error. Returns ErrSimulationFailed when the
// simulation itself succeeds but the transaction would fail on-chain (e.g.,
// insufficient balance). Details are printed to the console.
func SimulateTransactions(
	signedTxns [][]byte,
	algodClient *algod.Client,
) ([]string, error) {
	if len(signedTxns) == 0 {
		return nil, fmt.Errorf("no signed transactions to simulate")
	}

	fmt.Println("\nSimulating transaction...")

	// Decode signed transactions and compute transaction IDs
	decodedTxns := make([]types.SignedTxn, len(signedTxns))
	txIDs := make([]string, len(signedTxns))
	for i, signedTxn := range signedTxns {
		var stxn types.SignedTxn
		if err := msgpack.Decode(signedTxn, &stxn); err != nil {
			return nil, fmt.Errorf("failed to decode signed transaction %d: %w", i+1, err)
		}
		decodedTxns[i] = stxn
		txIDs[i] = crypto.GetTxID(stxn.Txn)
	}

	// Build simulate request with execution trace enabled
	req := models.SimulateRequest{
		TxnGroups: []models.SimulateRequestTransactionGroup{
			{Txns: decodedTxns},
		},
		AllowMoreLogging: true,
		ExecTraceConfig: models.SimulateTraceConfig{
			Enable:      true,
			StateChange: true,
		},
	}

	// Call simulate endpoint; fall back without trace if the node doesn't support it
	resp, err := algodClient.SimulateTransaction(req).Do(context.Background())
	if err != nil {
		// Retry without trace config — older nodes may reject ExecTraceConfig
		req.ExecTraceConfig = models.SimulateTraceConfig{}
		req.AllowMoreLogging = false
		resp, err = algodClient.SimulateTransaction(req).Do(context.Background())
		if err != nil {
			return nil, fmt.Errorf("simulation API call failed: %w", err)
		}
	}

	// Process results
	if len(resp.TxnGroups) == 0 {
		fmt.Println("Warning: simulation returned no transaction group results")
		return txIDs, nil
	}

	group := resp.TxnGroups[0]
	failed := group.FailureMessage != ""

	// Pass/fail status
	if failed {
		fmt.Printf("\n✗ Simulation FAILED (round %d)\n", resp.LastRound)
		fmt.Printf("  Reason: %s\n", group.FailureMessage)
		if len(group.FailedAt) > 0 {
			fmt.Printf("  Failed at: %s\n", formatFailedAt(group.FailedAt))
		}
	} else {
		fmt.Printf("\n✓ Simulation successful (round %d)\n", resp.LastRound)
	}

	// Transaction IDs
	fmt.Println("\nTransaction IDs:")
	for i, txID := range txIDs {
		fmt.Printf("  %d. %s\n", i+1, txID)
	}

	// Group-level app budget
	if group.AppBudgetAdded > 0 || group.AppBudgetConsumed > 0 {
		fmt.Printf("\nApp budget: %d consumed / %d added\n", group.AppBudgetConsumed, group.AppBudgetAdded)
	}

	// Per-transaction details
	for i, txnResult := range group.TxnResults {
		details := formatTxnDetails(i, txnResult)
		if details != "" {
			fmt.Print(details)
		}
	}

	if failed {
		return txIDs, ErrSimulationFailed
	}
	return txIDs, nil
}

// formatTxnDetails formats per-transaction simulation details including
// budget, logs, state deltas, inner transactions, and execution trace.
func formatTxnDetails(idx int, result models.SimulateTransactionResult) string {
	var b strings.Builder
	hasContent := false

	header := func() {
		if !hasContent {
			fmt.Fprintf(&b, "\n  Txn %d:\n", idx+1)
			hasContent = true
		}
	}

	// Budget info
	if result.LogicSigBudgetConsumed > 0 {
		header()
		fmt.Fprintf(&b, "    LogicSig budget consumed: %d\n", result.LogicSigBudgetConsumed)
	}
	if result.AppBudgetConsumed > 0 {
		header()
		fmt.Fprintf(&b, "    App budget consumed: %d\n", result.AppBudgetConsumed)
	}

	// App logs
	if len(result.TxnResult.Logs) > 0 {
		header()
		fmt.Fprintf(&b, "    Logs (%d):\n", len(result.TxnResult.Logs))
		for j, log := range result.TxnResult.Logs {
			fmt.Fprintf(&b, "      [%d] %s\n", j, formatLogEntry(log))
		}
	}

	// Global state delta
	if len(result.TxnResult.GlobalStateDelta) > 0 {
		header()
		fmt.Fprintf(&b, "    Global state changes:\n")
		for _, kv := range result.TxnResult.GlobalStateDelta {
			fmt.Fprintf(&b, "      %s\n", formatEvalDelta(kv))
		}
	}

	// Local state delta
	if len(result.TxnResult.LocalStateDelta) > 0 {
		header()
		fmt.Fprintf(&b, "    Local state changes:\n")
		for _, acctDelta := range result.TxnResult.LocalStateDelta {
			fmt.Fprintf(&b, "      %s:\n", shortAddr(acctDelta.Address))
			for _, kv := range acctDelta.Delta {
				fmt.Fprintf(&b, "        %s\n", formatEvalDelta(kv))
			}
		}
	}

	// Inner transactions
	if len(result.TxnResult.InnerTxns) > 0 {
		header()
		fmt.Fprintf(&b, "    Inner transactions (%d):\n", len(result.TxnResult.InnerTxns))
		for j, inner := range result.TxnResult.InnerTxns {
			formatInnerTxn(&b, j, inner, "      ")
		}
	}

	// Execution trace summary
	if traceStr := formatExecTrace(result.ExecTrace, "    "); traceStr != "" {
		header()
		fmt.Fprint(&b, traceStr)
	}

	return b.String()
}

// formatExecTrace formats execution trace information concisely.
// Shows opcode counts per program type, state changes from trace, and inner traces.
func formatExecTrace(trace models.SimulationTransactionExecTrace, indent string) string {
	var b strings.Builder

	if len(trace.ApprovalProgramTrace) > 0 {
		fmt.Fprintf(&b, "%sApproval program: %d opcodes executed\n", indent, len(trace.ApprovalProgramTrace))
		formatTraceStateChanges(&b, trace.ApprovalProgramTrace, indent+"  ")
	}

	if len(trace.ClearStateProgramTrace) > 0 {
		fmt.Fprintf(&b, "%sClear-state program: %d opcodes executed\n", indent, len(trace.ClearStateProgramTrace))
		if trace.ClearStateRollback {
			fmt.Fprintf(&b, "%s  Rolled back", indent)
			if trace.ClearStateRollbackError != "" {
				fmt.Fprintf(&b, ": %s", trace.ClearStateRollbackError)
			}
			fmt.Fprintln(&b)
		}
		formatTraceStateChanges(&b, trace.ClearStateProgramTrace, indent+"  ")
	}

	if len(trace.LogicSigTrace) > 0 {
		fmt.Fprintf(&b, "%sLogicSig: %d opcodes executed\n", indent, len(trace.LogicSigTrace))
	}

	// Inner call traces
	if len(trace.InnerTrace) > 0 {
		fmt.Fprintf(&b, "%sInner call traces (%d):\n", indent, len(trace.InnerTrace))
		for i, inner := range trace.InnerTrace {
			fmt.Fprintf(&b, "%s  [%d]:\n", indent, i)
			if innerStr := formatExecTrace(inner, indent+"    "); innerStr != "" {
				fmt.Fprint(&b, innerStr)
			}
		}
	}

	return b.String()
}

// formatTraceStateChanges extracts and displays state changes from an opcode trace.
func formatTraceStateChanges(b *strings.Builder, trace []models.SimulationOpcodeTraceUnit, indent string) {
	var changes []string
	for _, unit := range trace {
		for _, sc := range unit.StateChanges {
			changes = append(changes, formatAppStateOp(sc))
		}
	}
	if len(changes) > 0 {
		fmt.Fprintf(b, "%sState changes:\n", indent)
		for _, c := range changes {
			fmt.Fprintf(b, "%s  %s\n", indent, c)
		}
	}
}

// formatAppStateOp formats an application state operation from the execution trace.
func formatAppStateOp(op models.ApplicationStateOperation) string {
	stateType := "unknown"
	switch op.AppStateType {
	case "g":
		stateType = "global"
	case "l":
		stateType = "local"
	case "b":
		stateType = "box"
	}

	key := formatKeyBytes(op.Key)

	switch op.Operation {
	case "w":
		return fmt.Sprintf("%s write %s = %s", stateType, key, formatAvmValue(op.NewValue))
	case "d":
		return fmt.Sprintf("%s delete %s", stateType, key)
	default:
		return fmt.Sprintf("%s %s %s", stateType, op.Operation, key)
	}
}

// formatAvmValue formats an AVM value for display.
func formatAvmValue(v models.AvmValue) string {
	if v.Type == 2 {
		return fmt.Sprintf("%d", v.Uint)
	}
	if v.Type == 1 && len(v.Bytes) > 0 {
		if isPrintable(v.Bytes) {
			return fmt.Sprintf("%q", string(v.Bytes))
		}
		return fmt.Sprintf("0x%s", hex.EncodeToString(v.Bytes))
	}
	return fmt.Sprintf("%d", v.Uint)
}

// formatInnerTxn formats an inner transaction summary with recursive nesting.
func formatInnerTxn(b *strings.Builder, idx int, inner models.PendingTransactionResponse, indent string) {
	txn := inner.Transaction.Txn
	txType := string(txn.Type)
	fmt.Fprintf(b, "%s[%d] %s", indent, idx, txType)

	switch txn.Type {
	case types.PaymentTx:
		fmt.Fprintf(b, " %d microAlgo → %s", uint64(txn.Amount), shortAddr(txn.Receiver.String()))
	case types.ApplicationCallTx:
		fmt.Fprintf(b, " app %d", uint64(txn.ApplicationID))
	case types.AssetTransferTx:
		fmt.Fprintf(b, " asset %d amount %d", uint64(txn.XferAsset), txn.AssetAmount)
	}

	fmt.Fprintln(b)

	// Inner logs
	if len(inner.Logs) > 0 {
		fmt.Fprintf(b, "%s  Logs (%d):\n", indent, len(inner.Logs))
		for j, log := range inner.Logs {
			fmt.Fprintf(b, "%s    [%d] %s\n", indent, j, formatLogEntry(log))
		}
	}

	// Recursive inner transactions
	for j, nested := range inner.InnerTxns {
		formatInnerTxn(b, j, nested, indent+"  ")
	}
}

// formatEvalDelta formats a key-value state delta entry.
// EvalDelta.Bytes is base64-encoded in the REST API JSON response.
func formatEvalDelta(kv models.EvalDeltaKeyValue) string {
	key := decodeStateKey(kv.Key)

	switch kv.Value.Action {
	case 1: // set bytes
		decoded, err := base64.StdEncoding.DecodeString(kv.Value.Bytes)
		if err != nil {
			// Not valid base64 — display as-is
			return fmt.Sprintf("set %s = %q", key, kv.Value.Bytes)
		}
		if isPrintable(decoded) {
			return fmt.Sprintf("set %s = %q", key, string(decoded))
		}
		return fmt.Sprintf("set %s = 0x%s", key, hex.EncodeToString(decoded))
	case 2: // set uint
		return fmt.Sprintf("set %s = %d", key, kv.Value.Uint)
	case 3: // delete
		return fmt.Sprintf("delete %s", key)
	default:
		return fmt.Sprintf("action(%d) %s", kv.Value.Action, key)
	}
}

// formatLogEntry formats a single log entry, showing as string if printable.
func formatLogEntry(data []byte) string {
	if len(data) == 0 {
		return "(empty)"
	}
	if isPrintable(data) {
		return fmt.Sprintf("%q", string(data))
	}
	return fmt.Sprintf("(%d bytes) 0x%s", len(data), hex.EncodeToString(data))
}

// formatFailedAt formats the FailedAt path for display.
// The API returns 0-based indices; we display 1-based to match
// the rest of the output (Txn 1, 1. TXID, etc.).
func formatFailedAt(path []uint64) string {
	if len(path) == 0 {
		return "unknown"
	}
	parts := make([]string, len(path))
	parts[0] = fmt.Sprintf("transaction %d", path[0]+1)
	for i := 1; i < len(path); i++ {
		parts[i] = fmt.Sprintf("inner %d", path[i]+1)
	}
	return strings.Join(parts, " → ")
}

// formatKeyBytes formats raw bytes as a readable key name.
func formatKeyBytes(data []byte) string {
	if len(data) == 0 {
		return `""`
	}
	if isPrintable(data) {
		return fmt.Sprintf("%q", string(data))
	}
	return fmt.Sprintf("0x%s", hex.EncodeToString(data))
}

// decodeStateKey decodes a state delta key which may be base64 encoded.
func decodeStateKey(key string) string {
	if key == "" {
		return `""`
	}
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		// Not base64 — use as-is
		if isPrintable([]byte(key)) {
			return fmt.Sprintf("%q", key)
		}
		return fmt.Sprintf("0x%s", hex.EncodeToString([]byte(key)))
	}
	if isPrintable(decoded) {
		return fmt.Sprintf("%q", string(decoded))
	}
	return fmt.Sprintf("0x%s", hex.EncodeToString(decoded))
}

// shortAddr returns a shortened address for compact display.
func shortAddr(addr string) string {
	if len(addr) > 12 {
		return addr[:8] + "..." + addr[len(addr)-4:]
	}
	return addr
}

// isPrintable checks if all bytes are printable UTF-8 (ASCII 0x20-0x7e).
func isPrintable(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	for _, b := range data {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return len(data) > 0
}
