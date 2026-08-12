// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package harness

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/lsigresource"
)

func TestValidateDeclaredOpcodeCeilingAggregatesMaximums(t *testing.T) {
	program := []byte{13, 1, 2, 3}
	costs := []uint64{900, 1_100}
	requests := 0
	client := opcodeSimulationClient(t, func(t *testing.T, request models.SimulateRequest) models.SimulateResponse {
		if len(request.TxnGroups) != 1 || len(request.TxnGroups[0].Txns) != 1 {
			t.Fatalf("simulate request groups = %#v", request.TxnGroups)
		}
		if !request.ExecTraceConfig.Enable {
			t.Fatal("simulate request did not enable execution tracing")
		}
		cost := costs[requests]
		requests++
		return opcodeSimulationResponse(cost, "")
	})

	report, err := ValidateDeclaredOpcodeCeiling(context.Background(), client, OpcodeCeilingValidation{
		Name:          "test.template.v1",
		FinalProgram:  program,
		Profile:       lsigresource.DefaultOpcodeProfile(20_000),
		RequiredPaths: []lsigresource.AuthorizationPath{lsigresource.PathDefault},
		Vectors: []OpcodeCeilingVector{
			{Name: "short", Path: lsigresource.PathDefault, SignedTxns: opcodeVector(program), LSigIndex: 0},
			{Name: "maximum", Path: lsigresource.PathDefault, SignedTxns: opcodeVector(program), LSigIndex: 0},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("simulation requests = %d, want 2", requests)
	}
	if report.ProgramBytes != len(program) {
		t.Fatalf("program bytes = %d, want %d", report.ProgramBytes, len(program))
	}
	got := report.Paths[lsigresource.PathDefault]
	if got.DeclaredCeiling != 20_000 || got.MaximumObserved != 1_100 || got.Vector != "maximum" {
		t.Fatalf("default path report = %#v", got)
	}
}

func TestValidateDeclaredOpcodeCeilingFailsClosed(t *testing.T) {
	program := []byte{13, 1}
	base := func() OpcodeCeilingValidation {
		return OpcodeCeilingValidation{
			Name:          "test.template.v1",
			FinalProgram:  program,
			Profile:       lsigresource.DefaultOpcodeProfile(20_000),
			RequiredPaths: []lsigresource.AuthorizationPath{lsigresource.PathDefault},
			Vectors: []OpcodeCeilingVector{{
				Name: "maximum", Path: lsigresource.PathDefault,
				SignedTxns: opcodeVector(program), LSigIndex: 0,
			}},
		}
	}
	tests := []struct {
		name    string
		mutate  func(*OpcodeCeilingValidation)
		cost    uint64
		failure string
		want    string
	}{
		{name: "missing coverage", mutate: func(in *OpcodeCeilingValidation) { in.Vectors = nil }, want: "has no maximum-input simulation vector"},
		{name: "wrong program", mutate: func(in *OpcodeCeilingValidation) { in.Vectors[0].SignedTxns = opcodeVector([]byte{13, 9}) }, want: "does not carry the final compiled program"},
		{name: "missing cost", cost: 0, want: "did not report LogicSig opcode consumption"},
		{name: "ceiling exceeded", cost: 20_001, want: "exceeding declared ceiling 20000"},
		{name: "execution failed", failure: "assert failed", want: "simulation failed: assert failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := opcodeSimulationClient(t, func(_ *testing.T, _ models.SimulateRequest) models.SimulateResponse {
				return opcodeSimulationResponse(test.cost, test.failure)
			})
			input := base()
			if test.mutate != nil {
				test.mutate(&input)
			}
			_, err := ValidateDeclaredOpcodeCeiling(context.Background(), client, input)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestValidateDeclaredOpcodeCeilingRejectsWrongPathShape(t *testing.T) {
	client := opcodeSimulationClient(t, func(_ *testing.T, _ models.SimulateRequest) models.SimulateResponse {
		return opcodeSimulationResponse(1, "")
	})
	_, err := ValidateDeclaredOpcodeCeiling(context.Background(), client, OpcodeCeilingValidation{
		Name:          "bounded",
		FinalProgram:  []byte{13},
		Profile:       lsigresource.DefaultOpcodeProfile(20_000),
		Bounded:       true,
		RequiredPaths: []lsigresource.AuthorizationPath{lsigresource.PathSpend},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid declared opcode profile") {
		t.Fatalf("error = %v, want profile-shape rejection", err)
	}
}

func opcodeVector(program []byte) []types.SignedTxn {
	return []types.SignedTxn{{Lsig: types.LogicSig{Logic: append([]byte(nil), program...)}}}
}

func opcodeSimulationResponse(cost uint64, failure string) models.SimulateResponse {
	return models.SimulateResponse{TxnGroups: []models.SimulateTransactionGroupResult{{
		FailureMessage: failure,
		TxnResults:     []models.SimulateTransactionResult{{LogicSigBudgetConsumed: cost}},
	}}}
}

func opcodeSimulationClient(
	t *testing.T,
	handler func(*testing.T, models.SimulateRequest) models.SimulateResponse,
) *algod.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/transactions/simulate" {
			http.NotFound(w, r)
			return
		}
		var request models.SimulateRequest
		body, err := io.ReadAll(r.Body)
		if err == nil {
			err = msgpack.Decode(body, &request)
		}
		if err != nil {
			t.Errorf("decode simulate request: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(handler(t, request)); err != nil {
			t.Errorf("encode simulate response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	client, err := algod.MakeClient(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	return client
}
