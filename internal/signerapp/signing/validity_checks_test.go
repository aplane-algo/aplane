// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	sdkconfig "github.com/algorand/go-algorand-sdk/v2/protocol/config"
	"github.com/algorand/go-algorand-sdk/v2/types"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// The limits are the pinned consensus parameters' own, so the cases are written
// from them: a literal here would pass or fail with the code's mistake.
func TestCheckTransactionBounds(t *testing.T) {
	params, ok := sdkconfig.Consensus[lsigresource.CurrentConsensusVersion]
	if !ok {
		t.Fatalf("SDK has no parameters for %s", lsigresource.CurrentConsensusVersion)
	}
	// The absolute note maximum is above the size where a surcharge starts. A
	// check against the smaller one would refuse valid transactions.
	if params.MaxAbsoluteTxnNoteBytes <= params.MaxTxnNoteBytes {
		t.Fatalf("absolute note maximum %d is not above the surcharge threshold %d", params.MaxAbsoluteTxnNoteBytes, params.MaxTxnNoteBytes)
	}
	life := types.Round(params.MaxTxnLife)
	window := func(first, last types.Round) types.Transaction {
		return types.Transaction{Type: types.PaymentTx, Header: types.Header{FirstValid: first, LastValid: last}}
	}
	note := func(size int) types.Transaction {
		txn := window(10, 20)
		txn.Note = make([]byte, size)
		return txn
	}
	for _, test := range []struct {
		name string
		txn  types.Transaction
		want string
	}{
		{name: "an ordinary window", txn: window(10, 20)},
		{name: "a window of one round", txn: window(10, 10)},
		{name: "the longest window", txn: window(10, 10+life)},
		{name: "one round too long", txn: window(10, 11+life), want: "is longer than the network's maximum"},
		{name: "a reversed window", txn: window(20, 10), want: "can never be valid"},
		{name: "reversed by one round", txn: window(11, 10), want: "can never be valid"},
		{name: "no note", txn: note(0)},
		{name: "a note at the surcharge threshold", txn: note(params.MaxTxnNoteBytes)},
		{name: "a note that pays a surcharge", txn: note(params.MaxTxnNoteBytes + 1)},
		{name: "the largest note", txn: note(params.MaxAbsoluteTxnNoteBytes)},
		{name: "a note one byte too long", txn: note(params.MaxAbsoluteTxnNoteBytes + 1), want: "above the network's maximum"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := checkTransactionBounds(test.txn, params)
			if test.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

// The planner refuses such a transaction before any key is looked up, so
// nothing reaches policy or approval. A lone transaction is the case that used
// to pass: the group check compares windows only across members.
func TestPlanGroupRefusesATransactionTheNetworkNeverAccepts(t *testing.T) {
	params := sdkconfig.Consensus[lsigresource.CurrentConsensusVersion]
	genesisHash := types.Digest{5}
	resolver, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{
		base64.StdEncoding.EncodeToString(genesisHash[:]): "customnet_test",
	})
	if err != nil {
		t.Fatal(err)
	}
	authorizer := types.Address{8}
	payment := func(first, last types.Round, noteBytes int) types.Transaction {
		return types.Transaction{
			Type: types.PaymentTx,
			Header: types.Header{
				Sender: authorizer, Fee: 1_000, FirstValid: first, LastValid: last, GenesisHash: genesisHash,
				Note: make([]byte, noteBytes),
			},
		}
	}
	life := types.Round(params.MaxTxnLife)
	sign := func(txn types.Transaction) signerapi.SignRequest {
		return signerapi.SignRequest{AuthAddress: authorizer.String(), TxnBytesHex: hex.EncodeToString(msgpack.Encode(txn))}
	}
	foreign := func(txn types.Transaction) signerapi.SignRequest {
		// No auth address: another signer's position, here as context only.
		return signerapi.SignRequest{TxnBytesHex: hex.EncodeToString(msgpack.Encode(txn))}
	}
	for _, test := range []struct {
		name     string
		requests []signerapi.SignRequest
		want     string
	}{
		{name: "a lone reversed window", requests: []signerapi.SignRequest{sign(payment(20, 10, 0))}, want: "transaction 1: last valid round 10 is before first valid round 20"},
		{name: "a lone window one round too long", requests: []signerapi.SignRequest{sign(payment(10, 11+life, 0))}, want: "transaction 1: validity window"},
		{name: "a lone note one byte too long", requests: []signerapi.SignRequest{sign(payment(10, 20, params.MaxAbsoluteTxnNoteBytes+1))}, want: "transaction 1: note is"},
		// A member this signer doesn't sign still fails the whole group.
		{name: "a foreign member", requests: []signerapi.SignRequest{sign(payment(10, 20, 0)), foreign(payment(10, 11+life, 0))}, want: "transaction 2: validity window"},
	} {
		t.Run(test.name, func(t *testing.T) {
			planner := NewPlanner(stubPlannerDeps{keyTypes: map[string]string{authorizer.String(): "ed25519"}}, PlannerOptions{GenesisHashResolver: resolver})
			_, planErr := planner.PlanGroup(signerapi.GroupSignRequest{Requests: test.requests})
			if planErr == nil || planErr.Kind != ErrorBadRequest || !strings.Contains(planErr.Message, test.want) {
				t.Fatalf("PlanGroup error = %+v, want a bad request containing %q", planErr, test.want)
			}
		})
	}

	// The longest window the network allows still plans.
	planner := NewPlanner(stubPlannerDeps{keyTypes: map[string]string{authorizer.String(): "ed25519"}}, PlannerOptions{GenesisHashResolver: resolver})
	if _, planErr := planner.PlanGroup(signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{sign(payment(10, 10+life, 0))}}); planErr != nil {
		t.Fatalf("the longest window was refused: %+v", planErr)
	}
}
