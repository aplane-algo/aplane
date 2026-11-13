// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// submitNode is a fake algod for SubmitTransactionsWithContext: submit
// answers POST /v2/transactions, and pending answers the confirmation wait's
// pending-transaction reads; a nil pending leaves the transaction pending.
// statusFails makes /v2/status, which the wait reads first, answer 500.
type submitNode struct {
	submit      func(http.ResponseWriter)
	confirmed   bool
	statusFails bool
	posts       atomic.Int32
}

func (n *submitNode) client(t *testing.T) *algod.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/transactions" && r.Method == http.MethodPost:
			n.posts.Add(1)
			_, _ = io.Copy(io.Discard, r.Body)
			n.submit(w)
		case r.URL.Path == "/v2/status" || strings.HasPrefix(r.URL.Path, "/v2/status/wait-for-block-after/"):
			if n.statusFails {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": "node is catching up"})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(models.NodeStatus{LastRound: 10})
		case strings.HasPrefix(r.URL.Path, "/v2/transactions/pending/"):
			info := models.PendingTransactionInfoResponse{}
			if n.confirmed {
				info.ConfirmedRound = 11
			}
			w.Header().Set("Content-Type", "application/msgpack")
			_, _ = w.Write(msgpack.Encode(info))
		default:
			t.Errorf("unexpected algod request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client, err := algod.MakeClient(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func acceptSubmit(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"txId": "ACCEPTED"})
}

// dropSubmit closes the connection without an answer: the response is lost.
func dropSubmit(w http.ResponseWriter) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

func refuseSubmit(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "TransactionPool.Remember: transaction X: overspend"})
}

// signedPayments returns n signed payments and their IDs.
func signedPayments(t *testing.T, n int) ([][]byte, []string) {
	t.Helper()
	account := crypto.GenerateAccount()
	var signed [][]byte
	var ids []string
	for i := 0; i < n; i++ {
		txn, err := transaction.MakePaymentTxn(account.Address.String(), account.Address.String(), 0, []byte(fmt.Sprint(i)), "", types.SuggestedParams{
			Fee: 1000, FirstRoundValid: 1, LastRoundValid: 100, GenesisHash: make([]byte, 32), FlatFee: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		id, stx, err := SignTransactionWithKey(account.PrivateKey, txn)
		if err != nil {
			t.Fatal(err)
		}
		signed = append(signed, stx)
		ids = append(ids, id)
	}
	return signed, ids
}

// Each way a submission can end is told apart: algod accepting and the wait
// timing out or failing is "submitted"; a submit call with no answer is
// "unknown"; algod's 400 is "rejected"; a context that ended before the call
// is "not_sent". The error keeps the text it had before and names every
// transaction ID of the group, even when algod's own text names none.
func TestSubmitTransactionsReportsHowFarTheGroupGot(t *testing.T) {
	for _, tc := range []struct {
		name      string
		node      *submitNode
		cancelled bool
		state     SubmissionState
		text      string
		posts     int32
	}{
		{name: "accepted then the wait times out", node: &submitNode{submit: acceptSubmit},
			state: SubmissionSubmitted, text: "confirmation failed: wait for transaction id {id0} timed out", posts: 1},
		{name: "accepted then algod fails during the wait", node: &submitNode{submit: acceptSubmit, statusFails: true},
			state: SubmissionSubmitted, text: "confirmation failed: HTTP 500: {\"message\":\"node is catching up\"}\n", posts: 1},
		{name: "the submit response is lost", node: &submitNode{submit: dropSubmit},
			state: SubmissionUnknown, text: "failed to submit transaction group: ", posts: 1},
		{name: "algod answers 400", node: &submitNode{submit: refuseSubmit},
			state: SubmissionRejected, text: "failed to submit transaction group: HTTP 400: {\"message\":\"TransactionPool.Remember: transaction X: overspend\"}\n", posts: 1},
		{name: "the context ended before the call", node: &submitNode{submit: acceptSubmit}, cancelled: true,
			state: SubmissionNotSent, text: "failed to submit transaction group: context canceled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signed, ids := signedPayments(t, 2)
			ctx := context.Background()
			if tc.cancelled {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			_, err := SubmitTransactionsWithContext(ctx, signed, tc.node.client(t), true, io.Discard)
			var failure *SubmissionError
			if !errors.As(fmt.Errorf("outer: %w", err), &failure) {
				t.Fatalf("error = %v, want a *SubmissionError", err)
			}
			if failure.State != tc.state || failure.Submitted() != (tc.state == SubmissionSubmitted) {
				t.Fatalf("state = %q (submitted %v), want %q", failure.State, failure.Submitted(), tc.state)
			}
			if strings.Join(failure.TxIDs, ",") != strings.Join(ids, ",") {
				t.Fatalf("TxIDs = %v, want %v", failure.TxIDs, ids)
			}
			want := strings.ReplaceAll(tc.text, "{id0}", ids[0])
			if got := err.Error(); !strings.HasPrefix(got, want) {
				t.Fatalf("error text = %q, want it to start %q", got, want)
			}
			if got := tc.node.posts.Load(); got != tc.posts {
				t.Fatalf("submit calls = %d, want %d", got, tc.posts)
			}
		})
	}
}

// A single transaction keeps its own wording, and its ID.
func TestSubmitTransactionsReportsASingleTransaction(t *testing.T) {
	signed, ids := signedPayments(t, 1)
	node := &submitNode{submit: dropSubmit}
	_, err := SubmitTransactionsWithContext(context.Background(), signed, node.client(t), true, io.Discard)
	var failure *SubmissionError
	if !errors.As(err, &failure) || failure.State != SubmissionUnknown || len(failure.TxIDs) != 1 || failure.TxIDs[0] != ids[0] {
		t.Fatalf("error = %v (%+v), want an unknown outcome for %s", err, failure, ids[0])
	}
	if !strings.HasPrefix(err.Error(), "failed to submit transaction: ") {
		t.Fatalf("error text = %q", err.Error())
	}
}

// A confirmed group returns its IDs and no error.
func TestSubmitTransactionsConfirmed(t *testing.T) {
	signed, ids := signedPayments(t, 2)
	node := &submitNode{submit: acceptSubmit, confirmed: true}
	got, err := SubmitTransactionsWithContext(context.Background(), signed, node.client(t), true, io.Discard)
	if err != nil {
		t.Fatalf("SubmitTransactionsWithContext() error = %v", err)
	}
	if strings.Join(got, ",") != strings.Join(ids, ",") {
		t.Fatalf("IDs = %v, want %v", got, ids)
	}
}
