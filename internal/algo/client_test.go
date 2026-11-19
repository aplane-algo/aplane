// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package algo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
)

func TestConvertTokenAmountToBaseUnits(t *testing.T) {
	tests := []struct {
		name     string
		amount   string
		decimals uint64
		want     uint64
		wantErr  bool
	}{
		{
			name:     "whole number with 6 decimals",
			amount:   "1",
			decimals: 6,
			want:     1000000,
			wantErr:  false,
		},
		{
			name:     "decimal amount with 6 decimals",
			amount:   "1.5",
			decimals: 6,
			want:     1500000,
			wantErr:  false,
		},
		{
			name:     "decimals at protocol max",
			amount:   "1",
			decimals: 19,
			want:     10000000000000000000, // 10^19
			wantErr:  false,
		},
		{
			name:     "decimals above protocol max rejected",
			amount:   "1",
			decimals: 20,
			wantErr:  true,
		},
		{
			name:     "pathological decimals rejected before huge alloc",
			amount:   "1",
			decimals: 1 << 40,
			wantErr:  true,
		},
		{
			name:     "zero amount",
			amount:   "0",
			decimals: 6,
			want:     0,
			wantErr:  false,
		},
		{
			name:     "small decimal",
			amount:   "0.000001",
			decimals: 6,
			want:     1,
			wantErr:  false,
		},
		{
			name:     "0 decimals asset",
			amount:   "100",
			decimals: 0,
			want:     100,
			wantErr:  false,
		},
		{
			name:     "large amount",
			amount:   "1000000",
			decimals: 6,
			want:     1000000000000,
			wantErr:  false,
		},
		{
			name:     "invalid amount string",
			amount:   "abc",
			decimals: 6,
			want:     0,
			wantErr:  true,
		},
		{
			name:     "too many decimal places",
			amount:   "1.0000001",
			decimals: 6,
			want:     0,
			wantErr:  true,
		},
		{
			name:     "negative amount",
			amount:   "-1",
			decimals: 6,
			want:     0,
			wantErr:  true,
		},
		{
			name:     "bare decimal point",
			amount:   ".",
			decimals: 6,
			want:     0,
			wantErr:  true,
		},
		{
			name:     "leading decimal amount",
			amount:   ".5",
			decimals: 6,
			want:     500000,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConvertTokenAmountToBaseUnits(tt.amount, tt.decimals)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConvertTokenAmountToBaseUnits() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ConvertTokenAmountToBaseUnits() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWaitForConfirmationPollReturnsOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err := waitForConfirmationPoll(ctx, time.Hour)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForConfirmationPoll() error = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("waitForConfirmationPoll() took %s after cancellation", elapsed)
	}
}

// confirmationNode is an algod that advances one round each time it is asked
// to wait for a block, fails the first failFirst pending-status checks, and
// confirms the transaction once the ledger reaches confirmAt (never when it is
// zero).
type confirmationNode struct {
	mu                sync.Mutex
	round             uint64
	confirmAt         uint64
	failFirst         int
	failAll           bool
	pendingChecks     int
	waitsForNextBlock int
	// failBlockWaits fails the first block waits; advanceOnStatus moves the
	// ledger a round after each status read, as time passing would.
	failBlockWaits  int
	advanceOnStatus bool
	statusReads     int
}

func (n *confirmationNode) serve(t *testing.T) *algod.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.mu.Lock()
		defer n.mu.Unlock()
		switch {
		case r.URL.Path == "/v2/status":
			n.statusReads++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(models.NodeStatus{LastRound: n.round})
			if n.advanceOnStatus {
				n.round++
			}
		case strings.HasPrefix(r.URL.Path, "/v2/status/wait-for-block-after/"):
			after, err := strconv.ParseUint(strings.TrimPrefix(r.URL.Path, "/v2/status/wait-for-block-after/"), 10, 64)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			n.waitsForNextBlock++
			if n.waitsForNextBlock <= n.failBlockWaits {
				http.Error(w, `{"message":"node is busy"}`, http.StatusServiceUnavailable)
				return
			}
			if n.round <= after {
				n.round = after + 1
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(models.NodeStatus{LastRound: n.round})
		case strings.HasPrefix(r.URL.Path, "/v2/transactions/pending/"):
			n.pendingChecks++
			if n.failAll || n.pendingChecks <= n.failFirst {
				http.Error(w, `{"message":"node is catching up"}`, http.StatusServiceUnavailable)
				return
			}
			var info models.PendingTransactionInfoResponse
			if n.confirmAt != 0 && n.round >= n.confirmAt {
				info.ConfirmedRound = n.round
			}
			w.Header().Set("Content-Type", "application/msgpack")
			_, _ = w.Write(msgpack.Encode(info))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client, err := algod.MakeClient(server.URL, "")
	if err != nil {
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	return client
}

// One failed status check does not cut the caller's budget short: the wait
// carries on, round by round, and sees a confirmation that comes six rounds
// in, within the nine it was given.
func TestWaitForConfirmationKeepsTheBudgetThroughAFailedCheck(t *testing.T) {
	node := &confirmationNode{round: 100, confirmAt: 106, failFirst: 1}
	client := node.serve(t)

	var out bytes.Buffer
	if err := WaitForConfirmation(context.Background(), client, "TXID", 9, &out); err != nil {
		t.Fatalf("WaitForConfirmation() error = %v, output %q", err, out.String())
	}
	if !strings.Contains(out.String(), "Transaction confirmed in block 106") {
		t.Fatalf("output = %q, want the confirmation in block 106", out.String())
	}
	if !strings.Contains(out.String(), "could not check pending transaction status") {
		t.Fatalf("output = %q, want the failed check reported", out.String())
	}
}

// The budget is ledger rounds: each check but the last waits for the next
// block, not a fixed poll interval, and a wait that runs out says how many
// rounds it waited, and why the last check failed when it did.
func TestWaitForConfirmationCountsLedgerRounds(t *testing.T) {
	t.Run("never confirmed", func(t *testing.T) {
		node := &confirmationNode{round: 100}
		client := node.serve(t)

		var out bytes.Buffer
		err := WaitForConfirmation(context.Background(), client, "TXID", 3, &out)
		if err == nil || !strings.Contains(err.Error(), "not confirmed after 3 checks, about one a round") {
			t.Fatalf("WaitForConfirmation() error = %v, want the 3 checks run out", err)
		}
		node.mu.Lock()
		defer node.mu.Unlock()
		if node.pendingChecks != 3 || node.waitsForNextBlock != 2 || node.round != 102 {
			t.Fatalf("checks/block waits/round = %d/%d/%d, want 3/2/102", node.pendingChecks, node.waitsForNextBlock, node.round)
		}
	})
	t.Run("every check failed", func(t *testing.T) {
		node := &confirmationNode{round: 100, failAll: true}
		client := node.serve(t)

		var out bytes.Buffer
		err := WaitForConfirmation(context.Background(), client, "TXID", 2, &out)
		if err == nil || !strings.Contains(err.Error(), "not confirmed after 2 checks, about one a round; the last check failed") {
			t.Fatalf("WaitForConfirmation() error = %v, want the last failed check named", err)
		}
		if got := strings.Count(out.String(), "could not check pending transaction status"); got != 1 {
			t.Fatalf("output = %q, want the failure reported once", out.String())
		}
	})
}

// shortenConfirmationPacing makes the poll interval and the block-wait bound
// test-sized for the rest of the test.
func shortenConfirmationPacing(t *testing.T, poll, blockWait time.Duration) {
	t.Helper()
	oldPoll, oldBlockWait := confirmationPollInterval, blockWaitTimeout
	confirmationPollInterval, blockWaitTimeout = poll, blockWait
	t.Cleanup(func() { confirmationPollInterval, blockWaitTimeout = oldPoll, oldBlockWait })
}

// A dev-mode node writes no block while nothing is sent: a wait for the next
// block brings none, whether algod holds it past the client's bound or
// answers at once with the same round. The first such wait turns the rest of
// the confirmation wait to polling, so a txid that never confirms costs the
// poll interval a round, not the block wait each round.
func TestWaitForConfirmationPollsWhenNoBlockComes(t *testing.T) {
	for name, hold := range map[string]time.Duration{
		"algod holds the block wait":   5 * time.Second,
		"algod answers the same round": 0,
	} {
		t.Run(name, func(t *testing.T) {
			shortenConfirmationPacing(t, 20*time.Millisecond, 200*time.Millisecond)
			var mu sync.Mutex
			var blockWaits, pendingChecks int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v2/status":
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(models.NodeStatus{LastRound: 100})
				case strings.HasPrefix(r.URL.Path, "/v2/status/wait-for-block-after/"):
					mu.Lock()
					blockWaits++
					mu.Unlock()
					select {
					case <-time.After(hold):
					case <-r.Context().Done():
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(models.NodeStatus{LastRound: 100})
				case strings.HasPrefix(r.URL.Path, "/v2/transactions/pending/"):
					mu.Lock()
					pendingChecks++
					mu.Unlock()
					http.Error(w, `{"message":"txn does not exist"}`, http.StatusNotFound)
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(server.Close)
			client, err := algod.MakeClient(server.URL, "")
			if err != nil {
				t.Fatalf("algod.MakeClient() error = %v", err)
			}

			start := time.Now()
			err = WaitForConfirmation(context.Background(), client, "UNKNOWN", 5, &bytes.Buffer{})
			elapsed := time.Since(start)
			if err == nil || !strings.Contains(err.Error(), "not confirmed after 5 checks") {
				t.Fatalf("WaitForConfirmation() error = %v, want the budget run out", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if blockWaits != 1 || pendingChecks != 5 {
				t.Fatalf("block waits/checks = %d/%d, want 1/5: one wait with no block, then polling", blockWaits, pendingChecks)
			}
			if elapsed > 2*time.Second {
				t.Fatalf("WaitForConfirmation() took %s, want about one block-wait bound and four poll intervals", elapsed)
			}
		})
	}
}

// One block wait that fails turns the wait to polling only until a status
// read shows the ledger moving on: block waits then resume, and the checks
// follow the ledger's rounds again.
func TestWaitForConfirmationResumesBlockWaitsWhenTheRoundAdvances(t *testing.T) {
	shortenConfirmationPacing(t, 10*time.Millisecond, time.Second)
	node := &confirmationNode{round: 100, failBlockWaits: 1, advanceOnStatus: true}
	client := node.serve(t)

	err := WaitForConfirmation(context.Background(), client, "TXID", 4, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "not confirmed after 4 checks") {
		t.Fatalf("WaitForConfirmation() error = %v, want the 4 checks run out", err)
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	if node.pendingChecks != 4 || node.waitsForNextBlock != 3 || node.statusReads != 2 {
		t.Fatalf("checks/block waits/status reads = %d/%d/%d, want 4/3/2: one failed block wait, one poll, then block waits again",
			node.pendingChecks, node.waitsForNextBlock, node.statusReads)
	}
}
