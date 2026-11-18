// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package productruntime

import (
	"context"
	"errors"
	"testing"
	"time"

	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
)

// Every way the signer's session ends withdraws an approval waiting on the
// operator's screen: a request from the ended session cannot sign, so it
// answers that the session ended instead of staying up until it times out,
// or until an operator approves what will be refused.
func TestEverySessionEndWithdrawsAWaitingApproval(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  func(ir *Runtime)
	}{
		{"lock", func(ir *Runtime) { ir.Lock() }},
		{"recovery", func(ir *Runtime) { ir.SetRecovery() }},
		{"store maintenance", func(ir *Runtime) { ir.FinishStoreMaintenance(ir.BeginStoreMaintenance(), false) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ir := New(Config{})
			ir.SetUnlocked()
			shown := make(chan struct{}, 1)
			ir.SetApprovalCoordinator(signerapproval.New(
				func() bool { return true },
				func(*signerapproval.SignRequest) bool { shown <- struct{}{}; return true },
				func(*signerapproval.SignRequestCanceled) bool { return true },
			))
			ctx, finish := ir.BeginSigningRequest(context.Background(), "sign-1")
			defer finish()
			result := make(chan error, 1)
			go func() {
				_, err := ir.RequestSigningApprovalPrompt(ctx, signerapproval.Prompt{RequestID: "sign-1", Address: "A", TxnSender: "A", Description: "d"}, time.Minute)
				result <- err
			}()
			<-shown

			tc.end(ir)
			select {
			case err := <-result:
				if !errors.Is(err, signerapproval.ErrSessionEnded) {
					t.Fatalf("approval error = %v, want the session-ended withdrawal", err)
				}
			case <-time.After(time.Second):
				t.Fatal("the approval was still waiting after the session ended")
			}
		})
	}
}
