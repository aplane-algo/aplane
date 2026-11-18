// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package approval

import (
	"context"
	"errors"
	"testing"
	"time"
)

// When the signer's session ends, every signing request in flight is
// withdrawn: the one on the operator's screen, dismissed with the session-
// ended reason, and the one queued behind it, before it is ever shown. Both
// answer that the session ended, not that the operator rejected them.
func TestCancelAllSignRequestsWithdrawsTheShownAndTheQueued(t *testing.T) {
	sent := make(chan string, 2)
	canceled := make(chan SignRequestCanceled, 2)
	c := New(
		func() bool { return true },
		func(req *SignRequest) bool { sent <- req.ID; return true },
		func(msg *SignRequestCanceled) bool { canceled <- *msg; return true },
	)
	ask := func(requestID string) (<-chan error, func()) {
		ctx, finish := c.BeginSignRequest(context.Background(), requestID)
		result := make(chan error, 1)
		go func() {
			_, err := c.RequestSigningApprovalPrompt(ctx, Prompt{RequestID: requestID, Address: "A", TxnSender: "A", Description: requestID}, time.Minute)
			result <- err
		}()
		return result, finish
	}

	shown, finishShown := ask("sign-shown")
	defer finishShown()
	promptID := <-sent
	queued, finishQueued := ask("sign-queued")
	defer finishQueued()

	if n := c.CancelAllSignRequests(SignRequestCancelReasonSessionEnded); n != 2 {
		t.Fatalf("CancelAllSignRequests() canceled %d request(s), want 2", n)
	}
	for name, result := range map[string]<-chan error{"shown": shown, "queued": queued} {
		select {
		case err := <-result:
			if !errors.Is(err, ErrApprovalCanceled) || !errors.Is(err, ErrSessionEnded) {
				t.Fatalf("%s request error = %v, want a session-ended cancellation", name, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("the %s request was not withdrawn", name)
		}
	}
	select {
	case got := <-canceled:
		if got.ID != promptID || got.Reason != SignRequestCancelReasonSessionEnded {
			t.Fatalf("dismissal = %#v, want the shown prompt with reason session_ended", got)
		}
	case <-time.After(time.Second):
		t.Fatal("the shown prompt was not dismissed")
	}
	select {
	case id := <-sent:
		t.Fatalf("the queued request was shown (%s) after the session ended", id)
	default:
	}
	if got := c.PendingSignCount(); got != 0 {
		t.Fatalf("PendingSignCount() = %d, want 0", got)
	}
}
