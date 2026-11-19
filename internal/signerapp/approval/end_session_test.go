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
func TestEndSessionSignRequestsWithdrawsTheShownAndTheQueued(t *testing.T) {
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

	c.EndSessionSignRequests()
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

// A withdrawal belongs to the requests in flight when the session ended,
// not to their IDs: a request sent again under the same ID, while the old
// one is still finishing, is shown as usual.
func TestASessionEndDoesNotWithdrawALaterRequestUnderTheSameID(t *testing.T) {
	sent := make(chan string, 2)
	c := New(
		func() bool { return true },
		func(req *SignRequest) bool { sent <- req.ID; return true },
		func(*SignRequestCanceled) bool { return true },
	)
	_, finishOld := c.BeginSignRequest(context.Background(), "sign-1")
	defer finishOld()
	c.EndSessionSignRequests()

	ctx, finishNew := c.BeginSignRequest(context.Background(), "sign-1")
	defer finishNew()
	result := make(chan error, 1)
	go func() {
		_, err := c.RequestSigningApprovalPrompt(ctx, Prompt{RequestID: "sign-1", Address: "A", TxnSender: "A", Description: "again"}, time.Minute)
		result <- err
	}()
	select {
	case <-sent:
	case err := <-result:
		t.Fatalf("the later request was refused: %v", err)
	case <-time.After(time.Second):
		t.Fatal("the later request was never shown")
	}
}

// An operator's rejection stays a rejection whatever reason they type, even
// one spelled like a withdrawal: only the coordinator withdraws a request.
func TestAnOperatorRejectionIsNotTakenForAWithdrawal(t *testing.T) {
	sent := make(chan string, 1)
	c := New(
		func() bool { return true },
		func(req *SignRequest) bool { sent <- req.ID; return true },
		func(*SignRequestCanceled) bool { return true },
	)
	type outcome struct {
		response SignResponse
		err      error
	}
	result := make(chan outcome, 1)
	go func() {
		response, err := c.RequestSigningApprovalPrompt(context.Background(), Prompt{RequestID: "sign-1", Address: "A", TxnSender: "A", Description: "d"}, time.Minute)
		result <- outcome{response, err}
	}()
	promptID := <-sent
	c.HandleSignResponse(&SignResponse{ID: promptID, Approved: false, Reason: SignRequestCancelReasonSessionEnded})
	got := <-result
	if got.err != nil || got.response.Approved {
		t.Fatalf("operator rejection = %+v, %v; want a plain rejection", got.response, got.err)
	}
}

// A session end ends approval waits, not requests: the context of a request
// in flight is not canceled, so work it is doing meets the session check or
// a lock's key-use cut (answering locked) rather than looking canceled by
// its client. A request from the ended session that asks for approval
// afterwards is refused.
func TestASessionEndRefusesLaterApprovalsWithoutCancelingTheRequest(t *testing.T) {
	sent := make(chan string, 1)
	c := New(
		func() bool { return true },
		func(req *SignRequest) bool { sent <- req.ID; return true },
		func(*SignRequestCanceled) bool { return true },
	)
	ctx, finish := c.BeginSignRequest(context.Background(), "sign-1")
	defer finish()
	c.EndSessionSignRequests()
	if ctx.Err() != nil {
		t.Fatalf("the session end canceled the request's context: %v", ctx.Err())
	}
	_, err := c.RequestSigningApprovalPrompt(ctx, Prompt{RequestID: "sign-1", Address: "A", TxnSender: "A", Description: "d"}, time.Minute)
	if !errors.Is(err, ErrSessionEnded) {
		t.Fatalf("approval after the session ended = %v, want refused as session-ended", err)
	}
	select {
	case id := <-sent:
		t.Fatalf("a prompt (%s) was shown for a request whose session had ended", id)
	default:
	}
}

// A request sent without a request ID still belongs to the session it began
// in: after the session ends its approval is refused, not shown.
func TestASessionEndRefusesALaterApprovalOfARequestWithoutAnID(t *testing.T) {
	sent := make(chan string, 1)
	c := New(
		func() bool { return true },
		func(req *SignRequest) bool { sent <- req.ID; return true },
		func(*SignRequestCanceled) bool { return true },
	)
	ctx, finish := c.BeginSignRequest(context.Background(), "")
	defer finish()
	c.EndSessionSignRequests()
	if _, err := c.RequestSigningApprovalPrompt(ctx, Prompt{RequestID: "req-generated", Address: "A", TxnSender: "A", Description: "d"}, time.Minute); !errors.Is(err, ErrSessionEnded) {
		t.Fatalf("approval after the session ended = %v, want refused as session-ended", err)
	}
	select {
	case id := <-sent:
		t.Fatalf("a prompt (%s) was shown for a request whose session had ended", id)
	default:
	}
}

// An operator's rejection stays a rejection even when the session ends
// before the request reads it; only an approval or a withdrawal answered in
// the meantime gives way to the session end.
func TestARejectionStaysARejectionWhenTheSessionEndsAfterIt(t *testing.T) {
	for i := 0; i < 200; i++ {
		sent := make(chan string, 1)
		c := New(
			func() bool { return true },
			func(req *SignRequest) bool { sent <- req.ID; return true },
			func(*SignRequestCanceled) bool { return true },
		)
		ctx, finish := c.BeginSignRequest(context.Background(), "sign-1")
		type outcome struct {
			response SignResponse
			err      error
		}
		result := make(chan outcome, 1)
		go func() {
			response, err := c.RequestSigningApprovalPrompt(ctx, Prompt{RequestID: "sign-1", Address: "A", TxnSender: "A", Description: "d"}, time.Minute)
			result <- outcome{response, err}
		}()
		promptID := <-sent
		c.HandleSignResponse(&SignResponse{ID: promptID, Approved: false, Reason: "rejected by user"})
		c.EndSessionSignRequests()
		got := <-result
		finish()
		if got.err != nil || got.response.Approved {
			t.Fatalf("iteration %d: rejection then session end = %+v, %v; want the rejection", i, got.response, got.err)
		}
	}
}

// When the session ends and the requester then cancels before a queued
// request wakes, it answers that the session ended, whichever of the two it
// sees first.
func TestASessionEndThenAClientCancelAnswersSessionEnded(t *testing.T) {
	for i := 0; i < 300; i++ {
		sent := make(chan string, 2)
		c := New(
			func() bool { return true },
			func(req *SignRequest) bool { sent <- req.ID; return true },
			func(*SignRequestCanceled) bool { return true },
		)
		holderCtx, finishHolder := c.BeginSignRequest(context.Background(), "holder")
		go func() {
			_, _ = c.RequestSigningApprovalPrompt(holderCtx, Prompt{RequestID: "holder", Address: "A", TxnSender: "A", Description: "d"}, time.Minute)
		}()
		<-sent // the holder has the delivery turn
		ctx, finish := c.BeginSignRequest(context.Background(), "queued")
		result := make(chan error, 1)
		queued := make(chan struct{})
		go func() {
			close(queued)
			_, err := c.RequestSigningApprovalPrompt(ctx, Prompt{RequestID: "queued", Address: "A", TxnSender: "A", Description: "d"}, time.Minute)
			result <- err
		}()
		<-queued
		time.Sleep(time.Millisecond) // let it reach the delivery queue
		c.EndSessionSignRequests()
		finish() // the requester goes away
		if err := <-result; !errors.Is(err, ErrSessionEnded) {
			t.Fatalf("iteration %d: session end then cancel = %v, want session-ended", i, err)
		}
		finishHolder()
	}
}

// When a prompt's wait ends by its request's cancellation or by timeout
// while the operator's answer is already waiting, the answer is what counts:
// a rejection is recorded as the operator's, not lost to the cancellation.
func TestAnAnswerWaitingWinsOverACancellation(t *testing.T) {
	c := New(func() bool { return true }, nil, func(*SignRequestCanceled) bool { return true })
	responseChan := make(chan SignResponse, 1)
	trySendSignResponse(responseChan, SignResponse{ID: "prompt", Approved: false, Reason: "rejected by user"})
	c.EndSessionSignRequests() // the session ended too
	response, err := c.answerWaiting("prompt", 0, responseChan, func() (SignResponse, error) {
		return SignResponse{}, sessionEndedError()
	})
	if err != nil || response.Approved || response.Reason != "rejected by user" {
		t.Fatalf("answerWaiting() = %+v, %v; want the operator's rejection", response, err)
	}

	empty := make(chan SignResponse, 1)
	if _, err := c.answerWaiting("prompt", 0, empty, func() (SignResponse, error) {
		return SignResponse{}, sessionEndedError()
	}); !errors.Is(err, ErrSessionEnded) {
		t.Fatalf("answerWaiting() with no answer = %v, want the fallback", err)
	}
}

// A wait for the delivery turn whose context has already ended prefers a
// session end that has also happened.
func TestAnEndedTurnWaitPrefersTheSessionEnd(t *testing.T) {
	c := New(func() bool { return true }, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ended := make(chan struct{})
	close(ended)
	if err := c.acquireDeliveryTurnContext(ctx, ended); !errors.Is(err, errSessionEndedWait) {
		t.Fatalf("acquireDeliveryTurnContext() = %v, want the session end", err)
	}
	if err := c.acquireDeliveryTurnContext(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("acquireDeliveryTurnContext() without a session end = %v, want canceled", err)
	}
}
