// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package approval

import (
	"context"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/txnreview"
)

// An operator's late answer to a canceled prompt must not approve a different
// request that the client resubmitted under the same request ID.
func TestDelayedApprovalCannotAuthorizeReplacement(t *testing.T) {
	delivered := make(chan *SignRequest, 2)
	c := New(func() bool { return true }, func(r *SignRequest) bool {
		delivered <- r
		return true
	}, func(*SignRequestCanceled) bool { return true })

	type result struct {
		response SignResponse
		err      error
	}
	start := func(ctx context.Context, description string) <-chan result {
		out := make(chan result, 1)
		go func() {
			response, err := c.RequestSigningApprovalPrompt(ctx, Prompt{RequestID: "client-controlled-id", Address: "key", TxnSender: "sender", Description: description, FirstValid: 1, LastValid: 100}, time.Second)
			out <- result{response, err}
		}()
		return out
	}

	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	first := start(ctxA, "transfer to trusted recipient")
	var shown *SignRequest
	select {
	case shown = <-delivered:
	case <-time.After(time.Second):
		t.Fatal("first prompt not delivered")
	}
	cancelA()
	select {
	case r := <-first:
		if r.err == nil {
			t.Fatal("first request was not canceled")
		}
	case <-time.After(time.Second):
		t.Fatal("first request did not stop")
	}

	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	second := start(ctxB, "different transfer to attacker recipient")
	var replacement *SignRequest
	select {
	case replacement = <-delivered:
	case <-time.After(time.Second):
		t.Fatal("replacement prompt not delivered")
	}
	if replacement.ID == shown.ID {
		t.Fatalf("replacement prompt reused prompt ID %q", shown.ID)
	}

	// The operator's delayed answer to the first prompt.
	c.HandleSignResponse(&SignResponse{ID: shown.ID, Approved: true})
	select {
	case r := <-second:
		t.Fatalf("late approval of the canceled prompt resolved the replacement: %+v, %v", r.response, r.err)
	case <-time.After(100 * time.Millisecond):
	}

	// The replacement is still pending and resolves only on its own prompt ID.
	c.HandleSignResponse(&SignResponse{ID: replacement.ID, Approved: false})
	select {
	case r := <-second:
		if r.err != nil || r.response.Approved {
			t.Fatalf("replacement = %+v, %v; want its own rejection", r.response, r.err)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement did not resolve on its own prompt ID")
	}
}

// /sign/cancel still finds the live prompt by the client's request ID.
func TestCancelByClientRequestIDDismissesGeneratedPrompt(t *testing.T) {
	delivered := make(chan *SignRequest, 1)
	canceled := make(chan *SignRequestCanceled, 1)
	c := New(func() bool { return true }, func(r *SignRequest) bool {
		delivered <- r
		return true
	}, func(m *SignRequestCanceled) bool {
		canceled <- m
		return true
	})
	done := make(chan error, 1)
	go func() {
		_, err := approvedOf(c.RequestSigningApprovalPrompt(context.Background(), Prompt{RequestID: "client-id", Address: "key", TxnSender: "sender", Description: "d", FirstValid: 1, LastValid: 100}, time.Minute))
		done <- err
	}()
	prompt := <-delivered
	if got := c.CancelSignRequest("client-id", ""); got.State != SignRequestCancelStateCanceled {
		t.Fatalf("CancelSignRequest() = %+v", got)
	}
	if m := <-canceled; m.ID != prompt.ID {
		t.Fatalf("cancel notice for %q, want the prompt's ID %q", m.ID, prompt.ID)
	}
	if err := <-done; err == nil {
		t.Fatal("canceled request returned no error")
	}
	if got := c.CancelSignRequest(prompt.ID, ""); got.State != SignRequestCancelStateNotFound {
		t.Fatalf("cancel by prompt ID = %+v; a client never sees prompt IDs", got)
	}
}

// A prompt's review reaches the admin client with the prompt.
func TestPromptDeliversItsReview(t *testing.T) {
	delivered := make(chan *SignRequest, 1)
	var c *Coordinator
	c = New(func() bool { return true }, func(r *SignRequest) bool {
		delivered <- r
		go c.HandleSignResponse(&SignResponse{ID: r.ID, Approved: true})
		return true
	}, func(*SignRequestCanceled) bool { return true })

	review := &txnreview.Review{Group: true}
	response, err := c.RequestSigningApprovalPrompt(context.Background(), Prompt{
		RequestID: "req-1", Address: "key", TxnSender: "sender", Description: "text", FirstValid: 1, LastValid: 9, Review: review,
	}, time.Second)
	if err != nil || !response.Approved {
		t.Fatalf("response = %+v, err = %v", response, err)
	}
	shown := <-delivered
	if shown.Review != review || shown.Description != "text" || shown.Address != "key" || shown.TxnSender != "sender" || shown.FirstValid != 1 || shown.LastValid != 9 {
		t.Fatalf("delivered request = %+v", shown)
	}
}
