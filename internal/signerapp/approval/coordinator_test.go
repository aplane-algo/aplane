// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package approval

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestCoordinatorSerializesSigningRequests(t *testing.T) {
	sent := make(chan string, 2)
	c := New(
		func() bool { return true },
		func(req *SignRequest) bool {
			sent <- req.ID
			return true
		},
		nil,
		nil,
	)

	var wg sync.WaitGroup
	results := make(chan bool, 2)

	wg.Add(2)
	go func() {
		defer wg.Done()
		ok, err := c.RequestSigningApproval("sign-1", "A", "A", "first", 0, 0, nil, time.Second)
		if err != nil {
			t.Errorf("first signing request failed: %v", err)
			return
		}
		results <- ok
	}()

	if got := <-sent; got != "sign-1" {
		t.Fatalf("first delivered request = %q, want sign-1", got)
	}

	go func() {
		defer wg.Done()
		ok, err := c.RequestSigningApproval("sign-2", "B", "B", "second", 0, 0, nil, time.Second)
		if err != nil {
			t.Errorf("second signing request failed: %v", err)
			return
		}
		results <- ok
	}()

	select {
	case got := <-sent:
		t.Fatalf("second request delivered before first response: %s", got)
	case <-time.After(50 * time.Millisecond):
	}

	c.HandleSignResponse(&SignResponse{ID: "sign-1", Approved: true})

	if got := <-sent; got != "sign-2" {
		t.Fatalf("second delivered request = %q, want sign-2", got)
	}

	c.HandleSignResponse(&SignResponse{ID: "sign-2", Approved: true})

	wg.Wait()
	close(results)
	for ok := range results {
		if !ok {
			t.Fatal("expected approved signing result")
		}
	}
}

func TestCoordinatorCancelSignRequestDismissesPendingApproval(t *testing.T) {
	sent := make(chan string, 1)
	canceled := make(chan SignRequestCanceled, 1)
	c := New(
		func() bool { return true },
		func(req *SignRequest) bool {
			sent <- req.ID
			return true
		},
		func(msg *SignRequestCanceled) bool {
			canceled <- *msg
			return true
		},
		nil,
	)

	result := make(chan error, 1)
	go func() {
		_, err := c.RequestSigningApproval("sign-1", "A", "A", "first", 0, 0, nil, time.Minute)
		result <- err
	}()

	if got := <-sent; got != "sign-1" {
		t.Fatalf("delivered request = %q, want sign-1", got)
	}
	if got := c.CancelSignRequest("sign-1", SignRequestCancelReasonClientCanceled); got.State != SignRequestCancelStateCanceled {
		t.Fatalf("CancelSignRequest() state = %q, want canceled", got.State)
	}

	select {
	case got := <-canceled:
		if got.ID != "sign-1" || got.Reason != SignRequestCancelReasonClientCanceled {
			t.Fatalf("canceled message = %#v, want sign-1 client_canceled", got)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel notification was not sent")
	}

	select {
	case err := <-result:
		if !errors.Is(err, ErrApprovalCanceled) {
			t.Fatalf("RequestSigningApproval() error = %v, want ErrApprovalCanceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RequestSigningApproval() did not return after cancel")
	}
	if got := c.PendingSignCount(); got != 0 {
		t.Fatalf("PendingSignCount() = %d, want 0", got)
	}
}

func TestCoordinatorCancelSignRequestBeforeApprovalIsPending(t *testing.T) {
	delivered := make(chan string, 1)
	c := New(
		func() bool { return true },
		func(req *SignRequest) bool {
			delivered <- req.ID
			return true
		},
		nil,
		nil,
	)

	ctx, finish := c.BeginSignRequest(context.Background(), "sign-early")
	defer finish()

	if got := c.CancelSignRequest("sign-early", SignRequestCancelReasonClientCanceled); got.State != SignRequestCancelStateCanceled {
		t.Fatalf("CancelSignRequest() state = %q, want canceled", got.State)
	}
	if got := c.CancelSignRequest("sign-early", SignRequestCancelReasonClientCanceled); got.State != SignRequestCancelStateCanceled {
		t.Fatalf("duplicate CancelSignRequest() state = %q, want canceled", got.State)
	}
	_, err := c.RequestSigningApprovalContext(ctx, "sign-early", "A", "A", "first", 0, 0, nil, time.Minute)
	if !errors.Is(err, ErrApprovalCanceled) {
		t.Fatalf("RequestSigningApproval() error = %v, want ErrApprovalCanceled", err)
	}
	select {
	case got := <-delivered:
		t.Fatalf("approval request was delivered after early cancel: %s", got)
	default:
	}
}

func TestCoordinatorCancelSignRequestCancelsConcurrentSameIDRequests(t *testing.T) {
	c := New(
		func() bool { return true },
		func(req *SignRequest) bool { return true },
		nil,
		nil,
	)

	ctx1, finish1 := c.BeginSignRequest(context.Background(), "sign-same")
	defer finish1()
	ctx2, finish2 := c.BeginSignRequest(context.Background(), "sign-same")
	defer finish2()

	if got := c.CancelSignRequest("sign-same", SignRequestCancelReasonClientCanceled); got.State != SignRequestCancelStateCanceled {
		t.Fatalf("CancelSignRequest() state = %q, want canceled", got.State)
	}

	for name, ctx := range map[string]context.Context{"first": ctx1, "second": ctx2} {
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Fatalf("%s context was not canceled", name)
		}
	}

	finish1()
	if got := c.CancelSignRequest("sign-same", SignRequestCancelReasonClientCanceled); got.State != SignRequestCancelStateCanceled {
		t.Fatalf("CancelSignRequest() with second request still active = %q, want canceled", got.State)
	}

	finish2()
	if got := c.CancelSignRequest("sign-same", SignRequestCancelReasonClientCanceled); got.State != SignRequestCancelStateNotFound {
		t.Fatalf("CancelSignRequest() after both finishes = %q, want not_found", got.State)
	}
}

func TestCoordinatorCancelSignRequestUnknownIsNotFound(t *testing.T) {
	c := New(
		func() bool { return true },
		func(req *SignRequest) bool { return true },
		nil,
		nil,
	)

	if got := c.CancelSignRequest("sign-missing", SignRequestCancelReasonClientCanceled); got.State != SignRequestCancelStateNotFound {
		t.Fatalf("CancelSignRequest() state = %q, want not_found", got.State)
	}
}

func TestCoordinatorSerializesAcrossApprovalTypes(t *testing.T) {
	sent := make(chan string, 2)
	c := New(
		func() bool { return true },
		func(req *SignRequest) bool {
			sent <- "sign:" + req.ID
			return true
		},
		nil,
		func(req *TokenProvisioningRequest) bool {
			sent <- "token:" + req.ID
			return true
		},
	)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		ok, err := c.RequestSigningApproval("sign-1", "A", "A", "first", 0, 0, nil, time.Second)
		if err != nil {
			t.Errorf("signing approval failed: %v", err)
			return
		}
		if !ok {
			t.Error("expected signing approval to be granted")
		}
	}()

	if got := <-sent; got != "sign:sign-1" {
		t.Fatalf("first delivered request = %q, want sign:sign-1", got)
	}

	go func() {
		defer wg.Done()
		ok, err := c.RequestTokenProvisioning("token-1", "id", "fp", "addr", time.Second)
		if err != nil {
			t.Errorf("token approval failed: %v", err)
			return
		}
		if !ok {
			t.Error("expected token approval to be granted")
		}
	}()

	select {
	case got := <-sent:
		t.Fatalf("token request delivered before signing response: %s", got)
	case <-time.After(50 * time.Millisecond):
	}

	c.HandleSignResponse(&SignResponse{ID: "sign-1", Approved: true})

	if got := <-sent; got != "token:token-1" {
		t.Fatalf("second delivered request = %q, want token:token-1", got)
	}

	c.HandleTokenProvisioningResponse(&TokenProvisioningResponse{ID: "token-1", Approved: true})

	wg.Wait()
}

func TestCoordinatorRejectsEmptyRequestID(t *testing.T) {
	c := New(
		func() bool { return true },
		func(req *SignRequest) bool { return true },
		nil,
		func(req *TokenProvisioningRequest) bool { return true },
	)

	if _, err := c.RequestSigningApproval("", "A", "A", "desc", 0, 0, nil, time.Second); err == nil {
		t.Fatal("RequestSigningApproval() error = nil, want request ID rejection")
	}
	if _, err := c.RequestTokenProvisioning("", "id", "fp", "addr", time.Second); err == nil {
		t.Fatal("RequestTokenProvisioning() error = nil, want request ID rejection")
	}
}

func TestCoordinatorFailAllClearsPendingMaps(t *testing.T) {
	c := New(
		func() bool { return true },
		func(req *SignRequest) bool { return true },
		nil,
		func(req *TokenProvisioningRequest) bool { return true },
	)
	c.pendingRequests["sign-1"] = make(chan SignResponse, 1)
	c.pendingTokenRequests["tok-1"] = make(chan TokenProvisioningResponse, 1)

	c.FailAllPendingRequests("disconnected")

	if got := len(c.pendingRequests); got != 0 {
		t.Fatalf("len(pendingRequests) = %d, want 0", got)
	}
	if got := len(c.pendingTokenRequests); got != 0 {
		t.Fatalf("len(pendingTokenRequests) = %d, want 0", got)
	}
}

func TestCoordinatorLateResponseAfterTimeoutIsIgnored(t *testing.T) {
	sent := make(chan string, 1)
	c := New(
		func() bool { return true },
		func(req *SignRequest) bool {
			sent <- req.ID
			return true
		},
		nil,
		nil,
	)

	done := make(chan error, 1)
	go func() {
		_, err := c.RequestSigningApproval("sign-timeout", "A", "A", "first", 0, 0, nil, 20*time.Millisecond)
		done <- err
	}()

	if got := <-sent; got != "sign-timeout" {
		t.Fatalf("delivered request = %q, want sign-timeout", got)
	}
	if err := <-done; err == nil {
		t.Fatal("RequestSigningApproval() error = nil, want timeout")
	}

	c.HandleSignResponse(&SignResponse{ID: "sign-timeout", Approved: true})

	if got := c.PendingSignCount(); got != 0 {
		t.Fatalf("PendingSignCount() = %d, want 0", got)
	}
}

func TestCoordinatorRequestSigningApprovalContextCancelCleansPendingRequest(t *testing.T) {
	sent := make(chan string, 1)
	canceled := make(chan SignRequestCanceled, 1)
	c := New(
		func() bool { return true },
		func(req *SignRequest) bool {
			sent <- req.ID
			return true
		},
		func(msg *SignRequestCanceled) bool {
			canceled <- *msg
			return true
		},
		nil,
	)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := c.RequestSigningApprovalContext(ctx, "sign-cancel", "A", "A", "first", 0, 0, nil, time.Second)
		done <- err
	}()

	if got := <-sent; got != "sign-cancel" {
		t.Fatalf("delivered request = %q, want sign-cancel", got)
	}
	cancel()

	err := <-done
	if !errors.Is(err, ErrApprovalCanceled) {
		t.Fatalf("RequestSigningApprovalContext() error = %v, want ErrApprovalCanceled", err)
	}
	if got := c.PendingSignCount(); got != 0 {
		t.Fatalf("PendingSignCount() = %d, want 0", got)
	}
	gotCancel := <-canceled
	if gotCancel.ID != "sign-cancel" || gotCancel.Reason != SignRequestCancelReasonClientCanceled {
		t.Fatalf("canceled message = %#v, want client cancel for sign-cancel", gotCancel)
	}
}

func TestCoordinatorQueuedSigningApprovalContextCancelReturnsBeforeDeliveryTurn(t *testing.T) {
	sent := make(chan string, 2)
	c := New(
		func() bool { return true },
		func(req *SignRequest) bool {
			sent <- req.ID
			return true
		},
		nil,
		nil,
	)

	firstDone := make(chan error, 1)
	go func() {
		_, err := c.RequestSigningApproval("sign-1", "A", "A", "first", 0, 0, nil, time.Second)
		firstDone <- err
	}()

	if got := <-sent; got != "sign-1" {
		t.Fatalf("first delivered request = %q, want sign-1", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	secondDone := make(chan error, 1)
	go func() {
		_, err := c.RequestSigningApprovalContext(ctx, "sign-2", "B", "B", "second", 0, 0, nil, time.Second)
		secondDone <- err
	}()
	waitForDeliveryQueueLength(t, c, 1)

	cancel()

	select {
	case err := <-secondDone:
		if !errors.Is(err, ErrApprovalCanceled) {
			t.Fatalf("queued RequestSigningApprovalContext() error = %v, want ErrApprovalCanceled", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("queued RequestSigningApprovalContext() did not return after context cancellation")
	}

	c.HandleSignResponse(&SignResponse{ID: "sign-1", Approved: true})
	if err := <-firstDone; err != nil {
		t.Fatalf("first RequestSigningApproval() error = %v, want nil", err)
	}

	select {
	case got := <-sent:
		t.Fatalf("canceled queued request was delivered after first approval: %s", got)
	case <-time.After(50 * time.Millisecond):
	}
	if got := c.PendingSignCount(); got != 0 {
		t.Fatalf("PendingSignCount() = %d, want 0", got)
	}
}

func TestCoordinatorMismatchedResponseIDDoesNotSatisfyActiveRequest(t *testing.T) {
	sent := make(chan string, 1)
	c := New(
		func() bool { return true },
		func(req *SignRequest) bool {
			sent <- req.ID
			return true
		},
		nil,
		nil,
	)

	resultCh := make(chan struct {
		approved bool
		err      error
	}, 1)
	go func() {
		approved, err := c.RequestSigningApproval("sign-1", "A", "A", "first", 0, 0, nil, time.Second)
		resultCh <- struct {
			approved bool
			err      error
		}{approved: approved, err: err}
	}()

	if got := <-sent; got != "sign-1" {
		t.Fatalf("delivered request = %q, want sign-1", got)
	}

	c.HandleSignResponse(&SignResponse{ID: "other-request", Approved: false})

	select {
	case result := <-resultCh:
		t.Fatalf("active request resolved after mismatched response: approved=%v err=%v", result.approved, result.err)
	case <-time.After(50 * time.Millisecond):
	}

	if got := c.PendingSignCount(); got != 1 {
		t.Fatalf("PendingSignCount() = %d, want 1 after mismatched response", got)
	}

	c.HandleSignResponse(&SignResponse{ID: "sign-1", Approved: true})

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("RequestSigningApproval() error = %v, want nil", result.err)
	}
	if !result.approved {
		t.Fatal("RequestSigningApproval() approved = false, want true")
	}
	if got := c.PendingSignCount(); got != 0 {
		t.Fatalf("PendingSignCount() = %d, want 0 after matching response", got)
	}
}

func TestCoordinatorRequestSigningApprovalResponseReturnsApproverPrincipal(t *testing.T) {
	sent := make(chan string, 1)
	c := New(
		func() bool { return true },
		func(req *SignRequest) bool {
			sent <- req.ID
			return true
		},
		nil,
		nil,
	)

	resultCh := make(chan struct {
		response SignResponse
		err      error
	}, 1)
	go func() {
		response, err := c.RequestSigningApprovalResponse("sign-1", "A", "A", "first", 0, 0, nil, time.Second)
		resultCh <- struct {
			response SignResponse
			err      error
		}{response: response, err: err}
	}()

	if got := <-sent; got != "sign-1" {
		t.Fatalf("delivered request = %q, want sign-1", got)
	}

	c.HandleSignResponse(&SignResponse{ID: "sign-1", Approved: true, ApproverPrincipal: "alice-admin"})

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("RequestSigningApprovalResponse() error = %v, want nil", result.err)
	}
	if !result.response.Approved {
		t.Fatal("RequestSigningApprovalResponse() approved = false, want true")
	}
	if result.response.ApproverPrincipal != "alice-admin" {
		t.Fatalf("ApproverPrincipal = %q, want alice-admin", result.response.ApproverPrincipal)
	}
}

func TestCoordinatorMismatchedTokenResponseIDDoesNotSatisfyActiveRequest(t *testing.T) {
	sent := make(chan string, 1)
	c := New(
		func() bool { return true },
		nil,
		nil,
		func(req *TokenProvisioningRequest) bool {
			sent <- req.ID
			return true
		},
	)

	resultCh := make(chan struct {
		approved bool
		err      error
	}, 1)
	go func() {
		approved, err := c.RequestTokenProvisioning("token-1", "id", "fp", "addr", time.Second)
		resultCh <- struct {
			approved bool
			err      error
		}{approved: approved, err: err}
	}()

	if got := <-sent; got != "token-1" {
		t.Fatalf("delivered token request = %q, want token-1", got)
	}

	c.HandleTokenProvisioningResponse(&TokenProvisioningResponse{ID: "other-token-request", Approved: false})

	select {
	case result := <-resultCh:
		t.Fatalf("active token request resolved after mismatched response: approved=%v err=%v", result.approved, result.err)
	case <-time.After(50 * time.Millisecond):
	}

	c.pendingTokenRequestsLock.Lock()
	pendingCount := len(c.pendingTokenRequests)
	c.pendingTokenRequestsLock.Unlock()
	if pendingCount != 1 {
		t.Fatalf("len(pendingTokenRequests) = %d, want 1 after mismatched response", pendingCount)
	}

	c.HandleTokenProvisioningResponse(&TokenProvisioningResponse{ID: "token-1", Approved: true})

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("RequestTokenProvisioning() error = %v, want nil", result.err)
	}
	if !result.approved {
		t.Fatal("RequestTokenProvisioning() approved = false, want true")
	}

	c.pendingTokenRequestsLock.Lock()
	pendingCount = len(c.pendingTokenRequests)
	c.pendingTokenRequestsLock.Unlock()
	if pendingCount != 0 {
		t.Fatalf("len(pendingTokenRequests) = %d, want 0 after matching response", pendingCount)
	}
}

func TestCoordinatorTokenProvisioningContextCancelClearsPending(t *testing.T) {
	sent := make(chan string, 1)
	c := New(
		func() bool { return true },
		nil,
		nil,
		func(req *TokenProvisioningRequest) bool {
			sent <- req.ID
			return true
		},
	)

	ctx, cancel := context.WithCancel(context.Background())
	resultCh := make(chan error, 1)
	go func() {
		_, err := c.RequestTokenProvisioningContext(ctx, "token-1", "id", "fp", "addr", time.Minute)
		resultCh <- err
	}()

	if got := <-sent; got != "token-1" {
		t.Fatalf("delivered token request = %q, want token-1", got)
	}
	cancel()

	select {
	case err := <-resultCh:
		if err == nil {
			t.Fatal("RequestTokenProvisioningContext() error = nil, want cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("RequestTokenProvisioningContext did not return after context cancellation")
	}

	c.pendingTokenRequestsLock.Lock()
	pendingCount := len(c.pendingTokenRequests)
	c.pendingTokenRequestsLock.Unlock()
	if pendingCount != 0 {
		t.Fatalf("len(pendingTokenRequests) = %d, want 0 after context cancellation", pendingCount)
	}
}

func TestCoordinatorFailAllUnblocksPendingRequest(t *testing.T) {
	sent := make(chan string, 1)
	c := New(
		func() bool { return true },
		func(req *SignRequest) bool {
			sent <- req.ID
			return true
		},
		nil,
		nil,
	)

	resultCh := make(chan struct {
		approved bool
		err      error
	}, 1)
	go func() {
		approved, err := c.RequestSigningApproval("sign-fail", "A", "A", "first", 0, 0, nil, time.Second)
		resultCh <- struct {
			approved bool
			err      error
		}{approved: approved, err: err}
	}()

	if got := <-sent; got != "sign-fail" {
		t.Fatalf("delivered request = %q, want sign-fail", got)
	}

	c.FailAllPendingRequests("disconnected")

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("RequestSigningApproval() error = %v, want nil", result.err)
	}
	if result.approved {
		t.Fatal("RequestSigningApproval() approved = true, want false")
	}
}

func waitForDeliveryQueueLength(t *testing.T, c *Coordinator, want int) {
	t.Helper()
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		c.deliveryMu.Lock()
		got := len(c.deliveryQueue)
		c.deliveryMu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	c.deliveryMu.Lock()
	got := len(c.deliveryQueue)
	c.deliveryMu.Unlock()
	t.Fatalf("delivery queue length = %d, want %d", got, want)
}
