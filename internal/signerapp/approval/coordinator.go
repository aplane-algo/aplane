// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package approval

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrApprovalTimeout  = errors.New("approval timeout")
	ErrApprovalCanceled = errors.New("approval canceled")
	// ErrClientEnrollmentPreempted reports that a signing request took the
	// approval turn from a client access request; the client may retry.
	ErrClientEnrollmentPreempted = errors.New("the operator is handling a signing request; try again")
)

const maxRememberedCanceledSignRequests = 1024

type HasClientFunc func() bool
type SendSignRequestFunc func(*SignRequest) bool
type SendSignRequestCanceledFunc func(*SignRequestCanceled) bool
type SendClientEnrollmentRequestFunc func(*ClientEnrollmentRequest) bool
type SendClientEnrollmentCanceledFunc func(*ClientEnrollmentCanceled) bool

type activeSignRequest struct {
	cancel context.CancelFunc
}

type deliveryWaiter struct {
	ready    chan struct{}
	granted  bool
	canceled bool
	signing  bool
}

// Coordinator owns pending approval queues for signing and token provisioning.
type Coordinator struct {
	hasClient                   HasClientFunc
	sendSignRequest             SendSignRequestFunc
	sendSignRequestCanceled     SendSignRequestCanceledFunc
	sendClientEnrollmentRequest SendClientEnrollmentRequestFunc

	pendingRequests      map[string]chan SignResponse
	activeRequests       map[string]map[*activeSignRequest]struct{}
	canceledRequests     map[string]string
	canceledRequestOrder []string
	pendingRequestsLock  sync.Mutex

	pendingEnrollmentRequests     map[string]chan ClientEnrollmentResponse
	pendingEnrollmentRequestsLock sync.Mutex

	// One request is delivered at a time (AP4). Signing takes priority over
	// token provisioning: a signing request queues ahead of waiting token
	// requests and withdraws a delivered one, so an unauthenticated client
	// access request can never hold up a signing approval.
	deliveryMu       sync.Mutex
	deliveryInFlight bool
	deliveryQueue    []*deliveryWaiter
	enrollmentHolder chan struct{} // closed to preempt the delivered token request; nil when none holds the turn

	sendClientEnrollmentCanceled SendClientEnrollmentCanceledFunc
}

// SetClientEnrollmentCanceledSender sets how a preempted token provisioning
// request is withdrawn from the approval client.
func (c *Coordinator) SetClientEnrollmentCanceledSender(send SendClientEnrollmentCanceledFunc) {
	c.deliveryMu.Lock()
	defer c.deliveryMu.Unlock()
	c.sendClientEnrollmentCanceled = send
}

func trySendSignResponse(ch chan SignResponse, msg SignResponse) {
	if ch == nil {
		return
	}
	select {
	case ch <- msg:
	default:
	}
	close(ch)
}

func trySendEnrollmentResponse(ch chan ClientEnrollmentResponse, msg ClientEnrollmentResponse) {
	if ch == nil {
		return
	}
	select {
	case ch <- msg:
	default:
	}
	close(ch)
}

func New(hasClient HasClientFunc, sendSignRequest SendSignRequestFunc, sendSignRequestCanceled SendSignRequestCanceledFunc, sendClientEnrollmentRequest SendClientEnrollmentRequestFunc) *Coordinator {
	c := &Coordinator{
		hasClient:                   hasClient,
		sendSignRequest:             sendSignRequest,
		sendSignRequestCanceled:     sendSignRequestCanceled,
		sendClientEnrollmentRequest: sendClientEnrollmentRequest,
		pendingRequests:             make(map[string]chan SignResponse),
		activeRequests:              make(map[string]map[*activeSignRequest]struct{}),
		canceledRequests:            make(map[string]string),
		pendingEnrollmentRequests:   make(map[string]chan ClientEnrollmentResponse),
	}
	return c
}

func (c *Coordinator) PendingSignCount() int {
	c.pendingRequestsLock.Lock()
	defer c.pendingRequestsLock.Unlock()
	return len(c.pendingRequests)
}

func (c *Coordinator) HandleSignResponse(msg *SignResponse) {
	if msg == nil || msg.ID == "" {
		return
	}
	c.pendingRequestsLock.Lock()
	ch, exists := c.pendingRequests[msg.ID]
	if exists {
		delete(c.pendingRequests, msg.ID)
	}
	c.pendingRequestsLock.Unlock()

	if exists {
		trySendSignResponse(ch, *msg)
	}
}

// BeginSignRequest tracks a live /sign request before it reaches the manual
// approval wait. The returned context is canceled by CancelSignRequest.
func (c *Coordinator) BeginSignRequest(ctx context.Context, requestID string) (context.Context, func()) {
	if ctx == nil {
		ctx = context.Background()
	}
	if requestID == "" {
		return ctx, func() {}
	}
	requestCtx, cancel := context.WithCancel(ctx)
	active := &activeSignRequest{cancel: cancel}

	c.pendingRequestsLock.Lock()
	if c.activeRequests[requestID] == nil {
		c.activeRequests[requestID] = make(map[*activeSignRequest]struct{})
	}
	c.activeRequests[requestID][active] = struct{}{}
	c.pendingRequestsLock.Unlock()

	return requestCtx, func() {
		c.pendingRequestsLock.Lock()
		if activeSet := c.activeRequests[requestID]; activeSet != nil {
			delete(activeSet, active)
			if len(activeSet) == 0 {
				delete(c.activeRequests, requestID)
				delete(c.canceledRequests, requestID)
			}
		}
		c.pendingRequestsLock.Unlock()
		cancel()
	}
}

// CancelSignRequest cancels a queued or pending signing request and notifies
// connected admin clients so visible approval prompts can be dismissed.
func (c *Coordinator) CancelSignRequest(requestID, reason string) SignRequestCancelResult {
	if requestID == "" {
		return SignRequestCancelResult{State: SignRequestCancelStateNotFound}
	}
	if reason == "" {
		reason = SignRequestCancelReasonClientCanceled
	}

	var activeCancels []context.CancelFunc
	c.pendingRequestsLock.Lock()
	ch, exists := c.pendingRequests[requestID]
	if exists {
		delete(c.pendingRequests, requestID)
	}
	if activeSet := c.activeRequests[requestID]; len(activeSet) > 0 {
		activeCancels = make([]context.CancelFunc, 0, len(activeSet))
		for active := range activeSet {
			activeCancels = append(activeCancels, active.cancel)
		}
		c.rememberCanceledSignRequestLocked(requestID, reason)
		exists = true
	} else if _, canceled := c.canceledRequests[requestID]; canceled {
		exists = true
	}
	c.pendingRequestsLock.Unlock()

	for _, cancelActive := range activeCancels {
		cancelActive()
	}
	if exists {
		if ch != nil {
			c.notifySignRequestCanceled(requestID, reason)
			trySendSignResponse(ch, SignResponse{ID: requestID, Approved: false, Reason: reason})
		}
		return SignRequestCancelResult{State: SignRequestCancelStateCanceled}
	}
	return SignRequestCancelResult{State: SignRequestCancelStateNotFound}
}

func (c *Coordinator) rememberCanceledSignRequestLocked(requestID, reason string) {
	if _, exists := c.canceledRequests[requestID]; !exists {
		c.canceledRequestOrder = append(c.canceledRequestOrder, requestID)
	}
	c.canceledRequests[requestID] = reason
	if len(c.canceledRequestOrder) > maxRememberedCanceledSignRequests*2 {
		c.compactCanceledSignRequestOrderLocked()
	}
	for len(c.canceledRequests) > maxRememberedCanceledSignRequests {
		c.evictOldestCanceledSignRequestLocked()
	}
}

func (c *Coordinator) evictOldestCanceledSignRequestLocked() {
	for len(c.canceledRequestOrder) > 0 {
		oldest := c.canceledRequestOrder[0]
		c.canceledRequestOrder[0] = ""
		c.canceledRequestOrder = c.canceledRequestOrder[1:]
		if _, exists := c.canceledRequests[oldest]; exists {
			delete(c.canceledRequests, oldest)
			return
		}
	}
}

func (c *Coordinator) compactCanceledSignRequestOrderLocked() {
	compacted := c.canceledRequestOrder[:0]
	for _, requestID := range c.canceledRequestOrder {
		if _, exists := c.canceledRequests[requestID]; exists {
			compacted = append(compacted, requestID)
		}
	}
	c.canceledRequestOrder = compacted
}

func (c *Coordinator) consumeCanceledSignRequest(requestID string) (string, bool) {
	c.pendingRequestsLock.Lock()
	defer c.pendingRequestsLock.Unlock()
	reason, exists := c.canceledRequests[requestID]
	if exists {
		delete(c.canceledRequests, requestID)
	}
	return reason, exists
}

func isCancellationResponse(response SignResponse) bool {
	if response.Approved {
		return false
	}
	return response.Reason == SignRequestCancelReasonClientCanceled ||
		response.Reason == SignRequestCancelReasonTimeout
}

func (c *Coordinator) acquireDeliveryTurnContext(ctx context.Context, signing bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	waiter := &deliveryWaiter{ready: make(chan struct{}), signing: signing}
	c.deliveryMu.Lock()
	if !c.deliveryInFlight && len(c.deliveryQueue) == 0 {
		c.deliveryInFlight = true
		c.deliveryMu.Unlock()
		return nil
	}
	if signing {
		// Queue ahead of token requests and withdraw a delivered one.
		at := len(c.deliveryQueue)
		for i, queued := range c.deliveryQueue {
			if !queued.signing {
				at = i
				break
			}
		}
		c.deliveryQueue = append(c.deliveryQueue, nil)
		copy(c.deliveryQueue[at+1:], c.deliveryQueue[at:])
		c.deliveryQueue[at] = waiter
		if c.enrollmentHolder != nil {
			close(c.enrollmentHolder)
			c.enrollmentHolder = nil
		}
	} else {
		c.deliveryQueue = append(c.deliveryQueue, waiter)
	}
	c.deliveryMu.Unlock()

	select {
	case <-waiter.ready:
		return nil
	case <-ctx.Done():
		if c.cancelDeliveryWaiter(waiter) {
			c.releaseDeliveryTurn()
		}
		return ctx.Err()
	}
}

func (c *Coordinator) cancelDeliveryWaiter(waiter *deliveryWaiter) bool {
	c.deliveryMu.Lock()
	defer c.deliveryMu.Unlock()
	if waiter.granted {
		return true
	}
	for i, queued := range c.deliveryQueue {
		if queued != waiter {
			continue
		}
		copy(c.deliveryQueue[i:], c.deliveryQueue[i+1:])
		c.deliveryQueue[len(c.deliveryQueue)-1] = nil
		c.deliveryQueue = c.deliveryQueue[:len(c.deliveryQueue)-1]
		break
	}
	waiter.canceled = true
	return false
}

func (c *Coordinator) releaseDeliveryTurn() {
	c.deliveryMu.Lock()
	for len(c.deliveryQueue) > 0 {
		waiter := c.deliveryQueue[0]
		copy(c.deliveryQueue[0:], c.deliveryQueue[1:])
		c.deliveryQueue[len(c.deliveryQueue)-1] = nil
		c.deliveryQueue = c.deliveryQueue[:len(c.deliveryQueue)-1]
		if waiter.canceled {
			continue
		}
		waiter.granted = true
		c.deliveryInFlight = true
		close(waiter.ready)
		c.deliveryMu.Unlock()
		return
	}
	c.deliveryInFlight = false
	c.deliveryMu.Unlock()
}

func (c *Coordinator) RequestSigningApproval(requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []Violation, timeout time.Duration) (bool, error) {
	response, err := c.RequestSigningApprovalResponseContext(context.Background(), requestID, address, txnSender, description, firstValid, lastValid, violations, timeout)
	if err != nil {
		return false, err
	}
	return response.Approved, nil
}

func (c *Coordinator) RequestSigningApprovalResponse(requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []Violation, timeout time.Duration) (SignResponse, error) {
	return c.RequestSigningApprovalResponseContext(context.Background(), requestID, address, txnSender, description, firstValid, lastValid, violations, timeout)
}

func (c *Coordinator) RequestSigningApprovalContext(ctx context.Context, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []Violation, timeout time.Duration) (bool, error) {
	response, err := c.RequestSigningApprovalResponseContext(ctx, requestID, address, txnSender, description, firstValid, lastValid, violations, timeout)
	if err != nil {
		return false, err
	}
	return response.Approved, nil
}

func (c *Coordinator) RequestSigningApprovalResponseContext(ctx context.Context, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []Violation, timeout time.Duration) (SignResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if requestID == "" {
		return SignResponse{}, fmt.Errorf("request ID is required")
	}
	if reason, canceled := c.consumeCanceledSignRequest(requestID); canceled {
		return SignResponse{}, fmt.Errorf("%w: %s", ErrApprovalCanceled, reason)
	}
	if c.hasClient == nil || !c.hasClient() {
		return SignResponse{}, fmt.Errorf("no apadmin client connected")
	}

	if err := c.acquireDeliveryTurnContext(ctx, true); err != nil {
		return SignResponse{}, fmt.Errorf("%w: %w", ErrApprovalCanceled, err)
	}
	defer c.releaseDeliveryTurn()
	if err := ctx.Err(); err != nil {
		return SignResponse{}, fmt.Errorf("%w: %w", ErrApprovalCanceled, err)
	}
	if reason, canceled := c.consumeCanceledSignRequest(requestID); canceled {
		return SignResponse{}, fmt.Errorf("%w: %s", ErrApprovalCanceled, reason)
	}
	if c.hasClient == nil || !c.hasClient() {
		return SignResponse{}, fmt.Errorf("no apadmin client connected")
	}

	responseChan := make(chan SignResponse, 1)

	c.pendingRequestsLock.Lock()
	c.pendingRequests[requestID] = responseChan
	c.pendingRequestsLock.Unlock()

	defer func() {
		c.pendingRequestsLock.Lock()
		delete(c.pendingRequests, requestID)
		c.pendingRequestsLock.Unlock()
	}()

	request := &SignRequest{
		ID:          requestID,
		Address:     address,
		TxnSender:   txnSender,
		Description: description,
		Timestamp:   time.Now().Unix(),
		FirstValid:  firstValid,
		LastValid:   lastValid,
		Violations:  violations,
	}

	if c.sendSignRequest == nil || !c.sendSignRequest(request) {
		return SignResponse{}, fmt.Errorf("failed to send signing request via IPC")
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case response := <-responseChan:
		if isCancellationResponse(response) {
			return SignResponse{}, fmt.Errorf("%w: %s", ErrApprovalCanceled, response.Reason)
		}
		return response, nil
	case <-timer.C:
		c.notifySignRequestCanceled(requestID, SignRequestCancelReasonTimeout)
		return SignResponse{}, fmt.Errorf("%w - no response from apadmin within %v", ErrApprovalTimeout, timeout)
	case <-ctx.Done():
		c.notifySignRequestCanceled(requestID, SignRequestCancelReasonClientCanceled)
		return SignResponse{}, fmt.Errorf("%w: %w", ErrApprovalCanceled, ctx.Err())
	}
}

func (c *Coordinator) notifySignRequestCanceled(requestID, reason string) {
	if c.sendSignRequestCanceled == nil {
		return
	}
	_ = c.sendSignRequestCanceled(&SignRequestCanceled{
		ID:     requestID,
		Reason: reason,
	})
}

func (c *Coordinator) FailAllPendingRequests(reason string) {
	c.pendingRequestsLock.Lock()
	signRequests := c.pendingRequests
	c.pendingRequests = make(map[string]chan SignResponse)
	c.pendingRequestsLock.Unlock()

	for id, ch := range signRequests {
		trySendSignResponse(ch, SignResponse{ID: id, Approved: false, Reason: reason})
	}

	c.pendingEnrollmentRequestsLock.Lock()
	tokenRequests := c.pendingEnrollmentRequests
	c.pendingEnrollmentRequests = make(map[string]chan ClientEnrollmentResponse)
	c.pendingEnrollmentRequestsLock.Unlock()

	for id, ch := range tokenRequests {
		trySendEnrollmentResponse(ch, ClientEnrollmentResponse{ID: id, Approved: false, Reason: reason})
	}

}

func (c *Coordinator) HandleClientEnrollmentResponse(msg *ClientEnrollmentResponse) {
	if msg == nil || msg.ID == "" {
		return
	}
	c.pendingEnrollmentRequestsLock.Lock()
	ch, exists := c.pendingEnrollmentRequests[msg.ID]
	if exists {
		delete(c.pendingEnrollmentRequests, msg.ID)
	}
	c.pendingEnrollmentRequestsLock.Unlock()

	if exists {
		trySendEnrollmentResponse(ch, *msg)
	}
}

func (c *Coordinator) RequestClientEnrollment(requestID, sshFingerprint, label, remoteAddr string, timeout time.Duration) (bool, error) {
	return c.RequestClientEnrollmentContext(context.Background(), requestID, sshFingerprint, label, remoteAddr, timeout)
}

func (c *Coordinator) RequestClientEnrollmentContext(ctx context.Context, requestID, sshFingerprint, label, remoteAddr string, timeout time.Duration) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if requestID == "" {
		return false, fmt.Errorf("request ID is required")
	}
	if c.hasClient == nil || !c.hasClient() {
		return false, fmt.Errorf("no apadmin client connected")
	}

	if err := c.acquireDeliveryTurnContext(ctx, false); err != nil {
		return false, fmt.Errorf("client enrollment request canceled: %w", err)
	}
	defer c.releaseDeliveryTurn()
	preempted, holding := c.holdEnrollmentTurn()
	if !holding {
		return false, ErrClientEnrollmentPreempted
	}
	defer c.dropEnrollmentTurn(preempted)

	if c.hasClient == nil || !c.hasClient() {
		return false, fmt.Errorf("no apadmin client connected")
	}

	responseChan := make(chan ClientEnrollmentResponse, 1)

	c.pendingEnrollmentRequestsLock.Lock()
	c.pendingEnrollmentRequests[requestID] = responseChan
	c.pendingEnrollmentRequestsLock.Unlock()

	defer func() {
		c.pendingEnrollmentRequestsLock.Lock()
		delete(c.pendingEnrollmentRequests, requestID)
		c.pendingEnrollmentRequestsLock.Unlock()
	}()

	request := &ClientEnrollmentRequest{
		ID:             requestID,
		SSHFingerprint: sshFingerprint,
		Label:          label,
		RemoteAddr:     remoteAddr,
		Timestamp:      time.Now().Unix(),
	}

	if c.sendClientEnrollmentRequest == nil || !c.sendClientEnrollmentRequest(request) {
		return false, fmt.Errorf("failed to send client enrollment request via IPC")
	}

	select {
	case response := <-responseChan:
		if !response.Approved {
			return false, nil
		}
		return true, nil
	case <-preempted:
		// Withdraw the prompt before releasing the turn, so the operator
		// never has two requests delivered at once.
		c.notifyClientEnrollmentCanceled(requestID, ClientEnrollmentCancelReasonPreempted)
		return false, ErrClientEnrollmentPreempted
	case <-time.After(timeout):
		return false, fmt.Errorf("approval timeout - no response from apadmin within %v", timeout)
	case <-ctx.Done():
		return false, fmt.Errorf("client enrollment canceled: %w", ctx.Err())
	}
}

// holdEnrollmentTurn registers the token request that now holds the delivery
// turn. It reports false when a signing request is already waiting, which
// takes the turn before the token request is delivered.
func (c *Coordinator) holdEnrollmentTurn() (<-chan struct{}, bool) {
	c.deliveryMu.Lock()
	defer c.deliveryMu.Unlock()
	for _, queued := range c.deliveryQueue {
		if queued.signing && !queued.canceled {
			return nil, false
		}
	}
	c.enrollmentHolder = make(chan struct{})
	return c.enrollmentHolder, true
}

func (c *Coordinator) dropEnrollmentTurn(preempt <-chan struct{}) {
	c.deliveryMu.Lock()
	defer c.deliveryMu.Unlock()
	if c.enrollmentHolder != nil && (<-chan struct{})(c.enrollmentHolder) == preempt {
		c.enrollmentHolder = nil
	}
}

func (c *Coordinator) notifyClientEnrollmentCanceled(requestID, reason string) {
	c.deliveryMu.Lock()
	send := c.sendClientEnrollmentCanceled
	c.deliveryMu.Unlock()
	if send == nil {
		return
	}
	_ = send(&ClientEnrollmentCanceled{ID: requestID, Reason: reason})
}
