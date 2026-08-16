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
)

const maxRememberedCanceledSignRequests = 1024

type HasClientFunc func() bool
type SendSignRequestFunc func(*SignRequest) bool
type SendSignRequestCanceledFunc func(*SignRequestCanceled) bool
type SendTokenProvisioningRequestFunc func(*TokenProvisioningRequest) bool

type activeSignRequest struct {
	cancel context.CancelFunc
}

type deliveryWaiter struct {
	ready    chan struct{}
	granted  bool
	canceled bool
}

// Coordinator owns pending approval queues for signing and token provisioning.
type Coordinator struct {
	hasClient                    HasClientFunc
	sendSignRequest              SendSignRequestFunc
	sendSignRequestCanceled      SendSignRequestCanceledFunc
	sendTokenProvisioningRequest SendTokenProvisioningRequestFunc

	pendingRequests      map[string]chan SignResponse
	activeRequests       map[string]map[*activeSignRequest]struct{}
	canceledRequests     map[string]string
	canceledRequestOrder []string
	pendingRequestsLock  sync.Mutex

	pendingTokenRequests     map[string]chan TokenProvisioningResponse
	pendingTokenRequestsLock sync.Mutex

	deliveryMu       sync.Mutex
	deliveryInFlight bool
	deliveryQueue    []*deliveryWaiter
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

func trySendTokenResponse(ch chan TokenProvisioningResponse, msg TokenProvisioningResponse) {
	if ch == nil {
		return
	}
	select {
	case ch <- msg:
	default:
	}
	close(ch)
}

func New(hasClient HasClientFunc, sendSignRequest SendSignRequestFunc, sendSignRequestCanceled SendSignRequestCanceledFunc, sendTokenProvisioningRequest SendTokenProvisioningRequestFunc) *Coordinator {
	c := &Coordinator{
		hasClient:                    hasClient,
		sendSignRequest:              sendSignRequest,
		sendSignRequestCanceled:      sendSignRequestCanceled,
		sendTokenProvisioningRequest: sendTokenProvisioningRequest,
		pendingRequests:              make(map[string]chan SignResponse),
		activeRequests:               make(map[string]map[*activeSignRequest]struct{}),
		canceledRequests:             make(map[string]string),
		pendingTokenRequests:         make(map[string]chan TokenProvisioningResponse),
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

func (c *Coordinator) acquireDeliveryTurnContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	waiter := &deliveryWaiter{ready: make(chan struct{})}
	c.deliveryMu.Lock()
	if !c.deliveryInFlight && len(c.deliveryQueue) == 0 {
		c.deliveryInFlight = true
		c.deliveryMu.Unlock()
		return nil
	}
	c.deliveryQueue = append(c.deliveryQueue, waiter)
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

	if err := c.acquireDeliveryTurnContext(ctx); err != nil {
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

	c.pendingTokenRequestsLock.Lock()
	tokenRequests := c.pendingTokenRequests
	c.pendingTokenRequests = make(map[string]chan TokenProvisioningResponse)
	c.pendingTokenRequestsLock.Unlock()

	for id, ch := range tokenRequests {
		trySendTokenResponse(ch, TokenProvisioningResponse{ID: id, Approved: false, Reason: reason})
	}

}

func (c *Coordinator) HandleTokenProvisioningResponse(msg *TokenProvisioningResponse) {
	if msg == nil || msg.ID == "" {
		return
	}
	c.pendingTokenRequestsLock.Lock()
	ch, exists := c.pendingTokenRequests[msg.ID]
	if exists {
		delete(c.pendingTokenRequests, msg.ID)
	}
	c.pendingTokenRequestsLock.Unlock()

	if exists {
		trySendTokenResponse(ch, *msg)
	}
}

func (c *Coordinator) RequestTokenProvisioning(requestID, identityID, sshFingerprint, remoteAddr string, timeout time.Duration) (bool, error) {
	return c.RequestTokenProvisioningContext(context.Background(), requestID, identityID, sshFingerprint, remoteAddr, timeout)
}

func (c *Coordinator) RequestTokenProvisioningContext(ctx context.Context, requestID, identityID, sshFingerprint, remoteAddr string, timeout time.Duration) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if requestID == "" {
		return false, fmt.Errorf("request ID is required")
	}
	if c.hasClient == nil || !c.hasClient() {
		return false, fmt.Errorf("no apadmin client connected")
	}

	if err := c.acquireDeliveryTurnContext(ctx); err != nil {
		return false, fmt.Errorf("token provisioning request canceled: %w", err)
	}
	defer c.releaseDeliveryTurn()

	if c.hasClient == nil || !c.hasClient() {
		return false, fmt.Errorf("no apadmin client connected")
	}

	responseChan := make(chan TokenProvisioningResponse, 1)

	c.pendingTokenRequestsLock.Lock()
	c.pendingTokenRequests[requestID] = responseChan
	c.pendingTokenRequestsLock.Unlock()

	defer func() {
		c.pendingTokenRequestsLock.Lock()
		delete(c.pendingTokenRequests, requestID)
		c.pendingTokenRequestsLock.Unlock()
	}()

	request := &TokenProvisioningRequest{
		ID:             requestID,
		IdentityID:     identityID,
		SSHFingerprint: sshFingerprint,
		RemoteAddr:     remoteAddr,
		Timestamp:      time.Now().Unix(),
	}

	if c.sendTokenProvisioningRequest == nil || !c.sendTokenProvisioningRequest(request) {
		return false, fmt.Errorf("failed to send token provisioning request via IPC")
	}

	select {
	case response := <-responseChan:
		if !response.Approved {
			return false, nil
		}
		return true, nil
	case <-time.After(timeout):
		return false, fmt.Errorf("approval timeout - no response from apadmin within %v", timeout)
	case <-ctx.Done():
		return false, fmt.Errorf("token provisioning canceled: %w", ctx.Err())
	}
}
