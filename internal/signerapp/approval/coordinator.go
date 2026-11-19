// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrApprovalTimeout  = errors.New("approval timeout")
	ErrApprovalCanceled = errors.New("approval canceled")
	// ErrSessionEnded accompanies ErrApprovalCanceled when an approval wait
	// ended because the signer's session ended (EndSessionSignRequests):
	// the request began in an earlier session epoch.
	ErrSessionEnded = errors.New("the signer's session ended")
	// ErrApproverGone accompanies ErrApprovalCanceled when the apadmin
	// session a prompt was shown to disconnected or was displaced before
	// answering it (FailAllPendingRequests). Nobody rejected the request.
	ErrApproverGone = errors.New("the apadmin session it was shown to ended before answering")
)

const maxRememberedCanceledSignRequests = 1024

type HasClientFunc func() bool
type SendSignRequestFunc func(*SignRequest) bool
type SendSignRequestCanceledFunc func(*SignRequestCanceled) bool

type activeSignRequest struct {
	cancel context.CancelFunc
}

// sessionEpochKey keys the session epoch a request registered in
// (BeginSignRequest) in the request's context.
type sessionEpochKey struct{}

// errSessionEndedWait ends a wait for the delivery turn that a session end
// interrupted.
var errSessionEndedWait = errors.New("session ended while waiting for the delivery turn")

type deliveryWaiter struct {
	ready    chan struct{}
	granted  bool
	canceled bool
}

// Coordinator owns the pending approval queue for signing requests.
type Coordinator struct {
	hasClient               HasClientFunc
	sendSignRequest         SendSignRequestFunc
	sendSignRequestCanceled SendSignRequestCanceledFunc

	// pendingRequests is keyed by the prompt ID the coordinator generates for
	// each prompt, never by the client's request ID: an operator's answer must
	// reach only the prompt it was given for, so a client that cancels and
	// resubmits under the same request ID cannot inherit a late approval.
	pendingRequests map[string]chan SignResponse
	// promptIDs maps a client request ID to its live prompt, for /sign/cancel.
	promptIDs            map[string]string
	activeRequests       map[string]map[*activeSignRequest]struct{}
	canceledRequests     map[string]string
	canceledRequestOrder []string
	pendingRequestsLock  sync.Mutex

	// sessionEpoch counts the signer's session ends
	// (EndSessionSignRequests); sessionEnded is closed at the next one. An
	// approval wait from an earlier epoch is over: its session has ended.
	// Both are guarded by pendingRequestsLock.
	sessionEpoch uint64
	sessionEnded chan struct{}

	// One request is delivered at a time (AP4).
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

func New(hasClient HasClientFunc, sendSignRequest SendSignRequestFunc, sendSignRequestCanceled SendSignRequestCanceledFunc) *Coordinator {
	c := &Coordinator{
		hasClient:               hasClient,
		sendSignRequest:         sendSignRequest,
		sendSignRequestCanceled: sendSignRequestCanceled,
		pendingRequests:         make(map[string]chan SignResponse),
		promptIDs:               make(map[string]string),
		activeRequests:          make(map[string]map[*activeSignRequest]struct{}),
		canceledRequests:        make(map[string]string),
		sessionEnded:            make(chan struct{}),
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
// approval wait. The returned context is canceled by CancelSignRequest, and
// carries the session epoch the request began in, so an approval it asks
// for after the session ended is refused.
func (c *Coordinator) BeginSignRequest(ctx context.Context, requestID string) (context.Context, func()) {
	if ctx == nil {
		ctx = context.Background()
	}
	if requestID == "" {
		// Nothing to cancel by ID, but its approval still belongs to the
		// session it began in.
		c.pendingRequestsLock.Lock()
		epoch := c.sessionEpoch
		c.pendingRequestsLock.Unlock()
		return context.WithValue(ctx, sessionEpochKey{}, epoch), func() {}
	}
	requestCtx, cancel := context.WithCancel(ctx)
	active := &activeSignRequest{cancel: cancel}

	c.pendingRequestsLock.Lock()
	if c.activeRequests[requestID] == nil {
		c.activeRequests[requestID] = make(map[*activeSignRequest]struct{})
	}
	c.activeRequests[requestID][active] = struct{}{}
	epoch := c.sessionEpoch
	c.pendingRequestsLock.Unlock()

	return context.WithValue(requestCtx, sessionEpochKey{}, epoch), func() {
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

// CancelSignRequest cancels a queued or pending signing request. A prompt
// already shown is dismissed in the admin client by its own request when it
// reads the withdrawal, after the prompt itself was sent.
func (c *Coordinator) CancelSignRequest(requestID, reason string) SignRequestCancelResult {
	if requestID == "" {
		return SignRequestCancelResult{State: SignRequestCancelStateNotFound}
	}
	if reason == "" {
		reason = SignRequestCancelReasonClientCanceled
	}

	var activeCancels []context.CancelFunc
	c.pendingRequestsLock.Lock()
	promptID := c.promptIDs[requestID]
	ch, exists := c.pendingRequests[promptID]
	if exists {
		delete(c.pendingRequests, promptID)
		delete(c.promptIDs, requestID)
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
			// The waiter dismisses the prompt when it reads this, after its
			// own sendSignRequest, so the dismissal never overtakes the
			// prompt it dismisses.
			trySendSignResponse(ch, SignResponse{ID: promptID, Approved: false, Reason: reason, withdrawn: true})
		}
		return SignRequestCancelResult{State: SignRequestCancelStateCanceled}
	}
	return SignRequestCancelResult{State: SignRequestCancelStateNotFound}
}

// EndSessionSignRequests ends every approval wait in flight because the
// signer's session ended: the prompt on the operator's screen is answered
// as withdrawn, requests queued for the delivery turn stop waiting, and a
// request from the ended session that asks for approval later is refused.
// Each answers ErrApprovalCanceled wrapping ErrSessionEnded. It cancels no
// request's context: a request that is planning or signing meets the
// session check or a lock's key-use cut, which answer locked, not a
// cancellation by its client. The withdrawn prompt is dismissed, with
// reason session_ended, by its own request, so the caller never writes to
// the operator's connection.
func (c *Coordinator) EndSessionSignRequests() {
	c.pendingRequestsLock.Lock()
	c.sessionEpoch++
	close(c.sessionEnded)
	c.sessionEnded = make(chan struct{})
	pending := c.pendingRequests
	c.pendingRequests = make(map[string]chan SignResponse)
	c.promptIDs = make(map[string]string)
	c.pendingRequestsLock.Unlock()
	for promptID, ch := range pending {
		trySendSignResponse(ch, SignResponse{ID: promptID, Approved: false, Reason: SignRequestCancelReasonSessionEnded, withdrawn: true})
	}
}

// requestSession returns the session epoch a request's approval belongs to,
// the channel a session end closes, and whether that session has already
// ended. A request registered with BeginSignRequest belongs to the epoch it
// registered in; any other belongs to the current one.
func (c *Coordinator) requestSession(ctx context.Context) (uint64, <-chan struct{}, bool) {
	c.pendingRequestsLock.Lock()
	defer c.pendingRequestsLock.Unlock()
	epoch, ok := ctx.Value(sessionEpochKey{}).(uint64)
	if !ok {
		epoch = c.sessionEpoch
	}
	return epoch, c.sessionEnded, epoch != c.sessionEpoch
}

// sessionEndedSince reports whether a session end came after epoch.
func (c *Coordinator) sessionEndedSince(epoch uint64) bool {
	c.pendingRequestsLock.Lock()
	defer c.pendingRequestsLock.Unlock()
	return c.sessionEpoch != epoch
}

// sessionEndedError is the error a withdrawn approval wait answers.
func sessionEndedError() error {
	return fmt.Errorf("%w: %w", ErrApprovalCanceled, ErrSessionEnded)
}

// cancellationError is ErrApprovalCanceled with reason, or with ctxErr when
// there is no reason. A session end also wraps ErrSessionEnded.
func cancellationError(reason string, ctxErr error) error {
	switch reason {
	case SignRequestCancelReasonSessionEnded:
		return fmt.Errorf("%w: %w", ErrApprovalCanceled, ErrSessionEnded)
	case SignRequestCancelReasonApproverDisconnected, SignRequestCancelReasonApproverDisplaced:
		return fmt.Errorf("%w: %w (%s)", ErrApprovalCanceled, ErrApproverGone, reason)
	case "":
		if ctxErr == nil {
			return ErrApprovalCanceled
		}
		return fmt.Errorf("%w: %w", ErrApprovalCanceled, ctxErr)
	default:
		return fmt.Errorf("%w: %s", ErrApprovalCanceled, reason)
	}
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

// isCancellationResponse reports whether response withdrew the request
// rather than answering it: only the coordinator sends such a response
// (CancelSignRequest). An operator's rejection is never one, whatever its
// free-text reason says.
func isCancellationResponse(response SignResponse) bool {
	return !response.Approved && response.withdrawn
}

// acquireDeliveryTurnContext waits for the delivery turn until ctx ends or
// sessionEnded closes (errSessionEndedWait); a nil sessionEnded never does.
func (c *Coordinator) acquireDeliveryTurnContext(ctx context.Context, sessionEnded <-chan struct{}) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		select {
		case <-sessionEnded:
			return errSessionEndedWait
		default:
		}
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
		select {
		case <-sessionEnded:
			return errSessionEndedWait
		default:
		}
		return ctx.Err()
	case <-sessionEnded:
		if c.cancelDeliveryWaiter(waiter) {
			c.releaseDeliveryTurn()
		}
		return errSessionEndedWait
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
	return c.RequestSigningApprovalPrompt(ctx, Prompt{
		RequestID: requestID, Address: address, TxnSender: txnSender, Description: description,
		FirstValid: firstValid, LastValid: lastValid, Violations: violations,
	}, timeout)
}

// RequestSigningApprovalPrompt shows prompt to the operator and waits for the
// answer, the timeout, or the request's cancellation.
func (c *Coordinator) RequestSigningApprovalPrompt(ctx context.Context, prompt Prompt, timeout time.Duration) (SignResponse, error) {
	requestID := prompt.RequestID
	if ctx == nil {
		ctx = context.Background()
	}
	if requestID == "" {
		return SignResponse{}, fmt.Errorf("request ID is required")
	}
	epoch, sessionEnded, ended := c.requestSession(ctx)
	if ended {
		return SignResponse{}, sessionEndedError()
	}
	if reason, canceled := c.consumeCanceledSignRequest(requestID); canceled {
		return SignResponse{}, cancellationError(reason, nil)
	}
	if c.hasClient == nil || !c.hasClient() {
		return SignResponse{}, fmt.Errorf("no apadmin client connected")
	}

	if err := c.acquireDeliveryTurnContext(ctx, sessionEnded); err != nil {
		if errors.Is(err, errSessionEndedWait) {
			return SignResponse{}, sessionEndedError()
		}
		return SignResponse{}, fmt.Errorf("%w: %w", ErrApprovalCanceled, err)
	}
	defer c.releaseDeliveryTurn()
	if c.sessionEndedSince(epoch) {
		return SignResponse{}, sessionEndedError()
	}
	if err := ctx.Err(); err != nil {
		return SignResponse{}, fmt.Errorf("%w: %w", ErrApprovalCanceled, err)
	}
	if reason, canceled := c.consumeCanceledSignRequest(requestID); canceled {
		return SignResponse{}, cancellationError(reason, nil)
	}
	if c.hasClient == nil || !c.hasClient() {
		return SignResponse{}, fmt.Errorf("no apadmin client connected")
	}

	responseChan := make(chan SignResponse, 1)
	promptID, err := newPromptID()
	if err != nil {
		return SignResponse{}, err
	}

	// Registered under the same lock a session end takes, so the prompt is
	// either withdrawn by that end or refused here: it never outlives it.
	c.pendingRequestsLock.Lock()
	if c.sessionEpoch != epoch {
		c.pendingRequestsLock.Unlock()
		return SignResponse{}, sessionEndedError()
	}
	c.pendingRequests[promptID] = responseChan
	c.promptIDs[requestID] = promptID
	c.pendingRequestsLock.Unlock()

	defer func() {
		c.pendingRequestsLock.Lock()
		delete(c.pendingRequests, promptID)
		if c.promptIDs[requestID] == promptID {
			delete(c.promptIDs, requestID)
		}
		c.pendingRequestsLock.Unlock()
	}()

	request := &SignRequest{
		ID:          promptID,
		Address:     prompt.Address,
		TxnSender:   prompt.TxnSender,
		Description: prompt.Description,
		Timestamp:   time.Now().Unix(),
		FirstValid:  prompt.FirstValid,
		LastValid:   prompt.LastValid,
		Violations:  prompt.Violations,
		Review:      prompt.Review,
	}

	if c.sendSignRequest == nil || !c.sendSignRequest(request) {
		return SignResponse{}, fmt.Errorf("failed to send signing request via IPC")
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case response := <-responseChan:
		return c.answer(promptID, epoch, response)
	case <-timer.C:
		return c.answerWaiting(promptID, epoch, responseChan, func() (SignResponse, error) {
			c.notifySignRequestCanceled(promptID, SignRequestCancelReasonTimeout)
			return SignResponse{}, fmt.Errorf("%w - no response from apadmin within %v", ErrApprovalTimeout, timeout)
		})
	case <-ctx.Done():
		return c.answerWaiting(promptID, epoch, responseChan, func() (SignResponse, error) {
			if c.sessionEndedSince(epoch) {
				c.notifySignRequestCanceled(promptID, SignRequestCancelReasonSessionEnded)
				return SignResponse{}, sessionEndedError()
			}
			c.notifySignRequestCanceled(promptID, SignRequestCancelReasonClientCanceled)
			return SignResponse{}, fmt.Errorf("%w: %w", ErrApprovalCanceled, ctx.Err())
		})
	}
}

// answer is the outcome of a prompt the operator or the coordinator
// answered. A session end overrides an approval or a withdrawal answered in
// the meantime (no request from the ended session can sign), but an
// operator's rejection stays a rejection.
func (c *Coordinator) answer(promptID string, epoch uint64, response SignResponse) (SignResponse, error) {
	if response.withdrawn {
		c.notifySignRequestCanceled(promptID, response.Reason)
	}
	if (response.Approved || response.withdrawn) && c.sessionEndedSince(epoch) {
		return SignResponse{}, sessionEndedError()
	}
	if isCancellationResponse(response) {
		return SignResponse{}, cancellationError(response.Reason, nil)
	}
	return response, nil
}

// answerWaiting resolves a prompt whose wait ended by timeout or by its
// request's cancellation: an answer already waiting is handled as answer
// handles it, so an operator's rejection is not lost to a cancellation or a
// timeout that came at the same moment; otherwise ended decides.
func (c *Coordinator) answerWaiting(promptID string, epoch uint64, responseChan chan SignResponse, ended func() (SignResponse, error)) (SignResponse, error) {
	select {
	case response, ok := <-responseChan:
		if ok {
			return c.answer(promptID, epoch, response)
		}
	default:
	}
	return ended()
}

// newPromptID returns an unguessable, single-use ID for one approval prompt.
func newPromptID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate approval prompt ID: %w", err)
	}
	return "apv-" + hex.EncodeToString(b[:]), nil
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

// FailAllPendingRequests withdraws every prompt delivered to the apadmin
// session that is ending: reason is SignRequestCancelReasonApproverDisconnected
// or SignRequestCancelReasonApproverDisplaced. Each waiter ends with
// ErrApproverGone, not a rejection: nobody answered the request, and it can be
// sent again once an apadmin session is connected. Requests still queued for
// the delivery turn are not affected; they go to the next session, or fail
// because none is connected.
func (c *Coordinator) FailAllPendingRequests(reason string) {
	c.pendingRequestsLock.Lock()
	signRequests := c.pendingRequests
	c.pendingRequests = make(map[string]chan SignResponse)
	c.promptIDs = make(map[string]string)
	c.pendingRequestsLock.Unlock()

	for id, ch := range signRequests {
		trySendSignResponse(ch, SignResponse{ID: id, Approved: false, Reason: reason, withdrawn: true})
	}
}
