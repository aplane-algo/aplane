// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/aplane-algo/aplane/internal/adminipc"
	"github.com/aplane-algo/aplane/internal/clientlog"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/termsafe"
	"github.com/aplane-algo/aplane/internal/transport"

	"github.com/charmbracelet/x/ansi"
	"golang.org/x/term"
)

type approvalKind int

const (
	approvalKindSign approvalKind = iota
	approvalKindClientEnrollment
)

// approvalRequest is one queued request: the pointer that matches kind is
// always set, by decodeNotification.
type approvalRequest struct {
	kind              approvalKind
	signRequest       *protocol.SignRequestMessage
	enrollmentRequest *protocol.ClientEnrollmentRequestMessage
}

func (r approvalRequest) id() string {
	switch r.kind {
	case approvalKindSign:
		return r.signRequest.ID
	case approvalKindClientEnrollment:
		return r.enrollmentRequest.ID
	}
	return ""
}

type decodedNotification struct {
	request  *approvalRequest
	canceled *protocol.SignRequestCanceledMessage
	errMsg   *protocol.ErrorMessage
}

// enrollmentOutcome is the signer's answer to an enrollment approval or
// rejection this client sent.
type enrollmentOutcome struct {
	approved    bool
	fingerprint string
	label       string
	success     bool
	err         string
}

func (o enrollmentOutcome) String() string {
	switch {
	case o.success && o.approved && o.label != "":
		return fmt.Sprintf("✓ Client key %s enrolled (%s)", o.fingerprint, o.label)
	case o.success && o.approved:
		return fmt.Sprintf("✓ Client key %s enrolled", o.fingerprint)
	case o.success:
		return fmt.Sprintf("✓ Enrollment request for %s rejected", o.fingerprint)
	case o.approved:
		return fmt.Sprintf("⚠ Approval of %s failed: %s", o.fingerprint, o.err)
	default:
		return fmt.Sprintf("⚠ Rejection of %s failed: %s", o.fingerprint, o.err)
	}
}

// approvalPrompt asks for an answer to the request at the head of the queue.
// Approving means typing that request's code, so an answer typed for one
// request cannot approve another.
func approvalPrompt(code string) string {
	return fmt.Sprintf("Approve current request? [y %s / n / n <reason>]: ", code)
}

// enrollmentAnswerTimeout bounds the wait for the signer's reply to an
// enrollment answer; the signer answers from its own registry at once.
const enrollmentAnswerTimeout = 10 * time.Second

func main() {
	clientlog.Install(clientlog.StartLevel(slog.LevelWarn), clientlog.WriterSink(os.Stderr))

	dataDir := flag.String("d", "", "Data directory (required, or set APSIGNER_DATA)")
	ipcPathFlag := flag.String("ipc-path", "", "Admin IPC socket path (or set APSIGNER_IPC_PATH)")
	flag.Parse()

	ipcClient, ok := connectApprover(*dataDir, *ipcPathFlag)
	if !ok {
		os.Exit(1)
	}
	defer ipcClient.Close()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	inputChan := make(chan string)
	go readStdin(inputChan)

	logInfof("waiting for approval requests (Ctrl+C to quit)")
	a := &approver{
		send: ipcClient.WriteJSON,
		answer: func(msg any) ([]byte, error) {
			return ipcClient.SendAndReceive(msg, enrollmentAnswerTimeout)
		},
	}
	notifications := ipcClient.Notifications()
	lifecycle := ipcClient.LifecycleEvents()
	lost := notificationLossReporter{count: ipcClient.DroppedNotifications, warnf: logWarnf}
	notificationDrops := ipcClient.NotificationDrops()
	for {
		select {
		case <-sigChan:
			logInfof("shutting down")
			return
		case event := <-lifecycle:
			if connectionEnded(event) {
				lost.report()
				return
			}
		case <-notificationDrops:
			lost.report()
		case input := <-inputChan:
			a.handleInput(input)
		case notification := <-notifications:
			a.handleNotification(notification)
		}
	}
}

// notificationLossReporter tells the operator when the client lost signer
// notifications. Approval requests travel as notifications, so one may be
// missing from this screen.
type notificationLossReporter struct {
	count    func() uint64
	warnf    func(format string, args ...any)
	reported uint64
}

func (r *notificationLossReporter) report() {
	total := r.count()
	if total <= r.reported {
		return
	}
	r.reported = total
	r.warnf("%d signer notifications lost; an approval request may be missing", total)
}

// connectApprover reads the passphrase, connects to the signer's admin IPC
// socket, and authenticates, which also unlocks a locked signer. It logs the
// failure and reports false if any step fails.
func connectApprover(dataDir, ipcPathFlag string) (*transport.IPCClient, bool) {
	ipcPath, err := adminipc.ResolveClientPath(adminipc.ClientPathRequest{
		DataDir: serverconfig.GetSignerDataDir(dataDir), IPCPath: ipcPathFlag, DataDirExplicit: dataDir != "",
	})
	if err != nil {
		logErrorf("%v", err)
		return nil, false
	}

	logInfof("APApprover - Interactive Signing Approval CLI")
	logInfof("================================================")

	ipcClient := transport.NewIPC(ipcPath)
	if !loginApprover(ipcClient, ipcPath, readTerminalPassphrase) {
		return nil, false
	}
	return ipcClient, true
}

// approverConn is the part of the IPC client the login uses.
type approverConn interface {
	Dial() error
	Authenticate(passphrase []byte, timeout time.Duration) error
	Close()
}

// readTerminalPassphrase prompts for the passphrase and reads it unechoed.
func readTerminalPassphrase() ([]byte, error) {
	fmt.Print("Enter passphrase: ")
	passphrase, err := term.ReadPassword(syscall.Stdin)
	fmt.Println() // newline after password input
	return passphrase, err
}

// loginApprover reads the passphrase, dials the signer and authenticates. The
// passphrase is zeroed once the login is done, whatever its outcome. It logs a
// failure and reports false.
func loginApprover(conn approverConn, ipcPath string, readPassphrase func() ([]byte, error)) bool {
	passphrase, err := readPassphrase()
	defer crypto.ZeroBytes(passphrase)
	if err != nil {
		logErrorf("error reading passphrase: %v", err)
		return false
	}

	logInfof("connecting to signer via IPC")
	if err := conn.Dial(); err != nil {
		logErrorf("IPC connection failed: %v", err)
		return false
	}
	logInfof("connected via IPC (%s)", ipcPath)

	if err := conn.Authenticate(passphrase, 10*time.Second); err != nil {
		logErrorf("%v", err)
		conn.Close()
		return false
	}
	logInfof("authenticated and signer unlocked")
	return true
}

// connectionEnded logs a connection lifecycle event and reports whether it
// ends the session.
func connectionEnded(event transport.LifecycleEvent) bool {
	switch event.Type {
	case transport.LifecycleConnectionLost:
		if errors.Is(event.Err, io.EOF) {
			logWarnf("connection closed by server")
		} else {
			logErrorf("connection error: %v", event.Err)
		}
		return true
	case transport.LifecycleProtocolError:
		logErrorf("protocol error: %v", event.Err)
		return true
	case transport.LifecycleReaderStopped:
		return true
	}
	return false
}

// approver holds the FIFO queue of approval requests. The operator answers
// the request at the head; later requests wait their turn.
type approver struct {
	// send delivers a signing answer, which the signer does not reply to.
	send func(any) error
	// answer delivers an enrollment answer and returns the signer's reply:
	// approve_enrollment and reject_enrollment are requests with results,
	// and the result says whether the key was enrolled or the request
	// dropped (it may have been answered elsewhere, or lapsed).
	answer func(any) ([]byte, error)
	queue  []approvalRequest

	// headCode is the code the operator types to approve the request at the
	// head of the queue. A requester can withdraw a request and send another
	// in its place, and the terminal buffers a line until Enter: a "y" typed
	// for the first request must not approve the second. Each shown request
	// gets a fresh code, so an approval names the request it was meant for.
	headCode string
	// headShownNarrow reports that the request at the head of the queue was
	// shown on a terminal too narrow to review it, so its identity only: it
	// is shown whole, with a fresh code, before an answer is taken.
	headShownNarrow bool
	// newCode makes approval codes; tests replace it.
	newCode func() string
}

// minReviewWidth is the narrowest terminal apapprover takes an answer on,
// the width apadmin lays out for: every field row of a request fits it
// whole, so none is cut short of what the operator must check.
const minReviewWidth = 80

// terminalTooNarrow says why apapprover takes no answer.
const terminalTooNarrow = "terminal too narrow to review this request (needs 80 columns)"

// showHead displays the request at the head of the queue with a fresh
// approval code.
func (a *approver) showHead() {
	gen := a.newCode
	if gen == nil {
		gen = newApprovalCode
	}
	code := gen()
	for code == a.headCode {
		code = gen()
	}
	a.headCode = code
	width := terminalWidth()
	a.headShownNarrow = width < minReviewWidth
	if a.headShownNarrow {
		displayNarrow(a.queue[0])
	} else {
		displayRequest(a.queue[0], len(a.queue), width)
	}
	a.prompt()
}

func (a *approver) prompt() {
	if a.headShownNarrow {
		fmt.Print("Widen the terminal to 80 columns, then press Enter: ")
		return
	}
	fmt.Print(approvalPrompt(a.headCode))
}

// newApprovalCode returns a random four-digit approval code.
func newApprovalCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(10000))
	if err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return fmt.Sprintf("%04d", n.Int64())
}

// handleInput applies the operator's answer to the request at the head of the
// queue. A request stays queued if its response cannot be delivered.
func (a *approver) handleInput(input string) {
	if len(a.queue) == 0 {
		return
	}
	// No answer is taken on a terminal too narrow to review the request,
	// and none for a request shown only narrow: it is shown whole first.
	if terminalWidth() < minReviewWidth {
		fmt.Println(terminalTooNarrow)
		a.headShownNarrow = true
		a.prompt()
		return
	}
	if a.headShownNarrow {
		a.showHead()
		return
	}
	approved, code, reason, ok := parseApprovalInput(input)
	if !ok {
		fmt.Printf("Please enter y %s, or n / n <reason>: ", a.headCode)
		return
	}
	if approved && code != a.headCode {
		// Rejecting needs no code; approving must name the request shown.
		if code == "" {
			fmt.Printf("To approve, type y followed by this request's code: y %s\n", a.headCode)
		} else {
			fmt.Println("\n⚠ That code is not this request's; the request you meant may have been replaced. Review this one, then answer again.")
		}
		a.prompt()
		return
	}

	respMsg, err := buildApprovalResponse(a.queue[0], approved, reason)
	if err != nil {
		logErrorf("error building response: %v", err)
		a.prompt()
		return
	}
	if a.queue[0].kind == approvalKindClientEnrollment {
		if !a.answerEnrollment(a.queue[0], respMsg, approved) {
			a.prompt()
			return
		}
	} else {
		if approved {
			fmt.Println("✓ APPROVED")
		} else {
			fmt.Println("✗ REJECTED")
		}
		if err := a.send(respMsg); err != nil {
			logErrorf("error sending response: %v", err)
			logWarnf("request remains pending; retry your response")
			a.prompt()
			return
		}
	}
	a.queue = a.queue[1:]
	a.showHeadOrWait()
}

// answerEnrollment delivers an enrollment answer and prints the signer's
// verdict. It reports whether the request is settled: a delivery failure
// keeps it queued for a retry, while a refused answer (the request is no
// longer waiting, or the registry write failed) is final and is shown.
func (a *approver) answerEnrollment(req approvalRequest, respMsg any, approved bool) bool {
	raw, err := a.answer(respMsg)
	if err != nil {
		logErrorf("error delivering enrollment answer: %v", err)
		logWarnf("request remains pending; retry your response")
		return false
	}
	outcome, err := decodeEnrollmentOutcome(raw, req.enrollmentRequest.SSHFingerprint, approved)
	if err != nil {
		logErrorf("%v", err)
		logWarnf("request remains pending; retry your response")
		return false
	}
	fmt.Println(outcome)
	return true
}

// decodeEnrollmentOutcome reads the signer's reply to an enrollment answer.
func decodeEnrollmentOutcome(raw []byte, fingerprint string, approved bool) (enrollmentOutcome, error) {
	base, err := protocol.ParseAdminBaseMessage(raw)
	if err != nil {
		return enrollmentOutcome{}, fmt.Errorf("malformed enrollment answer reply: %w", err)
	}
	outcome := enrollmentOutcome{approved: approved, fingerprint: fingerprint}
	switch base.Type {
	case protocol.MsgTypeApproveEnrollmentResult:
		var result protocol.ApproveEnrollmentResultMessage
		if err := json.Unmarshal(raw, &result); err != nil {
			return enrollmentOutcome{}, fmt.Errorf("malformed approve enrollment result: %w", err)
		}
		outcome.success, outcome.err, outcome.label = result.Success, result.Error, result.Label
		if result.Fingerprint != "" {
			outcome.fingerprint = result.Fingerprint
		}
	case protocol.MsgTypeRejectEnrollmentResult:
		var result protocol.RejectEnrollmentResultMessage
		if err := json.Unmarshal(raw, &result); err != nil {
			return enrollmentOutcome{}, fmt.Errorf("malformed reject enrollment result: %w", err)
		}
		outcome.success, outcome.err = result.Success, result.Error
		if result.Fingerprint != "" {
			outcome.fingerprint = result.Fingerprint
		}
	case protocol.MsgTypeError:
		var errMsg protocol.ErrorMessage
		if err := json.Unmarshal(raw, &errMsg); err != nil {
			return enrollmentOutcome{}, fmt.Errorf("malformed error message: %w", err)
		}
		outcome.err = errMsg.Error
	default:
		return enrollmentOutcome{}, fmt.Errorf("unexpected reply %q to an enrollment answer", base.Type)
	}
	return outcome, nil
}

// handleNotification routes a server notification: an error, a withdrawn
// request, or a new request.
func (a *approver) handleNotification(notification transport.Notification) {
	decoded, handled, err := decodeNotification(notification)
	switch {
	case err != nil:
		slog.Warn(err.Error(), "component", "apapprover")
	case !handled:
		slog.Warn("ignoring unknown IPC message", "component", "apapprover", "type", notification.Base.Type)
	case decoded.errMsg != nil:
		logErrorf("%s", decoded.errMsg.Error)
	case decoded.canceled != nil:
		a.handleCanceled(decoded.canceled.ID, decoded.canceled.Reason)
	case decoded.request != nil:
		a.enqueue(*decoded.request)
	}
}

// handleCanceled removes a signing request the server withdrew. If it was the
// one being answered, the next request is shown. Enrollment requests are
// never withdrawn.
func (a *approver) handleCanceled(id, reason string) {
	var removed, active bool
	a.queue, removed, active = removeCanceledRequest(a.queue, id)
	if !removed {
		return
	}
	fmt.Printf("\n⚠ Signing request %s canceled (%s)\n", id, approvalCancelReason(reason))
	if active {
		a.showHeadOrWait()
	} else if len(a.queue) > 0 {
		a.prompt()
	}
}

func (a *approver) enqueue(req approvalRequest) {
	// A waiting enrollment request is announced again whenever this client
	// connects; one entry per request is enough.
	for _, queued := range a.queue {
		if queued.kind == req.kind && queued.id() == req.id() {
			return
		}
	}
	a.queue = append(a.queue, req)
	if len(a.queue) == 1 {
		a.showHead()
		return
	}
	fmt.Printf("\n⏳ New request queued (%d total pending). Current prompt still applies to the active request.\n", len(a.queue))
	a.prompt()
}

func (a *approver) showHeadOrWait() {
	if len(a.queue) > 0 {
		a.showHead()
	} else {
		logInfof("waiting for approval requests")
	}
}

func decodeNotification(notification transport.Notification) (decodedNotification, bool, error) {
	switch notification.Base.Type {
	case protocol.MsgTypeSignRequest:
		var req protocol.SignRequestMessage
		if err := json.Unmarshal(notification.Raw, &req); err != nil {
			return decodedNotification{}, true, fmt.Errorf("malformed sign request: %w", err)
		}
		req = req.TerminalSafe()
		return decodedNotification{
			request: &approvalRequest{
				kind:        approvalKindSign,
				signRequest: &req,
			},
		}, true, nil
	case protocol.MsgTypeSignRequestCanceled:
		var canceled protocol.SignRequestCanceledMessage
		if err := json.Unmarshal(notification.Raw, &canceled); err != nil {
			return decodedNotification{}, true, fmt.Errorf("malformed sign request cancellation: %w", err)
		}
		return decodedNotification{canceled: &canceled}, true, nil
	case protocol.MsgTypeClientEnrollmentRequest:
		var req protocol.ClientEnrollmentRequestMessage
		if err := json.Unmarshal(notification.Raw, &req); err != nil {
			return decodedNotification{}, true, fmt.Errorf("malformed client enrollment request: %w", err)
		}
		return decodedNotification{
			request: &approvalRequest{
				kind:              approvalKindClientEnrollment,
				enrollmentRequest: &req,
			},
		}, true, nil
	case protocol.MsgTypeError:
		var errMsg protocol.ErrorMessage
		if err := json.Unmarshal(notification.Raw, &errMsg); err != nil {
			return decodedNotification{}, true, fmt.Errorf("malformed error message: %w", err)
		}
		return decodedNotification{errMsg: &errMsg}, true, nil
	default:
		return decodedNotification{}, false, nil
	}
}

// removeCanceledRequest drops a withdrawn signing request. It reports whether
// the request was found and whether it was the active one.
func removeCanceledRequest(queue []approvalRequest, requestID string) ([]approvalRequest, bool, bool) {
	for i, req := range queue {
		if req.kind != approvalKindSign || req.id() != requestID {
			continue
		}
		out := append(queue[:i:i], queue[i+1:]...)
		return out, true, i == 0
	}
	return queue, false, false
}

func approvalCancelReason(reason string) string {
	switch reason {
	case "":
		return "canceled"
	case "client_canceled":
		return "requester canceled"
	case "timeout":
		return "timed out"
	case "session_ended":
		return "withdrawn: the signer locked or its session ended"
	case "approver_displaced":
		return "withdrawn: another apadmin session took over"
	case "approver_disconnected":
		return "withdrawn: its apadmin session disconnected"
	default:
		return reason
	}
}

func readStdin(ch chan<- string) {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		ch <- scanner.Text()
	}
}

// parseApprovalInput reads "y <code>", "n" or "n <reason>". An approval
// without a code parses, with an empty code, so the caller can ask for it.
func parseApprovalInput(input string) (approved bool, code, reason string, ok bool) {
	input = strings.TrimSpace(input)
	if input == "" {
		return false, "", "", false
	}
	lower := strings.ToLower(input)
	fields := strings.Fields(lower)
	switch {
	case fields[0] == "y" || fields[0] == "yes":
		switch len(fields) {
		case 1:
			return true, "", "", true
		case 2:
			return true, fields[1], "", true
		}
		return false, "", "", false
	case lower == "n" || lower == "no":
		return false, "", "rejected by user", true
	case strings.HasPrefix(lower, "n "):
		return false, "", strings.TrimSpace(input[2:]), true
	case strings.HasPrefix(lower, "no "):
		return false, "", strings.TrimSpace(input[3:]), true
	default:
		return false, "", "", false
	}
}

func buildApprovalResponse(req approvalRequest, approved bool, reason string) (interface{}, error) {
	switch req.kind {
	case approvalKindClientEnrollment:
		// The request waits in the signer's queue; the answer names the key.
		if approved {
			return protocol.ApproveEnrollmentMessage{
				BaseMessage: protocol.BaseMessage{
					Type: protocol.MsgTypeApproveEnrollment,
					ID:   req.enrollmentRequest.ID,
				},
				Fingerprint: req.enrollmentRequest.SSHFingerprint,
			}, nil
		}
		return protocol.RejectEnrollmentMessage{
			BaseMessage: protocol.BaseMessage{
				Type: protocol.MsgTypeRejectEnrollment,
				ID:   req.enrollmentRequest.ID,
			},
			Fingerprint: req.enrollmentRequest.SSHFingerprint,
		}, nil
	case approvalKindSign:
		return protocol.SignResponseMessage{
			BaseMessage: protocol.BaseMessage{
				Type: protocol.MsgTypeSignResponse,
				ID:   req.signRequest.ID,
			},
			Approved: approved,
			Reason:   reason,
		}, nil
	default:
		return nil, fmt.Errorf("unknown approval kind %d", req.kind)
	}
}

// displayRequest shows an approval request to the user.
func displayRequest(req approvalRequest, queueLen, width int) {
	switch req.kind {
	case approvalKindClientEnrollment:
		displayClientEnrollmentRequest(req.enrollmentRequest, queueLen, width)
	default:
		displaySignRequest(req.signRequest, queueLen)
	}
}

// displayNarrow shows which request waits, on a terminal too narrow to
// review it: its identity, whole, and why it cannot be answered here. The
// identity is the signer's own text, a key's fingerprint or an account's
// address, so the terminal's wrap of it cannot be steered.
func displayNarrow(req approvalRequest) {
	fmt.Println()
	switch req.kind {
	case approvalKindClientEnrollment:
		fmt.Println("CLIENT ENROLLMENT REQUEST")
		fmt.Println(termsafe.Line(req.enrollmentRequest.SSHFingerprint))
	default:
		fmt.Println("SIGNING REQUEST")
		account := req.signRequest.TxnSender
		if account == "" {
			account = req.signRequest.Address
		}
		fmt.Println(termsafe.Line(account))
	}
	fmt.Println(terminalTooNarrow)
}

// displaySignRequest shows a signing request to the user.
func displaySignRequest(req *protocol.SignRequestMessage, queueLen int) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	if queueLen > 1 {
		fmt.Printf("🔐 SIGNING REQUEST (1 of %d pending)\n", queueLen)
	} else {
		fmt.Println("🔐 SIGNING REQUEST")
	}
	fmt.Println(strings.Repeat("=", 60))

	if strings.HasPrefix(req.Description, "[GROUP APPROVAL]\n") {
		fmt.Printf("Group:   %s\n", req.TxnSender)
		if req.Address != "" {
			fmt.Printf("Auth:    %s\n", req.Address)
		}
	} else if req.TxnSender != "" && req.TxnSender != req.Address {
		fmt.Printf("From:    %s (rekeyed)\n", req.TxnSender)
		fmt.Printf("Auth:    %s\n", req.Address)
	} else if req.TxnSender != "" {
		fmt.Printf("From:    %s\n", req.TxnSender)
	} else {
		fmt.Printf("Address: %s\n", req.Address)
	}

	if req.Description != "" {
		fmt.Println()
		printConfined(req.Description, terminalWidth())
	}
	if line := protocol.ValidityWindowLine(req.FirstValid, req.LastValid); line != "" {
		fmt.Printf("\n%s\n", line)
	}
	// Notices are findings shown without alarm: listed apart, after the
	// warnings, and not counted among them.
	var warnings, notices []protocol.PolicyViolation
	for _, v := range req.Violations {
		if v.Severity == protocol.ViolationSeverityNotice {
			notices = append(notices, v)
		} else {
			warnings = append(warnings, v)
		}
	}
	for _, list := range []struct {
		heading string
		items   []protocol.PolicyViolation
	}{{"Policy warnings", warnings}, {"Notes", notices}} {
		if len(list.items) == 0 {
			continue
		}
		fmt.Printf("\n%s (%d):\n", list.heading, len(list.items))
		for _, v := range list.items {
			printConfined(violationLine(v), terminalWidth())
		}
	}

	fmt.Println(strings.Repeat("=", 60))
}

// continuationMark starts a line that continues the one above it.
const continuationMark = "| "

// printConfined prints text, each line cut at width columns, every piece
// after a line's first marked as its continuation. Much of a request comes
// from the client or the chain, an asset's URL or a note, so a value longer
// than the terminal is wide would otherwise wrap onto a line it starts,
// which could read like a field of its own.
func printConfined(text string, width int) {
	for _, line := range strings.Split(text, "\n") {
		for _, piece := range confinedLines(line, width) {
			fmt.Println(piece)
		}
	}
}

// confinedLines cuts line into pieces of at most width columns, every piece
// after the first starting with continuationMark. A piece holds at least one
// character, so a character wider than the room is a piece of its own.
func confinedLines(line string, width int) []string {
	if width <= len(continuationMark) || ansi.StringWidth(line) <= width {
		return []string{line}
	}
	var pieces []string
	for room := width; line != ""; room = width - len(continuationMark) {
		piece := ansi.Truncate(line, room, "")
		if piece == "" {
			_, size := utf8.DecodeRuneInString(line)
			piece = line[:size]
		}
		line = line[len(piece):]
		if pieces != nil {
			piece = continuationMark + piece
		}
		pieces = append(pieces, piece)
	}
	return pieces
}

// terminalWidth is the width of the terminal apapprover prints to, or 80
// when it cannot tell; tests replace it.
var terminalWidth = func() int {
	if width, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && width > 0 {
		return width
	}
	return 80
}

// violationLine is one warning or note of a signing request: its severity,
// its message, and the value it is about. A finding with no value, such as
// one about the request as a whole, is its message alone: its field names
// nothing the message doesn't.
func violationLine(v protocol.PolicyViolation) string {
	line := fmt.Sprintf("  - [%s] %s", strings.ToUpper(v.Severity), v.Message)
	switch field, value := strings.TrimSpace(v.Field), strings.TrimSpace(v.Value); {
	case value == "":
	case field == "":
		line += fmt.Sprintf(" (%s)", v.Value)
	default:
		line += fmt.Sprintf(" (%s=%s)", v.Field, v.Value)
	}
	return line
}

// displayClientEnrollmentRequest shows a client enrollment request to the user
// on a terminal width columns wide.
func displayClientEnrollmentRequest(req *protocol.ClientEnrollmentRequestMessage, queueLen, width int) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	if queueLen > 1 {
		fmt.Printf("🔑 CLIENT ENROLLMENT REQUEST (1 of %d pending)\n", queueLen)
	} else {
		fmt.Println("🔑 CLIENT ENROLLMENT REQUEST")
	}
	fmt.Println(strings.Repeat("=", 60))
	// Each field is one row its value cannot leave (termsafe.Field): the
	// label is the client's own text, quoted in ASCII, and no value can wrap
	// onto a line of its own that reads like a field.
	fmt.Println(termsafe.Field("SSH Key:     ", req.SSHFingerprint, width))
	if req.Label != "" {
		fmt.Println(termsafe.QuotedField("Label:       ", req.Label, width))
	}
	fmt.Println(termsafe.Field("Remote Addr: ", req.RemoteAddr, width))
	fmt.Println(termsafe.Field("Requested:   ", time.Unix(req.Timestamp, 0).Format(time.RFC3339), width))
	fmt.Println("Approving enrolls this key as a client; the client then connects on its own.")
	fmt.Println(strings.Repeat("=", 60))
}
