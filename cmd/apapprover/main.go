// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aplane-algo/aplane/internal/adminipc"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/transport"

	"golang.org/x/term"
)

type approvalKind int

const (
	approvalKindSign approvalKind = iota
	approvalKindClientEnrollment
)

type approvalRequest struct {
	kind              approvalKind
	signRequest       *protocol.SignRequestMessage
	enrollmentRequest *protocol.ClientEnrollmentRequestMessage
}

func (r approvalRequest) id() string {
	switch {
	case r.kind == approvalKindSign && r.signRequest != nil:
		return r.signRequest.ID
	case r.kind == approvalKindClientEnrollment && r.enrollmentRequest != nil:
		return r.enrollmentRequest.ID
	}
	return ""
}

type decodedNotification struct {
	request  *approvalRequest
	canceled *protocol.SignRequestCanceledMessage
	// enrollmentCanceled withdraws a delivered client access request.
	enrollmentCanceled *protocol.ClientEnrollmentRequestCanceledMessage
	errMsg             *protocol.ErrorMessage
}

const approvalPrompt = "Approve current request? [y/n or n <reason>]: "

func main() {
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
	a := &approver{send: ipcClient.WriteJSON}
	notifications := ipcClient.Notifications()
	lifecycle := ipcClient.LifecycleEvents()
	for {
		select {
		case <-sigChan:
			logInfof("shutting down")
			return
		case event := <-lifecycle:
			if connectionEnded(event) {
				return
			}
		case input := <-inputChan:
			a.handleInput(input)
		case notification := <-notifications:
			a.handleNotification(notification)
		}
	}
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

	fmt.Print("Enter passphrase: ")
	passphraseBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		logErrorf("error reading passphrase: %v", err)
		return nil, false
	}
	fmt.Println() // newline after password input
	passphrase := string(passphraseBytes)

	logInfof("connecting to signer via IPC")
	ipcClient := transport.NewIPC(ipcPath)
	if err := ipcClient.Dial(); err != nil {
		if errors.Is(err, transport.ErrAlreadyConnected) {
			logErrorf("another apadmin/apapprover is already connected")
		} else {
			logErrorf("IPC connection failed: %v", err)
		}
		return nil, false
	}
	logInfof("connected via IPC (%s)", ipcPath)

	if err := ipcClient.Authenticate(passphrase, 10*time.Second); err != nil {
		logErrorf("%v", err)
		ipcClient.Close()
		return nil, false
	}
	logInfof("authenticated and signer unlocked")
	return ipcClient, true
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
	send  func(any) error
	queue []approvalRequest
}

// handleInput applies the operator's answer to the request at the head of the
// queue. A request stays queued if its response cannot be sent.
func (a *approver) handleInput(input string) {
	if len(a.queue) == 0 {
		return
	}
	approved, reason, ok := parseApprovalInput(input)
	if !ok {
		fmt.Print("Please enter y/yes or n/no or n <reason>: ")
		return
	}
	if approved {
		fmt.Println("✓ APPROVED")
	} else {
		fmt.Println("✗ REJECTED")
	}

	respMsg, err := buildApprovalResponse(a.queue[0], approved, reason)
	if err != nil {
		logErrorf("error building response: %v", err)
		fmt.Print(approvalPrompt)
		return
	}
	if err := a.send(respMsg); err != nil {
		logErrorf("error sending response: %v", err)
		logWarnf("request remains pending; retry your response")
		fmt.Print(approvalPrompt)
		return
	}
	a.queue = a.queue[1:]
	a.showHeadOrWait()
}

// handleNotification routes a server notification: an error, a withdrawn
// request, or a new request.
func (a *approver) handleNotification(notification transport.Notification) {
	decoded, handled, err := decodeNotification(notification)
	switch {
	case err != nil:
		logWarnf("%v", err)
	case !handled:
		logWarnf("ignoring unknown IPC message type %q", notification.Base.Type)
	case decoded.errMsg != nil:
		logErrorf("%s", decoded.errMsg.Error)
	case decoded.canceled != nil:
		a.handleCanceled(approvalKindSign, "Signing request", decoded.canceled.ID, decoded.canceled.Reason)
	case decoded.enrollmentCanceled != nil:
		a.handleCanceled(approvalKindClientEnrollment, "Client enrollment request", decoded.enrollmentCanceled.ID, decoded.enrollmentCanceled.Reason)
	case decoded.request != nil:
		a.enqueue(*decoded.request)
	}
}

// handleCanceled removes a request the server withdrew. If it was the one
// being answered, the next request is shown.
func (a *approver) handleCanceled(kind approvalKind, label, id, reason string) {
	var removed, active bool
	a.queue, removed, active = removeCanceledRequest(a.queue, kind, id)
	if !removed {
		return
	}
	fmt.Printf("\n⚠ %s %s canceled (%s)\n", label, id, approvalCancelReason(reason))
	if active {
		a.showHeadOrWait()
	} else if len(a.queue) > 0 {
		fmt.Print(approvalPrompt)
	}
}

func (a *approver) enqueue(req approvalRequest) {
	a.queue = append(a.queue, req)
	if len(a.queue) == 1 {
		displayRequest(a.queue[0], 1)
		return
	}
	fmt.Printf("\n⏳ New request queued (%d total pending). Current prompt still applies to the active request.\n", len(a.queue))
	fmt.Print(approvalPrompt)
}

func (a *approver) showHeadOrWait() {
	if len(a.queue) > 0 {
		displayRequest(a.queue[0], len(a.queue))
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
	case protocol.MsgTypeClientEnrollmentRequestCanceled:
		var canceled protocol.ClientEnrollmentRequestCanceledMessage
		if err := json.Unmarshal(notification.Raw, &canceled); err != nil {
			return decodedNotification{}, true, fmt.Errorf("malformed client enrollment cancellation: %w", err)
		}
		return decodedNotification{enrollmentCanceled: &canceled}, true, nil
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

// removeCanceledRequest drops a withdrawn request of the given kind. It
// reports whether the request was found and whether it was the active one.
func removeCanceledRequest(queue []approvalRequest, kind approvalKind, requestID string) ([]approvalRequest, bool, bool) {
	for i, req := range queue {
		if req.kind != kind || req.id() != requestID {
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
	case protocol.ClientEnrollmentCancelReasonPreempted:
		return "withdrawn for a signing request; the client can retry"
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

func parseApprovalInput(input string) (approved bool, reason string, ok bool) {
	input = strings.TrimSpace(input)
	if input == "" {
		return false, "", false
	}
	lower := strings.ToLower(input)
	switch {
	case lower == "y" || lower == "yes":
		return true, "", true
	case lower == "n" || lower == "no":
		return false, "rejected by user", true
	case strings.HasPrefix(lower, "n "):
		return false, strings.TrimSpace(input[2:]), true
	case strings.HasPrefix(lower, "no "):
		return false, strings.TrimSpace(input[3:]), true
	default:
		return false, "", false
	}
}

func buildApprovalResponse(req approvalRequest, approved bool, reason string) (interface{}, error) {
	switch req.kind {
	case approvalKindClientEnrollment:
		if req.enrollmentRequest == nil {
			return nil, fmt.Errorf("missing client enrollment request")
		}
		return protocol.ClientEnrollmentResponseMessage{
			BaseMessage: protocol.BaseMessage{
				Type: protocol.MsgTypeClientEnrollmentResponse,
				ID:   req.enrollmentRequest.ID,
			},
			Approved: approved,
			Reason:   reason,
		}, nil
	case approvalKindSign:
		if req.signRequest == nil {
			return nil, fmt.Errorf("missing sign request")
		}
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
func displayRequest(req approvalRequest, queueLen int) {
	switch req.kind {
	case approvalKindClientEnrollment:
		displayClientEnrollmentRequest(req.enrollmentRequest, queueLen)
	default:
		displaySignRequest(req.signRequest, queueLen)
	}
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
		fmt.Printf("\n%s\n", req.Description)
	}
	if len(req.Violations) > 0 {
		fmt.Printf("\nPolicy warnings (%d):\n", len(req.Violations))
		for _, v := range req.Violations {
			line := fmt.Sprintf("  - [%s] %s", strings.ToUpper(v.Severity), v.Message)
			if strings.TrimSpace(v.Field) != "" || strings.TrimSpace(v.Value) != "" {
				line += fmt.Sprintf(" (%s=%s)", v.Field, v.Value)
			}
			fmt.Println(line)
		}
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Print(approvalPrompt)
}

// displayClientEnrollmentRequest shows a client enrollment request to the user.
func displayClientEnrollmentRequest(req *protocol.ClientEnrollmentRequestMessage, queueLen int) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	if queueLen > 1 {
		fmt.Printf("🔑 CLIENT ENROLLMENT REQUEST (1 of %d pending)\n", queueLen)
	} else {
		fmt.Println("🔑 CLIENT ENROLLMENT REQUEST")
	}
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("SSH Key:     %s\n", req.SSHFingerprint)
	if req.Label != "" {
		fmt.Printf("Label:       %s\n", req.Label)
	}
	fmt.Printf("Remote Addr: %s\n", req.RemoteAddr)
	fmt.Printf("Timestamp:   %s\n", time.Unix(req.Timestamp, 0).Format(time.RFC3339))
	fmt.Println(strings.Repeat("=", 60))
	fmt.Print(approvalPrompt)
}
