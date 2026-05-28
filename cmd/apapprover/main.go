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

	bootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/transport"

	"golang.org/x/term"
)

type approvalKind int

const (
	approvalKindSign approvalKind = iota
	approvalKindTokenProvisioning
)

type approvalRequest struct {
	kind         approvalKind
	signRequest  *protocol.SignRequestMessage
	tokenRequest *protocol.TokenProvisioningRequestMessage
}

type decodedNotification struct {
	request  *approvalRequest
	canceled *protocol.SignRequestCanceledMessage
	errMsg   *protocol.ErrorMessage
}

const approvalPrompt = "Approve current request? [y/n or n <reason>]: "

func main() {
	// Define flags
	dataDir := flag.String("d", "", "Data directory (required, or set APSIGNER_DATA)")
	flag.Parse()

	startup, err := bootstrap.Load(*dataDir)
	if err != nil {
		logErrorf("%v", err)
		logErrorf("use -d <path> or set APSIGNER_DATA environment variable")
		os.Exit(1)
	}
	config := startup.Config

	logInfof("APApprover - Interactive Signing Approval CLI")
	logInfof("================================================")

	// Prompt for passphrase
	fmt.Print("Enter passphrase: ")
	passphraseBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		logErrorf("error reading passphrase: %v", err)
		os.Exit(1)
	}
	fmt.Println() // newline after password input
	passphrase := string(passphraseBytes)

	// Connect via IPC
	logInfof("connecting to signer via IPC")

	ipcClient := transport.NewIPC(config.IPCPath)
	if err := ipcClient.Dial(); err != nil {
		if errors.Is(err, transport.ErrAlreadyConnected) {
			logErrorf("another apadmin/apapprover is already connected")
		} else {
			logErrorf("IPC connection failed: %v", err)
		}
		os.Exit(1)
	}
	defer ipcClient.Close()
	logInfof("connected via IPC (%s)", config.IPCPath)

	// Authenticate (also unlocks signer if locked)
	if err := ipcClient.Authenticate(passphrase, 10*time.Second); err != nil {
		logErrorf("%v", err)
		os.Exit(1)
	}
	logInfof("authenticated and signer unlocked")

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Channel for stdin input
	inputChan := make(chan string)
	go readStdin(inputChan)

	// Queue of pending approval requests (FIFO)
	var requestQueue []approvalRequest

	logInfof("waiting for approval requests (Ctrl+C to quit)")

	notifications := ipcClient.Notifications()
	lifecycle := ipcClient.LifecycleEvents()

	for {
		select {
		case <-sigChan:
			logInfof("shutting down")
			return

		case event := <-lifecycle:
			switch event.Type {
			case transport.LifecycleConnectionLost:
				if errors.Is(event.Err, io.EOF) {
					logWarnf("connection closed by server")
				} else {
					logErrorf("connection error: %v", event.Err)
				}
				return
			case transport.LifecycleProtocolError:
				logErrorf("protocol error: %v", event.Err)
				return
			case transport.LifecycleReaderStopped:
				return
			}

		case input := <-inputChan:
			if len(requestQueue) == 0 {
				continue
			}
			approved, reason, ok := parseApprovalInput(input)
			if !ok {
				fmt.Print("Please enter y/yes or n/no or n <reason>: ")
				continue
			}
			if approved {
				fmt.Println("✓ APPROVED")
			} else {
				fmt.Println("✗ REJECTED")
			}

			currentRequest := requestQueue[0]
			respMsg, err := buildApprovalResponse(currentRequest, approved, reason)
			if err != nil {
				logErrorf("error building response: %v", err)
				fmt.Print(approvalPrompt)
				continue
			}
			if err := ipcClient.WriteJSON(respMsg); err != nil {
				logErrorf("error sending response: %v", err)
				logWarnf("request remains pending; retry your response")
				fmt.Print(approvalPrompt)
				continue
			}

			requestQueue = requestQueue[1:]

			if len(requestQueue) > 0 {
				displayRequest(requestQueue[0], len(requestQueue))
			} else {
				logInfof("waiting for approval requests")
			}

		case notification := <-notifications:
			decoded, handled, err := decodeNotification(notification)
			if err != nil {
				logWarnf("%v", err)
				continue
			}
			if !handled {
				logWarnf("ignoring unknown IPC message type %q", notification.Base.Type)
				continue
			}
			if decoded.errMsg != nil {
				logErrorf("%s", decoded.errMsg.Error)
				continue
			}
			if decoded.canceled != nil {
				var removed, active bool
				requestQueue, removed, active = removeCanceledSignRequest(requestQueue, decoded.canceled.ID)
				if removed {
					fmt.Printf("\n⚠ Signing request %s canceled (%s)\n", decoded.canceled.ID, approvalCancelReason(decoded.canceled.Reason))
					if active {
						if len(requestQueue) > 0 {
							displayRequest(requestQueue[0], len(requestQueue))
						} else {
							logInfof("waiting for approval requests")
						}
					} else if len(requestQueue) > 0 {
						fmt.Print(approvalPrompt)
					}
				}
				continue
			}
			if decoded.request != nil {
				requestQueue = append(requestQueue, *decoded.request)
				if len(requestQueue) == 1 {
					displayRequest(requestQueue[0], 1)
				} else {
					fmt.Printf("\n⏳ New request queued (%d total pending). Current prompt still applies to the active request.\n", len(requestQueue))
					fmt.Print(approvalPrompt)
				}
			}
		}
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
	case protocol.MsgTypeTokenProvisioningRequest:
		var req protocol.TokenProvisioningRequestMessage
		if err := json.Unmarshal(notification.Raw, &req); err != nil {
			return decodedNotification{}, true, fmt.Errorf("malformed token provisioning request: %w", err)
		}
		return decodedNotification{
			request: &approvalRequest{
				kind:         approvalKindTokenProvisioning,
				tokenRequest: &req,
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

func removeCanceledSignRequest(queue []approvalRequest, requestID string) ([]approvalRequest, bool, bool) {
	for i, req := range queue {
		if req.kind != approvalKindSign || req.signRequest == nil || req.signRequest.ID != requestID {
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
	case approvalKindTokenProvisioning:
		if req.tokenRequest == nil {
			return nil, fmt.Errorf("missing token provisioning request")
		}
		return protocol.TokenProvisioningResponseMessage{
			BaseMessage: protocol.BaseMessage{
				Type: protocol.MsgTypeTokenProvisioningResponse,
				ID:   req.tokenRequest.ID,
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
	case approvalKindTokenProvisioning:
		displayTokenProvisioningRequest(req.tokenRequest, queueLen)
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

// displayTokenProvisioningRequest shows a token provisioning request to the user.
func displayTokenProvisioningRequest(req *protocol.TokenProvisioningRequestMessage, queueLen int) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	if queueLen > 1 {
		fmt.Printf("🎫 TOKEN PROVISIONING REQUEST (1 of %d pending)\n", queueLen)
	} else {
		fmt.Println("🎫 TOKEN PROVISIONING REQUEST")
	}
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Identity:    %s\n", req.IdentityID)
	fmt.Printf("SSH Key:     %s\n", req.SSHFingerprint)
	fmt.Printf("Remote Addr: %s\n", req.RemoteAddr)
	fmt.Printf("Timestamp:   %s\n", time.Unix(req.Timestamp, 0).Format(time.RFC3339))
	fmt.Println(strings.Repeat("=", 60))
	fmt.Print(approvalPrompt)
}
