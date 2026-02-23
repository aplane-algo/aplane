// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

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

	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/transport"
	"github.com/aplane-algo/aplane/internal/util"

	"golang.org/x/term"
)

func main() {
	// Define flags
	dataDir := flag.String("d", "", "Data directory (required, or set APSIGNER_DATA)")
	flag.Parse()

	// Resolve data directory from -d flag or APSIGNER_DATA env var
	resolvedDataDir := util.RequireSignerDataDir(*dataDir)

	// Load config from data directory
	config := util.LoadServerConfig(resolvedDataDir)

	fmt.Printf("ApApprover - Interactive Signing Approval CLI\n")
	fmt.Printf("================================================\n")

	// Prompt for passphrase
	fmt.Print("Enter passphrase: ")
	passphraseBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError reading passphrase: %v\n", err)
		os.Exit(1)
	}
	fmt.Println() // newline after password input
	passphrase := string(passphraseBytes)

	// Connect via IPC
	fmt.Printf("Connecting to Signer via IPC...\n")

	ipcClient := transport.NewIPC(config.IPCPath)
	if err := ipcClient.Dial(); err != nil {
		if errors.Is(err, transport.ErrAlreadyConnected) {
			fmt.Fprintln(os.Stderr, "Error: Another apadmin/apapprover is already connected")
		} else {
			fmt.Fprintf(os.Stderr, "Error: IPC connection failed: %v\n", err)
		}
		os.Exit(1)
	}
	defer ipcClient.Close()
	fmt.Printf("✓ Connected via IPC (%s)\n", config.IPCPath)

	// Authenticate (also unlocks signer if locked)
	if err := ipcClient.Authenticate(passphrase, 10*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Authenticated and signer unlocked")

	// Clear read deadline for main loop
	ipcClient.ClearReadDeadline()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Channel for stdin input
	inputChan := make(chan string)
	go readStdin(inputChan)

	// Queue of pending approval requests (FIFO)
	var requestQueue []*protocol.SignRequestMessage

	fmt.Println("\nWaiting for signing requests... (Ctrl+C to quit)")
	fmt.Println()

	// Channel for IPC messages
	msgChan := make(chan []byte)
	errChan := make(chan error)

	// Start goroutine to read messages
	go func() {
		for {
			message, err := ipcClient.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}
			msgChan <- message
		}
	}()

	for {
		select {
		case <-sigChan:
			fmt.Println("\nShutting down...")
			return

		case err := <-errChan:
			if errors.Is(err, io.EOF) {
				fmt.Fprintln(os.Stderr, "\nConnection closed by server")
			} else {
				fmt.Fprintf(os.Stderr, "\nConnection error: %v\n", err)
			}
			return

		case input := <-inputChan:
			if len(requestQueue) == 0 {
				continue
			}
			input = strings.ToLower(strings.TrimSpace(input))
			var approved bool
			var reason string

			switch input {
			case "y", "yes":
				approved = true
				fmt.Println("✓ APPROVED")
			case "n", "no":
				approved = false
				reason = "rejected by user"
				fmt.Println("✗ REJECTED")
			default:
				fmt.Print("Please enter y/yes or n/no: ")
				continue
			}

			// Send response for the first request in queue
			currentRequest := requestQueue[0]
			respMsg := protocol.SignResponseMessage{
				BaseMessage: protocol.BaseMessage{
					Type: protocol.MsgTypeSignResponse,
					ID:   currentRequest.ID,
				},
				Approved: approved,
				Reason:   reason,
			}
			if err := ipcClient.WriteJSON(respMsg); err != nil {
				fmt.Fprintf(os.Stderr, "Error sending response: %v\n", err)
			}

			// Remove processed request from queue
			requestQueue = requestQueue[1:]

			// Show next request or wait message
			if len(requestQueue) > 0 {
				displayRequest(requestQueue[0], len(requestQueue))
			} else {
				fmt.Println("\nWaiting for signing requests...")
			}

		case message := <-msgChan:
			// Parse message
			var base protocol.BaseMessage
			if err := json.Unmarshal(message, &base); err != nil {
				continue
			}

			switch base.Type {
			case protocol.MsgTypeSignRequest:
				var req protocol.SignRequestMessage
				if err := json.Unmarshal(message, &req); err != nil {
					continue
				}

				// Add to queue
				requestQueue = append(requestQueue, &req)

				// If this is the only request, display it
				// If there are multiple, show notification and keep current display
				if len(requestQueue) == 1 {
					displayRequest(&req, 1)
				} else {
					fmt.Printf("\n⏳ New request queued (%d pending total)\n", len(requestQueue))
					fmt.Print("Approve? [y/n]: ") // Re-prompt for current request
				}

			case protocol.MsgTypeError:
				var errMsg protocol.ErrorMessage
				if err := json.Unmarshal(message, &errMsg); err != nil {
					continue
				}
				fmt.Fprintf(os.Stderr, "Error: %s\n", errMsg.Error)
			}
		}
	}
}

func readStdin(ch chan<- string) {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		ch <- scanner.Text()
	}
}

// displayRequest shows a signing request to the user
func displayRequest(req *protocol.SignRequestMessage, queueLen int) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	if queueLen > 1 {
		fmt.Printf("🔐 SIGNING REQUEST (1 of %d pending)\n", queueLen)
	} else {
		fmt.Println("🔐 SIGNING REQUEST")
	}
	fmt.Println(strings.Repeat("=", 60))

	if req.TxnSender != "" && req.TxnSender != req.Address {
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

	fmt.Println(strings.Repeat("=", 60))
	fmt.Print("Approve? [y/n]: ")
}
