// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// JSON-RPC structures
type Request struct {
	Jsonrpc string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      interface{}     `json:"id"`
}

type Response struct {
	Jsonrpc string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *Error      `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

type Error struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Method-specific structures
type InitializeParams struct {
	Network    string `json:"network"`
	AlgodURL   string `json:"algodUrl"`
	AlgodToken string `json:"algodToken"`
	IndexerURL string `json:"indexerUrl"`
	Version    string `json:"version"` // APlane plugin protocol version
}

type InitializeResult struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Version string `json:"version"` // APlane plugin protocol version
}

type ExecuteParams struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

type ExecuteResult struct {
	Success      bool          `json:"success"`
	Message      string        `json:"message,omitempty"`
	Data         interface{}   `json:"data,omitempty"`
	Presentation *Presentation `json:"presentation,omitempty"`
}

type Presentation struct {
	Title    string                `json:"title,omitempty"`
	Summary  string                `json:"summary,omitempty"`
	Sections []PresentationSection `json:"sections,omitempty"`
}

type PresentationSection struct {
	Kind string `json:"kind"`
	Text string `json:"text,omitempty"`
}

type GetInfoResult struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Commands    []string `json:"commands"`
	Networks    []string `json:"networks"`
	Status      string   `json:"status"`
}

type ShutdownResult struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// Plugin state
var (
	network  string
	algodURL string
)

func main() {
	logInfo("Echo plugin starting...")

	scanner := bufio.NewScanner(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			logError("Failed to parse request: %v", err)
			continue
		}

		resp := handleRequest(&req)

		respBytes, err := json.Marshal(resp)
		if err != nil {
			logError("Failed to marshal response: %v", err)
			continue
		}

		_, _ = writer.Write(respBytes)
		_ = writer.WriteByte('\n')
		_ = writer.Flush()
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		logError("Scanner error: %v", err)
	}
}

func handleRequest(req *Request) *Response {
	switch req.Method {
	case "initialize":
		return handleInitialize(req)
	case "execute":
		return handleExecute(req)
	case "getInfo":
		return handleGetInfo(req)
	case "shutdown":
		return handleShutdown(req)
	default:
		return errorResponse(req.ID, -32601, "Method not found", nil)
	}
}

func handleInitialize(req *Request) *Response {
	var params InitializeParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return errorResponse(req.ID, -32602, "Invalid params", err.Error())
	}

	network = params.Network
	algodURL = params.AlgodURL

	logInfo("Initialized with network=%s, algod=%s", network, algodURL)

	result := InitializeResult{
		Success: true,
		Message: fmt.Sprintf("Echo plugin initialized on %s", network),
		Version: params.Version,
	}

	return successResponse(req.ID, result)
}

func handleExecute(req *Request) *Response {
	var params ExecuteParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return errorResponse(req.ID, -32602, "Invalid params", err.Error())
	}

	if params.Command != "echo" {
		return errorResponse(req.ID, -32601, "Unknown command", params.Command)
	}

	message := strings.Join(params.Args, " ")
	result := ExecuteResult{
		Success: true,
		Message: "Echo command completed",
		Data: map[string]string{
			"echoed": message,
		},
		Presentation: &Presentation{
			Sections: []PresentationSection{{
				Kind: "text",
				Text: fmt.Sprintf("Echo: %s", message),
			}},
		},
	}
	return successResponse(req.ID, result)
}

func handleGetInfo(req *Request) *Response {
	result := GetInfoResult{
		Name:        "echo-plugin",
		Version:     "1.0.0",
		Description: "Simple echo plugin for testing",
		Commands:    []string{"echo"},
		Networks:    []string{"testnet", "mainnet", "betanet"},
		Status:      "ready",
	}
	return successResponse(req.ID, result)
}

func handleShutdown(req *Request) *Response {
	logInfo("Shutting down...")

	result := ShutdownResult{
		Success: true,
		Message: "Echo plugin shutdown",
	}

	resp := successResponse(req.ID, result)

	go func() {
		os.Exit(0)
	}()

	return resp
}

func successResponse(id interface{}, result interface{}) *Response {
	return &Response{
		Jsonrpc: "2.0",
		Result:  result,
		ID:      id,
	}
}

func errorResponse(id interface{}, code int, message string, data interface{}) *Response {
	return &Response{
		Jsonrpc: "2.0",
		Error: &Error{
			Code:    code,
			Message: message,
			Data:    data,
		},
		ID: id,
	}
}

func logInfo(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[INFO] "+format+"\n", args...)
}

func logError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", args...)
}
