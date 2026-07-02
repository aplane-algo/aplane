// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsonrpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingWriter struct {
	writes [][]byte
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	cp := append([]byte(nil), p...)
	w.writes = append(w.writes, cp)
	return len(p), nil
}

func TestCallWithTimeoutFailsFastOnConnectionClose(t *testing.T) {
	reader, writer := io.Pipe()
	defer func() { _ = reader.Close() }()

	client := NewClient(reader, &bytes.Buffer{})
	client.Start()

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.CallWithTimeout(MethodExecute, ExecuteParams{}, nil, 5*time.Second)
	}()

	time.Sleep(50 * time.Millisecond)
	_ = writer.Close()

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrConnectionClosed) {
			t.Fatalf("CallWithTimeout() error = %v, want %v", err, ErrConnectionClosed)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("CallWithTimeout() did not fail fast after connection close")
	}
}

func TestCallWithTimeoutIgnoresInvalidStringResponseID(t *testing.T) {
	reader, writer := io.Pipe()
	defer func() { _ = reader.Close() }()

	var requestBuf bytes.Buffer
	client := NewClient(reader, &requestBuf)
	client.Start()

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.CallWithTimeout(MethodExecute, ExecuteParams{}, nil, 5*time.Second)
	}()

	time.Sleep(50 * time.Millisecond)
	_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","id":"1","result":{"success":true}}` + "\n"))
	_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"success":true}}` + "\n"))

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("CallWithTimeout() error = %v, want success after valid response", err)
		}
		if lastErr := client.GetLastError(); lastErr == nil || !strings.Contains(lastErr.Error(), "invalid response id") {
			t.Fatalf("GetLastError() = %v, want invalid response id", lastErr)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("CallWithTimeout() did not receive valid response after invalid string id")
	}
}

func TestCallWithTimeoutIgnoresNonIntegralResponseID(t *testing.T) {
	reader, writer := io.Pipe()
	defer func() { _ = reader.Close() }()

	var requestBuf bytes.Buffer
	client := NewClient(reader, &requestBuf)
	client.Start()

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.CallWithTimeout(MethodExecute, ExecuteParams{}, nil, 5*time.Second)
	}()

	time.Sleep(50 * time.Millisecond)
	_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","id":1.5,"result":{"success":true}}` + "\n"))
	_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"success":true}}` + "\n"))

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("CallWithTimeout() error = %v, want success after valid response", err)
		}
		if lastErr := client.GetLastError(); lastErr == nil || !strings.Contains(lastErr.Error(), "invalid response id") {
			t.Fatalf("GetLastError() = %v, want invalid response id", lastErr)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("CallWithTimeout() did not receive valid response after non-integral id")
	}
}

func TestCallWithTimeoutIgnoresNullResponseID(t *testing.T) {
	reader, writer := io.Pipe()
	defer func() { _ = reader.Close() }()

	var requestBuf bytes.Buffer
	client := NewClient(reader, &requestBuf)
	client.Start()

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.CallWithTimeout(MethodExecute, ExecuteParams{}, nil, 5*time.Second)
	}()

	time.Sleep(50 * time.Millisecond)
	_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","id":null,"result":{"success":true}}` + "\n"))
	_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"success":true}}` + "\n"))

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("CallWithTimeout() error = %v, want success after valid response", err)
		}
		if lastErr := client.GetLastError(); lastErr == nil || !strings.Contains(lastErr.Error(), "invalid response id") {
			t.Fatalf("GetLastError() = %v, want invalid response id", lastErr)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("CallWithTimeout() did not receive valid response after null id")
	}
}

func TestReadLoopDispatchesInboundRequest(t *testing.T) {
	serverToClientReader, serverToClientWriter := io.Pipe()
	clientToServerReader, clientToServerWriter := io.Pipe()
	defer func() { _ = serverToClientReader.Close() }()
	defer func() { _ = clientToServerReader.Close() }()

	client := NewClient(serverToClientReader, clientToServerWriter)
	client.SetRequestHandler(RequestHandlerFunc(func(method string, params json.RawMessage) (interface{}, *Error) {
		if method != CallbackGetBalance {
			t.Errorf("callback method = %q, want %q", method, CallbackGetBalance)
		}
		var req GetBalanceParams
		if err := json.Unmarshal(params, &req); err != nil {
			t.Errorf("callback params unmarshal: %v", err)
		}
		if req.Address != "ADDR" || req.AssetID != 7 {
			t.Errorf("callback params = %+v, want ADDR/7", req)
		}
		return GetBalanceResult{Balance: 42}, nil
	}))
	client.Start()

	_, _ = serverToClientWriter.Write([]byte(`{"jsonrpc":"2.0","method":"getBalance","params":{"address":"ADDR","assetId":7},"id":99}` + "\n"))

	var response struct {
		Result GetBalanceResult `json:"result"`
		Error  *Error           `json:"error"`
		ID     float64          `json:"id"`
	}
	if err := json.NewDecoder(clientToServerReader).Decode(&response); err != nil {
		t.Fatalf("callback response decode error: %v", err)
	}
	if response.Error != nil {
		t.Fatalf("callback response error = %v, want nil", response.Error)
	}
	if response.ID != 99 || response.Result.Balance != 42 {
		t.Fatalf("callback response = %+v, want id 99 balance 42", response)
	}
}

func TestReadLoopDoesNotTreatInboundRequestAsPendingResponse(t *testing.T) {
	serverToClientReader, serverToClientWriter := io.Pipe()
	clientToServerReader, clientToServerWriter := io.Pipe()
	defer func() { _ = serverToClientReader.Close() }()
	defer func() { _ = clientToServerReader.Close() }()

	client := NewClient(serverToClientReader, clientToServerWriter)
	client.SetRequestHandler(RequestHandlerFunc(func(method string, params json.RawMessage) (interface{}, *Error) {
		return LogResult{Success: true}, nil
	}))
	client.Start()

	errCh := make(chan error, 1)
	go func() {
		var result ExecuteResult
		errCh <- client.CallWithTimeout(MethodExecute, ExecuteParams{}, &result, 5*time.Second)
	}()

	decoder := json.NewDecoder(clientToServerReader)
	var outbound map[string]interface{}
	if err := decoder.Decode(&outbound); err != nil {
		t.Fatalf("outbound request decode error: %v", err)
	}
	callID := outbound["id"]

	_, _ = serverToClientWriter.Write([]byte(`{"jsonrpc":"2.0","method":"log","params":{"level":"info","message":"hello"},"id":99}` + "\n"))
	var callbackResponse map[string]interface{}
	if err := decoder.Decode(&callbackResponse); err != nil {
		t.Fatalf("callback response decode error: %v", err)
	}
	if callbackResponse["id"] != float64(99) {
		t.Fatalf("callback response id = %v, want 99", callbackResponse["id"])
	}

	response := map[string]interface{}{
		"jsonrpc": Version,
		"id":      callID,
		"result":  map[string]interface{}{"success": true},
	}
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal final response: %v", err)
	}
	_, _ = serverToClientWriter.Write(append(data, '\n'))

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("CallWithTimeout() error = %v, want nil", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("CallWithTimeout() did not receive final response")
	}
}

func TestInboundSignTransactionCallbackFailsClosedWithoutHandler(t *testing.T) {
	serverToClientReader, serverToClientWriter := io.Pipe()
	clientToServerReader, clientToServerWriter := io.Pipe()
	defer func() { _ = serverToClientReader.Close() }()
	defer func() { _ = clientToServerReader.Close() }()

	client := NewClient(serverToClientReader, clientToServerWriter)
	client.Start()

	_, _ = serverToClientWriter.Write([]byte(`{"jsonrpc":"2.0","method":"signTransaction","params":{"encoded":"TXN"},"id":99}` + "\n"))

	var response struct {
		Error *Error  `json:"error"`
		ID    float64 `json:"id"`
	}
	if err := json.NewDecoder(clientToServerReader).Decode(&response); err != nil {
		t.Fatalf("callback response decode error: %v", err)
	}
	if response.ID != 99 {
		t.Fatalf("callback response id = %v, want 99", response.ID)
	}
	if response.Error == nil {
		t.Fatal("callback response error = nil, want method-not-found")
	}
	if response.Error.Code != MethodNotFound {
		t.Fatalf("callback response code = %d, want %d", response.Error.Code, MethodNotFound)
	}
	if !strings.Contains(response.Error.Message, "signTransaction") {
		t.Fatalf("callback response message = %q, want method name", response.Error.Message)
	}
}

func TestNotifyWritesSingleJSONLineFrame(t *testing.T) {
	writer := &recordingWriter{}
	client := NewClient(&bytes.Buffer{}, writer)

	if err := client.Notify(CallbackLog, LogParams{Level: "info", Message: "hello"}); err != nil {
		t.Fatalf("Notify() error = %v", err)
	}
	if len(writer.writes) != 1 {
		t.Fatalf("Write calls = %d, want 1", len(writer.writes))
	}
	if !bytes.HasSuffix(writer.writes[0], []byte("\n")) {
		t.Fatalf("written frame %q does not end with newline", string(writer.writes[0]))
	}
}

func TestDeliverResponseConcurrentWithFailPendingDoesNotPanic(t *testing.T) {
	for i := 0; i < 100; i++ {
		client := NewClient(&bytes.Buffer{}, &bytes.Buffer{})
		respChan := make(chan *Response, 1)
		client.pending[1] = respChan

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			client.deliverResponse(1, &Response{Jsonrpc: Version, ID: uint64(1)})
		}()
		go func() {
			defer wg.Done()
			client.failPending(ErrConnectionClosed)
		}()
		wg.Wait()

		select {
		case resp, ok := <-respChan:
			if ok && resp.ID != uint64(1) {
				t.Fatalf("response ID = %v, want 1", resp.ID)
			}
		default:
			t.Fatal("pending response channel was neither delivered nor closed")
		}
	}
}
