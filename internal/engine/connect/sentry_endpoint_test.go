// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package connect

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

type sentrySSHDialerFunc func(context.Context) (net.Conn, error)

func (f sentrySSHDialerFunc) DialSignerAPI(ctx context.Context) (net.Conn, error) {
	return f(ctx)
}

func TestSentrySSHHTTPTransportUsesDirectSSHChannel(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()

	serverErr := make(chan error, 1)
	go func() {
		defer func() { _ = clientConn.Close() }()
		request, err := http.ReadRequest(bufio.NewReader(clientConn))
		if err != nil {
			serverErr <- err
			return
		}
		if request.Method != http.MethodGet || request.URL.Path != "/keys" {
			serverErr <- fmt.Errorf("request = %s %s", request.Method, request.URL.Path)
			return
		}
		_, err = io.WriteString(clientConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		serverErr <- err
	}()

	var dials atomic.Int32
	transport := newSentrySSHHTTPTransport(sentrySSHDialerFunc(func(context.Context) (net.Conn, error) {
		dials.Add(1)
		return serverConn, nil
	}))
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	response, err := client.Get("http://" + sentrySSHHTTPAuthority + "/keys")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if got := string(body); got != "ok" || dials.Load() != 1 {
		t.Fatalf("body/dials = %q/%d, want ok/1", got, dials.Load())
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestSentrySSHHTTPTransportRejectsOtherDestinations(t *testing.T) {
	dialed := false
	transport := newSentrySSHHTTPTransport(sentrySSHDialerFunc(func(context.Context) (net.Conn, error) {
		dialed = true
		return nil, errors.New("unexpected dial")
	}))
	defer transport.CloseIdleConnections()
	_, err := transport.DialContext(context.Background(), "tcp", "other.example:80")
	if err == nil || !strings.Contains(err.Error(), "unexpected sentry HTTP dial target") {
		t.Fatalf("DialContext() error = %v, want restricted-target error", err)
	}
	if dialed {
		t.Fatal("restricted transport invoked SSH dialer for another destination")
	}
}

func TestSentrySSHHTTPTransportPropagatesRequestCancellation(t *testing.T) {
	transport := newSentrySSHHTTPTransport(sentrySSHDialerFunc(func(ctx context.Context) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}))
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+sentrySSHHTTPAuthority+"/keys", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&http.Client{Transport: transport}).Do(request)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Do() error = %v, want context canceled", err)
	}
}

func TestSentrySSHLifetimeDetachesAfterSetup(t *testing.T) {
	setupCtx, cancelSetup := context.WithCancel(context.Background())
	lifetimeCtx, cancelLifetime, detach := newSentrySSHLifetime(setupCtx)
	defer cancelLifetime()

	if err := detach(); err != nil {
		t.Fatalf("detach() error = %v", err)
	}
	cancelSetup()
	select {
	case <-lifetimeCtx.Done():
		t.Fatalf("detached SSH connection canceled with setup context: %v", lifetimeCtx.Err())
	default:
	}

	cancelLifetime()
	if !errors.Is(lifetimeCtx.Err(), context.Canceled) {
		t.Fatalf("lifetime context error = %v, want canceled", lifetimeCtx.Err())
	}
}

func TestSentrySSHLifetimeHonorsSetupCancellation(t *testing.T) {
	setupCtx, cancelSetup := context.WithCancel(context.Background())
	_, cancelLifetime, detach := newSentrySSHLifetime(setupCtx)
	defer cancelLifetime()
	cancelSetup()

	if err := detach(); !errors.Is(err, context.Canceled) {
		t.Fatalf("detach() error = %v, want context canceled", err)
	}
}
