// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

// A request parked on its context, as a /sign waiting for operator approval
// is, must not hold shutdown until the deadline: stopping cancels it and the
// server shuts down cleanly.
func TestStopHTTPServerCancelsParkedRequests(t *testing.T) {
	parked := make(chan struct{})
	canceled := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(parked)
		<-r.Context().Done()
		close(canceled)
		w.WriteHeader(http.StatusServiceUnavailable)
	})}
	cancelRequests := withCancelableRequests(srv)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String() + "/sign")
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-parked:
	case <-time.After(5 * time.Second):
		t.Fatal("request never reached the handler")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := stopHTTPServer(ctx, srv, nil, cancelRequests); err != nil {
		t.Fatalf("stopHTTPServer() = %v, want a clean shutdown", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("shutdown took %v; the parked request held it", elapsed)
	}
	select {
	case <-canceled:
	default:
		t.Fatal("parked request was not canceled")
	}
}
