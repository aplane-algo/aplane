// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"sync"
	"testing"
	"time"
)

// The session callback names the connection's key and reports it after the
// connection is tracked and after it is untracked, so a callback that
// consults ConnectedFingerprints sees the state the event describes.
func TestSessionCallbackCarriesEnrolledKeyAndOrdersWithTracking(t *testing.T) {
	srv, tmpDir := testServer(t)
	set := newEnrolledSet()
	srv.SetProductHooks(set.hooks())
	srv.SetAPIHandoff(func(conn *APIConn) error { _ = conn.Close(); return nil })

	type seen struct {
		event SessionEvent
		count int
	}
	var mu sync.Mutex
	var events []seen
	srv.SetSessionCallback(func(event SessionEvent) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, seen{event: event, count: srv.ConnectedFingerprints()[event.Fingerprint]})
	})
	host, port, known := startServer(t, srv, tmpDir)
	client, fingerprint := connectEnrolledClient(t, srv, set, tmpDir, host, port, known)

	waitForEvents := func(n int) []seen {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			mu.Lock()
			got := append([]seen(nil), events...)
			mu.Unlock()
			if len(got) >= n {
				return got
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %d session events; got %+v", n, got)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	got := waitForEvents(1)
	if e := got[0]; !e.event.Connected || !e.event.EnrolledKey || e.event.Fingerprint != fingerprint || e.event.RemoteAddr == "" || e.count != 1 {
		t.Fatalf("connect event = %+v, want connected enrolled key %s tracked once", e, fingerprint)
	}

	_ = client.Close()
	got = waitForEvents(2)
	if e := got[1]; e.event.Connected || !e.event.EnrolledKey || e.event.Fingerprint != fingerprint || e.count != 0 {
		t.Fatalf("disconnect event = %+v, want disconnected enrolled key %s untracked", e, fingerprint)
	}
}
