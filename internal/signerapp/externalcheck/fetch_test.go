// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package externalcheck

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/policy"
)

func lookupFor(serverURL, path string, source policy.ExternalSourceV1) Lookup {
	if source.TimeoutMS == 0 {
		source.TimeoutMS = 2000
	}
	if source.MaxResponseBytes == 0 {
		source.MaxResponseBytes = 1 << 10
	}
	source.BaseURL = serverURL
	return Lookup{SourceName: "s", Source: source, URL: serverURL + path, Path: path}
}

func TestGetSendsTheRequestContract(t *testing.T) {
	var seen *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Clone(context.Background())
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()
	f := &Fetcher{UserAgent: "apsigner/test"}
	source := policy.ExternalSourceV1{Token: &policy.ExternalTokenV1{Header: "Authorization", Prefix: "Bearer "}}
	answer, err := f.Get(context.Background(), lookupFor(srv.URL, "/v1/x?a=b", source), "s3cret")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if answer.Root.Members["ok"] == nil || len(answer.RequestID) != 32 {
		t.Fatalf("answer = %+v", answer)
	}
	if seen.Method != http.MethodGet || seen.URL.RequestURI() != "/v1/x?a=b" {
		t.Fatalf("request = %s %s", seen.Method, seen.URL.RequestURI())
	}
	for header, want := range map[string]string{
		"Accept": "application/json", "Cache-Control": "no-store", "User-Agent": "apsigner/test",
		"Authorization": "Bearer s3cret", RequestIDHeader: answer.RequestID,
	} {
		if got := seen.Header.Get(header); got != want {
			t.Errorf("header %s = %q, want %q", header, got, want)
		}
	}
	if seen.Header.Get("Cookie") != "" {
		t.Error("a lookup carried a cookie")
	}
	if seen.Header.Get("Accept-Encoding") != "" {
		t.Errorf("Accept-Encoding = %q, want empty (compression disabled)", seen.Header.Get("Accept-Encoding"))
	}
	// A second lookup draws a fresh request ID, and a source without a
	// token sends none.
	second, err := f.Get(context.Background(), lookupFor(srv.URL, "/v1/x", policy.ExternalSourceV1{}), "unused")
	if err != nil || second.RequestID == answer.RequestID {
		t.Fatalf("second Get() = %+v, %v; want a fresh request ID", second, err)
	}
	if seen.Header.Get("Authorization") != "" {
		t.Error("a source without a token sent one")
	}
}

func TestGetFailsClosed(t *testing.T) {
	for _, tt := range []struct {
		name    string
		handler http.HandlerFunc
		want    string
	}{
		{"status 503", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }, "status 503"},
		{"status 204", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }, "status 204"},
		{"not found", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) }, "status 404"},
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/elsewhere" {
				_, _ = w.Write([]byte(`{"ok": true}`))
				return
			}
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}, "status 302"},
		{"oversize", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`"` + strings.Repeat("a", 1<<10) + `"`))
		}, "body over 1024 bytes"},
		{"oversize headers", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-Pad", strings.Repeat("a", maxResponseHeaderBytes+1024))
			_, _ = w.Write([]byte(`{"ok": true}`))
		}, "the lookup failed"},
		{"not JSON", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`<html>`)) }, "not acceptable JSON"},
		{"gzipped response is not decoded", func(w http.ResponseWriter, _ *http.Request) {
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			_, _ = gz.Write([]byte(`{"ok": true}`))
			_ = gz.Close()
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(buf.Bytes())
		}, "not acceptable JSON"},
		{"empty body", func(http.ResponseWriter, *http.Request) {}, "not acceptable JSON"},
		{"duplicate key", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"ok": false, "ok": true}`))
		}, "duplicate key"},
		{"trailing data", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"ok": true} {}`)) }, "unexpected data"},
		{"huge exponent", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"n": 1e999999}`)) }, "exponent"},
		{"timeout", func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		}, "timeout after 100ms"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()
			_, err := (&Fetcher{}).Get(context.Background(), lookupFor(srv.URL, "/x", policy.ExternalSourceV1{TimeoutMS: 100}), "")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Get() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestGetUnreachableAndCanceled(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	closedURL := srv.URL
	srv.Close()
	_, err := (&Fetcher{}).Get(context.Background(), lookupFor(closedURL, "/x", policy.ExternalSourceV1{}), "")
	if err == nil || err.Error() != "the source could not be reached" {
		t.Fatalf("Get() error = %v, want unreachable", err)
	}
	if strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatal("the failure quotes the URL")
	}

	started := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer slow.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := (&Fetcher{}).Get(ctx, lookupFor(slow.URL, "/x", policy.ExternalSourceV1{TimeoutMS: 10000}), "")
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, errCanceled) {
			t.Fatalf("Get() error = %v, want canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a canceled lookup did not return")
	}
}

func TestGetOverTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()
	leaf := srv.Certificate()
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	get := func(f *Fetcher, source policy.ExternalSourceV1, serverURL string) error {
		_, err := f.Get(context.Background(), lookupFor(serverURL, "/x", source), "")
		return err
	}

	// Without pins the roots decide: the test certificate is not in the
	// system's, and is accepted once it is trusted.
	if err := get(&Fetcher{}, policy.ExternalSourceV1{}, srv.URL); err == nil || err.Error() != "the server's certificate was not accepted" {
		t.Fatalf("untrusted certificate: error = %v", err)
	}
	if err := get(&Fetcher{RootCAs: roots}, policy.ExternalSourceV1{}, srv.URL); err != nil {
		t.Fatalf("trusted certificate: error = %v", err)
	}

	// With a pin the server's key is trusted directly, with no chain.
	pinned := policy.ExternalSourceV1{TLSPins: [][32]byte{{1}, pin}}
	if err := get(&Fetcher{}, pinned, srv.URL); err != nil {
		t.Fatalf("pinned key: error = %v", err)
	}
	if err := get(&Fetcher{}, policy.ExternalSourceV1{TLSPins: [][32]byte{{1}}}, srv.URL); !errors.Is(err, errPinMismatch) {
		t.Fatalf("another pin: error = %v, want a pin mismatch", err)
	}
	// A pin does not waive the host name: the test certificate is for
	// 127.0.0.1 and example.com, not localhost.
	u, _ := url.Parse(srv.URL)
	if err := get(&Fetcher{}, pinned, "https://localhost:"+u.Port()); err == nil || err.Error() != "the server's certificate was not accepted" {
		t.Fatalf("pinned key under another host name: error = %v", err)
	}
	// Nor the validity period.
	late := &Fetcher{Now: func() time.Time { return leaf.NotAfter.Add(time.Hour) }}
	if err := get(late, pinned, srv.URL); err == nil || err.Error() != "the server's certificate was not accepted" {
		t.Fatalf("pinned key after expiry: error = %v", err)
	}
	early := &Fetcher{Now: func() time.Time { return leaf.NotBefore.Add(-time.Hour) }}
	if err := get(early, pinned, srv.URL); err == nil {
		t.Fatal("pinned key before its validity period was accepted")
	}
}

func TestPlainHTTPDialsOnlyLoopback(t *testing.T) {
	target, _ := url.Parse("http://localhost:1")
	transport := (&Fetcher{}).transport(policy.ExternalSourceV1{TimeoutMS: 1000}, target)
	if transport.Proxy != nil {
		t.Fatal("an http source must not use a proxy")
	}
	// 192.0.2.1 is a documentation address: the dial must be refused before
	// any packet is sent.
	_, err := transport.DialContext(context.Background(), "tcp", "192.0.2.1:80")
	if !errors.Is(err, errNotLoopback) {
		t.Fatalf("dial off loopback: error = %v, want refusal", err)
	}
	httpsTransport := (&Fetcher{}).transport(policy.ExternalSourceV1{TimeoutMS: 1000}, &url.URL{Scheme: "https", Host: "example.com"})
	if httpsTransport.Proxy == nil || httpsTransport.TLSClientConfig.MinVersion != 0x0303 {
		t.Fatal("an https source honors the proxy and requires TLS 1.2")
	}
}

// One origin has one form, however a source that policy admits writes it: the
// host's case, an address's spelling, and the scheme's default port written,
// left out or left empty. Origins that differ stay apart.
func TestOriginHasOneForm(t *testing.T) {
	for want, spellings := range map[string][]string{
		"https://example.com:443": {"https://example.com/a", "https://Example.COM/b?q=1", "HTTPS://example.com:443",
			"https://EXAMPLE.com:443/c", "https://example.com:", "https://example.com:/d"},
		"https://example.com:8443":   {"https://example.com:8443", "https://EXAMPLE.com:8443/x"},
		"https://example.com:80":     {"https://example.com:80"},
		"http://localhost:80":        {"http://localhost", "http://localhost:80/", "http://localhost:"},
		"http://localhost:443":       {"http://localhost:443"},
		"http://127.0.0.1:80":        {"http://127.0.0.1", "http://127.0.0.1:80"},
		"http://[::1]:80":            {"http://[::1]", "http://[0::1]:", "http://[0:0:0:0:0:0:0:1]:80"},
		"https://[2001:db8::1]:443":  {"https://[2001:DB8::1]:443/x", "https://[2001:0db8::1]", "https://[2001:db8:0::1]:"},
		"https://[2001:db8::1]:444":  {"https://[2001:db8::1]:444"},
		"https://example.com443:443": {"https://example.com443"},
	} {
		for _, raw := range spellings {
			target, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if got := canonicalOrigin(target); got != want {
				t.Errorf("canonicalOrigin(%s) = %s, want %s", raw, got, want)
			}
		}
	}
}

func TestInFlightLimitIsPerOrigin(t *testing.T) {
	var inFlight, peak atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-release
		inFlight.Add(-1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	// Before the server closes, which waits for every lookup, a failure's too.
	letGo := sync.OnceFunc(func() { close(release) })
	defer letGo()
	f := &Fetcher{}
	const total = MaxInFlightPerOrigin + 6
	done := make(chan error, total)
	for i := 0; i < total; i++ {
		// Half the lookups write the one origin another way.
		base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
		if i%2 == 0 {
			base = strings.Replace(srv.URL, "127.0.0.1", "LocalHost", 1)
		}
		go func() {
			_, err := f.Get(context.Background(), lookupFor(base, "/x", policy.ExternalSourceV1{TimeoutMS: 5000}), "")
			done <- err
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for inFlight.Load() < MaxInFlightPerOrigin && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if got := inFlight.Load(); got != MaxInFlightPerOrigin {
		t.Fatalf("%d lookups in flight to one origin, want %d", got, MaxInFlightPerOrigin)
	}
	letGo()
	for i := 0; i < total; i++ {
		if err := <-done; err != nil {
			t.Fatalf("Get() error = %v", err)
		}
	}
	if got := peak.Load(); got != MaxInFlightPerOrigin {
		t.Fatalf("peak in flight = %d, want %d", got, MaxInFlightPerOrigin)
	}
}
