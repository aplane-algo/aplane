// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package externalcheck

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/strictjson"
)

const (
	// MaxInFlightPerOrigin is the most lookups in flight to one URL origin
	// across every request on the node. The origin is the key because two
	// documents can name one service differently, and the limit is there to
	// protect the service.
	MaxInFlightPerOrigin = 16
	// RequestIDHeader carries a lookup's fresh request ID.
	RequestIDHeader = "X-Aplane-Request-Id"

	answerMaxDepth         = 64
	answerMaxNumberLiteral = 64
	answerMaxExponent      = 64
)

// Answer is a lookup's accepted answer and the request ID it was sent with.
type Answer struct {
	Root      *strictjson.Node
	RequestID string
}

// Fetcher makes lookups. The zero value is ready to use.
type Fetcher struct {
	// UserAgent is sent with every lookup.
	UserAgent string
	// RootCAs replaces the system roots for sources without pins. Tests set
	// it; nil is the system roots.
	RootCAs *x509.CertPool
	// Now is the clock a pinned certificate's validity is checked against;
	// nil is time.Now.
	Now func() time.Time

	mu      sync.Mutex
	origins map[string]chan struct{}
}

// Get makes one lookup and reads its answer. token is sent when the source
// declares one. The error is what failed, in words fit for the audit record;
// it never holds the token.
func (f *Fetcher) Get(ctx context.Context, lookup Lookup, token string) (*Answer, error) {
	target, err := url.Parse(lookup.URL)
	if err != nil {
		return nil, errors.New("the request URL does not parse")
	}
	release, err := f.acquire(ctx, target.Scheme+"://"+target.Host)
	if err != nil {
		return nil, err
	}
	defer release()

	timeout := time.Duration(lookup.Source.TimeoutMS) * time.Millisecond
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, errors.New("no request ID could be drawn")
	}
	requestID := hex.EncodeToString(idBytes)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, lookup.URL, nil)
	if err != nil {
		return nil, errors.New("the request could not be built")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("User-Agent", f.UserAgent)
	req.Header.Set(RequestIDHeader, requestID)
	if lookup.Source.Token != nil {
		req.Header.Set(lookup.Source.Token.Header, lookup.Source.Token.Prefix+token)
	}

	transport := f.transport(lookup.Source, target)
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		// A redirect is a failure: the answer must come from the source.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, describeFetchError(err, ctx, timeout)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	limit := lookup.Source.MaxResponseBytes
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, describeFetchError(err, ctx, timeout)
	}
	if len(body) > limit {
		return nil, fmt.Errorf("body over %d bytes", limit)
	}
	root, err := strictjson.Parse(body, strictjson.Limits{
		MaxBytes: limit, MaxDepth: answerMaxDepth,
		MaxNumberLiteral: answerMaxNumberLiteral, MaxExponent: answerMaxExponent,
	})
	if err != nil {
		return nil, fmt.Errorf("the answer is not acceptable JSON: %s", quoteBare(err.Error()))
	}
	return &Answer{Root: root, RequestID: requestID}, nil
}

// errCanceled is a lookup that ended because its context was canceled: the
// request went away, the node locked, or another lookup had already failed.
var errCanceled = errors.New("canceled")

// errPinMismatch and its kin are TLS refusals the audit record names plainly.
var (
	errPinMismatch   = errors.New("TLS pin mismatch")
	errNoCertificate = errors.New("the server presented no certificate")
	errNotLoopback   = errors.New("an http source must be on a loopback address")
)

// describeFetchError turns a transport error into the audit record's words.
// It keeps to known causes: an error's own text can carry the URL.
func describeFetchError(err error, ctx context.Context, timeout time.Duration) error {
	switch {
	case errors.Is(err, errPinMismatch):
		return errPinMismatch
	case errors.Is(err, errNoCertificate):
		return errNoCertificate
	case errors.Is(err, errNotLoopback):
		return errNotLoopback
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return fmt.Errorf("timeout after %s", timeout)
	case errors.Is(ctx.Err(), context.Canceled):
		return errCanceled
	}
	var certErr *tls.CertificateVerificationError
	var hostErr x509.HostnameError
	var unknownErr x509.UnknownAuthorityError
	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &certErr) || errors.As(err, &hostErr) || errors.As(err, &unknownErr) || errors.As(err, &invalidErr) {
		return errors.New("the server's certificate was not accepted")
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return errors.New("the source could not be reached")
	}
	return errors.New("the lookup failed")
}

// acquire takes one of origin's in-flight places, waiting for one until ctx
// ends.
func (f *Fetcher) acquire(ctx context.Context, origin string) (func(), error) {
	f.mu.Lock()
	if f.origins == nil {
		f.origins = make(map[string]chan struct{})
	}
	places, ok := f.origins[origin]
	if !ok {
		places = make(chan struct{}, MaxInFlightPerOrigin)
		f.origins[origin] = places
	}
	f.mu.Unlock()
	select {
	case places <- struct{}{}:
		return func() { <-places }, nil
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("timeout while waiting for a place at the source")
		}
		return nil, errCanceled
	}
}

// transport builds the transport for one lookup. Nothing is kept between
// lookups, so every answer comes over a fresh connection.
//
//   - An https source honors the environment's proxy, as algod and the Indexer
//     do. Without pins the system roots decide. With pins Go's chain
//     verification is off and verifyPinned decides.
//   - An http source uses no proxy and connects only to a loopback address,
//     checked on the address actually dialed.
func (f *Fetcher) transport(source policy.ExternalSourceV1, target *url.URL) *http.Transport {
	t := &http.Transport{
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   false,
		TLSHandshakeTimeout: time.Duration(source.TimeoutMS) * time.Millisecond,
	}
	if target.Scheme == "http" {
		t.Proxy = nil
		dialer := &net.Dialer{Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return errNotLoopback
			}
			if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
				return errNotLoopback
			}
			return nil
		}}
		t.DialContext = dialer.DialContext
		return t
	}
	t.Proxy = http.ProxyFromEnvironment
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: f.RootCAs}
	if len(source.TLSPins) > 0 {
		host := target.Hostname()
		pins := source.TLSPins
		now := f.Now
		if now == nil {
			now = time.Now
		}
		// The pin replaces the chain: the server's key is trusted directly,
		// as an SSH host key is. The host name and the validity period are
		// still checked here, since nothing else checks them now.
		t.TLSClientConfig.InsecureSkipVerify = true // #nosec G402 -- verifyPinned decides
		t.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			return verifyPinned(cs, host, pins, now())
		}
	}
	return t
}

// verifyPinned accepts a connection whose leaf certificate is valid for host,
// is within its validity period at now, and has a pinned public key.
func verifyPinned(cs tls.ConnectionState, host string, pins [][32]byte, now time.Time) error {
	if len(cs.PeerCertificates) == 0 {
		return errNoCertificate
	}
	leaf := cs.PeerCertificates[0]
	if err := leaf.VerifyHostname(host); err != nil {
		return err
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return x509.CertificateInvalidError{Cert: leaf, Reason: x509.Expired}
	}
	if !slices.Contains(pins, sha256.Sum256(leaf.RawSubjectPublicKeyInfo)) {
		return errPinMismatch
	}
	return nil
}
