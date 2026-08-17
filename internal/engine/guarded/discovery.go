// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package guarded

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/tokenfile"
	"github.com/aplane-algo/aplane/internal/witness"
	"golang.org/x/crypto/ssh"
)

type sentryComponentClient interface {
	GetKeysWithContext(context.Context) (*signerapi.KeysResult, error)
	RequestComponentsWithContext(context.Context, signerapi.ComponentRequest) (*signerapi.ComponentResponse, error)
}

var (
	// ErrSentryDiscoveryInvalidMetadata marks malformed sentry-key
	// metadata returned by an endpoint's /keys response.
	ErrSentryDiscoveryInvalidMetadata = errors.New("invalid sentry discovery metadata")

	// ErrSentryDiscoveryUnavailable marks a temporary failure to query an
	// endpoint, such as a network outage, timeout, or server-side 5xx response.
	ErrSentryDiscoveryUnavailable = errors.New("sentry endpoint unavailable")

	// ErrSentryDiscoveryLocked marks an endpoint whose signer is reachable but
	// locked, so its /keys inventory cannot currently be queried.
	ErrSentryDiscoveryLocked = errors.New("sentry endpoint signer locked")

	// ErrSentryDiscoveryAuth marks missing, rejected, or invalid endpoint
	// credentials.
	ErrSentryDiscoveryAuth = errors.New("sentry endpoint authentication failed")

	// ErrSentryDiscoveryConfig marks endpoint configuration that is invalid or
	// incompatible with sentry discovery.
	ErrSentryDiscoveryConfig = errors.New("sentry endpoint configuration invalid")

	// errSentryDiscoveryHostKeyMismatch marks an SSH endpoint whose host key
	// differs from the client's existing pin. Discovery aborts globally when
	// this error is observed.
	errSentryDiscoveryHostKeyMismatch = errors.New("sentry endpoint SSH host key mismatch")

	errSentryEndpointAuth   = errors.New("sentry endpoint auth")
	errSentryEndpointConfig = errors.New("sentry endpoint config")
)

const (
	sentryDiscoveryTotalTimeout    = 30 * time.Second
	sentryDiscoveryEndpointTimeout = 10 * time.Second
	sentryDiscoveryWorkers         = 4
	maxSentryDiscoveryEndpoints    = 12
)

type resolvedSentryEndpoint struct {
	client  sentryComponentClient
	source  string
	cleanup func()
}

type sentryEndpointProbe func(context.Context, string, config.ClientEndpointConfig) (*resolvedSentryEndpoint, []DiscoveredSentryComponentKey, error)

type sentryEndpointProbeResult struct {
	index    int
	alias    string
	endpoint *resolvedSentryEndpoint
	keys     []DiscoveredSentryComponentKey
	err      error
}

type sentryEndpointSnapshot struct {
	routes    map[sentryRequestKey]*resolvedSentryEndpoint
	endpoints []*resolvedSentryEndpoint
}

func (s *sentryEndpointSnapshot) close() {
	if s == nil {
		return
	}
	for _, endpoint := range s.endpoints {
		endpoint.close()
	}
}

// DiscoveredSentryComponentKey is public sentry-key metadata
// advertised by a signer endpoint through /keys.
type DiscoveredSentryComponentKey struct {
	PublicKey    string
	ComponentKey string
	KeyType      string
}

func (r *resolvedSentryEndpoint) close() {
	if r != nil && r.cleanup != nil {
		r.cleanup()
	}
}

func (s *Signer) resolveSentryEndpoints(ctx context.Context, required []sentryRequestKey) (*sentryEndpointSnapshot, error) {
	required = distinctSortedSentryRequestKeys(required)
	if len(required) == 0 {
		return &sentryEndpointSnapshot{routes: map[sentryRequestKey]*resolvedSentryEndpoint{}}, nil
	}
	aliases := make([]string, 0, len(s.endpointRegistry.Endpoints))
	for alias, endpoint := range s.endpointRegistry.Endpoints {
		if endpoint.Role == config.ClientEndpointRoleSentry {
			aliases = append(aliases, alias)
		}
	}
	sort.Strings(aliases)
	if len(aliases) > maxSentryDiscoveryEndpoints {
		return nil, fmt.Errorf("%w: configured %d sentry endpoints; maximum is %d; remove or consolidate endpoint profiles", ErrSentryDiscoveryConfig, len(aliases), maxSentryDiscoveryEndpoints)
	}
	if len(aliases) == 0 {
		return nil, fmt.Errorf("%w: no sentry endpoints configured; add a role %q endpoint (use url: self for a co-located sentry)", ErrSentryDiscoveryConfig, config.ClientEndpointRoleSentry)
	}

	discoveryCtx, cancel := context.WithTimeout(ctx, sentryDiscoveryTotalTimeout)
	defer cancel()
	jobs := make(chan int)
	results := make(chan sentryEndpointProbeResult, len(aliases))
	probe := s.probeEndpoint
	if probe == nil {
		probe = s.probeConfiguredSentryEndpoint
	}

	var workers sync.WaitGroup
	workerCount := min(sentryDiscoveryWorkers, len(aliases))
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for index := range jobs {
				alias := aliases[index]
				endpointCtx, endpointCancel := context.WithTimeout(discoveryCtx, sentryDiscoveryEndpointTimeout)
				resolved, keys, err := probe(endpointCtx, alias, s.endpointRegistry.Endpoints[alias])
				endpointCancel()
				results <- sentryEndpointProbeResult{index: index, alias: alias, endpoint: resolved, keys: keys, err: err}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index := range aliases {
			select {
			case jobs <- index:
			case <-discoveryCtx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()

	states := make([]*sentryEndpointProbeResult, len(aliases))
	selected := map[sentryRequestKey]int{}
	resolvedAll := false
	var hostKeyMismatch error
	for result := range results {
		result := result
		states[result.index] = &result
		if errors.Is(result.err, connect.ErrSSHHostKeyMismatch) {
			hostKeyMismatch = fmt.Errorf("%w at endpoint %q", errSentryDiscoveryHostKeyMismatch, result.alias)
			cancel()
		}
		if hostKeyMismatch == nil && !resolvedAll {
			selected, resolvedAll = deterministicSentrySelections(required, states)
			if resolvedAll {
				cancel()
			}
		}
	}

	if hostKeyMismatch != nil {
		closeProbeResults(states, nil)
		return nil, hostKeyMismatch
	}
	if !resolvedAll {
		closeProbeResults(states, nil)
		return nil, unresolvedSentryDiscoveryError(required, selected, aliases, states, discoveryCtx.Err())
	}

	keep := map[*resolvedSentryEndpoint]bool{}
	snapshot := &sentryEndpointSnapshot{routes: make(map[sentryRequestKey]*resolvedSentryEndpoint, len(selected))}
	maxSelected := -1
	for key, index := range selected {
		endpoint := states[index].endpoint
		snapshot.routes[key] = endpoint
		if !keep[endpoint] {
			keep[endpoint] = true
			snapshot.endpoints = append(snapshot.endpoints, endpoint)
		}
		if index > maxSelected {
			maxSelected = index
		}
	}
	closeProbeResults(states, keep)
	s.warnSkippedSentryEndpoints(states, maxSelected)
	return snapshot, nil
}

func (s *Signer) connectConfiguredSentryEndpoint(ctx context.Context, endpoint config.ClientEndpointConfig) (*signerclient.Client, func(), string, error) {
	token, err := readSentryEndpointToken(endpoint.TokenFile)
	if err != nil {
		return nil, nil, "", err
	}
	parsed, err := url.Parse(endpoint.URL)
	if err != nil {
		return nil, nil, "", fmt.Errorf("%w: invalid endpoint URL: %v", errSentryEndpointConfig, err)
	}

	switch parsed.Scheme {
	case "http", "https":
		return signerclient.NewSignerClientWithToken(strings.TrimRight(endpoint.URL, "/"), token), nil, endpoint.URL, nil
	case "ssh":
		sshPort := config.DefaultSSHPort
		if parsed.Port() != "" {
			port, err := strconv.Atoi(parsed.Port())
			if err != nil || port <= 0 || port > 65535 {
				return nil, nil, "", fmt.Errorf("%w: invalid SSH port %q", errSentryEndpointConfig, parsed.Port())
			}
			sshPort = port
		}
		signerPort := endpoint.SignerPort
		if signerPort == 0 {
			signerPort = config.DefaultRESTPort
		}
		progressOut := s.signerProgressWriter()
		client, cleanup, err := connect.ConnectSentryWithTunnel(ctx, connect.SentryTunnelConfig{
			Host:           parsed.Hostname(),
			SSHPort:        sshPort,
			LocalPort:      endpoint.LocalPort,
			SignerPort:     signerPort,
			Token:          token,
			IdentityFile:   endpoint.IdentityFile,
			KnownHostsPath: endpoint.KnownHostsPath,
			ProgressOut:    progressOut,
		})
		if err != nil {
			return nil, nil, "", err
		}
		return client, cleanup, endpoint.URL, nil
	default:
		return nil, nil, "", fmt.Errorf("%w: unsupported endpoint URL scheme %q", errSentryEndpointConfig, parsed.Scheme)
	}
}

func (s *Signer) probeConfiguredSentryEndpoint(ctx context.Context, alias string, endpoint config.ClientEndpointConfig) (*resolvedSentryEndpoint, []DiscoveredSentryComponentKey, error) {
	var resolved *resolvedSentryEndpoint
	if endpoint.URL == "self" {
		resolved = &resolvedSentryEndpoint{client: s.conn, source: alias + " (self)"}
	} else {
		client, cleanup, source, err := s.connectConfiguredSentryEndpoint(ctx, endpoint)
		if err != nil {
			return nil, nil, classifySentryDiscoveryConnectError(err)
		}
		resolved = &resolvedSentryEndpoint{client: client, source: source, cleanup: cleanup}
	}
	keys, err := resolved.client.GetKeysWithContext(ctx)
	if err != nil {
		resolved.close()
		return nil, nil, classifySentryDiscoveryQueryError(err)
	}
	if keys.Locked {
		resolved.close()
		return nil, nil, fmt.Errorf("%w", ErrSentryDiscoveryLocked)
	}
	discovered, err := discoverSentryComponentKeys(keys.Keys)
	if err != nil {
		resolved.close()
		return nil, nil, err
	}
	return resolved, discovered, nil
}

// DiscoverSentryComponentKeys queries one endpoint and returns
// sentry component public keys that can be mapped for guarded signing.
func (s *Signer) DiscoverSentryComponentKeys(ctx context.Context, endpoint config.ClientEndpointConfig) ([]DiscoveredSentryComponentKey, error) {
	resolved, keys, err := s.probeConfiguredSentryEndpoint(ctx, "requested endpoint", endpoint)
	if resolved != nil {
		defer resolved.close()
	}
	return keys, err
}

func distinctSortedSentryRequestKeys(required []sentryRequestKey) []sentryRequestKey {
	seen := make(map[sentryRequestKey]bool, len(required))
	out := make([]sentryRequestKey, 0, len(required))
	for _, key := range required {
		if !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ComponentKeyType != out[j].ComponentKeyType {
			return out[i].ComponentKeyType < out[j].ComponentKeyType
		}
		return out[i].PublicKey < out[j].PublicKey
	})
	return out
}

func deterministicSentrySelections(required []sentryRequestKey, states []*sentryEndpointProbeResult) (map[sentryRequestKey]int, bool) {
	selected := make(map[sentryRequestKey]int, len(required))
	for _, key := range required {
		found := false
		for index, state := range states {
			if state == nil {
				break
			}
			if state.err == nil && discoveredSentryKeysContain(state.keys, key) {
				selected[key] = index
				found = true
				break
			}
		}
		if !found {
			return selected, false
		}
	}
	return selected, true
}

func discoveredSentryKeysContain(keys []DiscoveredSentryComponentKey, required sentryRequestKey) bool {
	for _, key := range keys {
		if key.PublicKey == required.PublicKey && key.KeyType == required.ComponentKeyType {
			return true
		}
	}
	return false
}

func closeProbeResults(states []*sentryEndpointProbeResult, keep map[*resolvedSentryEndpoint]bool) {
	closed := map[*resolvedSentryEndpoint]bool{}
	for _, state := range states {
		if state == nil || state.endpoint == nil || keep[state.endpoint] || closed[state.endpoint] {
			continue
		}
		state.endpoint.close()
		closed[state.endpoint] = true
	}
}

func unresolvedSentryDiscoveryError(required []sentryRequestKey, selected map[sentryRequestKey]int, aliases []string, states []*sentryEndpointProbeResult, cause error) error {
	missing := make([]string, 0, len(required))
	for _, key := range required {
		if _, ok := selected[key]; ok {
			continue
		}
		selector, err := sentryComponentSelector(key.ComponentKeyType, key.PublicKey)
		if err != nil {
			selector = "invalid"
		}
		missing = append(missing, fmt.Sprintf("Witness Key ID %s (%s)", selector, key.ComponentKeyType))
	}
	summary := make([]string, 0, len(aliases))
	causes := make([]error, 0, len(aliases)+1)
	if cause != nil {
		causes = append(causes, cause)
	}
	for index, alias := range aliases {
		state := states[index]
		switch {
		case state == nil:
			summary = append(summary, alias+": not probed")
		case state.err != nil:
			summary = append(summary, alias+": "+sentryDiscoveryFailureLabel(state.err))
			causes = append(causes, state.err)
		default:
			summary = append(summary, alias+": no matching key")
		}
	}
	message := fmt.Sprintf("no live sentry route for %s; endpoint results: %s; configure a role %q endpoint that advertises the required Witness Key ID (use url: self for a co-located sentry)", strings.Join(missing, ", "), strings.Join(summary, "; "), config.ClientEndpointRoleSentry)
	if len(causes) > 0 {
		return fmt.Errorf("%s: %w", message, errors.Join(causes...))
	}
	return errors.New(message)
}

func sentryDiscoveryFailureLabel(err error) string {
	switch {
	case errors.Is(err, connect.ErrSSHHostKeyMismatch):
		return "SSH host-key mismatch"
	case errors.Is(err, connect.ErrSSHUnknownHostKey):
		return "SSH host is not enrolled"
	case errors.Is(err, connect.ErrSSHKnownHostsFile):
		return "invalid known_hosts configuration"
	case errors.Is(err, ErrSentryDiscoveryLocked):
		return "signer locked"
	case errors.Is(err, ErrSentryDiscoveryAuth):
		return "authentication failed"
	case errors.Is(err, ErrSentryDiscoveryInvalidMetadata):
		return "invalid /keys metadata"
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, ErrSentryDiscoveryUnavailable):
		return "unavailable"
	default:
		return "invalid endpoint configuration"
	}
}

func (s *Signer) warnSkippedSentryEndpoints(states []*sentryEndpointProbeResult, maxSelected int) {
	w := s.signerProgressWriter()
	if w == nil {
		return
	}
	for index, state := range states {
		if index > maxSelected || state == nil || state.err == nil || errors.Is(state.err, context.Canceled) {
			continue
		}
		_, _ = fmt.Fprintf(w, "[sentry discovery] skipped endpoint %s: %s\n", state.alias, sentryDiscoveryFailureLabel(state.err))
	}
}

func readSentryEndpointToken(path string) (string, error) {
	token, err := tokenfile.ReadToken(path)
	if err != nil {
		return "", fmt.Errorf("%w: failed to read sentry token file %s: %v", errSentryEndpointAuth, path, err)
	}
	if token == "" {
		return "", fmt.Errorf("%w: sentry token file %s is empty", errSentryEndpointAuth, path)
	}
	return token, nil
}

func classifySentryDiscoveryConnectError(err error) error {
	switch {
	case errors.Is(err, errSentryEndpointAuth):
		return fmt.Errorf("%w: %w", ErrSentryDiscoveryAuth, err)
	case errors.Is(err, errSentryEndpointConfig):
		return fmt.Errorf("%w: %w", ErrSentryDiscoveryConfig, err)
	case isNetworkUnavailableError(err):
		return fmt.Errorf("%w: %w", ErrSentryDiscoveryUnavailable, err)
	}

	var sshAuthErr *ssh.ServerAuthError
	if errors.As(err, &sshAuthErr) {
		return fmt.Errorf("%w: %w", ErrSentryDiscoveryAuth, err)
	}
	return fmt.Errorf("%w: %w", ErrSentryDiscoveryConfig, err)
}

func classifySentryDiscoveryQueryError(err error) error {
	if errors.Is(err, signerclient.ErrInvalidResponse) {
		return fmt.Errorf("%w: %w", ErrSentryDiscoveryInvalidMetadata, err)
	}

	var statusErr *signerclient.HTTPStatusError
	if errors.As(err, &statusErr) {
		if classified := classifySentryDiscoveryQueryCode(statusErr.Code, err); classified != nil {
			return classified
		}
		switch {
		case statusErr.StatusCode == http.StatusUnauthorized || statusErr.StatusCode == http.StatusForbidden:
			return fmt.Errorf("%w: %w", ErrSentryDiscoveryAuth, err)
		case statusErr.StatusCode == http.StatusRequestTimeout ||
			statusErr.StatusCode == http.StatusTooManyRequests ||
			statusErr.StatusCode >= http.StatusInternalServerError:
			return fmt.Errorf("%w: %w", ErrSentryDiscoveryUnavailable, err)
		default:
			return fmt.Errorf("%w: %w", ErrSentryDiscoveryConfig, err)
		}
	}

	if isNetworkUnavailableError(err) {
		return fmt.Errorf("%w: %w", ErrSentryDiscoveryUnavailable, err)
	}
	return fmt.Errorf("%w: %w", ErrSentryDiscoveryConfig, err)
}

func classifySentryDiscoveryQueryCode(code string, err error) error {
	switch code {
	case "":
		return nil
	case signerapi.ErrCodeLocked:
		return fmt.Errorf("%w: %w", ErrSentryDiscoveryLocked, err)
	case signerapi.ErrCodeUnauthorized, signerapi.ErrCodeForbidden, signerapi.ErrCodeInvalidPassphrase:
		return fmt.Errorf("%w: %w", ErrSentryDiscoveryAuth, err)
	case signerapi.ErrCodeUnavailable, signerapi.ErrCodeCacheRefresh, signerapi.ErrCodeInternal:
		return fmt.Errorf("%w: %w", ErrSentryDiscoveryUnavailable, err)
	case signerapi.ErrCodeBadRequest, signerapi.ErrCodeNotFound:
		return fmt.Errorf("%w: %w", ErrSentryDiscoveryConfig, err)
	default:
		return nil
	}
}

func isNetworkUnavailableError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var urlErr *url.Error
	return errors.As(err, &urlErr)
}

func discoverSentryComponentKeys(keys []signerapi.KeyInfo) ([]DiscoveredSentryComponentKey, error) {
	discovered := make([]DiscoveredSentryComponentKey, 0)
	seen := map[string]struct{}{}
	for _, key := range keys {
		// Component key types are runtime metadata: any advertised component
		// key participates in discovery, and its key-type string is treated
		// as opaque. Selector cross-derivation below pins the advertised
		// Witness Key ID to the advertised key type and public key.
		if !key.IsWitnessKey || key.KeyType == "" {
			continue
		}
		publicKey, err := normalizeSentryPublicKeyHex(key.PublicKeyHex)
		if err != nil {
			return nil, fmt.Errorf("%w: Witness Key ID %q has invalid public_key_hex: %v", ErrSentryDiscoveryInvalidMetadata, key.Address, err)
		}
		selector, err := witness.NormalizeID(key.Address)
		if err != nil {
			return nil, fmt.Errorf("%w: metadata for %s has invalid advertised Witness Key ID %q: %v", ErrSentryDiscoveryInvalidMetadata, sentryComponentLabel(key.KeyType, publicKey), key.Address, err)
		}
		expectedSelector, err := sentryComponentSelector(key.KeyType, publicKey)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to derive Witness Key ID for sentry public key %s: %v", ErrSentryDiscoveryInvalidMetadata, shortSentryPublicKeyHex(publicKey), err)
		}
		if selector != expectedSelector {
			return nil, fmt.Errorf("%w: sentry component %s advertised selector %s, want %s", ErrSentryDiscoveryInvalidMetadata, sentryComponentLabel(key.KeyType, publicKey), selector, expectedSelector)
		}
		if _, ok := seen[publicKey]; ok {
			continue
		}
		seen[publicKey] = struct{}{}
		discovered = append(discovered, DiscoveredSentryComponentKey{
			PublicKey:    publicKey,
			ComponentKey: selector,
			KeyType:      key.KeyType,
		})
	}
	sort.Slice(discovered, func(i, j int) bool {
		if discovered[i].PublicKey != discovered[j].PublicKey {
			return discovered[i].PublicKey < discovered[j].PublicKey
		}
		return discovered[i].KeyType < discovered[j].KeyType
	})
	return discovered, nil
}

func (s *Signer) signerProgressWriter() io.Writer {
	if s == nil || s.conn == nil {
		return nil
	}
	s.conn.Mu.Lock()
	defer s.conn.Mu.Unlock()
	return s.conn.SignerProgressOut
}
