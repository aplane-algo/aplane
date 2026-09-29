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

type cosignerComponentClient interface {
	GetKeysWithContext(context.Context) (*signerapi.KeysResult, error)
	RequestComponentsWithContext(context.Context, signerapi.ComponentRequest) (*signerapi.ComponentResponse, error)
}

var (
	// ErrCosignerDiscoveryInvalidMetadata marks malformed cosigner-key
	// metadata returned by an endpoint's /keys response.
	ErrCosignerDiscoveryInvalidMetadata = errors.New("invalid cosigner discovery metadata")

	// ErrCosignerDiscoveryUnavailable marks a temporary failure to query an
	// endpoint, such as a network outage, timeout, or server-side 5xx response.
	ErrCosignerDiscoveryUnavailable = errors.New("cosigner endpoint unavailable")

	// ErrCosignerDiscoveryLocked marks an endpoint whose signer is reachable but
	// locked, so its /keys inventory cannot currently be queried.
	ErrCosignerDiscoveryLocked = errors.New("cosigner endpoint signer locked")

	// ErrCosignerDiscoveryAuth marks missing, rejected, or invalid endpoint
	// credentials.
	ErrCosignerDiscoveryAuth = errors.New("cosigner endpoint authentication failed")

	// ErrCosignerDiscoveryConfig marks endpoint configuration that is invalid or
	// incompatible with cosigner discovery.
	ErrCosignerDiscoveryConfig = errors.New("cosigner endpoint configuration invalid")

	// errCosignerDiscoveryDuplicateRoute marks a required witness key advertised
	// by more than one live cosigner endpoint. Guarded routing requires one
	// unambiguous live endpoint per witness.
	errCosignerDiscoveryDuplicateRoute = errors.New("duplicate live cosigner route")

	// errCosignerDiscoveryHostKeyMismatch marks an SSH endpoint whose host key
	// differs from the client's existing pin. Discovery aborts globally when
	// this error is observed.
	errCosignerDiscoveryHostKeyMismatch = errors.New("cosigner endpoint SSH host key mismatch")

	errCosignerEndpointAuth   = errors.New("cosigner endpoint auth")
	errCosignerEndpointConfig = errors.New("cosigner endpoint config")
)

const (
	cosignerDiscoveryTotalTimeout    = 30 * time.Second
	cosignerDiscoveryEndpointTimeout = 10 * time.Second
	cosignerDiscoveryWorkers         = 4
	maxCosignerDiscoveryEndpoints    = 12
)

type resolvedCosignerEndpoint struct {
	client  cosignerComponentClient
	source  string
	cleanup func()
}

type cosignerEndpointProbe func(context.Context, string, config.ClientEndpointConfig) (*resolvedCosignerEndpoint, []DiscoveredCosignerComponentKey, error)

type cosignerEndpointProbeResult struct {
	index    int
	alias    string
	endpoint *resolvedCosignerEndpoint
	keys     []DiscoveredCosignerComponentKey
	err      error
}

type cosignerEndpointSnapshot struct {
	routes    map[cosignerRequestKey]*resolvedCosignerEndpoint
	endpoints []*resolvedCosignerEndpoint
}

func (s *cosignerEndpointSnapshot) close() {
	if s == nil {
		return
	}
	for _, endpoint := range s.endpoints {
		endpoint.close()
	}
}

// DiscoveredCosignerComponentKey is public cosigner-key metadata
// advertised by a signer endpoint through /keys.
type DiscoveredCosignerComponentKey struct {
	PublicKey    string
	ComponentKey string
	KeyType      string
}

func (r *resolvedCosignerEndpoint) close() {
	if r != nil && r.cleanup != nil {
		r.cleanup()
	}
}

func (s *Signer) resolveCosignerEndpoints(ctx context.Context, required []cosignerRequestKey) (*cosignerEndpointSnapshot, error) {
	required = distinctSortedCosignerRequestKeys(required)
	if len(required) == 0 {
		return &cosignerEndpointSnapshot{routes: map[cosignerRequestKey]*resolvedCosignerEndpoint{}}, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	aliases, states, err := s.probeCosignerEndpoints(ctx)
	if err != nil {
		closeProbeResults(states, nil)
		return nil, err
	}
	selected, resolvedAll, err := uniqueCosignerSelections(required, states)
	if err != nil {
		closeProbeResults(states, nil)
		return nil, err
	}
	if !resolvedAll {
		closeProbeResults(states, nil)
		return nil, unresolvedCosignerDiscoveryError(required, selected, aliases, states, ctx.Err())
	}

	keep := map[*resolvedCosignerEndpoint]bool{}
	snapshot := &cosignerEndpointSnapshot{routes: make(map[cosignerRequestKey]*resolvedCosignerEndpoint, len(selected))}
	for key, index := range selected {
		endpoint := states[index].endpoint
		snapshot.routes[key] = endpoint
		if !keep[endpoint] {
			keep[endpoint] = true
			snapshot.endpoints = append(snapshot.endpoints, endpoint)
		}
	}
	closeProbeResults(states, keep)
	s.warnSkippedCosignerEndpoints(states)
	return snapshot, nil
}

// probeCosignerEndpoints owns the bounded sweep shared by signing and diagnostics.
// Callers own every returned connection, including when the sweep fails.
func (s *Signer) probeCosignerEndpoints(ctx context.Context) ([]string, []*cosignerEndpointProbeResult, error) {
	aliases := make([]string, 0, len(s.endpointRegistry.Endpoints))
	for alias, endpoint := range s.endpointRegistry.Endpoints {
		if endpoint.Role == config.ClientEndpointRoleCosigner {
			aliases = append(aliases, alias)
		}
	}
	sort.Strings(aliases)
	if len(aliases) > maxCosignerDiscoveryEndpoints {
		return aliases, nil, fmt.Errorf("%w: configured %d cosigner endpoints; maximum is %d; remove or consolidate endpoint profiles", ErrCosignerDiscoveryConfig, len(aliases), maxCosignerDiscoveryEndpoints)
	}
	if len(aliases) == 0 {
		return aliases, nil, fmt.Errorf("%w: no cosigner endpoints configured; add a role %q endpoint for the cosigner process", ErrCosignerDiscoveryConfig, config.ClientEndpointRoleCosigner)
	}

	if err := ctx.Err(); err != nil {
		return aliases, nil, err
	}
	discoveryCtx, cancel := context.WithTimeout(ctx, cosignerDiscoveryTotalTimeout)
	defer cancel()
	jobs := make(chan int)
	results := make(chan cosignerEndpointProbeResult, len(aliases))
	probe := s.probeEndpoint
	if probe == nil {
		probe = s.probeConfiguredCosignerEndpoint
	}

	var workers sync.WaitGroup
	workerCount := min(cosignerDiscoveryWorkers, len(aliases))
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for index := range jobs {
				alias := aliases[index]
				endpointCtx, endpointCancel := context.WithTimeout(discoveryCtx, cosignerDiscoveryEndpointTimeout)
				resolved, keys, err := probe(endpointCtx, alias, s.endpointRegistry.Endpoints[alias])
				endpointCancel()
				results <- cosignerEndpointProbeResult{index: index, alias: alias, endpoint: resolved, keys: keys, err: err}
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

	states := make([]*cosignerEndpointProbeResult, len(aliases))
	var hostKeyMismatch error
	for result := range results {
		result := result
		states[result.index] = &result
		if errors.Is(result.err, connect.ErrSSHHostKeyMismatch) {
			hostKeyMismatch = fmt.Errorf("%w at endpoint %q", errCosignerDiscoveryHostKeyMismatch, result.alias)
			cancel()
		}
	}

	if hostKeyMismatch != nil {
		return aliases, states, hostKeyMismatch
	}
	return aliases, states, completedCosignerSweepError(ctx, aliases, states, discoveryCtx.Err())
}

func completedCosignerSweepError(ctx context.Context, aliases []string, states []*cosignerEndpointProbeResult, discoveryErr error) error {
	if err := incompleteCosignerDiscoveryError(aliases, states, discoveryErr); err != nil {
		return err
	}
	// A completed sweep remains usable even if its internal deadline expired
	// while the final probe was returning. Caller cancellation still wins.
	return ctx.Err()
}

func incompleteCosignerDiscoveryError(aliases []string, states []*cosignerEndpointProbeResult, cause error) error {
	unprobed := make([]string, 0)
	for index, state := range states {
		if state == nil {
			unprobed = append(unprobed, aliases[index])
		}
	}
	if len(unprobed) == 0 {
		return nil
	}
	if cause == nil {
		cause = ErrCosignerDiscoveryUnavailable
	}
	return fmt.Errorf(
		"cosigner discovery ended before every configured endpoint could be checked (not probed: %s): %w",
		strings.Join(unprobed, ", "),
		cause,
	)
}

func (s *Signer) connectConfiguredCosignerEndpoint(ctx context.Context, endpoint config.ClientEndpointConfig) (*signerclient.Client, func(), string, error) {
	token, err := readCosignerEndpointToken(endpoint.TokenFile)
	if err != nil {
		return nil, nil, "", err
	}
	parsed, err := url.Parse(endpoint.URL)
	if err != nil {
		return nil, nil, "", fmt.Errorf("%w: invalid endpoint URL: %v", errCosignerEndpointConfig, err)
	}

	switch parsed.Scheme {
	case "http", "https":
		return signerclient.NewSignerClientWithToken(strings.TrimRight(endpoint.URL, "/"), token), nil, endpoint.URL, nil
	case "ssh":
		sshPort := config.DefaultSSHPort
		if parsed.Port() != "" {
			port, err := strconv.Atoi(parsed.Port())
			if err != nil || port <= 0 || port > 65535 {
				return nil, nil, "", fmt.Errorf("%w: invalid SSH port %q", errCosignerEndpointConfig, parsed.Port())
			}
			sshPort = port
		}
		signerPort := endpoint.SignerPort
		if signerPort == 0 {
			signerPort = config.DefaultRESTPort
		}
		progressOut := s.signerProgressWriter()
		client, cleanup, err := connect.ConnectCosignerWithSSH(ctx, connect.CosignerSSHConfig{
			Host:            parsed.Hostname(),
			SSHPort:         sshPort,
			SignerPort:      signerPort,
			Token:           token,
			IdentityFile:    endpoint.IdentityFile,
			KnownHostsPath:  endpoint.KnownHostsPath,
			ProgressOut:     progressOut,
			HostKeyApproval: s.hostKeyApproval,
		})
		if err != nil {
			return nil, nil, "", err
		}
		return client, cleanup, endpoint.URL, nil
	default:
		return nil, nil, "", fmt.Errorf("%w: unsupported endpoint URL scheme %q", errCosignerEndpointConfig, parsed.Scheme)
	}
}

func (s *Signer) probeConfiguredCosignerEndpoint(ctx context.Context, alias string, endpoint config.ClientEndpointConfig) (*resolvedCosignerEndpoint, []DiscoveredCosignerComponentKey, error) {
	client, cleanup, source, err := s.connectConfiguredCosignerEndpoint(ctx, endpoint)
	if err != nil {
		return nil, nil, classifyCosignerDiscoveryConnectError(err)
	}
	resolved := &resolvedCosignerEndpoint{client: client, source: source, cleanup: cleanup}
	keys, err := resolved.client.GetKeysWithContext(ctx)
	if err != nil {
		resolved.close()
		return nil, nil, classifyCosignerDiscoveryQueryError(err)
	}
	if keys.Locked {
		resolved.close()
		return nil, nil, fmt.Errorf("%w", ErrCosignerDiscoveryLocked)
	}
	discovered, err := discoverCosignerComponentKeys(keys.Keys)
	if err != nil {
		resolved.close()
		return nil, nil, err
	}
	return resolved, discovered, nil
}

// DiscoverCosignerComponentKeys queries one endpoint and returns
// cosigner component public keys that can be mapped for guarded signing.
func (s *Signer) DiscoverCosignerComponentKeys(ctx context.Context, endpoint config.ClientEndpointConfig) ([]DiscoveredCosignerComponentKey, error) {
	resolved, keys, err := s.probeConfiguredCosignerEndpoint(ctx, "requested endpoint", endpoint)
	if resolved != nil {
		defer resolved.close()
	}
	return keys, err
}

func distinctSortedCosignerRequestKeys(required []cosignerRequestKey) []cosignerRequestKey {
	seen := make(map[cosignerRequestKey]bool, len(required))
	out := make([]cosignerRequestKey, 0, len(required))
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

func uniqueCosignerSelections(required []cosignerRequestKey, states []*cosignerEndpointProbeResult) (map[cosignerRequestKey]int, bool, error) {
	selected := make(map[cosignerRequestKey]int, len(required))
	for _, key := range required {
		matches := matchingCosignerEndpointIndices(key, states)
		switch len(matches) {
		case 0:
			continue
		case 1:
			selected[key] = matches[0]
		default:
			aliases := make([]string, 0, len(matches))
			for _, index := range matches {
				aliases = append(aliases, states[index].alias)
			}
			selector, err := cosignerComponentSelector(key.ComponentKeyType, key.PublicKey)
			if err != nil {
				selector = "invalid"
			}
			return selected, false, fmt.Errorf(
				"%w: Witness Key ID %s (%s) is advertised by endpoints %s; remove duplicate endpoint profiles so each witness has exactly one live route",
				errCosignerDiscoveryDuplicateRoute,
				selector,
				key.ComponentKeyType,
				`"`+strings.Join(aliases, `", "`)+`"`,
			)
		}
	}
	return selected, len(selected) == len(required), nil
}

func matchingCosignerEndpointIndices(required cosignerRequestKey, states []*cosignerEndpointProbeResult) []int {
	matches := make([]int, 0, 1)
	for index, state := range states {
		if state != nil && state.err == nil && discoveredCosignerKeysContain(state.keys, required) {
			matches = append(matches, index)
		}
	}
	return matches
}

func discoveredCosignerKeysContain(keys []DiscoveredCosignerComponentKey, required cosignerRequestKey) bool {
	for _, key := range keys {
		if key.PublicKey == required.PublicKey && key.KeyType == required.ComponentKeyType {
			return true
		}
	}
	return false
}

func closeProbeResults(states []*cosignerEndpointProbeResult, keep map[*resolvedCosignerEndpoint]bool) {
	closed := map[*resolvedCosignerEndpoint]bool{}
	for _, state := range states {
		if state == nil || state.endpoint == nil || keep[state.endpoint] || closed[state.endpoint] {
			continue
		}
		state.endpoint.close()
		closed[state.endpoint] = true
	}
}

func unresolvedCosignerDiscoveryError(required []cosignerRequestKey, selected map[cosignerRequestKey]int, aliases []string, states []*cosignerEndpointProbeResult, cause error) error {
	missing := make([]string, 0, len(required))
	for _, key := range required {
		if _, ok := selected[key]; ok {
			continue
		}
		selector, err := cosignerComponentSelector(key.ComponentKeyType, key.PublicKey)
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
			summary = append(summary, alias+": "+cosignerDiscoveryFailureLabel(state.err))
			causes = append(causes, state.err)
		default:
			summary = append(summary, alias+": no matching key")
		}
	}
	message := fmt.Sprintf("no live cosigner route for %s; endpoint results: %s; configure a role %q endpoint for the cosigner process that advertises the required Witness Key ID", strings.Join(missing, ", "), strings.Join(summary, "; "), config.ClientEndpointRoleCosigner)
	if len(causes) > 0 {
		return fmt.Errorf("%s: %w", message, errors.Join(causes...))
	}
	return errors.New(message)
}

func cosignerDiscoveryFailureLabel(err error) string {
	switch {
	case errors.Is(err, connect.ErrSSHHostKeyMismatch):
		return "SSH host-key mismatch"
	case errors.Is(err, connect.ErrSSHUnknownHostKey):
		return "SSH host is not enrolled"
	case errors.Is(err, connect.ErrSSHKnownHostsFile):
		return "invalid known_hosts configuration"
	case errors.Is(err, ErrCosignerDiscoveryLocked):
		return "signer locked"
	case errors.Is(err, ErrCosignerDiscoveryAuth):
		return "authentication failed"
	case errors.Is(err, ErrCosignerDiscoveryInvalidMetadata):
		return "invalid /keys metadata"
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, ErrCosignerDiscoveryUnavailable):
		return "unavailable"
	default:
		return "invalid endpoint configuration"
	}
}

func (s *Signer) warnSkippedCosignerEndpoints(states []*cosignerEndpointProbeResult) {
	w := s.signerProgressWriter()
	if w == nil {
		return
	}
	for _, state := range states {
		if state == nil || state.err == nil || errors.Is(state.err, context.Canceled) {
			continue
		}
		_, _ = fmt.Fprintf(w, "[cosigner discovery] skipped endpoint %s: %s\n", state.alias, cosignerDiscoveryFailureLabel(state.err))
	}
}

func readCosignerEndpointToken(path string) (string, error) {
	token, err := tokenfile.ReadToken(path)
	if err != nil {
		return "", fmt.Errorf("%w: failed to read cosigner token file %s: %v", errCosignerEndpointAuth, path, err)
	}
	if token == "" {
		return "", fmt.Errorf("%w: cosigner token file %s is empty", errCosignerEndpointAuth, path)
	}
	return token, nil
}

func classifyCosignerDiscoveryConnectError(err error) error {
	switch {
	case errors.Is(err, errCosignerEndpointAuth):
		return fmt.Errorf("%w: %w", ErrCosignerDiscoveryAuth, err)
	case errors.Is(err, errCosignerEndpointConfig):
		return fmt.Errorf("%w: %w", ErrCosignerDiscoveryConfig, err)
	case isNetworkUnavailableError(err):
		return fmt.Errorf("%w: %w", ErrCosignerDiscoveryUnavailable, err)
	}

	var sshAuthErr *ssh.ServerAuthError
	if errors.As(err, &sshAuthErr) {
		return fmt.Errorf("%w: %w", ErrCosignerDiscoveryAuth, err)
	}
	return fmt.Errorf("%w: %w", ErrCosignerDiscoveryConfig, err)
}

func classifyCosignerDiscoveryQueryError(err error) error {
	if errors.Is(err, signerclient.ErrInvalidResponse) {
		return fmt.Errorf("%w: %w", ErrCosignerDiscoveryInvalidMetadata, err)
	}

	var statusErr *signerclient.HTTPStatusError
	if errors.As(err, &statusErr) {
		if classified := classifyCosignerDiscoveryQueryCode(statusErr.Code, err); classified != nil {
			return classified
		}
		switch {
		case statusErr.StatusCode == http.StatusUnauthorized || statusErr.StatusCode == http.StatusForbidden:
			return fmt.Errorf("%w: %w", ErrCosignerDiscoveryAuth, err)
		case statusErr.StatusCode == http.StatusRequestTimeout ||
			statusErr.StatusCode == http.StatusTooManyRequests ||
			statusErr.StatusCode >= http.StatusInternalServerError:
			return fmt.Errorf("%w: %w", ErrCosignerDiscoveryUnavailable, err)
		default:
			return fmt.Errorf("%w: %w", ErrCosignerDiscoveryConfig, err)
		}
	}

	if isNetworkUnavailableError(err) {
		return fmt.Errorf("%w: %w", ErrCosignerDiscoveryUnavailable, err)
	}
	return fmt.Errorf("%w: %w", ErrCosignerDiscoveryConfig, err)
}

func classifyCosignerDiscoveryQueryCode(code string, err error) error {
	switch code {
	case "":
		return nil
	case signerapi.ErrCodeLocked:
		return fmt.Errorf("%w: %w", ErrCosignerDiscoveryLocked, err)
	case signerapi.ErrCodeUnauthorized, signerapi.ErrCodeForbidden, signerapi.ErrCodeInvalidPassphrase:
		return fmt.Errorf("%w: %w", ErrCosignerDiscoveryAuth, err)
	case signerapi.ErrCodeUnavailable, signerapi.ErrCodeCacheRefresh, signerapi.ErrCodeInternal:
		return fmt.Errorf("%w: %w", ErrCosignerDiscoveryUnavailable, err)
	case signerapi.ErrCodeBadRequest, signerapi.ErrCodeNotFound:
		return fmt.Errorf("%w: %w", ErrCosignerDiscoveryConfig, err)
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

func discoverCosignerComponentKeys(keys []signerapi.KeyInfo) ([]DiscoveredCosignerComponentKey, error) {
	discovered := make([]DiscoveredCosignerComponentKey, 0)
	seen := map[string]struct{}{}
	for _, key := range keys {
		// Component key types are runtime metadata: any advertised component
		// key participates in discovery, and its key-type string is treated
		// as opaque. Selector cross-derivation below pins the advertised
		// Witness Key ID to the advertised key type and public key.
		if !key.IsWitnessKey || key.KeyType == "" {
			continue
		}
		publicKey, err := normalizeCosignerPublicKeyHex(key.PublicKeyHex)
		if err != nil {
			return nil, fmt.Errorf("%w: Witness Key ID %q has invalid public_key_hex: %v", ErrCosignerDiscoveryInvalidMetadata, key.Address, err)
		}
		selector, err := witness.NormalizeID(key.Address)
		if err != nil {
			return nil, fmt.Errorf("%w: metadata for %s has invalid advertised Witness Key ID %q: %v", ErrCosignerDiscoveryInvalidMetadata, cosignerComponentLabel(key.KeyType, publicKey), key.Address, err)
		}
		expectedSelector, err := cosignerComponentSelector(key.KeyType, publicKey)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to derive Witness Key ID for cosigner public key %s: %v", ErrCosignerDiscoveryInvalidMetadata, shortCosignerPublicKeyHex(publicKey), err)
		}
		if selector != expectedSelector {
			return nil, fmt.Errorf("%w: cosigner component %s advertised selector %s, want %s", ErrCosignerDiscoveryInvalidMetadata, cosignerComponentLabel(key.KeyType, publicKey), selector, expectedSelector)
		}
		if _, ok := seen[publicKey]; ok {
			continue
		}
		seen[publicKey] = struct{}{}
		discovered = append(discovered, DiscoveredCosignerComponentKey{
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
