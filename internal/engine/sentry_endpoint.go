// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

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

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/tokenfile"
	"golang.org/x/crypto/ssh"
)

type sentryComponentClient interface {
	GetKeysWithContext(context.Context) (*signerapi.KeysResult, error)
	RequestComponentSignWithContext(context.Context, signerapi.ComponentSignRequest) (*signerapi.ComponentSignResponse, error)
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

	errSentryEndpointAuth   = errors.New("sentry endpoint auth")
	errSentryEndpointConfig = errors.New("sentry endpoint config")
)

type resolvedSentryEndpoint struct {
	client  sentryComponentClient
	source  string
	cleanup func()
}

type sentryEndpointLockedError struct {
	source string
}

func (e sentryEndpointLockedError) Error() string {
	return e.source + " is locked"
}

func (e sentryEndpointLockedError) Unwrap() error {
	return ErrSentryDiscoveryLocked
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

func (e *Engine) resolveSentryEndpoint(ctx context.Context, sentryKey sentryRequestKey) (*resolvedSentryEndpoint, error) {
	if endpoint, ok := e.SentryEndpoints[sentryKey.PublicKey]; ok {
		if endpoint.URL == "self" {
			if err := verifySentryEndpointAdvertises(ctx, e.Connection, sentryKey, "configured self sentry endpoint"); err != nil {
				return nil, err
			}
			return &resolvedSentryEndpoint{client: e.Connection, source: "self"}, nil
		}
		client, cleanup, source, err := e.connectConfiguredSentryEndpoint(ctx, endpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to connect sentry endpoint for %s: %w", sentryComponentLabel(sentryKey.ComponentKeyType, sentryKey.PublicKey), err)
		}
		resolved := &resolvedSentryEndpoint{client: client, source: source, cleanup: cleanup}
		if err := verifySentryEndpointAdvertises(ctx, client, sentryKey, source); err != nil {
			resolved.close()
			return nil, err
		}
		return resolved, nil
	}

	if err := verifySentryEndpointAdvertises(ctx, e.Connection, sentryKey, "current signer"); err != nil {
		return nil, fmt.Errorf("no sentry endpoint configured for %s and current signer does not advertise a matching sentry component: %w", sentryComponentLabel(sentryKey.ComponentKeyType, sentryKey.PublicKey), err)
	}
	return &resolvedSentryEndpoint{client: e.Connection, source: "current signer"}, nil
}

func (e *Engine) connectConfiguredSentryEndpoint(ctx context.Context, endpoint config.SentryEndpointConfig) (*signerclient.Client, func(), string, error) {
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
		progressOut := e.signerProgressWriter()
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

// DiscoverSentryComponentKeys queries one endpoint and returns
// sentry component public keys that can be mapped for guarded signing.
func (e *Engine) DiscoverSentryComponentKeys(ctx context.Context, endpoint config.ClientEndpointConfig) ([]DiscoveredSentryComponentKey, error) {
	var client sentryComponentClient
	var cleanup func()
	if endpoint.URL == "self" {
		client = e.Connection
	} else {
		resolved := config.SentryEndpointConfig{
			URL:            endpoint.URL,
			TokenFile:      endpoint.TokenFile,
			SignerPort:     endpoint.SignerPort,
			LocalPort:      endpoint.LocalPort,
			IdentityFile:   endpoint.IdentityFile,
			KnownHostsPath: endpoint.KnownHostsPath,
		}
		c, closeFn, _, err := e.connectConfiguredSentryEndpoint(ctx, resolved)
		if err != nil {
			return nil, classifySentryDiscoveryConnectError(err)
		}
		client = c
		cleanup = closeFn
	}
	if cleanup != nil {
		defer cleanup()
	}

	keys, err := client.GetKeysWithContext(ctx)
	if err != nil {
		return nil, classifySentryDiscoveryQueryError(err)
	}
	if keys.Locked {
		return nil, fmt.Errorf("%w", ErrSentryDiscoveryLocked)
	}
	return discoverSentryComponentKeys(keys.Keys)
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
		// Sentry Key ID to the advertised key type and public key.
		if !key.IsComponentKey || key.KeyType == "" {
			continue
		}
		publicKey, err := normalizeSentryPublicKeyHex(key.PublicKeyHex)
		if err != nil {
			return nil, fmt.Errorf("%w: Sentry Key ID %q has invalid public_key_hex: %v", ErrSentryDiscoveryInvalidMetadata, key.Address, err)
		}
		selector, err := keytypes.NormalizeComponentKeySelector(key.Address)
		if err != nil {
			return nil, fmt.Errorf("%w: metadata for %s has invalid advertised Sentry Key ID %q: %v", ErrSentryDiscoveryInvalidMetadata, sentryComponentLabel(key.KeyType, publicKey), key.Address, err)
		}
		expectedSelector, err := sentryComponentSelector(key.KeyType, publicKey)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to derive Sentry Key ID for sentry public key %s: %v", ErrSentryDiscoveryInvalidMetadata, shortSentryPublicKeyHex(publicKey), err)
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

func (e *Engine) signerProgressWriter() io.Writer {
	if e == nil || e.Connection == nil {
		return nil
	}
	e.Connection.Mu.Lock()
	defer e.Connection.Mu.Unlock()
	return e.Connection.SignerProgressOut
}

func verifySentryEndpointAdvertises(ctx context.Context, client sentryComponentClient, sentryKey sentryRequestKey, source string) error {
	expectedPublicKey, err := normalizeSentryPublicKeyHex(sentryKey.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid expected sentry public key: %w", err)
	}
	expectedSelector, err := sentryComponentSelector(sentryKey.ComponentKeyType, expectedPublicKey)
	if err != nil {
		return fmt.Errorf("failed to derive expected Sentry Key ID: %w", err)
	}
	expectedLabel := fmt.Sprintf("Sentry Key ID %s (%s)", expectedSelector, sentryKey.ComponentKeyType)
	keys, err := client.GetKeysWithContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to inspect %s sentry keys: %w", source, err)
	}
	if keys.Locked {
		return sentryEndpointLockedError{source: source}
	}
	for _, key := range keys.Keys {
		if key.KeyType != sentryKey.ComponentKeyType || !key.IsComponentKey {
			continue
		}
		publicKey, err := normalizeSentryPublicKeyHex(key.PublicKeyHex)
		if err != nil {
			continue
		}
		if publicKey != expectedPublicKey {
			continue
		}
		selector, err := keytypes.NormalizeComponentKeySelector(key.Address)
		if err != nil {
			return fmt.Errorf("%s advertised %s with invalid Sentry Key ID %q: %w", source, expectedLabel, key.Address, err)
		}
		if selector != expectedSelector {
			return fmt.Errorf("%s advertised %s with Sentry Key ID %s, want %s", source, expectedLabel, selector, expectedSelector)
		}
		return nil
	}
	return fmt.Errorf("%s did not advertise %s", source, expectedLabel)
}
