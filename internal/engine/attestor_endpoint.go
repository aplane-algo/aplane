// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

type attestorComponentClient interface {
	GetKeysWithContext(context.Context) (*signerapi.KeysResult, error)
	RequestComponentSignWithContext(context.Context, signerapi.ComponentSignRequest) (*signerapi.ComponentSignResponse, error)
}

// ErrAttestorDiscoveryInvalidMetadata marks malformed attestor component-key
// metadata returned by an endpoint's /keys response.
var ErrAttestorDiscoveryInvalidMetadata = errors.New("invalid attestor discovery metadata")

type resolvedAttestorEndpoint struct {
	client  attestorComponentClient
	source  string
	cleanup func()
}

// DiscoveredAttestorComponentKey is public attestor component-key metadata
// advertised by a signer endpoint through /keys.
type DiscoveredAttestorComponentKey struct {
	PublicKey    string
	ComponentKey string
	KeyType      string
}

func (r *resolvedAttestorEndpoint) close() {
	if r != nil && r.cleanup != nil {
		r.cleanup()
	}
}

func (e *Engine) resolveAttestorEndpoint(ctx context.Context, attestorKey attestorRequestKey) (*resolvedAttestorEndpoint, error) {
	if endpoint, ok := e.AttestorEndpoints[attestorKey.PublicKey]; ok {
		if endpoint.URL == "self" {
			if err := verifyAttestorEndpointAdvertises(ctx, e.Connection, attestorKey, "configured self attestor endpoint"); err != nil {
				return nil, err
			}
			return &resolvedAttestorEndpoint{client: e.Connection, source: "self"}, nil
		}
		client, cleanup, source, err := e.connectConfiguredAttestorEndpoint(ctx, endpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to connect attestor endpoint for public key %s: %w", attestorKey.PublicKey, err)
		}
		resolved := &resolvedAttestorEndpoint{client: client, source: source, cleanup: cleanup}
		if err := verifyAttestorEndpointAdvertises(ctx, client, attestorKey, source); err != nil {
			resolved.close()
			return nil, err
		}
		return resolved, nil
	}

	if err := verifyAttestorEndpointAdvertises(ctx, e.Connection, attestorKey, "current signer"); err != nil {
		return nil, fmt.Errorf("no attestor endpoint configured for public key %s and current signer does not advertise a matching component key: %w", attestorKey.PublicKey, err)
	}
	return &resolvedAttestorEndpoint{client: e.Connection, source: "current signer"}, nil
}

func (e *Engine) connectConfiguredAttestorEndpoint(ctx context.Context, endpoint config.AttestorEndpointConfig) (*signerclient.Client, func(), string, error) {
	token, err := readAttestorEndpointToken(endpoint.TokenFile)
	if err != nil {
		return nil, nil, "", err
	}
	parsed, err := url.Parse(endpoint.URL)
	if err != nil {
		return nil, nil, "", fmt.Errorf("invalid endpoint URL: %w", err)
	}

	switch parsed.Scheme {
	case "http", "https":
		return signerclient.NewSignerClientWithToken(strings.TrimRight(endpoint.URL, "/"), token), nil, endpoint.URL, nil
	case "ssh":
		sshPort := config.DefaultSSHPort
		if parsed.Port() != "" {
			port, err := strconv.Atoi(parsed.Port())
			if err != nil || port <= 0 || port > 65535 {
				return nil, nil, "", fmt.Errorf("invalid SSH port %q", parsed.Port())
			}
			sshPort = port
		}
		signerPort := endpoint.SignerPort
		if signerPort == 0 {
			signerPort = config.DefaultRESTPort
		}
		progressOut := e.signerProgressWriter()
		client, cleanup, err := connect.ConnectAttestorWithTunnel(ctx, connect.AttestorTunnelConfig{
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
		return nil, nil, "", fmt.Errorf("unsupported endpoint URL scheme %q", parsed.Scheme)
	}
}

// DiscoverAttestorComponentKeysWithContext queries one endpoint and returns
// attestor component public keys that can be mapped for attested signing.
func (e *Engine) DiscoverAttestorComponentKeysWithContext(ctx context.Context, endpoint config.ClientEndpointConfig) ([]DiscoveredAttestorComponentKey, error) {
	var client attestorComponentClient
	var cleanup func()
	if endpoint.URL == "self" {
		client = e.Connection
	} else {
		resolved := config.AttestorEndpointConfig{
			URL:            endpoint.URL,
			TokenFile:      endpoint.TokenFile,
			SignerPort:     endpoint.SignerPort,
			LocalPort:      endpoint.LocalPort,
			IdentityFile:   endpoint.IdentityFile,
			KnownHostsPath: endpoint.KnownHostsPath,
		}
		c, closeFn, _, err := e.connectConfiguredAttestorEndpoint(ctx, resolved)
		if err != nil {
			return nil, err
		}
		client = c
		cleanup = closeFn
	}
	if cleanup != nil {
		defer cleanup()
	}

	keys, err := client.GetKeysWithContext(ctx)
	if err != nil {
		return nil, err
	}
	if keys.Locked {
		return nil, fmt.Errorf("endpoint signer is locked")
	}
	return discoverAttestorComponentKeys(keys.Keys)
}

func readAttestorEndpointToken(path string) (string, error) {
	token, err := tokenfile.ReadToken(path)
	if err != nil {
		return "", fmt.Errorf("failed to read attestor token file %s: %w", path, err)
	}
	if token == "" {
		return "", fmt.Errorf("attestor token file %s is empty", path)
	}
	return token, nil
}

func discoverAttestorComponentKeys(keys []signerapi.KeyInfo) ([]DiscoveredAttestorComponentKey, error) {
	discovered := make([]DiscoveredAttestorComponentKey, 0)
	seen := map[string]struct{}{}
	for _, key := range keys {
		if !key.IsComponentKey || !keytypes.IsAttestorComponentKeyType(key.KeyType) {
			continue
		}
		publicKey, err := normalizeAttestorPublicKeyHex(key.PublicKeyHex, key.KeyType)
		if err != nil {
			return nil, fmt.Errorf("%w: attestor component key %q has invalid public_key_hex: %v", ErrAttestorDiscoveryInvalidMetadata, key.Address, err)
		}
		selector, err := keytypes.NormalizeComponentKeySelector(key.Address)
		if err != nil {
			return nil, fmt.Errorf("%w: attestor component public key %s has invalid component selector %q: %v", ErrAttestorDiscoveryInvalidMetadata, publicKey, key.Address, err)
		}
		expectedSelector, err := attestorComponentSelector(key.KeyType, publicKey)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to derive component selector for attestor public key %s: %v", ErrAttestorDiscoveryInvalidMetadata, publicKey, err)
		}
		if selector != expectedSelector {
			return nil, fmt.Errorf("%w: attestor component public key %s advertised selector %s, want %s", ErrAttestorDiscoveryInvalidMetadata, publicKey, selector, expectedSelector)
		}
		if _, ok := seen[publicKey]; ok {
			continue
		}
		seen[publicKey] = struct{}{}
		discovered = append(discovered, DiscoveredAttestorComponentKey{
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

func verifyAttestorEndpointAdvertises(ctx context.Context, client attestorComponentClient, attestorKey attestorRequestKey, source string) error {
	expectedPublicKey, err := normalizeAttestorPublicKeyHex(attestorKey.PublicKey, attestorKey.ComponentKeyType)
	if err != nil {
		return fmt.Errorf("invalid expected attestor public key: %w", err)
	}
	expectedSelector, err := attestorComponentSelector(attestorKey.ComponentKeyType, expectedPublicKey)
	if err != nil {
		return fmt.Errorf("failed to derive expected attestor component selector: %w", err)
	}
	keys, err := client.GetKeysWithContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to inspect %s component keys for attestation: %w", source, err)
	}
	for _, key := range keys.Keys {
		if key.KeyType != attestorKey.ComponentKeyType || !key.IsComponentKey {
			continue
		}
		publicKey, err := normalizeAttestorPublicKeyHex(key.PublicKeyHex, attestorKey.ComponentKeyType)
		if err != nil {
			continue
		}
		if publicKey != expectedPublicKey {
			continue
		}
		selector, err := keytypes.NormalizeComponentKeySelector(key.Address)
		if err != nil {
			return fmt.Errorf("%s advertised attestor public key %s with invalid component selector %q: %w", source, expectedPublicKey, key.Address, err)
		}
		if selector != expectedSelector {
			return fmt.Errorf("%s advertised attestor public key %s with component selector %s, want %s", source, expectedPublicKey, selector, expectedSelector)
		}
		return nil
	}
	return fmt.Errorf("%s did not advertise attestor component public key %s", source, expectedPublicKey)
}
