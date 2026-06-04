// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
)

type attestorComponentClient interface {
	GetKeysWithContext(context.Context) (*signerapi.KeysResult, error)
	RequestComponentSignWithContext(context.Context, signerapi.ComponentSignRequest) (*signerapi.ComponentSignResponse, error)
}

type resolvedAttestorEndpoint struct {
	client  attestorComponentClient
	source  string
	cleanup func()
}

func (r *resolvedAttestorEndpoint) close() {
	if r != nil && r.cleanup != nil {
		r.cleanup()
	}
}

func (e *Engine) resolveAttestorEndpoint(ctx context.Context, attestorPublicKey string) (*resolvedAttestorEndpoint, error) {
	if endpoint, ok := e.AttestorEndpoints[attestorPublicKey]; ok {
		if endpoint.URL == "self" {
			if err := verifyAttestorEndpointAdvertises(ctx, e.Connection, attestorPublicKey, "configured self attestor endpoint"); err != nil {
				return nil, err
			}
			return &resolvedAttestorEndpoint{client: e.Connection, source: "self"}, nil
		}
		client, cleanup, source, err := e.connectConfiguredAttestorEndpoint(ctx, endpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to connect attestor endpoint for public key %s: %w", attestorPublicKey, err)
		}
		resolved := &resolvedAttestorEndpoint{client: client, source: source, cleanup: cleanup}
		if err := verifyAttestorEndpointAdvertises(ctx, client, attestorPublicKey, source); err != nil {
			resolved.close()
			return nil, err
		}
		return resolved, nil
	}

	if err := verifyAttestorEndpointAdvertises(ctx, e.Connection, attestorPublicKey, "current signer"); err != nil {
		return nil, fmt.Errorf("no attestor endpoint configured for public key %s and current signer does not advertise a matching component key: %w", attestorPublicKey, err)
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

func readAttestorEndpointToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read attestor token file %s: %w", path, err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("attestor token file %s is empty", path)
	}
	return token, nil
}

func (e *Engine) signerProgressWriter() io.Writer {
	if e == nil || e.Connection == nil {
		return nil
	}
	e.Connection.Mu.Lock()
	defer e.Connection.Mu.Unlock()
	return e.Connection.SignerProgressOut
}

func verifyAttestorEndpointAdvertises(ctx context.Context, client attestorComponentClient, attestorPublicKey string, source string) error {
	keys, err := client.GetKeysWithContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to inspect %s component keys for attestation: %w", source, err)
	}
	for _, key := range keys.Keys {
		if key.KeyType != keytypes.AttestorComponentEd25519V1 || !key.IsComponentKey {
			continue
		}
		selector, err := keytypes.NormalizeComponentKeySelector(firstNonEmpty(key.PublicKeyHex, key.Address))
		if err != nil {
			continue
		}
		if selector == attestorPublicKey {
			return nil
		}
	}
	return fmt.Errorf("%s did not advertise attestor component key %s", source, attestorPublicKey)
}
