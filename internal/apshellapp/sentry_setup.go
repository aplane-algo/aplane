// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/aplane-algo/aplane/internal/clientdata"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/sentry/enrollment"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"github.com/aplane-algo/aplane/internal/tokenfile"
	"github.com/aplane-algo/aplane/internal/witness"
)

// ErrSentryEndpointURLRequired marks setup documents that need a client-local
// route supplied by the caller.
var ErrSentryEndpointURLRequired = errors.New("sentry endpoint URL is required")

// SentrySetupRequest describes the public handoff and client-local route
// choices used to prepare a guided sentry setup.
type SentrySetupRequest struct {
	Document   []byte
	Alias      string
	URL        string
	SignerPort int
	DryRun     bool
}

// SentrySetupPlan is an immutable reviewed setup proposal. ExistingEndpoint is
// compared again under the client lock before the route is changed.
type SentrySetupPlan struct {
	Alias               string
	Witness             witness.PublicReference
	Endpoint            config.ClientEndpointConfig
	ExistingEndpoint    *config.ClientEndpointConfig
	Created             bool
	Updated             bool
	ReplacementRequired bool
	DestinationChanged  bool
	DryRun              bool
	BundledEndpoint     bool
}

// SentrySetupResult reports completed client-owned effects without exposing
// credential values or paths.
type SentrySetupResult struct {
	Alias        string
	WitnessKeyID string
	URL          string
	Created      bool
	Updated      bool
	TokenIssued  bool
	Verified     bool
	DryRun       bool
}

// PrepareSentrySetup validates the public document and calculates the exact
// client endpoint change. It performs no writes or network operations.
func (a *App) PrepareSentrySetup(req SentrySetupRequest) (SentrySetupPlan, error) {
	artifact, err := enrollment.ParseArtifact(req.Document)
	if err != nil {
		return SentrySetupPlan{}, err
	}
	alias := strings.TrimSpace(req.Alias)
	if err := config.ValidateClientEndpointAlias(alias); err != nil {
		return SentrySetupPlan{}, fmt.Errorf("sentry endpoint alias: %w", err)
	}
	registry, _, err := config.LoadStoredClientEndpointRegistry(a.DataDir)
	if err != nil {
		return SentrySetupPlan{}, err
	}
	existing, exists := registry.Endpoint(alias)
	if exists && existing.Role != config.ClientEndpointRoleSentry {
		return SentrySetupPlan{}, fmt.Errorf("endpoint alias %q has role %q; choose a sentry alias", alias, existing.Role)
	}
	candidate := existing
	candidate.Role = config.ClientEndpointRoleSentry

	bundled := artifact.Endpoint != nil
	if req.URL != "" {
		candidate.URL = strings.TrimSpace(req.URL)
	} else if artifact.Endpoint != nil && artifact.Endpoint.URL != "" {
		candidate.URL = artifact.Endpoint.URL
	}
	if candidate.URL == "" {
		return SentrySetupPlan{}, fmt.Errorf("%w; pass --endpoint <url>", ErrSentryEndpointURLRequired)
	}
	if req.SignerPort != 0 {
		candidate.SignerPort = req.SignerPort
	} else if artifact.Endpoint != nil && artifact.Endpoint.SignerPort != 0 {
		candidate.SignerPort = artifact.Endpoint.SignerPort
	}
	candidate.LocalPort = 0

	preview, err := config.PlanStoredClientEndpointUpsert(a.DataDir, alias, candidate, true)
	if err != nil {
		return SentrySetupPlan{}, err
	}
	plan := SentrySetupPlan{
		Alias: alias, Witness: artifact.Witness, Endpoint: preview.Endpoint,
		Created: preview.Created, Updated: preview.Updated,
		ReplacementRequired: exists && preview.Updated, DryRun: req.DryRun,
		BundledEndpoint: bundled,
	}
	if exists {
		plan.DestinationChanged = strings.TrimRight(strings.TrimSpace(existing.URL), "/") != preview.Endpoint.URL
		if !plan.DestinationChanged && strings.HasPrefix(preview.Endpoint.URL, "ssh://") {
			existingPort := existing.SignerPort
			if existingPort == 0 {
				existingPort = config.DefaultRESTPort
			}
			previewPort := preview.Endpoint.SignerPort
			if previewPort == 0 {
				previewPort = config.DefaultRESTPort
			}
			plan.DestinationChanged = existingPort != previewPort
		}
	}
	if exists {
		copy := existing
		plan.ExistingEndpoint = &copy
	}
	return plan, nil
}

// ApplySentrySetupEndpoint revalidates and applies a reviewed route under the
// shared client lock. Network and token operations must run after it returns.
func (a *App) ApplySentrySetupEndpoint(plan SentrySetupPlan, replace bool) (config.ClientEndpointConfig, error) {
	if plan.DryRun {
		return plan.Endpoint, nil
	}
	if plan.ReplacementRequired && !replace {
		return config.ClientEndpointConfig{}, fmt.Errorf("endpoint alias %q has different settings; confirm replacement", plan.Alias)
	}
	var resolved config.ClientEndpointConfig
	err := clientdata.WithExclusiveLock(a.DataDir, func() error {
		registry, _, err := config.LoadStoredClientEndpointRegistry(a.DataDir)
		if err != nil {
			return err
		}
		current, exists := registry.Endpoint(plan.Alias)
		if plan.ExistingEndpoint == nil {
			if exists {
				return fmt.Errorf("endpoint alias %q changed after review; review setup again", plan.Alias)
			}
		} else if !exists || current != *plan.ExistingEndpoint {
			return fmt.Errorf("endpoint alias %q changed after review; review setup again", plan.Alias)
		}
		upsert, err := config.PlanStoredClientEndpointUpsert(a.DataDir, plan.Alias, plan.Endpoint, replace)
		if err != nil {
			return err
		}
		if !upsert.Created && !upsert.Updated {
			return nil
		}
		return config.ApplyStoredClientEndpointUpsert(a.DataDir, upsert)
	})
	if err != nil {
		return config.ClientEndpointConfig{}, err
	}
	cfg, err := config.LoadConfig(a.DataDir)
	if err != nil {
		return config.ClientEndpointConfig{}, err
	}
	endpoint, ok := cfg.Endpoints.Endpoint(plan.Alias)
	if !ok {
		return config.ClientEndpointConfig{}, fmt.Errorf("configured endpoint %q is missing", plan.Alias)
	}
	a.Config = cfg
	a.eng.EndpointRegistry = cfg.Endpoints.Clone()
	resolved = endpoint
	return resolved, nil
}

// CompleteSentrySetup establishes endpoint access when needed and verifies the
// exact public witness from the handoff. It never changes the primary tunnel.
func (a *App) CompleteSentrySetup(ctx context.Context, plan SentrySetupPlan, endpoint config.ClientEndpointConfig, approve sshtunnel.HostKeyApprovalHandler, onProvisioningStarted func()) (*SentrySetupResult, error) {
	result := &SentrySetupResult{
		Alias: plan.Alias, WitnessKeyID: plan.Witness.WitnessKeyID,
		URL: endpoint.URL, Created: plan.Created, Updated: plan.Updated,
		DryRun: plan.DryRun,
	}
	if plan.DryRun {
		return result, nil
	}

	token, err := tokenfile.ReadToken(endpoint.TokenFile)
	if err != nil {
		return result, fmt.Errorf("read sentry endpoint token: %w", err)
	}
	if token == "" || plan.DestinationChanged {
		parsed, parseErr := url.Parse(endpoint.URL)
		if parseErr != nil {
			return result, parseErr
		}
		if parsed.Scheme != "ssh" {
			if plan.DestinationChanged {
				return result, fmt.Errorf("endpoint %q changed destinations; refusing to reuse the previous destination's token; install a token for the new endpoint and rerun", plan.Alias)
			}
			return result, fmt.Errorf("endpoint %q has no token; automatic enrollment requires ssh://", plan.Alias)
		}
		if err := a.requestSentryTokenIsolated(ctx, plan.Alias, endpoint, approve, onProvisioningStarted); err != nil {
			return result, err
		}
		result.TokenIssued = true
	}

	keys, err := a.eng.DiscoverSentryComponentKeysWithHostKeyApproval(ctx, endpoint, approve)
	if err != nil {
		switch {
		case errors.Is(err, engine.ErrSentryDiscoveryLocked):
			return result, fmt.Errorf("connected and authenticated; sentry is locked; unlock it in apadmin and rerun: %w", err)
		case errors.Is(err, engine.ErrSentryDiscoveryAuth) && !result.TokenIssued:
			return result, fmt.Errorf("stored token for endpoint %q was rejected; run request-token --endpoint %s to re-enroll: %w", plan.Alias, plan.Alias, err)
		default:
			return result, err
		}
	}
	matches := 0
	for _, key := range keys {
		if key.ComponentKey == plan.Witness.WitnessKeyID && key.KeyType == plan.Witness.KeyType && key.PublicKey == plan.Witness.PublicKeyHex {
			matches++
		}
	}
	if matches != 1 {
		return result, fmt.Errorf("endpoint %q does not advertise the expected Witness Key ID %s", plan.Alias, plan.Witness.WitnessKeyID)
	}
	result.Verified = true
	return result, nil
}

func (a *App) requestSentryTokenIsolated(ctx context.Context, alias string, endpoint config.ClientEndpointConfig, approve sshtunnel.HostKeyApprovalHandler, onProvisioningStarted func()) error {
	endpointSSH, err := config.ResolveClientEndpointSSH(endpoint)
	if err != nil {
		return err
	}
	token, err := a.eng.Connection.RequestTokenWithContext(ctx, endpointSSH.Host, endpointSSH.Port, endpointSSH.IdentityFile, endpointSSH.KnownHostsPath, approve, onProvisioningStarted)
	if err != nil {
		return fmt.Errorf("request token from endpoint %q: %w", alias, err)
	}
	if _, err := a.eng.SaveApshellTokenToPath(endpointSSH.TokenFile, token); err != nil {
		return fmt.Errorf("save token for endpoint %q: %w", alias, err)
	}
	return nil
}
