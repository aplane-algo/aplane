// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package guarded

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/signerclient"
)

// NodeRoleCosigner is the node role a cosigner endpoint reports in /status.
const NodeRoleCosigner = "cosigner"

// EndpointInspection is one authenticated setup-time observation of a
// configured endpoint.
type EndpointInspection struct {
	// NodeRole is the role the node reported in /status. It is empty when the
	// node did not report one.
	NodeRole string
	// Keys is the advertised cosigner key inventory. It is read only when
	// NodeRole is NodeRoleCosigner.
	Keys []DiscoveredCosignerComponentKey
}

// InspectCosignerEndpoint opens one isolated connection to endpoint, reads the
// node role, and reads the cosigner key inventory only from a node that
// reports the cosigner role. Sweeps never check the role; setup does, because
// an endpoint-only handoff carries nothing else that distinguishes a cosigner
// from a signer.
func (s *Signer) InspectCosignerEndpoint(ctx context.Context, endpoint config.ClientEndpointConfig) (EndpointInspection, error) {
	client, cleanup, _, err := s.connectConfiguredCosignerEndpoint(ctx, endpoint)
	if err != nil {
		return EndpointInspection{}, classifyCosignerDiscoveryConnectError(err)
	}
	if cleanup != nil {
		defer cleanup()
	}
	status, err := client.GetStatusWithContext(ctx)
	if err != nil {
		var statusErr *signerclient.HTTPStatusError
		if errors.As(err, &statusErr) && statusErr.IsLocked() {
			return EndpointInspection{}, fmt.Errorf("%w: %w", ErrCosignerDiscoveryLocked, err)
		}
		return EndpointInspection{}, classifyCosignerDiscoveryQueryError(err)
	}
	inspection := EndpointInspection{NodeRole: strings.TrimSpace(status.NodeRole)}
	if inspection.NodeRole != NodeRoleCosigner {
		return inspection, nil
	}
	keys, err := client.GetKeysWithContext(ctx)
	if err != nil {
		return inspection, classifyCosignerDiscoveryQueryError(err)
	}
	if keys.Locked {
		return inspection, fmt.Errorf("%w", ErrCosignerDiscoveryLocked)
	}
	inspection.Keys, err = discoverCosignerComponentKeys(keys.Keys)
	if err != nil {
		return inspection, err
	}
	return inspection, nil
}
