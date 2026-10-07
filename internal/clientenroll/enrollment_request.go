// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientenroll

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

// EnrollmentClient is the client-owned seam for asking a node to enroll this
// client's SSH key. The engine implementation disconnects an existing tunnel
// to the same node before requesting enrollment.
type EnrollmentClient interface {
	RequestEnrollmentWithContext(
		ctx context.Context,
		host string,
		sshPort int,
		identityFile string,
		knownHostsPath string,
		label string,
		hostKeyApproval sshtunnel.HostKeyApprovalHandler,
		onEnrollmentStart func(string),
	) (connect.EnrollmentResult, error)
}

// EnrollmentResult describes one endpoint-scoped enrollment request.
type EnrollmentResult struct {
	Alias       string
	Fingerprint string
	// Pending reports that the request now waits for the node's operator;
	// otherwise the key was already enrolled there.
	Pending bool
}

// RequestEndpointEnrollment submits an SSH request-enrollment to one
// endpoint and returns at once. Nothing is stored on the client: its key is
// its credential, and the node records the request for its operator.
func RequestEndpointEnrollment(
	ctx context.Context,
	client EnrollmentClient,
	alias string,
	endpoint config.ClientEndpointConfig,
	label string,
	hostKeyApproval sshtunnel.HostKeyApprovalHandler,
	onEnrollmentStart func(string),
) (EnrollmentResult, error) {
	if client == nil {
		return EnrollmentResult{}, fmt.Errorf("enrollment client is unavailable")
	}
	if alias == "" {
		return EnrollmentResult{}, fmt.Errorf("endpoint alias is required")
	}
	endpointSSH, err := config.ResolveClientEndpointSSH(endpoint)
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("resolve endpoint %q SSH configuration: %w", alias, err)
	}
	result, err := client.RequestEnrollmentWithContext(
		ctx,
		endpointSSH.Host,
		endpointSSH.Port,
		endpointSSH.IdentityFile,
		endpointSSH.KnownHostsPath,
		label,
		hostKeyApproval,
		onEnrollmentStart,
	)
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("request enrollment from endpoint %q: %w", alias, err)
	}
	return EnrollmentResult{Alias: alias, Fingerprint: result.Fingerprint, Pending: result.Pending}, nil
}
