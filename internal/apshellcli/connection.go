// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

func connectConfigured(r *REPLState) error {
	hostKeyApproval := buildHostKeyApproval(r)

	r.println("Using SSH public key authentication...")

	result, err := r.app().ConnectConfigured(r.commandContext(), hostKeyApproval, func() {
		r.println("⚠️  Disconnected from signer")
		r.print("> ")
	})
	if err != nil {
		return err
	}
	return r.renderConnectResult(result)
}

func connectEndpointAlias(r *REPLState, alias string) error {
	registry := r.Config.ClientEndpointsOrDefault()
	endpoint, ok := registry.Endpoint(alias)
	if !ok {
		return fmt.Errorf("unknown endpoint alias %q", alias)
	}
	hostKeyApproval := buildHostKeyApproval(r)

	r.printf("Connecting to endpoint %s...\n", alias)
	r.println("Using SSH public key authentication...")

	result, err := r.app().ConnectEndpoint(r.commandContext(), alias, endpoint, hostKeyApproval, func() {
		r.println("⚠️  Disconnected from signer")
		r.print("> ")
	})
	if err != nil {
		return err
	}
	return r.renderConnectResult(result)
}

func (r *REPLState) cmdDisconnect(args []string, _ interface{}) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: disconnect")
	}
	return disconnectTunnel(r)
}

// disconnectTunnel closes the SSH tunnel connection and reports the shell-visible result.
func disconnectTunnel(r *REPLState) error {
	if r.app().IsTunnelConnected() {
		r.println("Closing SSH tunnel...")
	}
	res, err := r.app().Disconnect(r.commandContext())
	if err != nil {
		return err
	}
	if res.WasConnected {
		r.println("✓ Tunnel disconnected")
	}
	return nil
}

func requestTokenConfigured(r *REPLState) error {
	registry := r.Config.ClientEndpointsOrDefault()
	alias, _, ok := registry.DefaultEndpoint()
	if !ok {
		return fmt.Errorf("no default signer endpoint in endpoints.yaml; import or configure a signer endpoint before running request-token")
	}
	return requestTokenEndpointAlias(r, alias)
}

func requestTokenEndpointAlias(r *REPLState, alias string) error {
	registry := r.Config.ClientEndpointsOrDefault()
	endpoint, ok := registry.Endpoint(alias)
	if !ok {
		return fmt.Errorf("unknown endpoint alias %q", alias)
	}
	autoConnect := shouldAutoConnectAfterEnrollment(registry, alias)

	if autoConnect && r.app().IsTunnelConnected() {
		r.println("Disconnecting current session...")
		_ = disconnectTunnel(r)
	}

	r.printf("Requesting token from endpoint %s...\n", alias)
	r.println("This requires an operator (apadmin) to approve on the server.")
	r.println()

	hostKeyApproval := buildHostKeyApproval(r)
	result, err := r.app().RequestTokenEndpoint(r.commandContext(), alias, endpoint, hostKeyApproval, r.printTokenProvisioningWait)
	if err != nil {
		return err
	}
	for _, line := range result.RenderLines {
		r.println(line)
	}
	if autoConnect {
		r.println("Connecting to signer with new token...")
		return connectEndpointAlias(r, alias)
	}
	return nil
}

func shouldAutoConnectAfterEnrollment(registry config.ClientEndpointRegistry, alias string) bool {
	defaultAlias, defaultEndpoint, ok := registry.DefaultEndpoint()
	return ok && alias == defaultAlias && defaultEndpoint.Role == config.ClientEndpointRoleSigner
}

func (r *REPLState) printTokenProvisioningWait() {
	r.progressPrintln("Waiting for operator approval in apadmin...")
	r.progressPrintln("Leave this shell open while the operator approves or rejects the token request.")
}

// buildHostKeyApproval returns a TOFU host key approval handler for SSH connections.
// In auto-confirm mode, unknown hosts are rejected. If a custom HostKeyApproval
// handler is set on the REPLState (e.g. by a TUI host), it is used instead of
// prompting via stdin. Otherwise the user is prompted interactively.
func buildHostKeyApproval(r *REPLState) sshtunnel.HostKeyApprovalHandler {
	return func(host string, fingerprint string) (bool, error) {
		if r.AutoConfirm {
			return false, fmt.Errorf("unknown SSH host key (fingerprint: %s). Connect via interactive apshell first to verify and trust this host", fingerprint)
		}
		if r.HostKeyApproval != nil {
			return r.HostKeyApproval(host, fingerprint)
		}
		response, err := r.readPromptResponse("Do you want to trust this server? [y/N]: ")
		if err != nil {
			return false, err
		}
		return response == "y" || response == "yes", nil
	}
}
