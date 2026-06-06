// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

// connectTunnelWithKey establishes an SSH tunnel using public key authentication.
// SSH prompts and host trust remain in the shell; connection orchestration lives in apshellapp.
func connectTunnelWithKey(r *REPLState, host string, sshPort, signerPort int) error {
	if r.Config.LegacySSH == nil {
		return fmt.Errorf("SSH defaults are not configured; use 'connect <endpoint-alias>' with an endpoints.yaml profile")
	}

	// Build TOFU callback (UI concern - stays in REPL)
	hostKeyApproval := buildHostKeyApproval(r)

	r.printf("Connecting to SSH server at %s:%d...\n", host, sshPort)
	r.println("Using SSH public key authentication...")

	result, err := r.app().Connect(r.commandContext(), apshellapp.ConnectRequest{
		Host:            host,
		SSHPort:         sshPort,
		SignerPort:      signerPort,
		IdentityFile:    r.Config.LegacySSH.IdentityFile,
		KnownHostsPath:  r.Config.LegacySSH.KnownHostsPath,
		HostKeyApproval: hostKeyApproval,
		OnDisconnect: func() {
			r.println("⚠️  Disconnected from signer")
			r.print("> ")
		},
	})
	if err != nil {
		return err
	}

	if result.AlreadyConnected {
		return r.renderConnectResult(result)
	}

	if err := r.renderConnectResult(result); err != nil {
		return err
	}
	return nil
}

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
	registry := r.Config.ClientEndpointsOrDefault(r.DataDir)
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

// requestToken connects to the SSH server and requests a token provisioning.
// The token is saved to the local token file if approved.
func requestToken(r *REPLState, host string, sshPort int) error {
	// Disconnect if currently connected (old token will be invalid after provisioning)
	if r.app().IsTunnelConnected() {
		r.println("Disconnecting current session...")
		_ = disconnectTunnel(r)
	}

	r.printf("Requesting token from %s (SSH port: %d)...\n", host, sshPort)
	r.println("This requires an operator (apadmin) to approve on the server.")
	r.println()

	if r.Config.LegacySSH == nil {
		return fmt.Errorf("SSH defaults are not configured; use 'request-token --endpoint <alias>' with an endpoints.yaml profile")
	}

	hostKeyApproval := buildHostKeyApproval(r)

	result, err := r.app().RequestToken(r.commandContext(), apshellapp.RequestTokenRequest{
		Host:                  host,
		SSHPort:               sshPort,
		IdentityFile:          r.Config.LegacySSH.IdentityFile,
		KnownHostsPath:        r.Config.LegacySSH.KnownHostsPath,
		HostKeyApproval:       hostKeyApproval,
		OnProvisioningStarted: r.printTokenProvisioningWait,
	})
	if err != nil {
		return err
	}

	for _, line := range result.RenderLines {
		r.println(line)
	}
	r.println("Connecting to signer with new token...")
	return connectTunnelWithKey(r, host, sshPort, r.Config.LegacySignerPort)
}

func requestTokenConfigured(r *REPLState) error {
	registry := r.Config.ClientEndpointsOrDefault(r.DataDir)
	alias, endpoint, ok := registry.DefaultEndpoint()
	if !ok {
		return fmt.Errorf("usage: request-token [<host> [--ssh-port <port>]]\n\n" +
			"Request an API token from the Signer. Requires an operator\n" +
			"(apadmin) to approve the request on the server.\n" +
			"If no arguments are given, apshell uses the default signer endpoint from endpoints.yaml.\n\n" +
			"Examples:\n" +
			"  request-token\n" +
			"  request-token 192.168.1.100\n" +
			"  request-token 192.168.1.100 --ssh-port 2222")
	}

	hostKeyApproval := buildHostKeyApproval(r)
	result, err := r.app().RequestTokenEndpoint(r.commandContext(), alias, endpoint, hostKeyApproval, r.printTokenProvisioningWait)
	if err != nil {
		return err
	}

	for _, line := range result.RenderLines {
		r.println(line)
	}
	r.println("Connecting to signer with new token...")
	return connectEndpointAlias(r, alias)
}

func requestTokenEndpointAlias(r *REPLState, alias string) error {
	registry := r.Config.ClientEndpointsOrDefault(r.DataDir)
	endpoint, ok := registry.Endpoint(alias)
	if !ok {
		return fmt.Errorf("unknown endpoint alias %q", alias)
	}
	defaultAlias, _, _ := registry.DefaultEndpoint()

	if alias == defaultAlias && r.app().IsTunnelConnected() {
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
	if alias == defaultAlias {
		r.println("Connecting to signer with new token...")
		return connectEndpointAlias(r, alias)
	}
	return nil
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
