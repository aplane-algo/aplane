// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"
	"io"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

func executeConnectConfigured(r *REPLState) (*apshellapp.ConnectResult, error) {
	hostKeyApproval := buildHostKeyApproval(r)
	return r.app().ConnectConfigured(r.commandContext(), hostKeyApproval, func() {
		r.println("⚠️  Disconnected from signer")
		r.print("> ")
	})
}

// connectConfigured is the startup/interactive lifecycle wrapper. Registered
// command execution uses the result-bearing cmdConnect path instead.
func connectConfigured(r *REPLState) error {
	r.println("Using SSH public key authentication...")
	result, err := executeConnectConfigured(r)
	if err != nil {
		return err
	}
	return r.renderConnectResult(result)
}

func executeConnectEndpointAlias(r *REPLState, alias string) (*apshellapp.ConnectResult, error) {
	hostKeyApproval := buildHostKeyApproval(r)
	return r.app().ConnectEndpointAlias(r.commandContext(), alias, hostKeyApproval, func() {
		r.println("⚠️  Disconnected from signer")
		r.print("> ")
	})
}

func (r *REPLState) cmdDisconnect(args []string, _ interface{}) (command.Result, error) {
	if len(args) != 0 {
		return nil, fmt.Errorf("usage: disconnect")
	}
	wasConnected := r.app().IsTunnelConnected()
	result, err := r.app().Disconnect(r.commandContext())
	if err != nil {
		return nil, err
	}
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() {
			if wasConnected {
				r.println("Closing SSH tunnel...")
			}
			if result.WasConnected {
				r.println("✓ Tunnel disconnected")
			}
		})
	}, disconnectProjection{WasConnected: result.WasConnected})
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

// requestEnrollment asks alias, or the default signer endpoint when alias is
// empty, to enroll this client's SSH key.
func requestEnrollment(r *REPLState, alias, label string) error {
	target, err := r.app().ResolveEnrollmentTarget(alias)
	if err != nil {
		return err
	}
	alias = target.Alias

	r.printf("Requesting enrollment at endpoint %s...\n", alias)
	r.println("The node's operator approves the request later in apadmin; this command returns at once.")
	r.println()

	hostKeyApproval := buildHostKeyApproval(r)
	result, err := r.app().RequestEnrollmentEndpointAlias(r.commandContext(), alias, label, hostKeyApproval, r.printEnrollmentWait)
	if err != nil {
		return err
	}
	for _, line := range result.RenderLines {
		r.println(line)
	}
	if target.AutoConnect && !result.Pending {
		// The key is enrolled now, so the session is replaced with one that
		// uses it. A pending request leaves the current session untouched:
		// nothing could follow it until the operator approves.
		if r.app().IsTunnelConnected() {
			r.println("Disconnecting current session...")
			_ = disconnectTunnel(r)
		}
		r.println("Connecting to signer with the enrolled key...")
		connectResult, err := executeConnectEndpointAlias(r, alias)
		if err != nil {
			return err
		}
		return r.renderConnectResult(connectResult)
	}
	return nil
}

func (r *REPLState) printEnrollmentWait(clientFingerprint string) {
	r.progressPrintln("Client SSH key fingerprint: " + clientFingerprint)
	r.progressPrintln("The operator compares this complete fingerprint with the enrollment request in apadmin before approving it.")
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
		if r.HostKeyApprovalContext != nil {
			return r.HostKeyApprovalContext(r.commandContext(), host, fingerprint)
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
