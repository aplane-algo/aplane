// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"github.com/aplane-algo/aplane/internal/util"
)

// checkAlreadyConnected checks if already connected to target
func (r *REPLState) checkAlreadyConnected(target string) (bool, error) {
	if r.Engine.SignerClient != nil {
		if r.Engine.GetConnectionTarget() == target {
			// Already connected to same target
			return true, nil
		}
		// Connected to different target
		return false, fmt.Errorf("already connected to Signer at %s. Restart apshell to connect to a different target", r.Engine.GetConnectionTarget())
	}
	// Not connected
	return false, nil
}

// clearConnectionState clears all connection-related state
func (r *REPLState) clearConnectionState() {
	r.Engine.SetSSHTunnelClient(nil)
	r.Engine.SetTunnelConnected(false)
	r.Engine.SignerClient = nil
	r.Engine.SetConnectionTarget("")
	r.Engine.SignerCache = util.NewSignerCache()
	r.Engine.SignerCache.SetColorFormatter(algorithm.GetDisplayColor)
}

// connectTunnelWithKey establishes an SSH tunnel using public key authentication.
func (r *REPLState) connectTunnelWithKey(host string, sshPort, signerPort int) error {
	// Build target string for display/tracking
	target := fmt.Sprintf("%s (ssh:%d, signer:%d)", host, sshPort, signerPort)

	// Check if already connected to the same target
	alreadyConnected, err := r.checkAlreadyConnected(target)
	if err != nil {
		return err
	}
	if alreadyConnected {
		fmt.Printf("Already connected to %s\n", target)
		return nil
	}

	// Load API token for HTTP requests and SSH key registration
	token, _ := util.LoadApshellToken()
	if token == "" {
		return fmt.Errorf("no token configured.\nRun 'request-token' to obtain a token, or copy aplane.token to %s", getTokenPathDescription())
	}

	// Find an available local port for the tunnel
	localPort, err := findAvailablePort()
	if err != nil {
		return fmt.Errorf("failed to find available local port: %w", err)
	}

	// Create SSH tunnel client using paths from config
	// SSH config is required - paths are already resolved to absolute by LoadConfig
	if r.Config.SSH == nil {
		return fmt.Errorf("SSH not configured. Add an 'ssh:' block to config.yaml with identity_file and known_hosts_path")
	}
	client := sshtunnel.NewClient(host, sshPort, localPort, signerPort, r.Config.SSH.IdentityFile, r.Config.SSH.KnownHostsPath)

	// Set API token for authenticating new key registration
	// This allows the server to verify the client has the correct token before registering SSH keys
	client.SetAPIToken(token)

	// Set up TOFU host key approval handler
	client.SetHostKeyApprovalHandler(func(host string, fingerprint string) (bool, error) {
		fmt.Printf("Do you want to trust this server? [y/N]: ")
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return false, err
		}
		response = strings.TrimSpace(strings.ToLower(response))
		return response == "y" || response == "yes", nil
	})

	// Set up disconnect callback to detect when Signer dies
	client.SetDisconnectCallback(func() {
		// Close the SSH tunnel (listener + SSH connection)
		if tunnelClient := r.Engine.GetSSHTunnelClient(); tunnelClient != nil {
			_ = tunnelClient.Close() // Best-effort close, already disconnecting
		}
		r.clearConnectionState()
		fmt.Println("\n⚠️  SSH tunnel disconnected (server may have died)")
		fmt.Print("> ") // Show prompt again
	})

	// Create context for connection
	ctx := context.Background()

	fmt.Printf("Connecting to SSH server at %s:%d...\n", host, sshPort)
	fmt.Println("Using SSH public key authentication...")

	if err := client.ConnectWithKey(ctx); err != nil {
		return fmt.Errorf("SSH auth failed: %w", err)
	}

	// Start port forwarding
	if err := client.StartPortForwarding(ctx); err != nil {
		_ = client.Close() // Best-effort close on error path
		return fmt.Errorf("failed to start port forwarding: %w", err)
	}

	// Wait a moment for tunnel to establish
	time.Sleep(1 * time.Second)

	// Create client and verify token by fetching keys
	signerClient := util.NewSignerClientWithToken(fmt.Sprintf("http://localhost:%d", localPort), token)

	// Verify connection and token by fetching keys (requires auth)
	keysResp, err := signerClient.GetKeys("")
	if err != nil {
		_ = client.Close()
		// Check for auth failure specifically
		if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "Invalid token") {
			tokenPath, _ := util.GetApshellTokenPath()
			return fmt.Errorf("authentication failed: token mismatch\n\nYour token at %s does not match the server's token.\nCopy the correct token from Signer's aplane.token file", tokenPath)
		}
		return fmt.Errorf("failed to verify connection: %w", err)
	}

	// Connection and auth verified, set up state
	r.Engine.SignerClient = signerClient
	r.Engine.SetConnectionTarget(target)
	r.Engine.SetSSHTunnelClient(client)
	r.Engine.SetTunnelConnected(true)
	tunnelCtx, tunnelCancel := context.WithCancel(context.Background())
	r.Engine.SetTunnelContext(tunnelCtx, tunnelCancel)

	// Set up signer cache from the keys we already fetched
	r.Engine.SignerCache = util.NewSignerCache()
	r.populateSignerCacheFromKeys(keysResp.Keys)
	r.Engine.SignerCache.SetColorFormatter(algorithm.GetDisplayColor)

	fmt.Println("✓ SSH tunnel established via public key")
	fmt.Printf("✓ Signer verified via tunnel at http://localhost:%d\n", localPort)
	if keysResp.Locked {
		fmt.Println("⚠️  Signer is locked — unlock via apadmin before signing")
	} else if keysResp.Count > 0 {
		fmt.Printf("✓ Loaded %d signing key(s)\n", keysResp.Count)
	}
	return nil
}

// findAvailablePort finds an available local port for the tunnel
func findAvailablePort() (int, error) {
	// Let the OS assign an available port by listening on :0
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = listener.Close() }()

	// Get the assigned port
	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

// connectDirect connects directly to Signer (for localhost only, no SSH tunnel)
func (r *REPLState) connectDirect(hostPort string) error {
	// Check if already connected to the same target
	alreadyConnected, err := r.checkAlreadyConnected(hostPort)
	if err != nil {
		return err
	}
	if alreadyConnected {
		fmt.Printf("Already connected to %s\n", hostPort)
		return nil
	}

	// Load auth token
	token, err := util.LoadApshellToken()
	if err != nil {
		return fmt.Errorf("failed to load auth token: %w", err)
	}
	if token == "" {
		return fmt.Errorf("no token configured.\nRun 'request-token' to obtain a token, or copy aplane.token to %s", getTokenPathDescription())
	}

	baseURL := fmt.Sprintf("http://%s", hostPort)

	// Create client with token
	signerClient := util.NewSignerClientWithToken(baseURL, token)

	// Verify connection and token by fetching keys (requires auth)
	keysResp, err := signerClient.GetKeys("")
	if err != nil {
		// Check for auth failure specifically
		if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "Invalid token") {
			tokenPath, _ := util.GetApshellTokenPath()
			return fmt.Errorf("authentication failed: token mismatch\n\nYour token at %s does not match the server's token.\nCopy the correct token from Signer's aplane.token file", tokenPath)
		}
		return fmt.Errorf("failed to connect: %w", err)
	}

	// Connection and auth verified, set up state
	r.Engine.SignerClient = signerClient
	r.Engine.SetConnectionTarget(hostPort)

	// Set up signer cache from the keys we already fetched
	r.Engine.SignerCache = util.NewSignerCache()
	r.populateSignerCacheFromKeys(keysResp.Keys)
	r.Engine.SignerCache.SetColorFormatter(algorithm.GetDisplayColor)

	fmt.Printf("✓ Signer verified at %s\n", baseURL)
	if keysResp.Locked {
		fmt.Println("⚠️  Signer is locked — unlock via apadmin before signing")
	} else if keysResp.Count > 0 {
		fmt.Printf("✓ Loaded %d signing key(s)\n", keysResp.Count)
	}
	return nil
}

// disconnectTunnel closes the SSH tunnel connection
func (r *REPLState) disconnectTunnel() error {
	tunnelClient := r.Engine.GetSSHTunnelClient()
	if tunnelClient == nil {
		return nil // Already disconnected
	}

	fmt.Println("Closing SSH tunnel...")

	// Cancel context to signal clean shutdown to monitor goroutine
	_, tunnelCancel := r.Engine.GetTunnelContext()
	if tunnelCancel != nil {
		tunnelCancel()
	}

	// Close the SSH tunnel client
	if tunnelClient != nil {
		_ = tunnelClient.Close() // Best-effort close, already disconnecting
	}

	// Clear state
	r.clearConnectionState()

	fmt.Println("✓ Tunnel disconnected")
	return nil
}

// checkLocalhostConnection does a quick port check for localhost connections
// (SSH tunnel connections have their own disconnect callback)
// Returns true if connected, false if disconnected
func (r *REPLState) checkLocalhostConnection() bool {
	client := r.Engine.SignerClient
	isTunnel := r.Engine.IsTunnelConnected()
	target := r.Engine.GetConnectionTarget()

	// No client or using SSH tunnel (which has its own detection)
	if client == nil || isTunnel {
		return client != nil
	}

	// Quick TCP check for localhost connection
	conn, err := net.DialTimeout("tcp", target, 100*time.Millisecond)
	if err != nil {
		// Server is down - clear connection state
		r.clearConnectionState()
		fmt.Println("⚠️  Signer connection lost. Use 'connect' to reconnect.")
		return false
	}
	_ = conn.Close()
	return true
}

// requestToken connects to the SSH server and requests a token provisioning.
// The token is saved to the local token file if approved.
func (r *REPLState) requestToken(host string, sshPort int) error {
	fmt.Printf("Requesting token from %s (SSH port: %d)...\n", host, sshPort)
	fmt.Println("This requires an operator (apadmin) to approve on the server.")
	fmt.Println()

	// Create SSH client for token request using paths from config
	// SSH config is required - paths are already resolved to absolute by LoadConfig
	if r.Config.SSH == nil {
		return fmt.Errorf("SSH not configured. Add an 'ssh:' block to config.yaml with identity_file and known_hosts_path")
	}
	client := sshtunnel.NewClient(host, sshPort, 0, 0, r.Config.SSH.IdentityFile, r.Config.SSH.KnownHostsPath)

	// Set up TOFU host key approval handler
	client.SetHostKeyApprovalHandler(func(host string, fingerprint string) (bool, error) {
		fmt.Printf("Do you want to trust this server? [y/N]: ")
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return false, err
		}
		response = strings.TrimSpace(strings.ToLower(response))
		return response == "y" || response == "yes", nil
	})

	// Request the token (this blocks until operator approves or rejects)
	fmt.Println("Waiting for operator approval...")
	ctx := context.Background()
	token, err := client.RequestToken(ctx, "default")
	if err != nil {
		return fmt.Errorf("token request failed: %w", err)
	}

	// Save the token
	tokenPath, err := util.GetApshellTokenPath()
	if err != nil {
		return fmt.Errorf("failed to get token path: %w", err)
	}
	if err := util.WriteToken(tokenPath, token); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	fmt.Printf("✓ Token received and saved to %s\n", tokenPath)
	fmt.Println("You can now use 'connect' to connect to the Signer.")
	return nil
}

// populateSignerCacheFromKeys populates the signer cache with key info from the /keys response.
// This extracts key types, bytecode sizes (for budget calculation), generic LSig markers,
// and runtime args schema for generic LogicSigs.
func (r *REPLState) populateSignerCacheFromKeys(keys []util.KeyInfo) {
	for _, keyInfo := range keys {
		r.Engine.SignerCache.Keys[keyInfo.Address] = keyInfo.KeyType

		// Populate total LSig size for budget calculation
		if keyInfo.LsigSize > 0 {
			r.Engine.SignerCache.SetLsigSize(keyInfo.Address, keyInfo.LsigSize)
		}

		// Mark generic LSigs (no crypto signature needed)
		if keyInfo.IsGenericLsig {
			r.Engine.SignerCache.SetGenericLsig(keyInfo.Address, true)
		}

		// Store runtime args schema for generic LogicSigs (enables client-side validation)
		if len(keyInfo.RuntimeArgs) > 0 {
			r.Engine.SignerCache.SetRuntimeArgs(keyInfo.Address, keyInfo.RuntimeArgs)
		}
	}
}

// getTokenPathDescription returns a user-friendly description of where the token file should be placed.
// Shows the environment variable name if APCLIENT_DATA is set, otherwise shows the default path.
func getTokenPathDescription() string {
	if envDir := os.Getenv("APCLIENT_DATA"); envDir != "" {
		return fmt.Sprintf("$APCLIENT_DATA/aplane.token (%s/aplane.token)", envDir)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "~/.apclient/aplane.token"
	}
	return fmt.Sprintf("%s/.apclient/aplane.token", home)
}
