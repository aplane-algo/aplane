// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package aplane

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// SignerClient is the client for connecting to apsignerd.
type SignerClient struct {
	baseURL   string
	token     string
	client    *http.Client
	sshTunnel *sshTunnel
	keyCache  map[string]*KeyInfo
}

// ConnectLocal creates a client connected to a local signer.
func ConnectLocal(token string, opts *ConnectOptions) *SignerClient {
	host := "localhost"
	port := DefaultSignerPort
	timeout := DefaultTimeout

	if opts != nil {
		if opts.Host != "" {
			host = opts.Host
		}
		if opts.Port > 0 {
			port = opts.Port
		}
		if opts.Timeout > 0 {
			timeout = opts.Timeout
		}
	}

	return &SignerClient{
		baseURL: fmt.Sprintf("http://%s:%d", host, port),
		token:   token,
		client:  &http.Client{Timeout: time.Duration(timeout) * time.Second},
	}
}

// ConnectSSH creates a client connected via SSH tunnel.
func ConnectSSH(host, token, sshKeyPath string, opts *SSHConnectOptions) (*SignerClient, error) {
	sshPort := DefaultSSHPort
	signerPort := DefaultSignerPort
	timeout := DefaultTimeout

	if opts != nil {
		if opts.SSHPort > 0 {
			sshPort = opts.SSHPort
		}
		if opts.SignerPort > 0 {
			signerPort = opts.SignerPort
		}
		if opts.Timeout > 0 {
			timeout = opts.Timeout
		}
	}

	tunnel := &sshTunnel{}
	localPort, err := tunnel.connect(host, sshPort, signerPort, token, ExpandPath(sshKeyPath))
	if err != nil {
		return nil, fmt.Errorf("failed to establish SSH tunnel: %w", err)
	}

	return &SignerClient{
		baseURL:   fmt.Sprintf("http://localhost:%d", localPort),
		token:     token,
		client:    &http.Client{Timeout: time.Duration(timeout) * time.Second},
		sshTunnel: tunnel,
	}, nil
}

// FromEnv creates a client from environment configuration.
// Reads token from dataDir/aplane.token and config from dataDir/config.yaml.
// If config contains SSH settings, connects via SSH tunnel.
func FromEnv(opts *FromEnvOptions) (*SignerClient, error) {
	dataDir := ""
	timeout := DefaultTimeout

	if opts != nil {
		if opts.DataDir != "" {
			dataDir = opts.DataDir
		}
		if opts.Timeout > 0 {
			timeout = opts.Timeout
		}
	}

	dataDir = ResolveDataDir(dataDir)

	// Load token
	token, err := LoadTokenFromDir(dataDir)
	if err != nil {
		return nil, err
	}

	// Load config
	config, err := LoadConfig(dataDir)
	if err != nil {
		return nil, err
	}

	// Connect via SSH if configured
	if config.SSH != nil && config.SSH.Host != "" {
		sshKeyPath := filepath.Join(dataDir, config.SSH.IdentityFile)
		return ConnectSSH(config.SSH.Host, token, sshKeyPath, &SSHConnectOptions{
			SSHPort:    config.SSH.Port,
			SignerPort: config.SignerPort,
			Timeout:    timeout,
		})
	}

	// Connect locally
	return ConnectLocal(token, &ConnectOptions{
		Port:    config.SignerPort,
		Timeout: timeout,
	}), nil
}

// Close closes the client and any SSH tunnel.
func (c *SignerClient) Close() {
	if c.sshTunnel != nil {
		c.sshTunnel.close()
	}
}

// Health checks if the signer is reachable.
func (c *SignerClient) Health() (bool, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/health", nil)
	if err != nil {
		return false, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return false, nil // Not reachable
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200, nil
}

// ListKeys returns all available signing keys.
func (c *SignerClient) ListKeys(refresh bool) ([]KeyInfo, error) {
	if !refresh && c.keyCache != nil {
		keys := make([]KeyInfo, 0, len(c.keyCache))
		for _, k := range c.keyCache {
			keys = append(keys, *k)
		}
		return keys, nil
	}

	req, err := http.NewRequest("GET", c.baseURL+"/keys", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "aplane "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, ErrAuthentication
	}
	if resp.StatusCode == 403 {
		return nil, ErrSignerLocked
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("signer error (%d): %s", resp.StatusCode, string(body))
	}

	var keysResp keysResponse
	if err := json.NewDecoder(resp.Body).Decode(&keysResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Update cache
	c.keyCache = make(map[string]*KeyInfo)
	for i := range keysResp.Keys {
		k := &keysResp.Keys[i]
		c.keyCache[k.Address] = k
	}

	return keysResp.Keys, nil
}

// GetKeyInfo returns info for a specific key address.
func (c *SignerClient) GetKeyInfo(address string) (*KeyInfo, error) {
	if c.keyCache == nil {
		if _, err := c.ListKeys(true); err != nil {
			return nil, err
		}
	}
	if k, ok := c.keyCache[address]; ok {
		return k, nil
	}
	return nil, nil
}

// SignTransaction signs a single transaction.
// Returns the signed transaction as base64.
func (c *SignerClient) SignTransaction(txn types.Transaction, authAddress string, lsigArgs LsigArgs) (string, error) {
	signed, err := c.SignTransactions([]types.Transaction{txn}, []string{authAddress}, lsigArgsToMap(authAddress, lsigArgs))
	return signed, err
}

// SignTransactions signs multiple transactions as a group.
// Returns concatenated signed transactions as base64.
func (c *SignerClient) SignTransactions(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap) (string, error) {
	requests := make([]SignRequest, len(txns))

	for i, txn := range txns {
		// Encode transaction
		txnBytes := encodeTxn(txn)
		txnBytesHex := hex.EncodeToString(txnBytes)

		// Determine auth address
		authAddr := txn.Sender.String()
		if i < len(authAddresses) && authAddresses[i] != "" {
			authAddr = authAddresses[i]
		}

		// Build request
		req := SignRequest{
			AuthAddress: authAddr,
			TxnSender:   txn.Sender.String(),
			TxnBytesHex: txnBytesHex,
		}

		// Add lsig args if present
		if lsigArgsMap != nil {
			if args, ok := lsigArgsMap[authAddr]; ok {
				req.LsigArgs = make(map[string]string)
				for name, value := range args {
					req.LsigArgs[name] = hex.EncodeToString(value)
				}
			}
		}

		requests[i] = req
	}

	return c.sign(requests)
}

// SignTransactionsList signs transactions and returns individual base64 strings.
func (c *SignerClient) SignTransactionsList(txns []types.Transaction, authAddresses []string, lsigArgsMap LsigArgsMap) ([]string, error) {
	// For now, sign as group and return as single item
	// TODO: parse individual transactions from response
	signed, err := c.SignTransactions(txns, authAddresses, lsigArgsMap)
	if err != nil {
		return nil, err
	}
	return []string{signed}, nil
}

// sign performs the actual signing request.
func (c *SignerClient) sign(requests []SignRequest) (string, error) {
	groupReq := groupSignRequest{Requests: requests}

	jsonBody, err := json.Marshal(groupReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", c.baseURL+"/sign", bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "aplane "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return "", ErrAuthentication
	}
	if resp.StatusCode == 403 {
		return "", ErrSigningRejected
	}
	if resp.StatusCode == 503 {
		return "", ErrSignerUnavailable
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("signer error (%d): %s", resp.StatusCode, string(body))
	}

	var groupResp GroupSignResponse
	if err := json.NewDecoder(resp.Body).Decode(&groupResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if groupResp.Error != "" {
		return "", fmt.Errorf("signing failed: %s", groupResp.Error)
	}

	// Concatenate signed transactions and convert to base64
	return hexArrayToBase64(groupResp.Signed)
}

// lsigArgsToMap converts single LsigArgs to LsigArgsMap.
func lsigArgsToMap(authAddress string, args LsigArgs) LsigArgsMap {
	if args == nil {
		return nil
	}
	return LsigArgsMap{authAddress: args}
}
