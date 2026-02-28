// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/transport"
	"github.com/aplane-algo/aplane/internal/util"
)

// BatchClient wraps transport.Transport with apadmin-specific operations.
type BatchClient struct {
	transport transport.Transport
	config    util.ServerConfig
	serverURL string
	apiToken  string
}

// NewBatchClient creates a new batch client.
func NewBatchClient(config util.ServerConfig, serverURL, apiToken string) *BatchClient {
	return &BatchClient{
		config:    config,
		serverURL: serverURL,
		apiToken:  apiToken,
	}
}

// Connect establishes the connection via IPC.
func (c *BatchClient) Connect() error {
	ipcClient := transport.NewIPC(c.config.IPCPath)
	if err := ipcClient.Dial(); err != nil {
		return fmt.Errorf("IPC connection failed: %w", err)
	}
	c.transport = ipcClient
	return nil
}

// Authenticate performs the IPC authentication handshake.
func (c *BatchClient) Authenticate(passphrase string) error {
	return c.transport.Authenticate(passphrase, 10*time.Second)
}

// Close closes the connection.
func (c *BatchClient) Close() {
	if c.transport != nil {
		c.transport.Close()
	}
}

// WaitForStatus waits for the initial status message.
func (c *BatchClient) WaitForStatus(timeout time.Duration) (*protocol.StatusMessage, error) {
	return c.transport.WaitForStatus(timeout)
}

// SendAndReceive sends a message and waits for response.
func (c *BatchClient) SendAndReceive(msg interface{}, timeout time.Duration) ([]byte, error) {
	return c.transport.SendAndReceive(msg, timeout)
}

// Unlock sends an unlock request.
func (c *BatchClient) Unlock(passphrase string) error {
	result, err := c.transport.Unlock(passphrase, 30*time.Second)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("unlock failed: %s", result.Error)
	}
	return nil
}

// ListKeys lists all keys.
func (c *BatchClient) ListKeys() ([]protocol.KeyInfo, error) {
	msg := protocol.ListKeysMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeListKeys,
			ID:   fmt.Sprintf("list-%d", time.Now().UnixNano()),
		},
	}

	response, err := c.SendAndReceive(msg, 30*time.Second)
	if err != nil {
		return nil, err
	}

	var result protocol.KeysListMessage
	if err := json.Unmarshal(response, &result); err != nil {
		return nil, fmt.Errorf("failed to parse keys list: %w", err)
	}

	return result.Keys, nil
}

// GenerateKey generates a new key.
func (c *BatchClient) GenerateKey(keyType string) (string, error) {
	return c.GenerateKeyWithParams(keyType, nil)
}

// GenerateKeyWithParams generates a new key with creation parameters.
func (c *BatchClient) GenerateKeyWithParams(keyType string, params map[string]string) (string, error) {
	msg := protocol.GenerateKeyMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeGenerateKey,
			ID:   fmt.Sprintf("gen-%d", time.Now().UnixNano()),
		},
		KeyType:    keyType,
		Parameters: params,
	}

	response, err := c.SendAndReceive(msg, 30*time.Second)
	if err != nil {
		return "", err
	}

	var result protocol.GenerateResultMessage
	if err := json.Unmarshal(response, &result); err != nil {
		return "", fmt.Errorf("failed to parse generate result: %w", err)
	}

	if !result.Success {
		return "", fmt.Errorf("generate failed: %s", result.Error)
	}

	return result.Address, nil
}

// ImportKey imports a key from mnemonic.
func (c *BatchClient) ImportKey(keyType, mnemonic string) (string, error) {
	return c.ImportKeyWithParams(keyType, mnemonic, nil)
}

// ImportKeyWithParams imports a key from mnemonic with creation parameters.
func (c *BatchClient) ImportKeyWithParams(keyType, mnemonic string, params map[string]string) (string, error) {
	msg := protocol.ImportKeyMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeImportKey,
			ID:   fmt.Sprintf("imp-%d", time.Now().UnixNano()),
		},
		KeyType:    keyType,
		Mnemonic:   mnemonic,
		Parameters: params,
	}

	response, err := c.SendAndReceive(msg, 30*time.Second)
	if err != nil {
		return "", err
	}

	var result protocol.ImportResultMessage
	if err := json.Unmarshal(response, &result); err != nil {
		return "", fmt.Errorf("failed to parse import result: %w", err)
	}

	if !result.Success {
		return "", fmt.Errorf("import failed: %s", result.Error)
	}

	return result.Address, nil
}

// DeleteKey deletes a key.
func (c *BatchClient) DeleteKey(address string) error {
	msg := protocol.DeleteKeyMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeDeleteKey,
			ID:   fmt.Sprintf("del-%d", time.Now().UnixNano()),
		},
		Address: address,
	}

	response, err := c.SendAndReceive(msg, 30*time.Second)
	if err != nil {
		return err
	}

	var result protocol.DeleteResultMessage
	if err := json.Unmarshal(response, &result); err != nil {
		return fmt.Errorf("failed to parse delete result: %w", err)
	}

	if !result.Success {
		return fmt.Errorf("delete failed: %s", result.Error)
	}

	return nil
}

// ExportKey exports a key's mnemonic.
func (c *BatchClient) ExportKey(address, passphrase string) (string, error) {
	msg := protocol.ExportKeyMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeExportKey,
			ID:   fmt.Sprintf("exp-%d", time.Now().UnixNano()),
		},
		Address:    address,
		Passphrase: passphrase,
	}

	response, err := c.SendAndReceive(msg, 30*time.Second)
	if err != nil {
		return "", err
	}

	var result protocol.ExportResultMessage
	if err := json.Unmarshal(response, &result); err != nil {
		return "", fmt.Errorf("failed to parse export result: %w", err)
	}

	if !result.Success {
		return "", fmt.Errorf("export failed: %s", result.Error)
	}

	return result.Mnemonic, nil
}

// runBatchMode runs apadmin in batch mode
func runBatchMode(config util.ServerConfig, serverAddr string, args []string) {
	if len(args) == 0 {
		printBatchUsage()
		os.Exit(1)
	}

	// Get passphrase from environment (used for both auth and unlock)
	passphrase := os.Getenv("TEST_PASSPHRASE")

	// Connect to server via IPC
	client := NewBatchClient(config, serverAddr, "")
	if err := client.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	// Authenticate the IPC session
	if err := client.Authenticate(passphrase); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Wait for initial status
	status, err := client.WaitForStatus(10 * time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// If signer is locked, try to unlock with TEST_PASSPHRASE or empty passphrase
	if status.State == "locked" {
		if err := client.Unlock(passphrase); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Signer is locked and could not unlock: %v\n", err)
			os.Exit(1)
		}
	}

	// Parse and execute command
	cmd := strings.ToLower(args[0])
	cmdArgs := args[1:]

	switch cmd {
	case "list":
		runBatchList(client)

	case "generate":
		runBatchGenerate(client, cmdArgs)

	case "import":
		runBatchImport(client, cmdArgs)

	case "delete":
		runBatchDelete(client, cmdArgs)

	case "export":
		runBatchExport(client, cmdArgs)

	case "unlock":
		runBatchUnlock(client)

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printBatchUsage()
		os.Exit(1)
	}
}

func runBatchList(client *BatchClient) {
	keys, err := client.ListKeys()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(keys) == 0 {
		fmt.Println("No keys found")
		return
	}

	for _, key := range keys {
		fmt.Printf("%s\t%s\n", key.Address, key.KeyType)
	}
}

func runBatchGenerate(client *BatchClient, args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: apadmin --batch generate <key-type>\n")
		fmt.Fprintf(os.Stderr, "Key types: ed25519, falcon1024-v1\n")
		os.Exit(1)
	}

	keyType := args[0]
	address, err := client.GenerateKey(keyType)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated %s key: %s\n", keyType, address)
}

func runBatchImport(client *BatchClient, args []string) {
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: apadmin --batch import <key-type> <mnemonic>\n")
		fmt.Fprintf(os.Stderr, "Key types: ed25519, falcon1024-v1\n")
		os.Exit(1)
	}

	keyType := args[0]
	mnemonic := strings.Join(args[1:], " ")

	address, err := client.ImportKey(keyType, mnemonic)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Imported %s key: %s\n", keyType, address)
}

func runBatchDelete(client *BatchClient, args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: apadmin --batch delete <address>\n")
		os.Exit(1)
	}

	address := args[0]
	if err := client.DeleteKey(address); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Deleted key: %s\n", address)
}

func runBatchExport(client *BatchClient, args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: apadmin --batch export <address> [passphrase]\n")
		os.Exit(1)
	}

	address := args[0]
	passphrase := ""
	if len(args) > 1 {
		passphrase = args[1]
	} else {
		// Try TEST_PASSPHRASE env var
		passphrase = os.Getenv("TEST_PASSPHRASE")
	}

	mnemonic, err := client.ExportKey(address, passphrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Security warning: mnemonic is sensitive key material
	fmt.Fprintln(os.Stderr, "WARNING: The following mnemonic is sensitive key material.")
	fmt.Fprintln(os.Stderr, "         Store securely and clear shell history after use.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Println(mnemonic)
}

func runBatchUnlock(client *BatchClient) {
	// Check if --wait flag is set (keeps connection open)
	wait := false
	for _, arg := range os.Args {
		if arg == "--wait" {
			wait = true
			break
		}
	}

	fmt.Println("Signer unlocked")

	if wait {
		fmt.Println("Keeping connection open (Ctrl+C to exit)...")
		// Block forever (or until Ctrl+C)
		select {}
	}
}

func printBatchUsage() {
	fmt.Fprintf(os.Stderr, `Usage: apadmin --batch [--server <addr>] <command> [args...]

Commands:
  list                              List all keys
  generate <key-type>               Generate a new key (ed25519, falcon1024-v1)
  import <key-type> <mnemonic>      Import key from mnemonic
  delete <address>                  Delete a key
  export <address> [passphrase]     Export key's mnemonic
  unlock                            Unlock the signer (uses TEST_PASSPHRASE)

Environment variables:
  TEST_PASSPHRASE                   Passphrase for unlock/export (for testing)
  DISABLE_MEMORY_LOCK               Set to disable memory locking

Examples:
  apadmin --batch list
  apadmin --batch generate falcon1024-v1
  apadmin --batch import ed25519 word1 word2 ... word25
  apadmin --batch --server localhost:12345 list
`)
}
