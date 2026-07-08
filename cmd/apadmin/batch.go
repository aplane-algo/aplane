//go:build testmode

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// This file exists only for `apadmin --test` workflows. It is test-only code,
// built behind the `testmode` tag, and is intentionally scoped to integration
// and harness usage rather than the normal interactive admin client.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"os"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/keytypefmt"
	"github.com/aplane-algo/aplane/internal/keytypeux"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/transport"
)

var testFlag *bool

func initTestFlag() {
	testFlag = flag.Bool("test", false, "Run in test mode (non-interactive, testing only)")
}

func isTestMode() bool {
	return testFlag != nil && *testFlag
}

// testModeClient is a dispatcher-backed request client used only by
// `apadmin --test`. Once connected, it should communicate through
// request/response helpers rather than mixing in raw reads.
type testModeClient struct {
	transport transport.Transport
}

func newTestModeClient() *testModeClient {
	return &testModeClient{}
}

// Connect establishes the connection using the provided transport.
func (c *testModeClient) Connect(conn transport.Transport) error {
	if err := conn.Dial(); err != nil {
		return err
	}
	c.transport = conn
	return nil
}

// Authenticate performs the IPC authentication handshake.
func (c *testModeClient) Authenticate(passphrase string) error {
	return c.transport.Authenticate(passphrase, 10*time.Second)
}

// Close closes the connection.
func (c *testModeClient) Close() {
	if c.transport != nil {
		c.transport.Close()
	}
}

// WaitForStatus waits for the initial status message.
func (c *testModeClient) WaitForStatus(timeout time.Duration) (*protocol.StatusMessage, error) {
	return c.transport.WaitForStatus(timeout)
}

// request sends a single admin request and waits for the matching response.
func (c *testModeClient) request(msg interface{}, timeout time.Duration) ([]byte, error) {
	return c.transport.SendAndReceive(msg, timeout)
}

// Unlock sends an unlock request.
func (c *testModeClient) Unlock(passphrase string) error {
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
func (c *testModeClient) ListKeys() ([]protocol.KeyInfo, error) {
	msg := protocol.ListKeysMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeListKeys,
			ID:   fmt.Sprintf("list-%d", time.Now().UnixNano()),
		},
	}

	response, err := c.request(msg, 30*time.Second)
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
func (c *testModeClient) GenerateKey(keyType string) (string, error) {
	return c.GenerateKeyWithParams(keyType, nil)
}

// GenerateKeyWithParams generates a new key with creation parameters.
func (c *testModeClient) GenerateKeyWithParams(keyType string, params map[string]string) (string, error) {
	keyType = keytypecatalog.Canonicalize(keyType)
	msg := protocol.GenerateKeyMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeGenerateKey,
			ID:   fmt.Sprintf("gen-%d", time.Now().UnixNano()),
		},
		KeyType:    keyType,
		Parameters: params,
	}

	response, err := c.request(msg, 30*time.Second)
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

// ImportKeyWithParams imports a key from mnemonic with creation parameters.
func (c *testModeClient) ImportKeyWithParams(keyType, mnemonic string, params map[string]string) (string, error) {
	keyType = keytypecatalog.Canonicalize(keyType)
	msg := protocol.ImportKeyMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeImportKey,
			ID:   fmt.Sprintf("imp-%d", time.Now().UnixNano()),
		},
		KeyType:    keyType,
		Mnemonic:   mnemonic,
		Parameters: params,
	}

	response, err := c.request(msg, 30*time.Second)
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
func (c *testModeClient) DeleteKey(address string) error {
	msg := protocol.DeleteKeyMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeDeleteKey,
			ID:   fmt.Sprintf("del-%d", time.Now().UnixNano()),
		},
		Address: address,
	}

	response, err := c.request(msg, 30*time.Second)
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

// runTestMode runs apadmin in test mode against the local IPC socket.
func runTestMode(config serverconfig.ServerConfig, args []string) {
	runTestSession(transport.NewIPC(config.IPCPath), false, args)
}

// runRemoteTestMode runs apadmin test mode over the legacy SSH admin transport.
func runRemoteTestMode(remoteCfg *remoteAdminConfig, args []string) {
	conn := transport.NewSSHAdmin(
		remoteCfg.config.LegacySSH.Host,
		remoteCfg.config.LegacySSH.Port,
		remoteCfg.token,
		remoteCfg.config.LegacySSH.IdentityFile,
		remoteCfg.config.LegacySSH.KnownHostsPath,
	)
	runTestSession(conn, true, args)
}

// runTestSession is the shared test-mode flow: connect, authenticate, wait
// for status, unlock if needed, then execute the command. remote selects the
// SSH-specific connect error formatting and the requirement that an unlock
// passphrase be provided explicitly.
func runTestSession(conn transport.Transport, remote bool, args []string) {
	if len(args) == 0 {
		printTestUsage()
		os.Exit(1)
	}

	// Get passphrase from environment (used for both auth and unlock)
	passphrase := os.Getenv("TEST_PASSPHRASE")
	if passphrase != "" {
		logWarnf("using TEST_PASSPHRASE from environment for test authentication/unlock")
	}

	client := newTestModeClient()
	if err := client.Connect(conn); err != nil {
		if remote {
			logErrorf("%v", formatRemoteConnectError(err))
		} else {
			logErrorf("%v", err)
		}
		os.Exit(1)
	}
	defer client.Close()

	if err := client.Authenticate(passphrase); err != nil {
		logErrorf("authentication failed: %v", err)
		os.Exit(1)
	}

	status, err := client.WaitForStatus(10 * time.Second)
	if err != nil {
		logErrorf("failed to receive signer status: %v", err)
		os.Exit(1)
	}

	// If signer is locked, try to unlock with TEST_PASSPHRASE
	if status.State == "locked" {
		if remote && passphrase == "" {
			logErrorf("signer is locked; set TEST_PASSPHRASE for test remote mode")
			os.Exit(1)
		}
		if err := client.Unlock(passphrase); err != nil {
			logErrorf("signer is locked and could not unlock: %v", err)
			os.Exit(1)
		}
	}

	executeTestCommand(client, args)
}

func executeTestCommand(client *testModeClient, args []string) {
	cmd := strings.ToLower(args[0])
	cmdArgs := args[1:]

	switch cmd {
	case "list":
		runTestList(client)
	case "generate":
		runTestGenerate(client, cmdArgs)
	case "import":
		runTestImport(client, cmdArgs)
	case "delete":
		runTestDelete(client, cmdArgs)
	case "unlock":
		runTestUnlock(client)
	default:
		logErrorf("unknown command: %s", cmd)
		printTestUsage()
		os.Exit(1)
	}
}

func runTestList(client *testModeClient) {
	keys, err := client.ListKeys()
	if err != nil {
		logErrorf("%v", err)
		os.Exit(1)
	}

	if len(keys) == 0 {
		fmt.Println("No keys found")
		return
	}

	for _, key := range keys {
		fmt.Printf("%s\t%s\n", key.Address, formatBatchKeyType(key.KeyType, key.TemplateProvenanceStatus))
	}
}

func formatBatchKeyType(keyType, templateProvenanceStatus string) string {
	label := keytypefmt.Display(keyType)
	if provenanceLabel := keytypeux.TemplateProvenanceLabel(templateProvenanceStatus); provenanceLabel != "" {
		return label + " [" + provenanceLabel + "]"
	}
	return label
}

func runTestGenerate(client *testModeClient, args []string) {
	if len(args) < 1 {
		logErrorf("usage: apadmin --test generate <key-type>")
		logErrorf("key types: ed25519, falcon1024.v1")
		os.Exit(1)
	}

	keyType := keytypecatalog.Canonicalize(args[0])
	address, err := client.GenerateKey(keyType)
	if err != nil {
		logErrorf("%v", err)
		os.Exit(1)
	}

	fmt.Printf("Generated %s key: %s\n", keytypefmt.Display(keyType), address)
}

func runTestImport(client *testModeClient, args []string) {
	if len(args) < 2 {
		logErrorf("usage: apadmin --test import <key-type> [key=value ...] <mnemonic words>")
		logErrorf("key types: ed25519, falcon1024.v1")
		os.Exit(1)
	}

	keyType := keytypecatalog.Canonicalize(args[0])
	remaining := args[1:]

	// Split remaining args into params (key=value) and mnemonic words
	var params map[string]string
	var words []string
	for _, arg := range remaining {
		if strings.Contains(arg, "=") && params != nil || strings.Contains(arg, "=") {
			if params == nil {
				params = make(map[string]string)
			}
			parts := strings.SplitN(arg, "=", 2)
			params[parts[0]] = parts[1]
		} else {
			words = append(words, arg)
		}
	}

	if len(words) == 0 {
		logErrorf("no mnemonic words provided")
		os.Exit(1)
	}

	mnemonic := strings.Join(words, " ")

	address, err := client.ImportKeyWithParams(keyType, mnemonic, params)
	if err != nil {
		logErrorf("%v", err)
		os.Exit(1)
	}

	fmt.Printf("Imported %s key: %s\n", keytypefmt.Display(keyType), address)
}

func runTestDelete(client *testModeClient, args []string) {
	if len(args) < 1 {
		logErrorf("usage: apadmin --test delete <address>")
		os.Exit(1)
	}

	address := args[0]
	if err := client.DeleteKey(address); err != nil {
		logErrorf("%v", err)
		os.Exit(1)
	}

	fmt.Printf("Deleted key: %s\n", address)
}

func runTestUnlock(client *testModeClient) {
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
		logInfof("keeping connection open (Ctrl+C to exit)")
		// Block forever (or until Ctrl+C)
		select {}
	}
}

func printTestUsage() {
	logErrorf(`Usage: apadmin --test [--remote --client-data <dir>] <command> [args...]

Commands:
  list                              List all keys
  generate <key-type>               Generate a new key (ed25519, falcon1024.v1)
  import <key-type> <mnemonic>      Import key from mnemonic
  delete <address>                  Delete a key
  unlock                            Unlock the signer (uses TEST_PASSPHRASE)

Environment variables:
  TEST_PASSPHRASE                   Passphrase for unlock (for testing)
  DISABLE_MEMORY_LOCK               Set to disable memory locking

Examples:
  apadmin --test list
  apadmin --test --remote --client-data ~/aplane/apclient list
  apadmin --test generate aplane.falcon1024.v1
  apadmin --test import ed25519 word1 word2 ... word25
`)
}
