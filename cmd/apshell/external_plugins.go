// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

// External plugin execution and transaction intent processing

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/cmd/apshell/internal/repl"
	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/util"
)

// printPluginTransactionResult prints the standard success message for plugin transactions.
func (r *REPLState) printPluginTransactionResult(txIDs []string) {
	fmt.Println("\n✓ Transaction(s) submitted successfully!")
	for i, txID := range txIDs {
		fmt.Printf("  [%d] %s\n", i+1, txID)
	}
}

// processTransactionIntents converts transaction intents to actual transactions
func (r *REPLState) processTransactionIntents(intents []jsonrpc.TransactionIntent) ([]types.Transaction, []types.SignedTxn, error) {
	txns := make([]types.Transaction, 0, len(intents))
	stxns := make([]types.SignedTxn, 0, len(intents))

	for i, intent := range intents {
		switch intent.Type {
		case "raw":
			// Decode base64-encoded raw transaction
			if intent.Encoded == "" {
				return nil, nil, fmt.Errorf("transaction %d: missing encoded data", i+1)
			}

			decoded, err := base64.StdEncoding.DecodeString(intent.Encoded)
			if err != nil {
				return nil, nil, fmt.Errorf("transaction %d: failed to decode base64: %w", i+1, err)
			}

			// Decode as unsigned transaction
			var txn types.Transaction
			if err := msgpack.Decode(decoded, &txn); err != nil {
				return nil, nil, fmt.Errorf("transaction %d: failed to decode msgpack: %w", i+1, err)
			}

			// Clear group ID - will be re-grouped during signing if needed
			txn.Group = types.Digest{}

			txns = append(txns, txn)
			stxns = append(stxns, types.SignedTxn{}) // Will be signed later

		case "payment":
			// Build payment transaction from fields
			// TODO: Implement if needed
			return nil, nil, fmt.Errorf("transaction %d: payment intent building not yet implemented", i+1)

		case "asset-transfer":
			// Build asset transfer from fields
			// TODO: Implement if needed
			return nil, nil, fmt.Errorf("transaction %d: asset-transfer intent building not yet implemented", i+1)

		case "app-call":
			// Build app call from fields
			// TODO: Implement if needed
			return nil, nil, fmt.Errorf("transaction %d: app-call intent building not yet implemented", i+1)

		default:
			return nil, nil, fmt.Errorf("transaction %d: unsupported type %s", i+1, intent.Type)
		}
	}

	return txns, stxns, nil
}

// LocalSigner represents a plugin-controlled account that should be signed locally.
// This is used when a plugin generates ephemeral accounts or controls keys
// that aren't managed by the user's apsignerd keystore.
type LocalSigner struct {
	Address   string // Algorand address
	SecretKey []byte // 64-byte Ed25519 secret key
}

// signAndSubmitWithLocalSigners handles mixed signing for external plugins.
// Transactions from localSigners are signed locally by apshell.
// All other transactions are sent to apsignerd for signing.
// Client orchestrates the group (dummies, fees, group ID) because it has local keys.
func (r *REPLState) signAndSubmitWithLocalSigners(txns []types.Transaction, localSigners []LocalSigner, lsigArgs []map[string][]byte) ([]string, error) {
	// Build lookup map for local signers
	localSignerKeys := make(map[string][]byte, len(localSigners))
	for _, signer := range localSigners {
		localSignerKeys[signer.Address] = signer.SecretKey
	}

	// Count LSig transactions and build indices (for fee distribution)
	lsigCount := 0
	var lsigIndices []int
	for i, txn := range txns {
		sender := txn.Sender.String()
		if _, isLocal := localSignerKeys[sender]; isLocal {
			continue // Local signers don't contribute to LSig count (they're Ed25519)
		}
		effectiveSigner := sender
		if authAddr, exists := r.Engine.AuthCache.GetAuthAddress(sender); exists && authAddr != "" {
			effectiveSigner = authAddr
		}
		// SignerCache is the source of truth (populated from server's /keys response)
		// Any key type other than ed25519 is an LSig
		keyType := r.Engine.SignerCache.GetKeyType(effectiveSigner)
		if keyType != "" && keyType != "ed25519" {
			lsigCount++
			lsigIndices = append(lsigIndices, i)
		}
	}

	// Calculate dummies needed
	dummiesNeeded := 0
	if lsigCount > 0 {
		// Conservative estimate: 3180 bytes per LSig transaction (bytecode + crypto signature)
		totalLsigBytes := lsigCount * 3180
		totalCapacity := len(txns) * 1000
		if totalCapacity < totalLsigBytes {
			slotsNeeded := (totalLsigBytes + 1000 - 1) / 1000
			dummiesNeeded = slotsNeeded - len(txns)
		}
	}

	// Get suggested params for dummies
	sp, err := r.Engine.AlgodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get suggested params: %w", err)
	}
	sp.FlatFee = true

	// Create dummy transactions if needed
	var allTxns []types.Transaction
	if dummiesNeeded > 0 {
		dummyTxns, err := signing.CreateDummyTransactions(dummiesNeeded, sp)
		if err != nil {
			return nil, fmt.Errorf("failed to create dummy transactions: %w", err)
		}
		allTxns = make([]types.Transaction, 0, len(txns)+len(dummyTxns))
		allTxns = append(allTxns, txns...)
		allTxns = append(allTxns, dummyTxns...)
	} else {
		allTxns = txns
	}

	// Adjust fees for dummies
	if dummiesNeeded > 0 && len(lsigIndices) > 0 {
		err = signing.AdjustLSigFeesForDummies(allTxns[:len(txns)], lsigIndices, dummiesNeeded, sp.MinFee, 0)
		if err != nil {
			return nil, fmt.Errorf("failed to adjust fees for dummies: %w", err)
		}
	}

	// Assign group ID to all transactions
	_, err = signing.AssignGroupID(allTxns)
	if err != nil {
		return nil, fmt.Errorf("failed to assign group ID: %w", err)
	}

	// Identify which transactions need server signing (user transactions, not local/dummies)
	var signRequests []util.SignRequest
	for i, txn := range allTxns[:len(txns)] {
		sender := txn.Sender.String()
		if _, isLocal := localSignerKeys[sender]; isLocal {
			continue // Local signers are signed locally
		}

		effectiveSigner := sender
		if authAddr, exists := r.Engine.AuthCache.GetAuthAddress(sender); exists && authAddr != "" {
			effectiveSigner = authAddr
		}

		// Build sign request for server
		txnBytes := append([]byte("TX"), msgpack.Encode(txn)...)
		req := util.SignRequest{
			AuthAddress: effectiveSigner,
			TxnSender:   sender,
			TxnBytesHex: hex.EncodeToString(txnBytes),
		}
		if i < len(lsigArgs) && lsigArgs[i] != nil {
			req.LsigArgs = make(map[string]string, len(lsigArgs[i]))
			for name, value := range lsigArgs[i] {
				req.LsigArgs[name] = hex.EncodeToString(value)
			}
		}
		signRequests = append(signRequests, req)
	}

	// Send user transactions to server for signing (they have group ID set, server won't modify)
	var serverSignedBytes [][]byte
	if len(signRequests) > 0 {
		resp, err := r.Engine.SignerClient.RequestGroupSign(signRequests)
		if err != nil {
			return nil, fmt.Errorf("server signing failed: %w", err)
		}
		serverSignedBytes = make([][]byte, len(resp.Signed))
		for i, hexStr := range resp.Signed {
			signedBytes, err := hex.DecodeString(hexStr)
			if err != nil {
				return nil, fmt.Errorf("failed to decode signed transaction %d: %w", i+1, err)
			}
			serverSignedBytes[i] = signedBytes
		}
	}

	// Assemble final signed transaction array
	finalSignedTxns := make([][]byte, len(allTxns))
	serverIdx := 0

	for i, txn := range allTxns {
		if i < len(txns) {
			sender := txn.Sender.String()
			if secretKey, isLocal := localSignerKeys[sender]; isLocal {
				// Sign local signer transaction locally
				stxn, err := signing.SignWithRawKey(txn, secretKey, sender)
				if err != nil {
					return nil, fmt.Errorf("failed to sign local transaction for %s: %w", sender, err)
				}
				finalSignedTxns[i] = msgpack.Encode(stxn)
			} else {
				// Use server-signed transaction
				finalSignedTxns[i] = serverSignedBytes[serverIdx]
				serverIdx++
			}
		} else {
			// Sign dummy transaction locally
			stxn, err := signing.SignDummyTransaction(txn)
			if err != nil {
				return nil, err
			}
			finalSignedTxns[i] = msgpack.Encode(stxn)
		}
	}

	// Submit or simulate
	if r.Engine.Simulate {
		return signing.SimulateTransactions(finalSignedTxns, r.Engine.AlgodClient)
	}
	return signing.SubmitTransactions(finalSignedTxns, r.Engine.AlgodClient, true)
}

// parseLocalSigners extracts local signer information from plugin result data.
// Format: data.localSigners array of {address, secretKey} objects
func parseLocalSigners(data interface{}) ([]LocalSigner, error) {
	if data == nil {
		return nil, nil
	}

	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return nil, nil
	}

	signers, ok := dataMap["localSigners"].([]interface{})
	if !ok {
		return nil, nil
	}

	result := make([]LocalSigner, 0, len(signers))
	for i, s := range signers {
		signer, ok := s.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("localSigners[%d]: expected object", i)
		}

		addr, ok := signer["address"].(string)
		if !ok || addr == "" {
			return nil, fmt.Errorf("localSigners[%d]: missing address", i)
		}

		skB64, ok := signer["secretKey"].(string)
		if !ok || skB64 == "" {
			return nil, fmt.Errorf("localSigners[%d]: missing secretKey", i)
		}

		secretKey, err := base64.StdEncoding.DecodeString(skB64)
		if err != nil {
			return nil, fmt.Errorf("localSigners[%d]: failed to decode secretKey: %w", i, err)
		}

		result = append(result, LocalSigner{
			Address:   addr,
			SecretKey: secretKey,
		})
	}
	return result, nil
}

// normalizeAddressArgs uppercases arguments that are Algorand addresses based on ArgSpecs.
// This ensures plugins receive properly normalized addresses regardless of how the user typed them.
func normalizeAddressArgs(specs []cmdspec.ArgSpec, args []string) []string {
	if len(specs) == 0 || len(args) == 0 {
		return args
	}

	// Make a copy to avoid mutating the original
	result := make([]string, len(args))
	copy(result, args)

	// Algorand address pattern: 58 base32 characters
	addrPattern := regexp.MustCompile(`^[A-Za-z2-7]{58}$`)

	// Walk through each argument and resolve its ArgSpec
	currentSpecs := specs
	currentOffset := 0

	for i := 0; i < len(args); i++ {
		specIdx := i - currentOffset
		if specIdx >= len(currentSpecs) {
			break // No more specs
		}

		spec := currentSpecs[specIdx]

		// Handle branching specs
		if len(spec.Branches) > 0 {
			var matchedBranch *cmdspec.ArgBranch
			for _, branch := range spec.Branches {
				if branch.When.Arg < len(args) {
					argValue := args[branch.When.Arg]
					if matched, _ := regexp.MatchString(branch.When.Matches, argValue); matched {
						matchedBranch = &branch
						break
					}
				}
			}

			if matchedBranch != nil {
				currentSpecs = matchedBranch.Specs
				currentOffset = i
				specIdx = 0
				spec = currentSpecs[specIdx]
			} else {
				continue // No branch matched, skip normalization for this position
			}
		}

		// If this spec is an address type and the value looks like an address, uppercase it
		if spec.Type == cmdspec.ArgTypeAddress && addrPattern.MatchString(result[i]) {
			result[i] = strings.ToUpper(result[i])
		}
	}

	return result
}

// extractLsigArgs separates arg: tokens from command args.
// Returns the remaining args (without arg: tokens) and the parsed lsig args map.
func extractLsigArgs(args []string) ([]string, map[string][]byte, error) {
	var cleanArgs []string
	var lsigArgs map[string][]byte
	for _, a := range args {
		if strings.HasPrefix(a, "arg:") {
			name, value, err := repl.ParseLsigArg(a)
			if err != nil {
				return nil, nil, err
			}
			if lsigArgs == nil {
				lsigArgs = make(map[string][]byte)
			}
			lsigArgs[name] = value
		} else {
			cleanArgs = append(cleanArgs, a)
		}
	}
	return cleanArgs, lsigArgs, nil
}

// executeExternalPlugin tries to execute a command as an external plugin
func (r *REPLState) executeExternalPlugin(cmd Command) error {
	// Discover plugins that handle this command
	disc := discovery.New()
	plugins, err := disc.FindByCommand(cmd.Name)
	if err != nil || len(plugins) == 0 {
		// Plugin not found
		fmt.Printf("Unknown command: %s\nType 'help' for available commands\n", cmd.Name)
		return nil
	}

	// Use the first plugin that handles this command
	plugin := plugins[0]

	// Check if plugin supports current network
	if !plugin.Manifest.SupportsNetwork(r.Engine.Network) {
		supportedNetworks := plugin.Manifest.Networks
		if len(supportedNetworks) == 0 {
			supportedNetworks = []string{"all networks"}
		}
		fmt.Printf("Error: Plugin '%s' does not support network '%s'\n", plugin.Manifest.Name, r.Engine.Network)
		fmt.Printf("Supported networks: %s\n", strings.Join(supportedNetworks, ", "))
		return nil
	}

	// Build execution context
	// Build ASA name->asset ID map (PRIORITY: resolved first)
	assetMap := make(map[string]uint64)
	for assetID, asaInfo := range r.Engine.AsaCache.Assets {
		// Map both Name and UnitName to asset ID
		if asaInfo.Name != "" {
			assetMap[asaInfo.Name] = assetID
		}
		if asaInfo.UnitName != "" {
			assetMap[asaInfo.UnitName] = assetID
		}
	}
	// Note: ALGO is not added to assetMap - it's the native currency, not an ASA.
	// Plugins should handle "ALGO" or "algo" natively (e.g., Tinyman SDK uses asset ID 0).

	// Build alias->address map (resolved second)
	addressMap := make(map[string]string)
	for alias, address := range r.Engine.AliasCache.Aliases {
		addressMap[alias] = address
	}

	// Build accounts list (all signable addresses)
	// Ensure signer cache is populated (auto-refresh if connected but empty)
	r.Engine.EnsureSignerCache()
	var accounts []string
	for address := range r.Engine.SignerCache.Keys {
		accounts = append(accounts, address)
	}

	pluginContext := jsonrpc.Context{
		Network:    r.Engine.Network,
		Accounts:   accounts,
		AssetMap:   assetMap,
		AddressMap: addressMap,
	}

	// Extract arg: tokens (LogicSig arguments) before passing to plugin
	pluginArgs, lsigArgs, err := extractLsigArgs(cmd.Args)
	if err != nil {
		return err
	}

	// Normalize address arguments based on ArgSpecs
	normalizedArgs := pluginArgs
	if manifestCmd := plugin.Manifest.FindCommand(cmd.Name); manifestCmd != nil && len(manifestCmd.ArgSpecs) > 0 {
		normalizedArgs = normalizeAddressArgs(manifestCmd.ArgSpecs, pluginArgs)
	}

	// Execute the plugin command
	result, err := r.PluginManager.ExecuteCommand(plugin.Manifest.Name, cmd.Name, normalizedArgs, pluginContext)
	if err != nil {
		return fmt.Errorf("plugin execution failed: %w", err)
	}

	// Display result message
	if result.Message != "" {
		fmt.Println(result.Message)
	}

	// Handle transaction intents (if any)
	if len(result.Transactions) > 0 {
		// Check if Signer is connected
		if r.Engine.SignerClient == nil {
			return fmt.Errorf("not connected to Signer. Use 'connect' first to sign transactions")
		}

		fmt.Printf("\nPlugin generated %d transaction(s):\n", len(result.Transactions))
		for i, txn := range result.Transactions {
			fmt.Printf("  [%d] %s\n", i+1, txn.Description)
		}

		// Ask for user confirmation if required
		if result.RequiresApproval {
			fmt.Print("\nProceed with signing and submission? [y/N]: ")
			var response string
			_, _ = fmt.Scanln(&response)
			if response != "y" && response != "Y" {
				fmt.Println("Transaction cancelled by user")
				return nil
			}
		}

		// Process transaction intents
		txns, _, err := r.processTransactionIntents(result.Transactions)
		if err != nil {
			return fmt.Errorf("failed to process transaction intents: %w", err)
		}

		// Sign and submit the transactions
		fmt.Println("\nSigning and submitting transactions...")

		// Check if plugin returned local signer data
		localSigners, err := parseLocalSigners(result.Data)
		if err != nil {
			return fmt.Errorf("failed to parse local signers: %w", err)
		}

		// Build per-transaction lsigArgs slice from extracted arg: tokens
		var lsigArgsSlice []map[string][]byte
		if len(lsigArgs) > 0 {
			lsigArgsSlice = make([]map[string][]byte, len(txns))
			for i := range txns {
				lsigArgsSlice[i] = lsigArgs
			}
		}

		var txIDs []string
		if len(localSigners) > 0 {
			// Plugin returned local signer data - use mixed signing
			txIDs, err = r.signAndSubmitWithLocalSigners(txns, localSigners, lsigArgsSlice)
		} else {
			// Use /sign endpoint (server handles dummies, fees, grouping)
			txIDs, err = signing.SignAndSubmitViaGroup(
				txns,
				&r.Engine.AuthCache,
				r.Engine.SignerClient,
				r.Engine.AlgodClient,
				signing.SubmitOptions{
					WaitForConfirmation: true,
					Verbose:             r.Engine.Verbose,
					LsigArgsMap:         lsigArgsSlice,
					Simulate:            r.Engine.Simulate,
					TxnWriter:           r.Engine.WriteTxnCallback(),
				},
			)
		}
		if err != nil {
			return fmt.Errorf("failed to sign and submit: %w", err)
		}

		// Display success
		r.printPluginTransactionResult(txIDs)

		// Handle continuation (multi-step workflow)
		if result.Continuation != nil {
			if result.Continuation.Message != "" {
				fmt.Println("\n" + result.Continuation.Message)
			}

			// Execute the next step
			fmt.Println("Executing next step...")

			// Build context with continuation data
			continuationContext := jsonrpc.Context{
				Network:      r.Engine.Network,
				AssetMap:     assetMap,
				AddressMap:   addressMap,
				Continuation: result.Continuation.Context, // Pass continuation context
			}

			// Execute continuation command (use same plugin)
			contResult, err := r.PluginManager.ExecuteCommand(plugin.Manifest.Name, result.Continuation.Command, result.Continuation.Args, continuationContext)
			if err != nil {
				return fmt.Errorf("continuation failed: %w", err)
			}

			// Recursively process continuation result
			return r.processContinuationResult(contResult, assetMap, addressMap, plugin.Manifest.Name)
		}
	}

	// Display additional data
	if result.Data != nil {
		fmt.Printf("\nAdditional data: %+v\n", result.Data)
	}

	return nil
}

// processContinuationResult processes a result that may contain continuations
// This is extracted to handle recursive continuations
func (r *REPLState) processContinuationResult(result *jsonrpc.ExecuteResult, assetMap map[string]uint64, addressMap map[string]string, pluginName string) error {
	// Display result message
	if result.Message != "" {
		fmt.Println(result.Message)
	}

	// Handle transaction intents (if any)
	if len(result.Transactions) > 0 {
		// Check if Signer is connected
		if r.Engine.SignerClient == nil {
			return fmt.Errorf("not connected to Signer. Use 'connect' first to sign transactions")
		}

		fmt.Printf("\nPlugin generated %d transaction(s):\n", len(result.Transactions))
		for i, txn := range result.Transactions {
			fmt.Printf("  [%d] %s\n", i+1, txn.Description)
		}

		// Ask for user confirmation if required
		if result.RequiresApproval {
			fmt.Print("\nProceed with signing and submission? [y/N]: ")
			var response string
			_, _ = fmt.Scanln(&response)
			if response != "y" && response != "Y" {
				fmt.Println("Transaction cancelled by user")
				return nil
			}
		}

		// Process transaction intents
		txns, _, err := r.processTransactionIntents(result.Transactions)
		if err != nil {
			return fmt.Errorf("failed to process transaction intents: %w", err)
		}

		// Sign and submit the transactions
		fmt.Println("\nSigning and submitting transactions...")

		// Check if plugin returned local signer data
		localSigners, err := parseLocalSigners(result.Data)
		if err != nil {
			return fmt.Errorf("failed to parse local signers: %w", err)
		}

		var txIDs []string
		if len(localSigners) > 0 {
			// Plugin returned local signer data - use mixed signing
			txIDs, err = r.signAndSubmitWithLocalSigners(txns, localSigners, nil)
		} else {
			// Use /sign endpoint (server handles dummies, fees, grouping)
			txIDs, err = signing.SignAndSubmitViaGroup(
				txns,
				&r.Engine.AuthCache,
				r.Engine.SignerClient,
				r.Engine.AlgodClient,
				signing.SubmitOptions{
					WaitForConfirmation: true,
					Verbose:             r.Engine.Verbose,
					Simulate:            r.Engine.Simulate,
					TxnWriter:           r.Engine.WriteTxnCallback(),
				},
			)
		}
		if err != nil {
			return fmt.Errorf("failed to sign and submit: %w", err)
		}

		// Display success
		r.printPluginTransactionResult(txIDs)

		// Handle nested continuation (multi-step workflow)
		if result.Continuation != nil {
			if result.Continuation.Message != "" {
				fmt.Println("\n" + result.Continuation.Message)
			}

			// Execute the next step
			fmt.Println("Executing next step...")

			// Build context with continuation data
			continuationContext := jsonrpc.Context{
				Network:      r.Engine.Network,
				AssetMap:     assetMap,
				AddressMap:   addressMap,
				Continuation: result.Continuation.Context, // Pass continuation context
			}

			// Execute continuation command (use same plugin)
			contResult, err := r.PluginManager.ExecuteCommand(pluginName, result.Continuation.Command, result.Continuation.Args, continuationContext)
			if err != nil {
				return fmt.Errorf("continuation failed: %w", err)
			}

			// Recursively process continuation result
			return r.processContinuationResult(contResult, assetMap, addressMap, pluginName)
		}
	}

	// Display additional data
	if result.Data != nil {
		fmt.Printf("\nAdditional data: %+v\n", result.Data)
	}

	return nil
}
