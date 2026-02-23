// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package engine

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	sdkjson "github.com/algorand/go-algorand-sdk/v2/encoding/json"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// WriteTransactionJSON writes a transaction to txnjson/<txid>.json if WriteMode is enabled.
// In simulate mode, uses the suffix .sim.json instead of .json.
// Returns the filename if written, empty string if WriteMode is disabled.
func (e *Engine) WriteTransactionJSON(txn types.Transaction, txID string) (string, error) {
	if !e.WriteMode {
		return "", nil
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll("txnjson", 0750); err != nil {
		return "", fmt.Errorf("failed to create txnjson directory: %w", err)
	}

	// Use SDK's JSON encoder (outputs base64 addresses, not byte arrays)
	data := sdkjson.Encode(txn)

	// Add indentation for readability
	var formatted interface{}
	if err := json.Unmarshal(data, &formatted); err != nil {
		return "", fmt.Errorf("failed to unmarshal for formatting: %w", err)
	}

	// Convert known address fields from base64 to base32
	if m, ok := formatted.(map[string]interface{}); ok {
		convertKnownAddressFields(m)
	}

	indented, err := json.MarshalIndent(formatted, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal with indentation: %w", err)
	}

	// Write to file (use .sim.json suffix in simulate mode)
	suffix := ".json"
	if e.Simulate {
		suffix = ".sim.json"
	}
	filename := fmt.Sprintf("txnjson/%s%s", txID, suffix)
	if err := os.WriteFile(filename, indented, 0600); err != nil {
		return "", fmt.Errorf("failed to write transaction file: %w", err)
	}

	return filename, nil
}

// WriteTxnCallback returns a TxnWriter callback for use with signing.SubmitOptions.
// Returns nil if WriteMode is disabled, so callers can pass it directly.
func (e *Engine) WriteTxnCallback() func(types.Transaction, string) {
	if !e.WriteMode {
		return nil
	}
	return func(txn types.Transaction, txID string) {
		filename, err := e.WriteTransactionJSON(txn, txID)
		if err != nil {
			fmt.Printf("  Warning: failed to write transaction JSON: %v\n", err)
		} else if filename != "" {
			fmt.Printf("  Saved transaction to %s\n", filename)
		}
	}
}

// convertKnownAddressFields converts known address field names from base64 to base32
func convertKnownAddressFields(m map[string]interface{}) {
	// Top-level address field names (msgpack codec tags)
	addressFields := map[string]bool{
		"snd":    true, // Sender
		"rcv":    true, // Receiver
		"close":  true, // CloseRemainderTo
		"rekey":  true, // RekeyTo
		"asnd":   true, // AssetSender
		"arcv":   true, // AssetReceiver
		"aclose": true, // AssetCloseTo
		"fadd":   true, // FreezeAccount
	}

	for key, value := range m {
		// Convert known address fields
		if addressFields[key] {
			if base64Str, ok := value.(string); ok {
				if base32Str := base64ToBase32Address(base64Str); base32Str != "" {
					m[key] = base32Str
				}
			}
		}

		// Handle nested AssetParams (apar)
		if key == "apar" {
			if apar, ok := value.(map[string]interface{}); ok {
				convertAssetParamAddresses(apar)
			}
		}

		// Handle Accounts array (apat)
		if key == "apat" {
			if accounts, ok := value.([]interface{}); ok {
				convertAccountsArray(accounts)
			}
		}
	}
}

// convertAssetParamAddresses converts address fields in AssetParams
func convertAssetParamAddresses(apar map[string]interface{}) {
	// AssetParams address field names
	paramAddressFields := map[string]bool{
		"m": true, // Manager
		"r": true, // Reserve
		"f": true, // Freeze
		"c": true, // Clawback
	}

	for key, value := range apar {
		if paramAddressFields[key] {
			if base64Str, ok := value.(string); ok {
				if base32Str := base64ToBase32Address(base64Str); base32Str != "" {
					apar[key] = base32Str
				}
			}
		}
	}
}

// convertAccountsArray converts addresses in application accounts array
func convertAccountsArray(accounts []interface{}) {
	for i, value := range accounts {
		if base64Str, ok := value.(string); ok {
			if base32Str := base64ToBase32Address(base64Str); base32Str != "" {
				accounts[i] = base32Str
			}
		}
	}
}

// base64ToBase32Address converts a base64-encoded address to base32 format
// Returns empty string if conversion fails
func base64ToBase32Address(base64Str string) string {
	// Decode from base64
	data, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil || len(data) != 32 {
		return "" // Not a valid address
	}

	// Convert to Address type
	var addr types.Address
	copy(addr[:], data)

	// Return base32 format
	return addr.String()
}
