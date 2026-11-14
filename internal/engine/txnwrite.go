// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	sdkjson "github.com/algorand/go-algorand-sdk/v2/encoding/json"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/algo"
)

// TransactionWriteNotice records the result of writing a submitted transaction
// JSON file for presentation by callers.
type TransactionWriteNotice struct {
	TxID     string
	Filename string
	Error    string
}

// WriteTransactionJSON writes a transaction to txnjson/<txid>.json if WriteMode is enabled.
// In simulate mode, uses the suffix .sim.json instead of .json.
// Returns the filename if written, empty string if WriteMode is disabled.
// A transaction whose JSON would not read back as itself is not written.
func (e *Engine) WriteTransactionJSON(txn types.Transaction, txID string) (string, error) {
	if !e.WriteMode {
		return "", nil
	}

	formatted, err := exactTransactionJSON(txn)
	if err != nil {
		return "", fmt.Errorf("transaction %s cannot be written exactly as JSON: %w", txID, err)
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll("txnjson", 0750); err != nil {
		return "", fmt.Errorf("failed to create txnjson directory: %w", err)
	}

	// Write to file (use .sim.json suffix in simulate mode)
	suffix := ".json"
	if e.Simulate {
		suffix = ".sim.json"
	}
	filename := fmt.Sprintf("txnjson/%s%s", txID, suffix)
	if err := os.WriteFile(filename, formatted, 0600); err != nil {
		return "", fmt.Errorf("failed to write transaction file: %w", err)
	}

	return filename, nil
}

// exactTransactionJSON formats a transaction for a txnjson/ file and reads
// the result back with the reader sign uses. The file is named after the
// transaction's ID, so it has to read back as that transaction: the SDK's
// encoder writes text that is not UTF-8 as U+FFFD, a nil app argument as
// null, and a state proof's reveals as invalid JSON.
func exactTransactionJSON(txn types.Transaction) ([]byte, error) {
	// Use SDK's JSON encoder (outputs base64 addresses, not byte arrays)
	data := sdkjson.Encode(txn)

	// Numbers stay as written: a float64 would round an amount past 2^53 and
	// put 2^64-1 in exponent form.
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var formatted interface{}
	if err := decoder.Decode(&formatted); err != nil {
		return nil, fmt.Errorf("the SDK's JSON for it is not valid JSON: %w", err)
	}

	// Convert known address fields from base64 to base32
	if m, ok := formatted.(map[string]interface{}); ok {
		convertKnownAddressFields(m)
	}

	indented, err := json.MarshalIndent(formatted, "", "  ")
	if err != nil {
		return nil, err
	}

	parsed, err := algo.ParseTransactions(indented)
	if err != nil {
		return nil, err
	}
	if len(parsed) != 1 || !bytes.Equal(msgpack.Encode(parsed[0]), msgpack.Encode(txn)) {
		return nil, fmt.Errorf("it reads back as another transaction")
	}
	return indented, nil
}

// WriteTxnCallback returns a TxnWriter callback for use with signing.SubmitOptions
// and appends user-visible write outcomes to notices.
func (e *Engine) WriteTxnCallback(notices *[]TransactionWriteNotice) func(types.Transaction, string) {
	if !e.WriteMode {
		return nil
	}
	return func(txn types.Transaction, txID string) {
		filename, err := e.WriteTransactionJSON(txn, txID)
		if err != nil {
			if notices != nil {
				*notices = append(*notices, TransactionWriteNotice{TxID: txID, Error: err.Error()})
			}
		} else if filename != "" {
			if notices != nil {
				*notices = append(*notices, TransactionWriteNotice{TxID: txID, Filename: filename})
			}
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
