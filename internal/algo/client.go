// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package algo

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/util"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
)

// GetAlgodClientWithConfig returns an algod client using config settings.
// Returns an error if config is nil or algod URL is not configured for the network.
func GetAlgodClientWithConfig(network string, config *util.Config) (*algod.Client, error) {
	if config == nil {
		return nil, fmt.Errorf("algod not configured: no config provided")
	}
	algodConfig, err := config.GetAlgodConfig(network)
	if err != nil {
		return nil, fmt.Errorf("algod not configured for %s: %w", network, err)
	}
	if algodConfig.Server == "" {
		return nil, fmt.Errorf("algod not configured: %s_algod_server is empty in config.yaml", network)
	}
	return algod.MakeClient(algodConfig.Address(), algodConfig.Token)
}

// ParseCommand parses command line, handling quoted strings
func ParseCommand(input string) (string, []string) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", nil
	}

	var parts []string
	var current strings.Builder
	inQuotes := false

	for i := 0; i < len(input); i++ {
		ch := input[i]

		switch ch {
		case '"':
			inQuotes = !inQuotes
		case ' ', '\t':
			if inQuotes {
				current.WriteByte(ch)
			} else {
				if current.Len() > 0 {
					parts = append(parts, current.String())
					current.Reset()
				}
			}
		default:
			current.WriteByte(ch)
		}
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	if len(parts) == 0 {
		return "", nil
	}

	return parts[0], parts[1:]
}

func ConvertTokenAmountToBaseUnits(tokenAmount string, decimals uint64) (uint64, error) {
	// Validate input format (digits and optional dot)
	if tokenAmount == "" {
		return 0, fmt.Errorf("empty amount")
	}
	if strings.HasPrefix(tokenAmount, "-") {
		return 0, fmt.Errorf("amount cannot be negative")
	}

	// Split into integer and fractional parts
	parts := strings.Split(tokenAmount, ".")
	if len(parts) > 2 {
		return 0, fmt.Errorf("invalid amount format: multiple decimal points")
	}

	integerPart := parts[0]
	fractionalPart := ""
	if len(parts) == 2 {
		fractionalPart = parts[1]
	}

	// Handle empty integer part like ".5" -> "0.5"
	if integerPart == "" {
		integerPart = "0"
	}

	// Verify decimals
	if uint64(len(fractionalPart)) > decimals {
		return 0, fmt.Errorf("amount has too many decimal places (max %d)", decimals)
	}

	// Pad fractional part with zeros
	padding := int(decimals) - len(fractionalPart)
	paddedFractional := fractionalPart + strings.Repeat("0", padding)

	// Concatenate to get base units string
	// e.g., "1.5" (6 dec) -> "1" + "500000" -> "1500000"
	// e.g., "100" (2 dec) -> "100" + "00" -> "10000"
	baseUnitsStr := integerPart + paddedFractional

	// Trim leading zeros (unless string is just "0")
	baseUnitsStr = strings.TrimLeft(baseUnitsStr, "0")
	if baseUnitsStr == "" {
		baseUnitsStr = "0"
	}

	// Parse as uint64
	baseUnits, err := strconv.ParseUint(baseUnitsStr, 10, 64)
	if err != nil {
		// Differentiate between overflow and format error
		if numErr, ok := err.(*strconv.NumError); ok && numErr.Err == strconv.ErrRange {
			return 0, fmt.Errorf("amount too large (exceeds uint64 capacity)")
		}
		return 0, fmt.Errorf("invalid amount format: %s", tokenAmount)
	}

	return baseUnits, nil
}

func WaitForConfirmation(algodClient *algod.Client, txid string, maxRounds uint64) error {
	fmt.Print("Waiting for confirmation")

	for round := uint64(0); round < maxRounds; round++ {
		pendingTxn, _, err := algodClient.PendingTransactionInformation(txid).Do(context.Background())
		if err != nil {
			fmt.Printf("\nWarning: Could not check pending transaction status: %v\n", err)
			fmt.Println("Falling back to standard confirmation wait...")
			confirmedTxn, err := transaction.WaitForConfirmation(algodClient, txid, 4, context.Background())
			if err != nil {
				return fmt.Errorf("confirmation failed: %w", err)
			}
			if confirmedTxn.ConfirmedRound != 0 {
				fmt.Printf("Transaction confirmed in block %d\n", confirmedTxn.ConfirmedRound)
			} else {
				fmt.Println("Transaction confirmed!")
			}
			return nil
		}

		fmt.Print(".")

		if pendingTxn.ConfirmedRound != 0 {
			fmt.Printf("\nTransaction confirmed in block %d\n", pendingTxn.ConfirmedRound)
			return nil
		}

		if pendingTxn.PoolError != "" {
			fmt.Println()
			return fmt.Errorf("transaction failed: %s", pendingTxn.PoolError)
		}

		time.Sleep(time.Second * 3)
	}

	fmt.Println()
	return fmt.Errorf("transaction timed out after %d rounds", maxRounds)
}
