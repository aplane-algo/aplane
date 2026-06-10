// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package algo

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/config"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
)

// algodRequestTimeout is the maximum time to wait for algod to start responding.
// Covers remote providers (e.g., Nodely) where network issues could hang indefinitely.
// This is a ResponseHeaderTimeout — it does not limit body reads, only the wait
// for the server to begin its response.
const algodRequestTimeout = 30 * time.Second
const confirmationPollInterval = 3 * time.Second

// GetAlgodClientWithConfig returns an algod client using config settings.
// Returns an error if config is nil or algod URL is not configured for the network.
func GetAlgodClientWithConfig(network string, config *config.Config) (*algod.Client, error) {
	if config == nil {
		return nil, fmt.Errorf("algod not configured: no config provided")
	}
	algodConfig, err := config.GetAlgodConfig(network)
	if err != nil {
		return nil, fmt.Errorf("algod not configured for %s: %w", network, err)
	}
	if algodConfig.Server == "" {
		return nil, fmt.Errorf("algod not configured: algod.%s.server is empty in config.yaml", network)
	}
	var rt http.RoundTripper
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		transport := t.Clone()
		transport.ResponseHeaderTimeout = algodRequestTimeout
		rt = transport
	} else {
		rt = http.DefaultTransport
	}
	return algod.MakeClientWithTransport(algodConfig.Server, algodConfig.Token, nil, rt)
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
	if integerPart == "" && fractionalPart == "" {
		return 0, fmt.Errorf("invalid amount format: missing digits")
	}
	if (integerPart != "" && !isDecimalDigits(integerPart)) ||
		(fractionalPart != "" && !isDecimalDigits(fractionalPart)) {
		return 0, fmt.Errorf("invalid amount format: %s", tokenAmount)
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

func isDecimalDigits(s string) bool {
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func WaitForConfirmation(ctx context.Context, algodClient *algod.Client, txid string, maxRounds uint64, w io.Writer) error {
	if w == nil {
		w = os.Stdout
	}
	_, _ = fmt.Fprint(w, "\nWaiting for confirmation")

	for round := uint64(0); round < maxRounds; round++ {
		pendingTxn, _, err := algodClient.PendingTransactionInformation(txid).Do(ctx)
		if err != nil {
			_, _ = fmt.Fprintf(w, "\nWarning: Could not check pending transaction status: %v\n", err)
			_, _ = fmt.Fprintln(w, "Falling back to standard confirmation wait...")
			confirmedTxn, err := transaction.WaitForConfirmation(algodClient, txid, 4, ctx)
			if err != nil {
				return fmt.Errorf("confirmation failed: %w", err)
			}
			if confirmedTxn.ConfirmedRound != 0 {
				_, _ = fmt.Fprintf(w, "Transaction confirmed in block %d\n", confirmedTxn.ConfirmedRound)
			} else {
				_, _ = fmt.Fprintln(w, "Transaction confirmed!")
			}
			return nil
		}

		_, _ = fmt.Fprint(w, ".")

		if pendingTxn.ConfirmedRound != 0 {
			_, _ = fmt.Fprintf(w, "\nTransaction confirmed in block %d\n", pendingTxn.ConfirmedRound)
			return nil
		}

		if pendingTxn.PoolError != "" {
			_, _ = fmt.Fprintln(w)
			return fmt.Errorf("transaction failed: %s", pendingTxn.PoolError)
		}

		if err := waitForConfirmationPoll(ctx, confirmationPollInterval); err != nil {
			_, _ = fmt.Fprintln(w)
			return fmt.Errorf("confirmation canceled: %w", err)
		}
	}

	_, _ = fmt.Fprintln(w)
	return fmt.Errorf("transaction timed out after %d rounds", maxRounds)
}

func waitForConfirmationPoll(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
