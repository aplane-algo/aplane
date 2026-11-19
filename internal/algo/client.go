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
	// Algorand asset decimals are capped at 19 by the protocol. Reject anything
	// larger up front: a pathological value would drive strings.Repeat below to
	// a gigabyte allocation (and len(fractionalPart)-vs-decimals math into
	// nonsense), and no real asset reaches it.
	if decimals > 19 {
		return 0, fmt.Errorf("invalid asset decimals %d (max 19)", decimals)
	}

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

// WaitForConfirmation waits up to maxRounds ledger rounds for txid to be
// confirmed, printing a dot for each round it checks. Each check is followed
// by a wait for the next block (StatusAfterBlock), so the budget counts the
// ledger's rounds; when algod cannot say which round it is on, the wait is one
// poll interval, about a round, and counts as one. A status check that fails
// does not end the wait: the next round checks again, and the failure is
// reported only if the budget runs out without a confirmation.
func WaitForConfirmation(ctx context.Context, algodClient *algod.Client, txid string, maxRounds uint64, w io.Writer) error {
	if w == nil {
		w = os.Stdout
	}
	_, _ = fmt.Fprint(w, "\nWaiting for confirmation")

	clock := newRoundClock(ctx, algodClient)
	var lastErr error
	for checked := uint64(0); checked < maxRounds; checked++ {
		pendingTxn, _, err := algodClient.PendingTransactionInformation(txid).Do(ctx)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				_, _ = fmt.Fprintln(w)
				return fmt.Errorf("confirmation canceled: %w", ctxErr)
			}
			if lastErr == nil {
				_, _ = fmt.Fprintf(w, "\nWarning: could not check pending transaction status: %v; still waiting", err)
			}
			lastErr = err
		} else {
			lastErr = nil
			_, _ = fmt.Fprint(w, ".")

			if pendingTxn.ConfirmedRound != 0 {
				_, _ = fmt.Fprintf(w, "\nTransaction confirmed in block %d\n", pendingTxn.ConfirmedRound)
				return nil
			}

			if pendingTxn.PoolError != "" {
				_, _ = fmt.Fprintln(w)
				return fmt.Errorf("transaction failed: %s", pendingTxn.PoolError)
			}
		}

		if err := clock.next(ctx); err != nil {
			_, _ = fmt.Fprintln(w)
			return fmt.Errorf("confirmation canceled: %w", err)
		}
	}

	_, _ = fmt.Fprintln(w)
	if lastErr != nil {
		return fmt.Errorf("transaction not confirmed after %d rounds; the last status check failed: %w", maxRounds, lastErr)
	}
	return fmt.Errorf("transaction timed out after %d rounds", maxRounds)
}

// roundClock paces a confirmation wait by the ledger's rounds.
type roundClock struct {
	client *algod.Client
	round  uint64 // the last round algod reported
	known  bool   // whether round is algod's answer
}

func newRoundClock(ctx context.Context, client *algod.Client) *roundClock {
	clock := &roundClock{client: client}
	clock.read(ctx)
	return clock
}

// read asks algod for its last round.
func (c *roundClock) read(ctx context.Context) {
	status, err := c.client.Status().Do(ctx)
	c.known = err == nil
	if c.known {
		c.round = status.LastRound
	}
}

// next waits for the block after the last round algod reported. When algod
// cannot say, it waits one poll interval instead and asks for the round
// again. It returns an error only when ctx ends.
func (c *roundClock) next(ctx context.Context) error {
	if c.known {
		status, err := c.client.StatusAfterBlock(c.round).Do(ctx)
		if err == nil {
			c.round = status.LastRound
			return nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
	}
	if err := waitForConfirmationPoll(ctx, confirmationPollInterval); err != nil {
		return err
	}
	c.read(ctx)
	return nil
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
