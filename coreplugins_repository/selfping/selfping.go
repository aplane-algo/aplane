// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

//go:build selfping
// +build selfping

package selfping

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/signing"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Register plugin at compile time
func init() {
	command.RegisterStaticPlugin(&command.Command{
		Name:        "selfping",
		Description: "Send 5 zero ALGO payment transactions in an atomic group from an address to itself",
		Usage:       "selfping <address>",
		Category:    command.CategoryTransaction,
		Handler:     &Handler{},
		ArgSpecs: []cmdspec.ArgSpec{
			{Type: cmdspec.ArgTypeAddress},
		},
	})
}

// Handler implements the command.Handler interface
type Handler struct{}

// Execute implements the Handler interface
func (h *Handler) Execute(args []string, ctx *command.Context) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: selfping <address>")
	}

	// Use the PluginAPI to access caches and clients
	caches := ctx.GetCaches()
	if caches == nil {
		return fmt.Errorf("plugin API not available")
	}

	algodClient := ctx.Algod()
	signerClient := ctx.Signer()

	address := args[0]

	// Resolve aliases to actual address
	resolvedAddr, err := caches.Alias.ResolveAddress(address)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}

	// Validate the address format
	_, err = types.DecodeAddress(resolvedAddr)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	// Check if we have signing capability for this address
	canSign := caches.Signer.HasAddress(resolvedAddr)
	if !canSign {
		return fmt.Errorf("no signing key available for address %s", resolvedAddr)
	}

	keyType := caches.Signer.GetKeyType(resolvedAddr)
	fmt.Printf("Building 5 zero ALGO self-payment transactions for %s using %s...\n", resolvedAddr, keyType)

	// For Falcon accounts, ensure lsig is available (will auto-fetch if connected to Signer)
	// The SignAndSubmitTransactions helper will handle lsig lookup and auto-fetch

	// Get suggested params
	sp, err := algodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get suggested params: %w", err)
	}

	// Create 5 self-payment transactions
	txns := make([]types.Transaction, 5)
	for i := 0; i < 5; i++ {
		txn, err := transaction.MakePaymentTxn(
			resolvedAddr,
			resolvedAddr,
			0, // 0 ALGO
			[]byte(fmt.Sprintf("selfping-%d", i+1)),
			"",
			sp,
		)
		if err != nil {
			return fmt.Errorf("failed to create transaction %d: %w", i+1, err)
		}
		txns[i] = txn
	}

	fmt.Printf("Created 5 transactions, signing via /sign...\n\n")

	// Use SignAndSubmitViaGroup (server handles dummies, fees, grouping)
	txIDs, err := signing.SignAndSubmitViaGroup(
		txns,
		caches.Auth,
		signerClient,
		algodClient,
		signing.SubmitOptions{
			WaitForConfirmation: true,
			Verbose:             true, // selfping is a diagnostic tool
			Simulate:            ctx.Simulate,
			TxnWriter:           ctx.WriteTxnCallback(),
		},
	)
	if err != nil {
		return fmt.Errorf("failed to sign and submit atomic group: %w", err)
	}

	fmt.Printf("\n✓ Atomic group submitted successfully!\n")
	fmt.Printf("  Group size: %d transactions\n", len(txIDs))
	fmt.Printf("  First transaction ID: %s\n", txIDs[0])

	return nil
}
