// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/util"
)

// BuildSigningContext builds a complete signing context.
// Delegates to Engine.BuildSigningContext but adds UI feedback for rekeyed accounts.
func (r *REPLState) BuildSigningContext(addressOrAlias string) (*engine.SigningContext, error) {
	// First, resolve the address to check for rekey (for UI message)
	resolver := r.NewAddressResolver()
	address, err := resolver.ResolveSingle(addressOrAlias)
	if err == nil {
		// Check if rekeyed and print message if so
		if isRekeyed, authAddr := r.Engine.IsRekeyed(address); isRekeyed {
			fmt.Printf("Account is rekeyed to %s\n", r.FormatAddress(authAddr, ""))
		}
	}

	// Delegate to Engine for the actual work
	return r.Engine.BuildSigningContext(addressOrAlias)
}

// checkIncentiveEligibility checks if an account is already incentive eligible and determines
// whether to charge the 2 ALGO fee. Returns true if fee should be charged, false otherwise.
// userWantsEligible: for manual mode (true if user passed eligible=true parameter)
// promptUser: for paste mode (true to prompt user interactively, false to use userWantsEligible)
func (r *REPLState) checkIncentiveEligibility(address string, userWantsEligible bool, promptUser bool) (bool, error) {
	// Query blockchain for current eligibility status
	util.Debug("checking incentive eligibility", "address", r.FormatAddress(address, ""))
	acctInfo, err := r.Engine.AlgodClient.AccountInformation(address).Do(context.Background())
	if err != nil {
		return false, fmt.Errorf("failed to query account info: %w", err)
	}

	alreadyEligible := acctInfo.IncentiveEligible

	// If already eligible, never charge again
	if alreadyEligible {
		if userWantsEligible || promptUser {
			fmt.Println("✓ Account is already incentive eligible (will maintain eligibility, no additional fee)")
		} else {
			fmt.Println("✓ Account is already incentive eligible (will maintain eligibility)")
		}
		return false, nil
	}

	// Account is not yet incentive eligible - determine user's preference
	var wantsEligible bool
	if promptUser {
		// Paste mode: prompt user interactively
		fmt.Print("Enable consensus incentive eligibility? (2 ALGO fee) [y/N]: ")
		var incentiveResponse string
		// Ignore Scanln errors - defaults to empty string (treated as "N")
		_, _ = fmt.Scanln(&incentiveResponse)
		wantsEligible = incentiveResponse == "y" || incentiveResponse == "Y" || incentiveResponse == "yes" || incentiveResponse == "Yes"
	} else {
		// Manual mode: use the parameter
		wantsEligible = userWantsEligible
	}

	// Use pure logic function to determine if fee should be charged
	chargeFee := shouldChargeFee(alreadyEligible, wantsEligible)

	// Display the decision
	if chargeFee {
		fmt.Println("✓ Consensus incentive eligibility enabled (2 ALGO fee)")
	} else if promptUser || userWantsEligible {
		fmt.Println("  Consensus incentive eligibility disabled (standard fee)")
	}

	return chargeFee, nil
}

// shouldChargeFee determines if the 2 ALGO incentive fee should be charged
// Pure logic function with no I/O
func shouldChargeFee(alreadyEligible bool, userWantsEligible bool) bool {
	// Already eligible - never charge again
	if alreadyEligible {
		return false
	}
	// Not eligible yet - charge if user wants it
	return userWantsEligible
}

// refreshAuthCache refreshes the auth address cache from blockchain.
// Delegates to Engine.RefreshAuthCache but adds UI feedback.
func (r *REPLState) refreshAuthCache() error {
	if err := r.Engine.RefreshAuthCache(); err != nil {
		return err
	}
	fmt.Println("✓ Auth cache refreshed")
	return nil
}
