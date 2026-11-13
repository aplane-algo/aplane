// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import "github.com/aplane-algo/aplane/internal/apshellapp"

// askIncentiveEligibility asks paste mode's user whether to request incentive
// eligibility. The registration decides whether the 2 ALGO fee is paid.
func askIncentiveEligibility(r *REPLState) (bool, error) {
	incentiveResponse, err := r.readPromptResponse("Enable consensus incentive eligibility? (2 ALGO fee) [y/N]: ")
	if err != nil {
		return false, err
	}
	return incentiveResponse == "y" || incentiveResponse == "yes", nil
}

// reportIncentiveEligibility tells the user what an online registration
// decided about incentive eligibility. prompted is true in paste mode, where
// the user was asked.
func reportIncentiveEligibility(r *REPLState, result *apshellapp.IncentiveEligibilityResult, prompted bool) {
	if result.AlreadyEligible {
		if result.Requested || prompted {
			r.println("✓ Account is already incentive eligible (will maintain eligibility, no additional fee)")
		} else {
			r.println("✓ Account is already incentive eligible (will maintain eligibility)")
		}
		return
	}

	if result.ChargeFee {
		r.println("✓ Consensus incentive eligibility enabled (2 ALGO fee)")
	} else if prompted || result.Requested {
		r.println("  Consensus incentive eligibility disabled (standard fee)")
	}
}
