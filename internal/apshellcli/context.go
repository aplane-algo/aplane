// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"
)

// checkIncentiveEligibility checks if an account is already incentive eligible and determines
// whether to charge the 2 ALGO fee. Returns true if fee should be charged, false otherwise.
// userWantsEligible: for manual mode (true if user passed eligible=true parameter)
// promptUser: for paste mode (true to prompt user interactively, false to use userWantsEligible)
func checkIncentiveEligibility(r *REPLState, address string, userWantsEligible bool, promptUser bool) (bool, error) {
	wantsEligible := userWantsEligible
	if promptUser {
		r.print("Enable consensus incentive eligibility? (2 ALGO fee) [y/N]: ")
		var incentiveResponse string
		_, _ = fmt.Scanln(&incentiveResponse)
		wantsEligible = incentiveResponse == "y" || incentiveResponse == "Y" || incentiveResponse == "yes" || incentiveResponse == "Yes"
	}

	result, err := r.app().ResolveIncentiveEligibility(r.commandContext(), address, wantsEligible)
	if err != nil {
		return false, err
	}

	if result.AlreadyEligible {
		if result.Requested || promptUser {
			r.println("✓ Account is already incentive eligible (will maintain eligibility, no additional fee)")
		} else {
			r.println("✓ Account is already incentive eligible (will maintain eligibility)")
		}
		return false, nil
	}

	if result.ChargeFee {
		r.println("✓ Consensus incentive eligibility enabled (2 ALGO fee)")
	} else if promptUser || result.Requested {
		r.println("  Consensus incentive eligibility disabled (standard fee)")
	}

	return result.ChargeFee, nil
}
