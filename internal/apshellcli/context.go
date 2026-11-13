// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import "github.com/aplane-algo/aplane/internal/apshellapp"

// askIncentiveEligibility asks paste mode's user whether to request incentive
// eligibility. Nothing is known about the account yet: the registration
// decides whether the 2 ALGO fee is paid.
func askIncentiveEligibility(r *REPLState) (bool, error) {
	incentiveResponse, err := r.readPromptResponse("Request consensus incentive eligibility? (2 ALGO fee unless already eligible) [y/N]: ")
	if err != nil {
		return false, err
	}
	return incentiveResponse == "y" || incentiveResponse == "yes", nil
}

// reportIncentiveEligibility says what a registration's transaction carries
// for incentive eligibility. prompted is true in paste mode, where the user
// was asked and a "no" is worth saying.
func reportIncentiveEligibility(r *REPLState, result *apshellapp.KeyRegCommandResult, prompted bool) {
	switch {
	case result.IncentiveRequested && result.AlreadyIncentiveEligible:
		r.println("Already incentive eligible: no incentive fee paid")
	case result.IncentiveRequested:
		r.println("Incentive eligibility requested: 2 ALGO fee")
	case prompted:
		r.println("Incentive eligibility not requested: ordinary fee")
	}
}
