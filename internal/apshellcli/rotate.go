// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"
	"io"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
)

const rotateUsage = "rotate <account> [nowait] | rotate status [<account>]"

type rotateProjection struct {
	Account            string `json:"account"`
	PreviousAuthorizer string `json:"previous_authorizer"`
	Authorizer         string `json:"authorizer,omitempty"`
	TxID               string `json:"tx_id,omitempty"`
	Confirmed          bool   `json:"confirmed"`
	Simulated          bool   `json:"simulated"`
}

type rotatingAccountProjection struct {
	Account    string   `json:"account"`
	Authorizer string   `json:"authorizer"`
	Alerts     []string `json:"alerts,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

type rotateStatusProjection struct {
	Accounts []rotatingAccountProjection `json:"accounts"`
}

// cmdRotate sends a rotate-only spend or reports rotating accounts.
func (r *REPLState) cmdRotate(args []string, _ interface{}) (command.Result, error) {
	if len(args) >= 1 && args[0] == "status" {
		if len(args) > 2 {
			return nil, fmt.Errorf("usage: %s", rotateUsage)
		}
		account := ""
		if len(args) == 2 {
			account = args[1]
		}
		return r.runRotateStatus(account)
	}
	if len(args) < 1 || len(args) > 2 || (len(args) == 2 && args[1] != "nowait") {
		return nil, fmt.Errorf("usage: %s", rotateUsage)
	}
	result, err := r.app().Rotate(r.commandContext(), apshellapp.RotateRequest{
		Account: args[0],
		Wait:    len(args) == 1,
	})
	if err != nil {
		return nil, err
	}
	simulated := r.app().IsSimulateEnabled()
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() {
			r.renderSubmissionOutput(result.Output)
			r.renderWarnings(result.Warnings)
			if simulated {
				return
			}
			r.printf("Rotate-only spend submitted: %s\n", result.TxID)
			if result.Confirmed {
				r.printf("Rotated %s: authorizer %s -> %s\n",
					r.app().FormatAddress(result.Account, ""), result.PreviousAuthorizer, result.Authorizer)
			}
		})
	}, rotateProjection{
		Account: result.Account, PreviousAuthorizer: result.PreviousAuthorizer, Authorizer: result.Authorizer,
		TxID: result.TxID, Confirmed: result.Confirmed, Simulated: simulated,
	})
}

func (r *REPLState) runRotateStatus(account string) (command.Result, error) {
	result, err := r.app().RotateStatus(r.commandContext(), account)
	if err != nil {
		return nil, err
	}
	projection := rotateStatusProjection{Accounts: []rotatingAccountProjection{}}
	for _, status := range result.Accounts {
		projection.Accounts = append(projection.Accounts, rotatingAccountProjection{
			Account: status.Account, Authorizer: status.Authorizer, Alerts: status.Alerts, Notes: status.Notes,
		})
	}
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() {
			if len(result.Accounts) == 0 {
				r.printf("No rotating accounts\n")
				return
			}
			for _, status := range result.Accounts {
				r.printf("%s\n  authorizer: %s\n", r.app().FormatAddress(status.Account, ""), status.Authorizer)
				if len(status.Alerts) == 0 {
					r.printf("  alerts: none\n")
				}
				for _, alert := range status.Alerts {
					r.printf("  ALERT: %s\n", alert)
				}
				for _, note := range status.Notes {
					r.printf("  note: %s\n", note)
				}
			}
		})
	}, projection)
}
