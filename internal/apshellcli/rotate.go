// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

const rotateUsage = "rotate <account> [nowait] | rotate status [<account>] | rotate recover <account> [--stage N] [--window W] [--max-stages M] [--timeout SECONDS] | rotate recover <account> cancel"

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
	// Signer is the signer's own view of the account: observed authorizer,
	// classification, cached stages and recovery state.
	Signer *signerapi.RotatingAccountStatus `json:"signer,omitempty"`
}

type rotateStatusProjection struct {
	Accounts []rotatingAccountProjection `json:"accounts"`
}

type rotateRecoverProjection struct {
	Account  string                           `json:"account"`
	Action   string                           `json:"action"`
	GrantID  uint64                           `json:"grant_id,omitempty"`
	Recovery signerapi.RotatingRecoveryStatus `json:"recovery"`
}

// cmdRotate sends a rotate-only spend, reports rotating accounts, or asks
// the signer to search for an account's live stage.
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
	if len(args) >= 1 && args[0] == "recover" {
		req, err := parseRotateRecover(args[1:])
		if err != nil {
			return nil, err
		}
		return r.runRotateRecover(req)
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

// parseRotateRecover parses `rotate recover <account> [...]`: the account,
// then either `cancel` or any of the search options.
func parseRotateRecover(args []string) (apshellapp.RotateRecoverRequest, error) {
	usage := fmt.Errorf("usage: %s", rotateUsage)
	if len(args) < 1 {
		return apshellapp.RotateRecoverRequest{}, usage
	}
	req := apshellapp.RotateRecoverRequest{Account: args[0]}
	rest := args[1:]
	if len(rest) >= 1 && rest[0] == "cancel" {
		if len(rest) != 1 {
			return apshellapp.RotateRecoverRequest{}, usage
		}
		req.Cancel = true
		return req, nil
	}
	number := func(flag, value string) (uint64, error) {
		n, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%s: %q is not a non-negative integer", flag, value)
		}
		return n, nil
	}
	for i := 0; i < len(rest); i++ {
		flag := rest[i]
		if !strings.HasPrefix(flag, "--") || i+1 >= len(rest) {
			return apshellapp.RotateRecoverRequest{}, usage
		}
		value := rest[i+1]
		i++
		n, err := number(flag, value)
		if err != nil {
			return apshellapp.RotateRecoverRequest{}, err
		}
		switch flag {
		case "--stage":
			req.Stage = &n
		case "--window":
			req.Window = n
		case "--max-stages":
			req.MaxStages = n
		case "--timeout":
			req.TimeoutSeconds = int64(n)
		default:
			return apshellapp.RotateRecoverRequest{}, usage
		}
	}
	if req.Window != 0 && req.Stage == nil {
		return apshellapp.RotateRecoverRequest{}, fmt.Errorf("--window needs --stage")
	}
	return req, nil
}

func (r *REPLState) runRotateRecover(req apshellapp.RotateRecoverRequest) (command.Result, error) {
	result, err := r.app().RotateRecover(r.commandContext(), req)
	if err != nil {
		return nil, err
	}
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() {
			account := r.app().FormatAddress(result.Account, "")
			switch {
			case result.Action == signerapi.RotatingRecoverActionCancel && result.GrantID == 0:
				r.printf("%s: no recovery was running\n", account)
			case result.Action == signerapi.RotatingRecoverActionCancel:
				r.printf("%s: recovery grant %d cancelled\n", account, result.GrantID)
			default:
				r.printf("%s: recovery grant %d started; the signer searches in the background, watch `rotate status`\n", account, result.GrantID)
			}
			renderRecoveryStatus(r, "  ", &result.Recovery)
		})
	}, rotateRecoverProjection{Account: result.Account, Action: result.Action, GrantID: result.GrantID, Recovery: result.Recovery})
}

func (r *REPLState) runRotateStatus(account string) (command.Result, error) {
	result, err := r.app().RotateStatus(r.commandContext(), account)
	if err != nil {
		return nil, err
	}
	projection := rotateStatusProjection{Accounts: []rotatingAccountProjection{}}
	for _, status := range result.Accounts {
		projection.Accounts = append(projection.Accounts, rotatingAccountProjection{
			Account: status.Account, Authorizer: status.Authorizer, Alerts: status.Alerts, Notes: status.Notes, Signer: status.Signer,
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
				if s := status.Signer; s != nil {
					renderSignerRotatingView(r, "  ", s)
				}
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

// renderSignerRotatingView prints the signer's classification, cached
// stages and recovery state for one account.
func renderSignerRotatingView(r *REPLState, indent string, s *signerapi.RotatingAccountStatus) {
	switch s.Classification {
	case signerapi.RotatingClassStage:
		if s.Stage != nil {
			r.printf("%ssigner: live stage %d, %d stages cached\n", indent, *s.Stage, s.CachedStages)
		}
	case signerapi.RotatingClassHeldKey:
		r.printf("%ssigner: rekeyed to a key this signer holds, %d stages cached\n", indent, s.CachedStages)
	case signerapi.RotatingClassUnknown:
		r.printf("%ssigner: authorizer not placed, %d stages cached\n", indent, s.CachedStages)
	default:
		r.printf("%ssigner: account not read in the last pass, %d stages cached\n", indent, s.CachedStages)
	}
	renderRecoveryStatus(r, indent, s.Recovery)
}

func renderRecoveryStatus(r *REPLState, indent string, rec *signerapi.RotatingRecoveryStatus) {
	if rec == nil {
		return
	}
	if rec.Active {
		line := fmt.Sprintf("%srecovery: %s grant %d running, %d of %d stages used", indent, rec.Kind, rec.GrantID, rec.StagesCharged, rec.MaxStages)
		if rec.FoundStage != nil {
			line += fmt.Sprintf(", stage %d found, filling the cache", *rec.FoundStage)
		} else if rec.Hint != nil {
			line += fmt.Sprintf(", probing around stage %d", *rec.Hint)
		}
		r.printf("%s\n", line)
	} else if rec.Stopped != "" {
		line := fmt.Sprintf("%srecovery: last %s grant %d stopped: %s", indent, rec.StoppedKind, rec.StoppedGrantID, rec.Stopped)
		if rec.StoppedStage != nil {
			line += fmt.Sprintf(" (stage %d)", *rec.StoppedStage)
		}
		r.printf("%s\n", line)
	}
	if rec.AllowanceMax > 0 {
		r.printf("%sautomatic allowance: %d of %d stages used this unlock\n", indent, rec.AllowanceSpent, rec.AllowanceMax)
	} else {
		r.printf("%sautomatic recovery: disabled\n", indent)
	}
	if rec.SuppressedAuthorizer != "" {
		r.printf("%sautomatic recovery exhausted for authorizer %s\n", indent, rec.SuppressedAuthorizer)
	}
}
