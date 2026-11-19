// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/termsafe"
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
	// SignerViewDiffers is set when signer, the signer's last finished
	// pass, is of another authorizer than authorizer, which apshell read
	// now. When signer is absent the signer reported no view at all.
	SignerViewDiffers bool `json:"signer_view_differs,omitempty"`
	// Signer is the signer's own view of the account: observed authorizer,
	// classification, cached entry count and recovery state.
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
func (r *REPLState) cmdRotate(args []string, _ *command.Context) (command.Result, error) {
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
					r.app().FormatAddress(result.Account), result.PreviousAuthorizer, result.Authorizer)
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
	seen := cmdspec.SeenOptions{}
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
		// Each option is single-valued; an unknown one is refused below.
		if err := seen.Once(flag); err != nil {
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
			account := r.app().FormatAddress(result.Account)
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
			Account: status.Account, Authorizer: status.Authorizer, Alerts: status.Alerts, Notes: status.Notes,
			SignerViewDiffers: status.SignerViewDiffers, Signer: status.Signer,
		})
	}
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() {
			if len(result.Accounts) == 0 {
				r.printf("No rotating accounts\n")
				return
			}
			for _, status := range result.Accounts {
				r.printf("%s\n  authorizer: %s\n", r.app().FormatAddress(status.Account), status.Authorizer)
				renderSignerRotatingView(r, "  ", status.Signer, status.SignerViewDiffers)
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

// renderSignerRotatingView prints the signer's classification, cached entry
// count (sparse records, not coverage from stage 0) and recovery state for one
// account.
//
// The authorizer printed above is read from apshell's algod now. The signer's
// view is from its last finished pass, which read the signer's algod when it
// began. differs says the signer saw another authorizer. Most often a spend
// confirmed after the signer's read; it can also be apshell's node that is
// behind, or the two reading different networks, and nothing here can tell
// which. So the line claims no direction: it names what the signer saw and
// when, does not call that stage live, leaves out its readiness, and the
// lines after it say that the alerts and notes below come from the same read.
func renderSignerRotatingView(r *REPLState, indent string, s *signerapi.RotatingAccountStatus, differs bool) {
	if s == nil {
		r.printf("%ssigner: no view of this account in its status; it reports the keys it holds after a background pass, while unlocked\n", indent)
		return
	}
	lead := indent + "signer: "
	preparation := ", " + termsafe.Line(s.Preparation)
	if differs {
		lead += "sees another authorizer; "
		if s.Round != 0 {
			lead += fmt.Sprintf("at round %d ", s.Round)
		}
		lead += fmt.Sprintf("it saw %s, ", termsafe.Line(s.Authorizer))
		// Readiness is of the stage the signer saw, not of the authorizer above.
		preparation = ""
	}
	switch s.Classification {
	case signerapi.RotatingClassStage:
		switch {
		case s.Stage == nil:
			// A signer that names no stage still gets its line, so the lines
			// that follow a differing view are never left without it.
			r.printf("%sa stage it did not number%s, %d cached entries\n", lead, preparation, s.CachedEntries)
		case differs:
			r.printf("%sstage %d%s, %d cached entries\n", lead, *s.Stage, preparation, s.CachedEntries)
		default:
			r.printf("%slive stage %d%s, %d cached entries\n", lead, *s.Stage, preparation, s.CachedEntries)
		}
	case signerapi.RotatingClassHeldKey:
		r.printf("%srekeyed to a key this signer holds, %d cached entries\n", lead, s.CachedEntries)
	case signerapi.RotatingClassUnknown:
		r.printf("%sauthorizer not placed, %d cached entries\n", lead, s.CachedEntries)
	default:
		r.printf("%saccount not read in the last pass, %d cached entries\n", lead, s.CachedEntries)
	}
	if differs {
		r.printf("%s  this view, and any alert or note below, is from that read; the signer reads again on its next pass\n", indent)
		r.printf("%s  if the two still differ after that, apshell and the signer are reading different nodes or networks\n", indent)
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
			line += fmt.Sprintf(", stage %d found", *rec.FoundStage)
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
	if rec.Lookup != nil {
		r.printf("%slookup: %s\n", indent, stageLookupLine(rec.Lookup, rec.Active))
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

// stageLookupLine words the chain lookup a search began with. While the
// grant is active the search goes on, and the line says so; once it has
// stopped the line says only what the lookup found, and the stop line beside
// it says why the grant ended. The transaction ID came from the signer's
// Indexer and is escaped as request text is.
func stageLookupLine(l *signerapi.RotatingStageLookupStatus, active bool) string {
	spend := func(round bool) string {
		ref := ""
		if l.TxID != "" {
			ref = termsafe.Line(l.TxID)
		}
		if round && l.Round != 0 {
			if ref != "" {
				ref += ", "
			}
			ref += fmt.Sprintf("round %d", l.Round)
		}
		if ref == "" {
			return "the last spend"
		}
		return "the last spend (" + ref + ")"
	}
	stage := uint64(0)
	if l.Stage != nil {
		stage = *l.Stage
	}
	var now, then string
	switch l.Outcome {
	case signerapi.RotatingLookupCandidate:
		switch l.Probe {
		case signerapi.RotatingLookupProbeMatched:
			// The grant ends at once; there is no active form.
			line := fmt.Sprintf("stage %d was read from %s and confirmed", stage, spend(true))
			now, then = line, line
		case signerapi.RotatingLookupProbeMissed:
			then = fmt.Sprintf("stage %d read from %s did not match", stage, spend(false))
			now = then + "; searching"
		case signerapi.RotatingLookupProbeAlreadyCached:
			then = fmt.Sprintf("stage %d read from %s was not the authorizer's", stage, spend(false))
			now = fmt.Sprintf("stage %d read from %s is not the authorizer's; searching", stage, spend(false))
		default:
			then = fmt.Sprintf("stage %d read from %s was not tried", stage, spend(false))
			now = then + "; searching"
		}
	case signerapi.RotatingLookupUnavailable:
		then = "the Indexer could not be read"
		now = then + "; searching without it"
	case signerapi.RotatingLookupNoOutgoingRekey:
		then = "the Indexer showed no rekey sent by this account"
		now = "the Indexer shows no rekey sent by this account; searching"
	case signerapi.RotatingLookupNotCurrent:
		then = "the Indexer's newest rekey for this account was not the current one"
		now = "the Indexer's newest rekey for this account is not the current one; searching"
	case signerapi.RotatingLookupNotAStageProgram:
		then = "the account's last rekey was not signed by a stage program"
		now = then + "; searching"
	case signerapi.RotatingLookupWrongNetwork:
		then = "the Indexer answered for another network"
		now = then + "; searching without it"
	default:
		then = "outcome " + termsafe.Line(l.Outcome)
		now = then + "; searching"
	}
	if active {
		return now
	}
	return then
}
