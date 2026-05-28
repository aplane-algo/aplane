// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/asa"
)

func (r *REPLState) renderSendResult(result *apshellapp.SendExecutionResult) error {
	if result == nil {
		return fmt.Errorf("send result is nil")
	}

	switch result.Mode {
	case apshellapp.SendModeAtomicFromMultiple:
		return r.renderAtomicFromMultipleSendResult(result)
	case apshellapp.SendModeAtomicToMultiple:
		return r.renderAtomicToMultipleSendResult(result)
	case apshellapp.SendModeNonAtomic:
		return r.renderNonAtomicSendResult(result)
	default:
		return fmt.Errorf("unsupported send mode: %s", result.Mode)
	}
}

func (r *REPLState) renderNonAtomicSendResult(result *apshellapp.SendExecutionResult) error {
	nonAtomic := result.NonAtomic
	if nonAtomic == nil {
		return fmt.Errorf("non-atomic send result is nil")
	}

	if len(result.From) > 1 {
		r.printf("Sending from %d addresses to %s\n", len(result.From), r.app().FormatAddress(result.To[0], ""))
	} else if len(result.To) > 1 {
		r.printf("Sending to %d addresses\n", len(result.To))
	}

	for idx, item := range nonAtomic.Items {
		if len(nonAtomic.Items) > 1 {
			if nonAtomic.FromCount > 1 {
				r.printf("\n[%d/%d] Sending from %s to %s\n", idx+1, len(nonAtomic.Items),
					r.app().FormatAddress(item.From, ""), r.app().FormatAddress(item.To, ""))
			} else {
				r.printf("\n[%d/%d] Sending to %s\n", idx+1, len(nonAtomic.Items), r.app().FormatAddress(item.To, ""))
			}
		}
		r.renderSendItemResult(item, nonAtomic.Amount, result.Wait, result.Note)
		if item.Error != "" {
			if r.app().IsSimulateEnabled() {
				r.printf("\n✗ Simulation failed: %v\n", item.Error)
			} else {
				r.printf("\n✗ Failed: %v\n", item.Error)
			}
		}
	}

	if len(nonAtomic.Items) > 1 {
		r.printf("\n=== Summary ===\n")
		r.printf("Successful: %d/%d\n", nonAtomic.SuccessCount, len(nonAtomic.Items))
		if nonAtomic.FailureCount > 0 {
			r.printf("Failed: %d/%d\n", nonAtomic.FailureCount, len(nonAtomic.Items))
		}
		if nonAtomic.FailureCount > 0 && nonAtomic.SuccessCount == 0 && nonAtomic.LastError != "" {
			return fmt.Errorf("%s", nonAtomic.LastError)
		}
	}

	return nil
}

func (r *REPLState) renderSendItemResult(item apshellapp.SendItemResult, amount asa.Amount, wait bool, note string) {
	assetName := asa.DisplayRef(amount.Meta)
	r.renderWarnings(item.Warnings)

	amountStr := asa.FormatDisplayAmount(amount.Raw, amount.Meta)
	r.printf("Sending %s %s from %s to %s using %s...\n",
		amountStr, assetName, r.app().FormatAddress(item.From, ""), r.app().FormatAddress(item.To, ""), item.SigningKeyType)
	if note != "" {
		r.printf("Note: %s\n", note)
	}
	r.renderSubmissionOutput(item.Output)
	if item.Error != "" {
		return
	}
	if !r.app().IsSimulateEnabled() && item.TxID != "" {
		r.printf("Transaction submitted: %s\n", item.TxID)
	}
	if wait && item.Confirmed {
		r.printf("Confirmed: sent %s %s to %s\n",
			amountStr, assetName, r.app().FormatAddress(item.To, ""))
	}
}

func (r *REPLState) renderAtomicToMultipleSendResult(result *apshellapp.SendExecutionResult) error {
	atomic := result.Atomic
	if atomic == nil {
		return fmt.Errorf("atomic send result is nil")
	}

	r.printf("Building atomic transaction group: %s → %d receivers\n",
		r.app().FormatAddress(result.From[0], ""), len(result.To))
	for _, note := range atomic.ValidationNotes {
		r.println(note)
	}

	amountStr := asa.FormatDisplayAmount(atomic.Amount.Raw, atomic.Amount.Meta)
	assetName := asa.DisplayRef(atomic.Amount.Meta)
	r.printf("\nAtomic transaction group (%d transactions):\n", len(atomic.To))
	for i, to := range atomic.To {
		r.printf("  %d. Send %s %s to %s\n", i+1, amountStr, assetName, r.app().FormatAddress(to, ""))
	}
	r.println()
	r.printAtomicSendResult(atomic)
	return nil
}

func (r *REPLState) renderAtomicFromMultipleSendResult(result *apshellapp.SendExecutionResult) error {
	atomic := result.Atomic
	if atomic == nil {
		return fmt.Errorf("atomic send result is nil")
	}

	r.printf("Building atomic transaction group: %d senders → %s\n",
		len(result.From), r.app().FormatAddress(result.To[0], ""))
	for _, note := range atomic.ValidationNotes {
		r.println(note)
	}

	amountStr := asa.FormatDisplayAmount(atomic.Amount.Raw, atomic.Amount.Meta)
	assetName := asa.DisplayRef(atomic.Amount.Meta)
	r.printf("\nAtomic transaction group (%d transactions):\n", len(atomic.From))
	for i, from := range atomic.From {
		r.printf("  %d. %s sends %s %s to %s\n",
			i+1, r.app().FormatAddress(from, ""), amountStr, assetName, r.app().FormatAddress(atomic.To[0], ""))
	}
	totalUnits := atomic.Amount.Raw * uint64(len(atomic.From))
	totalStr := asa.FormatDisplayAmount(totalUnits, atomic.Amount.Meta)
	r.printf("Total received by %s: %s %s\n", r.app().FormatAddress(atomic.To[0], ""), totalStr, assetName)
	r.println()
	r.printAtomicSendResult(atomic)
	return nil
}

func (r *REPLState) printAtomicSendResult(result *apshellapp.AtomicSendResult) {
	r.renderSubmissionOutput(result.Output)
	r.renderWarnings(result.Warnings)
	if !r.app().IsSimulateEnabled() {
		r.printf("✓ Atomic transaction group submitted successfully\n")
		r.printf("Group contains %d transaction(s)\n", len(result.TxIDs))
		if len(result.TxIDs) > 0 {
			r.printf("First transaction ID: %s\n", result.TxIDs[0])
		}
	}
}
