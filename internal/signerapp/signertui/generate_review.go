// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	reviewFocusCancel = iota
	reviewFocusDetails
	reviewFocusGenerate
	reviewFocusCount

	reviewBodyWidth = 64
	reviewIDWidth   = 44

	recipientsParameter  = "recipients"
	unlockRoundParameter = "unlock_round"
)

// handlePreparedGeneration receives what a request would create. A bounded account
// goes to review. Anything else was never reviewed here, so it generates from the
// request as entered, exactly as it did before preparation existed.
func (m Model) handlePreparedGeneration(result PrepareGenerateResultMessage) (tea.Model, tea.Cmd) {
	if !result.Success {
		m.forms.generateError = result.Error
		m.viewState = m.generateErrorView()
		return m, m.waitForMessageCmd()
	}
	if result.Bounded == nil {
		id := m.beginOperation(ViewGenerating)
		return m, tea.Batch(m.sendGenerateKeyWithParamsCmd(result.KeyType, "", m.forms.pendingGenerateParams, id), m.waitForMessageCmd())
	}
	m.forms.review = &result
	m.forms.reviewFocus = reviewFocusCancel
	m.viewState = ViewGenerateReview
	return m, m.waitForMessageCmd()
}

func (m Model) generateErrorView() ViewState {
	if m.forms.boundaryFileRequest {
		return ViewBoundaryPreset
	}
	if m.forms.genericLSigParams != nil {
		return ViewGenerateParams
	}
	return ViewGenerateForm
}

func (m Model) handleGenerateReviewKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.forms.review = nil
		m.viewState = m.generateErrorView()
	case "tab", "right", "l":
		m.forms.reviewFocus = (m.forms.reviewFocus + 1) % reviewFocusCount
	case "shift+tab", "left", "h":
		m.forms.reviewFocus = (m.forms.reviewFocus + reviewFocusCount - 1) % reviewFocusCount
	case "d", "D":
		m.viewState = ViewGenerateReviewDetails
	case "enter", " ":
		switch m.forms.reviewFocus {
		case reviewFocusCancel:
			m.forms.review = nil
			m.viewState = m.generateErrorView()
		case reviewFocusDetails:
			m.viewState = ViewGenerateReviewDetails
		case reviewFocusGenerate:
			return m.submitReviewedGeneration()
		}
	}
	return m, nil
}

// submitReviewedGeneration sends the exact resolved values the operator reviewed,
// not the original request, so a reference edited since cannot substitute a
// different authority. The expected values let the signer refuse if anything else
// changed. They are comparisons: the signer repeats every check regardless.
func (m Model) submitReviewedGeneration() (tea.Model, tea.Cmd) {
	review := m.forms.review
	if review == nil {
		m.viewState = m.generateErrorView()
		return m, nil
	}
	id := m.beginOperation(ViewGenerating)
	m.forms.reviewedRequestID = id
	return m, tea.Batch(m.sendReviewedGenerateKeyCmd(*review, id), m.waitForMessageCmd())
}

func (m Model) handleGenerateReviewDetailsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q", "enter", "d", "D":
		m.viewState = ViewGenerateReview
	}
	return m, nil
}

func reviewRow(label, value string) string {
	return fmt.Sprintf("%-11s %s\n", label+":", value)
}

func spendEffectLabel(effect string) string {
	if effect == "asset_opt_in" {
		return "asset opt-in"
	}
	return effect
}

func spendEffectsLabel(effects []string) string {
	labels := make([]string, len(effects))
	for i, effect := range effects {
		labels[i] = spendEffectLabel(effect)
	}
	return strings.Join(labels, ", ")
}

func recipientList(parameters map[string]string) []string {
	value := strings.TrimSpace(parameters[recipientsParameter])
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func isMerklePolicy(policy string) bool {
	switch policy {
	case boundedmeta.Layer3PolicyMerkleAllowlist, boundedmeta.Layer3PolicyMerkleAllowlistCustom, boundedmeta.Layer3PolicyMerkleAllowlistTimelock:
		return true
	}
	return false
}

func isTimelockPolicy(policy string) bool {
	switch policy {
	case boundedmeta.Layer3PolicyTimelock, boundedmeta.Layer3PolicyFixedAllowlistTimelock, boundedmeta.Layer3PolicyMerkleAllowlistTimelock:
		return true
	}
	return false
}

func isCustomPolicy(policy string) bool {
	switch policy {
	case boundedmeta.Layer3PolicyCustom, boundedmeta.Layer3PolicyFixedAllowlistCustom, boundedmeta.Layer3PolicyMerkleAllowlistCustom:
		return true
	}
	return false
}

// reviewRekey states who can rekey the account and what that means, because the
// escape path is the most consequential choice on the screen.
func reviewRekey(review PrepareGenerateResultMessage) (label, consequence string) {
	profile := review.Bounded
	if len(profile.AdminOperations) == 0 {
		return "None", "No rekey path. Losing a required authority cannot be repaired."
	}
	operation := profile.AdminOperations[0]
	if operation.Authorization == boundedmeta.AdminAuthorizationAdmin {
		return "Spending key plus admin " + middleEllipsize(review.AdminKeyID, reviewIDWidth-29),
			"Admin rekey bypasses the allowlist and any cosigner."
	}
	if operation.PolicyGate == boundedmeta.PolicyGateLayer3 {
		return "Spending key, if the policy allows", "Rekey must pass the same policy as a spend."
	}
	return "Spending key alone", "That key can rekey out of this boundary."
}

// reviewUnlockRound names the round and what it depends on: the same number means
// a different time on another network. A template can call the parameter anything,
// so one that does not use the usual name points to the details.
func reviewUnlockRound(parameters map[string]string) string {
	if round := parameters[unlockRoundParameter]; round != "" {
		return "round " + round + " on the network it runs on"
	}
	return "a round set by this template; see details"
}

func (m Model) renderGenerateReview() string {
	review := m.forms.review
	if review == nil {
		return m.renderPopup(70, errorStyle.Render("No request to review"))
	}
	profile := review.Bounded
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("Review New Account"))
	sb.WriteString("\n\n")
	sb.WriteString(reviewRow("Key type", displayKeyType(review.KeyType)+", fixed once created"))
	sb.WriteString(reviewRow("Transfers", fmt.Sprintf("%s, fee limit %d", spendEffectsLabel(profile.SpendEffects), profile.MaxFee)))
	custom := isCustomPolicy(profile.Layer3Policy)
	var note string
	if recipients := recipientList(review.Parameters); len(recipients) > 0 {
		encoding := "inline"
		note = "The whole list is public once the program is published."
		if isMerklePolicy(profile.Layer3Policy) {
			encoding = "Merkle"
			note = "A spend reveals its recipient and proof, so the list is only partly hidden."
		}
		if custom {
			encoding += ", custom policy"
		}
		digest := boundary.RecipientListDigest(strings.Join(recipients, ","))
		sb.WriteString(reviewRow("Recipients", fmt.Sprintf("%d, %s, list %s", len(recipients), encoding, digest[:12])))
	} else if custom {
		sb.WriteString(reviewRow("Policy", "Custom policy, from the template author's code"))
	}
	rekey, consequence := reviewRekey(*review)
	sb.WriteString(reviewRow("Rekey", rekey))
	cosigner := "None"
	if profile.CosignerRequired {
		cosigner = "Required, " + middleEllipsize(review.CosignerKeyID, reviewIDWidth-10)
	}
	sb.WriteString(reviewRow("Cosigner", cosigner))
	// The extra row takes the spacer's place, so the buttons stay on screen. Custom
	// timelock code is a parameter here too, so the policy name alone cannot decide.
	if isTimelockPolicy(profile.Layer3Policy) || review.Parameters[unlockRoundParameter] != "" {
		sb.WriteString(reviewRow("Unlocks at", reviewUnlockRound(review.Parameters)))
	} else {
		sb.WriteString("\n")
	}
	sb.WriteString(subtitleStyle.Render(wrapText(strings.TrimSpace(note+" "+consequence), reviewBodyWidth)))
	sb.WriteString("\n\n")

	buttons := []string{"CANCEL", "DETAILS", "GENERATE"}
	rendered := make([]string, len(buttons))
	for i, label := range buttons {
		if i == m.forms.reviewFocus {
			rendered[i] = buttonActiveStyle.Render(label)
		} else {
			rendered[i] = buttonInactiveStyle.Render(label)
		}
	}
	sb.WriteString(lipgloss.JoinHorizontal(lipgloss.Center, rendered[0], "  ", rendered[1], "  ", rendered[2]))
	return m.renderPopup(72, sb.String())
}

// renderGenerateReviewDetails has everything the main review shortens, in full.
// It scrolls, so nothing here is truncated to fit.
func (m Model) renderGenerateReviewDetails() string {
	review := m.forms.review
	if review == nil {
		return m.renderPopup(70, errorStyle.Render("No request to review"))
	}
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("Review Details"))
	sb.WriteString("\n\n")
	field := func(label, value string) {
		if value == "" {
			return
		}
		sb.WriteString(label + ":\n  " + value + "\n")
	}
	field("Policy", review.Bounded.Layer3Policy)
	field("Contract admin Witness Key ID", review.AdminKeyID)
	field("Cosigner Witness Key ID", review.CosignerKeyID)
	if review.BoundaryDigest != "" {
		field("Grammar fingerprint", review.ReviewFingerprint)
		field("Selected-shape fingerprint", review.Fingerprint)
		field("Boundary digest", review.BoundaryDigest)
	} else {
		field("Template fingerprint", review.ReviewFingerprint)
	}
	for _, name := range reviewDetailParameters(review.Parameters) {
		field(name, wrapLongValue(review.Parameters[name]))
	}
	if recipients := recipientList(review.Parameters); len(recipients) > 0 {
		sb.WriteString(fmt.Sprintf("Recipients (%d):\n", len(recipients)))
		for _, recipient := range recipients {
			sb.WriteString("  " + recipient + "\n")
		}
	}
	return m.renderPopup(72, sb.String())
}

// settleGenerateReview ends the review with the generation result. A receipt comes
// only from the request sent from review and only for the account it created, so
// no other result, before or after, can inherit these values.
func (m Model) settleGenerateReview(result GenerateResultMsg) Model {
	review := m.forms.review
	reviewed := review != nil && m.forms.reviewedRequestID != "" && result.ID == m.forms.reviewedRequestID
	m.forms.review = nil
	m.forms.reviewedRequestID = ""
	m.forms.receipt = nil
	m.forms.receiptPath = ""
	m.forms.receiptError = ""
	if !reviewed || !result.Success || review.BoundaryDigest == "" || result.KeyType != review.KeyType {
		return m
	}
	m.forms.receipt = &boundary.Receipt{
		Address:            result.Address,
		KeyType:            result.KeyType,
		Parameters:         review.Parameters,
		AdminKeyID:         review.AdminKeyID,
		CosignerKeyID:      review.CosignerKeyID,
		GrammarFingerprint: review.ReviewFingerprint,
		ShapeFingerprint:   review.Fingerprint,
		BoundaryDigest:     review.BoundaryDigest,
	}
	return m
}

// reviewDetailParameters is every resolved parameter the details have not already
// shown, sorted so the screen is stable. Custom templates name their own, so this
// lists what is there rather than what is expected. The authority keys are left
// out because their Witness Key IDs above identify them.
func reviewDetailParameters(parameters map[string]string) []string {
	names := make([]string, 0, len(parameters))
	for name := range parameters {
		switch name {
		case recipientsParameter, boundedmeta.AdminPublicKeyParameter, boundedmeta.CosignerPublicKeyParameter:
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// wrapLongValue breaks a value with no spaces so all of it stays on screen.
func wrapLongValue(value string) string {
	const width = 64
	var sb strings.Builder
	for len(value) > width {
		sb.WriteString(value[:width] + "\n  ")
		value = value[width:]
	}
	sb.WriteString(value)
	return sb.String()
}

// generatedReceipt is the receipt for the account on screen, if it has one.
func (m Model) generatedReceipt() (boundary.Receipt, bool) {
	if m.forms.receipt == nil || m.forms.receipt.Address != m.forms.generatedAddress {
		return boundary.Receipt{}, false
	}
	return *m.forms.receipt, true
}

// saveGeneratedReceipt writes the receipt beside where apadmin runs. It refuses to
// overwrite, so a receipt on disk always names the account it was written for.
func (m Model) saveGeneratedReceipt() Model {
	receipt, ok := m.generatedReceipt()
	if !ok {
		return m
	}
	encoded, err := receipt.Encode()
	if err != nil {
		m.forms.receiptError = err.Error()
		return m
	}
	path, err := filepath.Abs(m.forms.generatedAddress + ".receipt.json")
	if err != nil {
		m.forms.receiptError = err.Error()
		return m
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		m.forms.receiptError = "save receipt: " + err.Error()
		return m
	}
	_, writeErr := file.Write(encoded)
	if closeErr := file.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		m.forms.receiptError = "save receipt: " + writeErr.Error()
		return m
	}
	m.forms.receiptError = ""
	m.forms.receiptPath = path
	return m
}
