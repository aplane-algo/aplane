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
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
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

// rekeyToList is the account's rekey-to list, under only these or plus
// cosigned. A template without a list may have a parameter of the same name,
// which is not one.
func rekeyToList(review PrepareGenerateResultMessage) []string {
	if review.Bounded == nil || !review.Bounded.RekeyList {
		return nil
	}
	value := strings.TrimSpace(review.Parameters[boundedmeta.RekeyListEntriesParameter])
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
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
	setting := boundedmeta.RekeySetting(review.Bounded.Rekey)
	cosigned := review.Bounded.CosignerRequired
	plain := review.Bounded.Contract == boundedmeta.PlainContract
	if review.Bounded.RekeyList {
		count := len(rekeyToList(review))
		these, them := fmt.Sprintf("these %d addresses", count), "any of them"
		if count == 1 {
			these, them = "this address", "it"
		}
		consequence = "The spending key alone can hand the account to " + them + ", at any time."
		if setting == boundedmeta.RekeySpendingKey {
			// Plus cosigned: the listed targets, and any other the cosigner allows.
			short := fmt.Sprintf("These %d", count)
			if count == 1 {
				short = "This one"
			}
			return short + ", spending key alone; others need the cosigner",
				"The spending key alone can hand the account to " + them + ". Any other rekey needs both online keys."
		}
		// On a cosigned account the label's "spending key alone" says the cosigner
		// is not asked; the screen has no room to say it twice.
		if isTimelockPolicy(review.Bounded.Layer3Policy) {
			consequence += " That is a way around the lock."
		}
		return "Only " + these + ", spending key alone", consequence
	}
	switch setting {
	case boundedmeta.RekeyRefused:
		if plain && cosigned {
			// A plain host can always close out, with the cosigner.
			return "None", "No rekey path. Every spend, closes included, needs the cosigner."
		}
		if plain {
			return "None", "No rekey path. The spending key alone can spend or close everything."
		}
		return "None", "No rekey path. Losing a required authority cannot be repaired."
	case boundedmeta.RekeySpendingKey:
		if cosigned {
			return "Spending key and cosigner", "Together they can rekey out of this boundary, to a target both nodes' policies allow."
		}
		return "Spending key alone", "That key can rekey out of this boundary."
	default:
		return "Unknown authority " + review.Bounded.Rekey, "This client cannot describe that rekey path."
	}
}

// reviewRecipients describes who the account can pay, decided by its policy and never
// by a parameter's name: a template can call its list anything, or give a parameter
// called recipients to code the framework does not check. Overstating what an account
// can pay is the mistake to avoid, so only the policies with no list say "any". A
// policy this client does not know claims neither: it is named, with the details.
func reviewRecipients(contract, policy string, cosigned bool, recipients []string) (row, note string) {
	switch {
	case contract == boundedmeta.PlainContract && cosigned:
		return reviewRow("Recipients", "any; the cosigner's policy decides what it signs"), ""
	case contract == boundedmeta.PlainContract:
		return reviewRow("Recipients", "any; the spending key alone decides"), ""
	case policy == boundedmeta.Layer3PolicyCustom:
		return reviewRow("Policy", "Custom policy, from the template author's code"), ""
	case policy == boundedmeta.Layer3PolicyTimelock:
		return reviewRow("Recipients", "any, once unlocked"), ""
	case policy == boundedmeta.Layer3PolicyNone:
		return reviewRow("Recipients", "any; only the fee limit and transfer kinds apply"), ""
	case !boundedmeta.IsRecipientListPolicy(policy):
		return reviewRow("Policy", fmt.Sprintf("%s, see details", policy)), ""
	}
	encoding := "inline"
	note = "The whole list is public once the program is published."
	if isMerklePolicy(policy) {
		encoding = "Merkle"
		note = "A spend reveals its recipient and proof, so the list is only partly hidden."
	}
	if isCustomPolicy(policy) {
		encoding += ", custom policy"
	}
	if len(recipients) == 0 {
		return reviewRow("Recipients", fmt.Sprintf("restricted, %s, see details", encoding)), note
	}
	digest := boundary.RecipientListDigest(strings.Join(recipients, ","))
	return reviewRow("Recipients", fmt.Sprintf("%d, %s, list %s", len(recipients), encoding, digest[:12])), note
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
	sb.WriteString(reviewRow("Transfers", transfersLabel(profile)))
	row, note := reviewRecipients(profile.Contract, profile.Layer3Policy, profile.CosignerRequired, recipientList(review.Parameters))
	// A plain host on a classical base, such as Ed25519, has a classical spending
	// key; say so where it is chosen.
	if construction, ok := sigconstruction.ForBaseKeyType(review.KeyType); profile.Contract == boundedmeta.PlainContract && ok && !construction.PostQuantum() {
		note = strings.TrimSpace(note + " The " + displayKeyType(review.KeyType) + " spending key is classical, not post-quantum.")
	}
	sb.WriteString(row)
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
	field("Rekey protection", wrapText(reviewRekeyProtection(*review), 64))
	field("Cosigner Witness Key ID", review.CosignerKeyID)
	if review.BoundaryDigest != "" {
		field("Grammar fingerprint", review.ReviewFingerprint)
		field("Selected-shape fingerprint", review.Fingerprint)
		field("Boundary digest", review.BoundaryDigest)
	} else {
		field("Template fingerprint", review.ReviewFingerprint)
	}
	for _, name := range reviewDetailParameters(*review) {
		field(name, wrapLongValue(review.Parameters[name]))
	}
	if recipients := recipientList(review.Parameters); len(recipients) > 0 {
		sb.WriteString(fmt.Sprintf("Recipients (%d):\n", len(recipients)))
		for _, recipient := range recipients {
			sb.WriteString("  " + recipient + "\n")
		}
	}
	if targets := rekeyToList(*review); len(targets) > 0 {
		postQuantum, known := reviewSpendingKeyPostQuantum(*review)
		sb.WriteString(fmt.Sprintf("Rekey-to addresses (%d):\n", len(targets)))
		for _, target := range targets {
			sb.WriteString("  " + target + "\n")
			if note := m.rekeyTargetNote(target, postQuantum && known); note != "" {
				sb.WriteString(indentLines(wrapText(note, 64), "    ") + "\n")
			}
		}
		cosigner := ""
		if review.Bounded.CosignerRequired {
			cosigner = ", without the cosigner and outside its policy"
		}
		unknown := ""
		if !known {
			unknown = " This client can't tell whether this key type's spending key is post-quantum; " +
				"if it is, list only post-quantum keys, since an address doesn't reveal its key type."
		}
		sb.WriteString(wrapText("Each listed address can take the account over with the spending key alone, "+
			"at any time"+cosigner+"; in a mesh, each is an exit. "+
			"The list is in the key's backup and can't be used without it."+unknown, 68) + "\n")
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
		CosignerKeyID:      review.CosignerKeyID,
		GrammarFingerprint: review.ReviewFingerprint,
		ShapeFingerprint:   review.Fingerprint,
		BoundaryDigest:     review.BoundaryDigest,
	}
	return m
}

// reviewDetailParameters is every resolved parameter the details have not already
// shown, sorted so the screen is stable. Custom templates name their own, so this
// lists what is there rather than what is expected. The cosigner key is left out
// because its Witness Key ID above identifies it.
func reviewDetailParameters(review PrepareGenerateResultMessage) []string {
	names := make([]string, 0, len(review.Parameters))
	listed := rekeyToList(review) != nil
	for name := range review.Parameters {
		switch {
		case name == recipientsParameter, name == boundedmeta.CosignerPublicKeyParameter:
			continue
		case name == boundedmeta.RekeyListEntriesParameter && listed:
			// Shown below as the rekey-to list.
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

// rekeyTargetNote flags a listed address this signer holds: a compromise of the
// signer could then take the account through it. On a post-quantum account it
// also says which held targets are classical, and asks the operator to confirm
// the rest: an address alone doesn't reveal its key type.
func (m Model) rekeyTargetNote(address string, postQuantum bool) string {
	for _, key := range m.keylist.keys {
		if key.Address != address {
			continue
		}
		note := "held by this signer: a compromise of this signer can take the account through it"
		if !postQuantum {
			return note
		}
		switch pq, known := keyTypePostQuantum(key.KeyType); {
		case known && !pq:
			note += "; a classical key, so the account would be classical after a handover"
		case !known:
			note += "; confirm it is a post-quantum key"
		}
		return note
	}
	if postQuantum {
		return "not held by this signer: confirm it is a post-quantum key"
	}
	return ""
}

// keyTypePostQuantum classifies a held key's spending authority, where this
// client knows it: the native types and the LogicSig bases, and the general
// bounded type, whose base is Falcon-1024.
func keyTypePostQuantum(keyType string) (postQuantum, known bool) {
	if construction, ok := sigconstruction.ForBaseKeyType(keyType); ok {
		return construction.PostQuantum(), true
	}
	switch strings.ToLower(strings.TrimSpace(keyType)) {
	case "ed25519":
		return false, true
	case "falcon1024", boundary.KeyTypeV1:
		return true, true
	}
	return false, false
}

// reviewSpendingKeyPostQuantum reports whether the new account's spending key
// is post-quantum, where the key type tells this client: a plain host's base,
// and the general type's Falcon-1024. The contract alone doesn't: an expert
// template may put bounded2 on an Ed25519 base, and the inventory doesn't name
// a template's base.
func reviewSpendingKeyPostQuantum(review PrepareGenerateResultMessage) (postQuantum, known bool) {
	return keyTypePostQuantum(review.KeyType)
}

// reviewRekeyProtection says which kind of protection the rekey setting is: only
// a refused rekey and only these bound where authority can go independently of
// the online keys.
func reviewRekeyProtection(review PrepareGenerateResultMessage) string {
	profile := review.Bounded
	switch setting := boundedmeta.RekeySetting(profile.Rekey); {
	case setting != boundedmeta.RekeyRefused && setting != boundedmeta.RekeySpendingKey:
		return "This client cannot describe that rekey setting, so it claims no protection for it."
	case profile.RekeyList && setting == boundedmeta.RekeyRefused:
		return "Independent of the online keys: rekeys go only to the listed addresses."
	case profile.RekeyList:
		return "As strong as its two online keys: together they can rekey it anywhere their policies allow."
	case setting == boundedmeta.RekeyRefused:
		return "Independent of the online keys: no key can rekey it."
	case profile.CosignerRequired:
		return "As strong as its two online keys: together they can rekey it anywhere their policies allow."
	default:
		return "As strong as the spending key: it alone can rekey it anywhere."
	}
}

// indentLines indents every line of text.
func indentLines(text, prefix string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}

// transfersLabel names what the account may spend and its fee limit. A plain
// host has neither rule: every transaction that doesn't rekey is a spend.
func transfersLabel(profile *protocol.PreparedBoundedProfile) string {
	if profile.MaxFee == nil {
		return "Any transaction, no fee limit"
	}
	return fmt.Sprintf("%s, fee limit %d", spendEffectsLabel(profile.SpendEffects), *profile.MaxFee)
}
