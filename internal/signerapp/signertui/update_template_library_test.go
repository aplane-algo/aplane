// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
)

func TestLibraryTemplatesMsgPreservesServerOrder(t *testing.T) {
	m := Model{library: libraryState{selectedTemplate: 9}, height: 30}

	next, _ := m.Update(LibraryTemplatesMsg{
		Templates: []protocol.LibraryTemplateInfo{
			{KeyType: "z-key-v1", DisplayName: "Alpha"},
			{KeyType: "a-key-v1", DisplayName: "Zulu"},
			{KeyType: "m-key-v1", DisplayName: "Middle"},
		},
	})

	got := next.(Model)
	if len(got.library.templates) != 3 {
		t.Fatalf("template count = %d, want 3", len(got.library.templates))
	}
	wantOrder := []string{"z-key-v1", "a-key-v1", "m-key-v1"}
	for i, want := range wantOrder {
		if got.library.templates[i].KeyType != want {
			t.Fatalf("template[%d].KeyType = %q, want %q", i, got.library.templates[i].KeyType, want)
		}
	}
	if got.library.selectedTemplate != 2 {
		t.Fatalf("selectedTemplate = %d, want clamped index 2", got.library.selectedTemplate)
	}
}

func TestLockedSignerStatusFetchesKeyTypes(t *testing.T) {
	m := Model{
		viewState: ViewKeyList,
		auth:      authState{passphraseInput: "secret", passphraseError: "old error"},
	}

	next, cmd := m.Update(SignerStatusMsg{Locked: true, KeyCount: 12})
	got := next.(Model)
	if !got.signerLocked || !got.signerStatusKnown {
		t.Fatalf("signer status = locked %v known %v, want locked and known", got.signerLocked, got.signerStatusKnown)
	}
	if got.viewState != ViewUnlock {
		t.Fatalf("viewState = %v, want ViewUnlock", got.viewState)
	}
	if got.auth.passphraseInput != "" || got.auth.passphraseError != "" {
		t.Fatalf("passphrase state = input %q error %q, want cleared", got.auth.passphraseInput, got.auth.passphraseError)
	}
	if cmd == nil {
		t.Fatal("Update returned nil cmd, want wait, key-type fetch, and admin settings fetch")
	}
	msg := cmd()
	batch, ok := msg.(tea.BatchMsg)
	if !ok {
		t.Fatalf("cmd message type = %T, want tea.BatchMsg", msg)
	}
	if len(batch) != 3 {
		t.Fatalf("batch command count = %d, want wait, key-type fetch, and admin settings fetch", len(batch))
	}
}

func TestTemplateLibraryDescriptionIsSingleLineEllipsized(t *testing.T) {
	m := Model{width: 42, height: 30}
	tmpl := protocol.LibraryTemplateInfo{
		KeyType:     "long-description-v1",
		DisplayName: "Long Description",
		Description: "This is a deliberately long template description that should not wrap",
	}

	rendered := m.renderTemplateDetails(tmpl)
	if strings.Contains(rendered, "should not wrap") {
		t.Fatalf("description was not ellipsized:\n%s", rendered)
	}
	if !strings.Contains(rendered, "...") {
		t.Fatalf("description missing ellipsis:\n%s", rendered)
	}
}

func TestDisabledInstalledTemplateStatusIsDisabled(t *testing.T) {
	tmpl := protocol.LibraryTemplateInfo{
		KeyType:      "aplane.falcon1024-allowlist.v1",
		TemplateType: "falcon",
		Installed:    true,
		Enabled:      false,
	}

	if got := templateLibraryStatus(tmpl); got != "Disabled" {
		t.Fatalf("templateLibraryStatus() = %q, want Disabled", got)
	}
	if libraryEntryEnabled(tmpl) {
		t.Fatal("libraryEntryEnabled() = true, want false for disabled installed template")
	}
	if got := libraryActionVerb(tmpl); got != "enable" {
		t.Fatalf("libraryActionVerb() = %q, want enable", got)
	}
}

func TestCompiledProviderLifecycleVocabulary(t *testing.T) {
	inactive := protocol.LibraryTemplateInfo{
		KeyType:      "aplane.falcon1024.v1",
		TemplateType: libraryTypeCompiledProvider,
		Installed:    false,
	}
	if got := libraryActionVerb(inactive); got != "enable" {
		t.Fatalf("inactive compiled provider action = %q, want enable", got)
	}
	if got := libraryConfirmTitle(inactive); got != "Enable Key Type" {
		t.Fatalf("inactive compiled provider title = %q, want Enable Key Type", got)
	}

	active := inactive
	active.Installed = true
	if got := libraryActionVerb(active); got != "disable" {
		t.Fatalf("active compiled provider action = %q, want disable", got)
	}
	if got := libraryConfirmTitle(active); got != "Disable Key Type" {
		t.Fatalf("active compiled provider title = %q, want Disable Key Type", got)
	}
}

func TestTemplateLibraryViewKeyOpensDetailsViewerForYAMLEntry(t *testing.T) {
	m := Model{
		viewState: ViewTemplateLibrary,
		library: libraryState{selectedTemplate: 0, templates: []protocol.LibraryTemplateInfo{{
			KeyType:      "aplane.allowlist.v1",
			TemplateType: "generic",
			SourcePath:   "/tmp/keystore/library/templates/aplane.allowlist.v1.yaml",
		}}},
	}

	next, _ := m.handleTemplateLibraryKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'t'}})
	got := next.(Model)
	if got.viewState != ViewLibraryTemplateDetails {
		t.Fatalf("viewState after t = %v, want ViewLibraryTemplateDetails", got.viewState)
	}
	if !got.library.detailsLoading {
		t.Fatal("libraryDetailsLoading = false after t on YAML entry, want true")
	}
	if got.library.detailsKeyType != "aplane.allowlist.v1" || got.library.detailsTemplateType != "generic" {
		t.Fatalf("libraryDetailsKeyType/TemplateType = %q/%q, want aplane.allowlist.v1/generic", got.library.detailsKeyType, got.library.detailsTemplateType)
	}
	closed, _ := got.handleLibraryTemplateDetailsKeys(tea.KeyMsg{Type: tea.KeyEsc})
	if closed.(Model).viewState != ViewTemplateLibrary {
		t.Fatalf("viewState after closing library details = %v, want ViewTemplateLibrary", closed.(Model).viewState)
	}
}

func TestTemplateLibraryViewKeySynthesizesCompiledProviderDetails(t *testing.T) {
	tmpl := protocol.LibraryTemplateInfo{
		KeyType:      "aplane.ed25519.v1",
		TemplateType: libraryTypeCompiledProvider,
		DisplayName:  "Ed25519 LogicSig",
		Description:  "Ed25519 DSA provider",
		Parameters: []protocol.TemplateParamInfo{
			{Name: "threshold", Label: "Threshold", Type: "uint64", Required: true, Description: "Signing threshold"},
		},
	}
	m := Model{
		viewState: ViewTemplateLibrary,
		library:   libraryState{selectedTemplate: 0, templates: []protocol.LibraryTemplateInfo{tmpl}},
	}

	next, cmd := m.handleTemplateLibraryKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'t'}})
	got := next.(Model)
	if got.viewState != ViewLibraryTemplateDetails {
		t.Fatalf("viewState after t on compiled provider = %v, want ViewLibraryTemplateDetails", got.viewState)
	}
	if got.library.detailsLoading {
		t.Fatal("libraryDetailsLoading = true after t on compiled provider, want false (no IPC roundtrip)")
	}
	if cmd != nil {
		t.Fatalf("t on compiled provider returned cmd = %v, want nil (no IPC roundtrip)", cmd)
	}
	for _, want := range []string{"Source: built-in key type", "Publisher: aplane", "Ed25519 LogicSig", "Threshold", "Signing threshold"} {
		if !strings.Contains(got.library.detailsContent, want) {
			t.Fatalf("compiled provider details missing %q:\n%s", want, got.library.detailsContent)
		}
	}
}

func TestTemplateLibraryViewKeyRejectsMissingYAMLSource(t *testing.T) {
	m := Model{
		viewState: ViewTemplateLibrary,
		library: libraryState{selectedTemplate: 0, templates: []protocol.LibraryTemplateInfo{{
			KeyType:      "orphan-v1",
			TemplateType: "generic",
		}}},
	}

	next, _ := m.handleTemplateLibraryKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'t'}})
	got := next.(Model)
	if got.viewState != ViewTemplateLibrary {
		t.Fatalf("viewState after t on missing source = %v, want ViewTemplateLibrary unchanged", got.viewState)
	}
	if !strings.Contains(got.library.installError, "no plaintext library YAML source") {
		t.Fatalf("templateInstallError = %q, want missing-source message", got.library.installError)
	}
}

func TestLibraryDetailsViewerRendersSourceIntegrityMetadata(t *testing.T) {
	m := Model{
		viewState: ViewLibraryTemplateDetails,
		width:     100,
		height:    30,
		library:   libraryState{detailsLoading: true, detailsKeyType: "aplane.allowlist.v1", detailsTemplateType: "generic"},
	}

	next, _ := m.Update(ShowLibraryTemplateResultMsg{
		Success:       true,
		KeyType:       "aplane.allowlist.v1",
		TemplateType:  "generic",
		SourcePath:    "/tmp/keystore/library/templates/aplane.allowlist.v1.yaml",
		SourceSHA256:  "0123456789abcdef",
		SourceModTime: 1778600000,
		TemplateYAML:  []byte("schema_version: 1\n"),
	})
	got := next.(Model)
	if got.library.detailsSourceSHA256 != "0123456789abcdef" || got.library.detailsSourceModTime != 1778600000 {
		t.Fatalf("source metadata = %q/%d, want checksum and mtime", got.library.detailsSourceSHA256, got.library.detailsSourceModTime)
	}

	rendered := got.renderLibraryTemplateDetails()
	for _, want := range []string{"Library YAML: aplane.allowlist.v1", "Publisher: aplane", "SHA-256: 0123456789abcdef", "Modified: 2026-05-12 15:33:20 UTC"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered details missing %q:\n%s", want, rendered)
		}
	}
}

func TestCompiledProviderLibraryEntryUsesActivationLanguage(t *testing.T) {
	tmpl := protocol.LibraryTemplateInfo{
		KeyType:      "aplane.ed25519.v1",
		TemplateType: libraryTypeCompiledProvider,
		DisplayName:  "Ed25519 LogicSig",
		Description:  "Ed25519 DSA provider",
	}
	m := Model{
		viewState: ViewTemplateLibrary,
		width:     100,
		height:    30,
		library:   libraryState{selectedTemplate: 0, templates: []protocol.LibraryTemplateInfo{tmpl}},
	}

	rendered := m.View()
	for _, want := range []string{
		"KeyType Library",
		"dsa",
		"Disabled",
		"Source: built-in key type",
		"Publisher: aplane",
		"Toggle availability",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered library missing %q:\n%s", want, rendered)
		}
	}

	next, _ := m.handleTemplateLibraryKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if got.viewState != ViewTemplateInstallConfirm || got.library.pendingTemplate == nil {
		t.Fatalf("enter moved to %v pending=%#v, want enable confirm with pending template", got.viewState, got.library.pendingTemplate)
	}

	confirm := got.renderTemplateInstallConfirm()
	for _, want := range []string{"Enable Key Type", "Key type:  aplane.ed25519.v1", "Publisher: aplane", "Source:    dsa", "ENABLE"} {
		if !strings.Contains(confirm, want) {
			t.Fatalf("confirm view missing %q:\n%s", want, confirm)
		}
	}
}

func TestUninstalledTemplateOpensEnableConfirmation(t *testing.T) {
	m := Model{
		viewState: ViewTemplateLibrary,
		library: libraryState{selectedTemplate: 0, templates: []protocol.LibraryTemplateInfo{{
			KeyType:      "aplane.timed-allowlist.v1",
			TemplateType: "generic",
			Installed:    false,
			Enabled:      false,
		}}},
	}

	next, _ := m.handleTemplateLibraryKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if got.viewState != ViewTemplateInstallConfirm || got.library.pendingTemplate == nil {
		t.Fatalf("enter moved to %v pending=%#v, want enable confirm", got.viewState, got.library.pendingTemplate)
	}
	confirm := got.renderTemplateInstallConfirm()
	for _, want := range []string{"Enable Key Type", "Key type:  aplane.timed-allowlist.v1", "Publisher: aplane", "Source:    generic", "ENABLE"} {
		if !strings.Contains(confirm, want) {
			t.Fatalf("confirm view missing %q:\n%s", want, confirm)
		}
	}
	if strings.Contains(confirm, "Install Template") || strings.Contains(confirm, "INSTALL") {
		t.Fatalf("confirm view exposed install language:\n%s", confirm)
	}
}

func TestCompiledProviderLibraryEntryUsesDSAColumn(t *testing.T) {
	tmpl := protocol.LibraryTemplateInfo{
		KeyType:      "aplane.ed25519.v1",
		TemplateType: libraryTypeCompiledProvider,
		Installed:    true,
		Enabled:      true,
	}

	if got := libraryTypeColumn(tmpl); got != "dsa" {
		t.Fatalf("libraryTypeColumn() = %q, want dsa", got)
	}
	if got := templateLibraryStatus(tmpl); got != "Enabled" {
		t.Fatalf("templateLibraryStatus() = %q, want Enabled", got)
	}
}

func TestCompiledProviderInstallResultUsesActivatedStatus(t *testing.T) {
	m := Model{viewState: ViewTemplateInstalling}

	next, _ := m.Update(ActivateKeyTypeResultMsg{
		Success: true,
		KeyType: "aplane.ed25519.v1",
	})
	got := next.(Model)
	if got.library.installStatus != "aplane.ed25519.v1 Enabled" {
		t.Fatalf("templateInstallStatus = %q, want Enabled status", got.library.installStatus)
	}
}

func TestTemplateInstallResultUsesEnabledStatus(t *testing.T) {
	m := Model{viewState: ViewTemplateInstalling}

	next, _ := m.Update(InstallLibraryTemplateResultMsg{
		Success:      true,
		KeyType:      "aplane.timed-allowlist.v1",
		TemplateType: "generic",
	})
	got := next.(Model)
	if got.library.installStatus != "aplane.timed-allowlist.v1 Enabled" {
		t.Fatalf("templateInstallStatus = %q, want Enabled status", got.library.installStatus)
	}
}

func TestCompiledProviderAlreadyActivatedStatus(t *testing.T) {
	m := Model{
		viewState: ViewTemplateLibrary,
		library: libraryState{selectedTemplate: 0, templates: []protocol.LibraryTemplateInfo{{
			KeyType:      "aplane.ed25519.v1",
			TemplateType: libraryTypeCompiledProvider,
			Installed:    true,
		}}},
	}

	next, _ := m.handleTemplateLibraryKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if got.viewState != ViewTemplateInstallConfirm || got.library.pendingTemplate == nil {
		t.Fatalf("enter moved to %v pending=%#v, want disable confirm", got.viewState, got.library.pendingTemplate)
	}

	confirm := got.renderTemplateInstallConfirm()
	for _, want := range []string{"Disable Key Type", "Key type:  aplane.ed25519.v1", "Publisher: aplane", "Source:    dsa", "DISABLE"} {
		if !strings.Contains(confirm, want) {
			t.Fatalf("confirm view missing %q:\n%s", want, confirm)
		}
	}
}

func TestCompiledProviderDeactivateResultUsesDeactivatedStatus(t *testing.T) {
	m := Model{viewState: ViewTemplateInstalling}

	next, _ := m.Update(DeactivateKeyTypeResultMsg{
		Success: true,
		KeyType: "aplane.ed25519.v1",
		Removed: true,
	})
	got := next.(Model)
	if got.library.installStatus != "aplane.ed25519.v1 Disabled" {
		t.Fatalf("templateInstallStatus = %q, want Disabled status", got.library.installStatus)
	}
}

func TestInstalledEnabledTemplateOpensDisableConfirmation(t *testing.T) {
	m := Model{
		viewState: ViewTemplateLibrary,
		library: libraryState{selectedTemplate: 0, templates: []protocol.LibraryTemplateInfo{{
			KeyType:      "aplane.timed-allowlist.v1",
			TemplateType: "generic",
			Installed:    true,
			Enabled:      true,
		}}},
	}

	next, _ := m.handleTemplateLibraryKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if got.viewState != ViewTemplateInstallConfirm || got.library.pendingTemplate == nil {
		t.Fatalf("enter moved to %v pending=%#v, want disable confirm", got.viewState, got.library.pendingTemplate)
	}
	confirm := got.renderTemplateInstallConfirm()
	for _, want := range []string{"Disable Key Type", "Key type:  aplane.timed-allowlist.v1", "Publisher: aplane", "Source:    generic", "DISABLE"} {
		if !strings.Contains(confirm, want) {
			t.Fatalf("confirm view missing %q:\n%s", want, confirm)
		}
	}
}

func TestInstalledDisabledTemplateOpensEnableConfirmation(t *testing.T) {
	m := Model{
		viewState: ViewTemplateLibrary,
		library: libraryState{selectedTemplate: 0, templates: []protocol.LibraryTemplateInfo{{
			KeyType:      "aplane.falcon1024-allowlist.v1",
			TemplateType: "falcon",
			Installed:    true,
			Enabled:      false,
		}}},
	}

	next, _ := m.handleTemplateLibraryKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if got.viewState != ViewTemplateInstallConfirm || got.library.pendingTemplate == nil {
		t.Fatalf("enter moved to %v pending=%#v, want enable confirm", got.viewState, got.library.pendingTemplate)
	}
	confirm := got.renderTemplateInstallConfirm()
	for _, want := range []string{"Enable Key Type", "Key type:  aplane.falcon1024-allowlist.v1", "Publisher: aplane", "Source:    falcon", "ENABLE"} {
		if !strings.Contains(confirm, want) {
			t.Fatalf("confirm view missing %q:\n%s", want, confirm)
		}
	}
}
