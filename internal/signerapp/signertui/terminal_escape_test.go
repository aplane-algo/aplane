// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// Text a template, a boundary file, an archive, a policy file or the daemon
// supplies can hold terminal control sequences and bidirectional controls.
// Each screen that shows such text shows them as escapes.

const (
	clearScreen = "\x1b[2J"
	setTitle    = "\x1b]0;pwned\a"
	rightToLeft = "\u202e"
)

// sgrSequence is the styling a screen writes itself.
var sgrSequence = regexp.MustCompile("\x1b\\[[0-9;:]*m")

// assertNeutralized fails when rendered holds a raw control or bidirectional
// character from the injected text, or lacks the escaped form of each of
// wantEscaped.
func assertNeutralized(t *testing.T, what, rendered string, wantEscaped ...string) {
	t.Helper()
	unstyled := sgrSequence.ReplaceAllString(rendered, "")
	for _, raw := range []string{"\x1b", "\a", rightToLeft, "\u200b", "\r"} {
		if strings.Contains(unstyled, raw) {
			t.Fatalf("%s shows a raw %q:\n%s", what, raw, rendered)
		}
	}
	for _, want := range wantEscaped {
		if !strings.Contains(rendered, want) {
			t.Fatalf("%s lacks the escaped %q:\n%s", what, want, rendered)
		}
	}
}

func TestTemplateLibraryEscapesTemplateText(t *testing.T) {
	tmpl := protocol.LibraryTemplateInfo{
		KeyType:      "test.inject.v1",
		TemplateType: "generic",
		DisplayName:  "HTLC" + clearScreen + rightToLeft,
		Description:  "Pays " + setTitle,
		FileName:     "inject" + clearScreen + ".yaml",
		Parameters: []protocol.TemplateParamInfo{{
			Name: "hash", Label: "Hash" + setTitle, Type: "bytes", Description: "secret" + rightToLeft,
		}},
	}
	invalid := protocol.LibraryTemplateInfo{
		FileName: "bad" + rightToLeft + ".yaml",
		Invalid:  "YAML parse error: field " + clearScreen + " not found",
	}
	m := Model{width: 100, height: 40, viewState: ViewTemplateLibrary, library: libraryState{
		templates:    []protocol.LibraryTemplateInfo{tmpl, invalid},
		installError: "Cannot enable invalid template: " + clearScreen,
	}}
	assertNeutralized(t, "library list", m.renderTemplateLibrary(), `HTLC\x1b[2J\u202e`, `inject\x1b[2J.yaml`, `Pays \x1b]0;pwned\a`)

	m.library.selectedTemplate = 1
	assertNeutralized(t, "invalid entry", m.renderTemplateLibrary(), `bad\u202e.yaml`, `field \x1b[2J not found`)

	assertNeutralized(t, "parameter lines", strings.Join(templateDetailsBoxLines(tmpl), "\n"), `Hash\x1b]0;pwned\a`, `secret\u202e`)

	m.library.pendingTemplate = &tmpl
	m.viewState = ViewTemplateInstallConfirm
	assertNeutralized(t, "enable confirm", m.renderTemplateInstallConfirm(), `HTLC\x1b[2J\u202e`)
}

func TestLibraryYAMLPagerEscapesFileContentAndKeepsLines(t *testing.T) {
	content := "display_name: \"HTLC" + rightToLeft + "\"\r\n" +
		"teal: |\n" +
		"  int 1 // \u200b" + clearScreen + "\n" +
		"  return\n"
	m := Model{width: 100, height: 40, viewState: ViewLibraryTemplateDetails, library: libraryState{
		detailsKeyType:    "test.inject.v1",
		detailsSourcePath: "/library/inject" + clearScreen + ".yaml",
		detailsContent:    content,
	}}
	rendered := m.renderLibraryTemplateDetails()
	assertNeutralized(t, "YAML pager", rendered, `HTLC\u202e`, `int 1 // \u200b\x1b[2J`, `inject\x1b[2J.yaml`)
	for _, line := range []string{`display_name: "HTLC\u202e"`, "teal: |", `  int 1 // \u200b\x1b[2J`, "  return"} {
		if !strings.Contains(rendered, "\n"+line+"\n") {
			t.Fatalf("YAML pager does not show %q on a line of its own:\n%s", line, rendered)
		}
	}
	if strings.Contains(rendered, `\r`) {
		t.Fatalf("YAML pager shows a CRLF line end as an escape:\n%s", rendered)
	}
}

// An installed template's text reaches the Generate forms and Key Details
// through the daemon's key-type list.
func TestInstalledTemplateTextIsEscapedOnGenerateAndKeyDetails(t *testing.T) {
	const keyType = "test.inject.v1"
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:     keyType,
		DisplayName: "HTLC" + clearScreen + rightToLeft,
		Description: "Pays " + setTitle,
		CreationParams: []protocol.TemplateParamInfo{
			{Name: "hash", Label: "Hash" + setTitle, Type: "string", Required: true},
			{Name: "mode", Label: "Mode", Type: "string", Options: []string{"fast" + clearScreen}},
			{Name: "payee", Label: "Payee", Type: "string", InputModes: []protocol.InputModeInfo{
				{Name: "a", Label: "As text" + rightToLeft}, {Name: "b", Label: "As hex"},
			}},
		},
	}})

	m := Model{width: 100, height: 50, viewState: ViewGenerateForm}
	assertNeutralized(t, "Generate form", m.renderGenerateForm(), `HTLC\x1b[2J\u202e`)

	m = m.initGenericLSigParamsForKeyType(keyType)
	m.forms.genericLSigParams["hash"] = "pasted" + clearScreen
	m.viewState = ViewGenerateParams
	for focus := range 3 {
		m.forms.generateFocus = focus
		assertNeutralized(t, "parameter form", m.renderParameterModalForKeyType(keyType, "GENERATE", "refused: "+setTitle),
			`HTLC\x1b[2J\u202e Parameters`, `Hash\x1b]0;pwned\a`, `pasted\x1b[2J`, `fast\x1b[2J`, `As text\u202e`, `refused: \x1b]0;pwned\a`)
	}

	details := Model{height: 40, details: keyDetailsState{keyType: keyType, parameters: map[string]string{
		"hash": "pasted" + clearScreen,
	}}}
	assertNeutralized(t, "Key Details", details.renderKeyDetails(), `Hash\x1b]0;pwned\a: pasted\x1b[2J`)
}

func TestKeyDetailsTEALViewerEscapesAndKeepsLines(t *testing.T) {
	m := Model{width: 100, height: 40, viewState: ViewTEALFullDisplay, details: keyDetailsState{
		address: "ADDR",
		teal:    "#pragma version 10\n// owner " + rightToLeft + "evil\nint 1 " + clearScreen + "\nreturn",
	}}
	rendered := m.renderTEALFullDisplay()
	assertNeutralized(t, "TEAL viewer", rendered, `// owner \u202eevil`, `int 1 \x1b[2J`)
	for _, line := range []string{"#pragma version 10", `// owner \u202eevil`, `int 1 \x1b[2J`, "return"} {
		if !strings.Contains(rendered, "\n"+line+"\n") {
			t.Fatalf("TEAL viewer does not show %q on a line of its own:\n%s", line, rendered)
		}
	}

	params := Model{height: 40, details: keyDetailsState{keyType: "unknown.type.v1", parameters: map[string]string{
		"note" + rightToLeft: "x" + clearScreen,
	}}}
	assertNeutralized(t, "Key Details without a spec", params.renderKeyDetails(), `note\u202e: x\x1b[2J`)
}

func TestBoundaryFileLoadErrorIsEscaped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shared.yaml")
	// A YAML double-quoted key decodes \e to a raw ESC, which the load error quotes.
	if err := os.WriteFile(path, []byte("schema: aplane.boundary.v1\n\"\\e[2J\": 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{path, filepath.Join(dir, "missing"+setTitle+".yaml")} {
		m := Model{width: 100, height: 40, viewState: ViewBoundaryPreset, forms: formsState{
			boundaryKeyType: secondPerKeyType, boundaryFile: file, boundaryPresetIndex: len(boundaryPresetChoices()),
		}}
		next, _ := m.handleBoundaryPresetKeys(tea.KeyMsg{Type: tea.KeyEnter})
		got := next.(Model)
		if got.forms.generateError == "" {
			t.Fatalf("%s: loading the boundary file did not fail", file)
		}
		assertNeutralized(t, "boundary preset screen", got.renderBoundaryPreset())
	}
}

func TestGenerateReviewDetailsEscapeWarningsAndValues(t *testing.T) {
	m := Model{width: 100, height: 60, forms: formsState{review: &PrepareGenerateResultMessage{
		KeyType:    secondPerKeyType,
		Warnings:   []string{"Check this" + clearScreen + ". More."},
		Parameters: map[string]string{"note": "typed" + setTitle},
		Bounded:    &protocol.PreparedBoundedProfile{SpendEffects: []string{"pay"}},
	}}}
	assertNeutralized(t, "review details", m.renderGenerateReviewDetails(), `Check this\x1b[2J`)
	assertNeutralized(t, "review", m.renderGenerateReview(), `Check this\x1b[2J`)
}

func TestRestoreScreensEscapeArchiveNameAndConflicts(t *testing.T) {
	archive := "/backups/migration" + setTitle + clearScreen + ".tar"
	m := Model{width: 120, height: 40, viewState: ViewRestorePassphrase, restore: restoreState{
		archivePath:     archive,
		replaceExisting: true,
		replaceConflicts: []RestoreConflict{{
			Selector: "KEY" + rightToLeft, KeyType: "test.inject" + clearScreen + ".v1",
		}},
		passphraseError: "backup archive not found: " + archive,
	}}
	assertNeutralized(t, "restore passphrase screen", m.renderRestorePassphrase(),
		`migration\x1b]0;pwned\a\x1b[2J.tar`, `KEY\u202e`, `test.inject\x1b[2J.v1`)

	m.viewState = ViewRestorePreview
	m.restore.previewKeys = []RestoreKeyInfo{{Address: "ADDR" + rightToLeft, KeyType: "aplane.falcon1024.v1", Error: "bad " + clearScreen}}
	m.restore.previewErrors = []RestoreError{{Address: "ADDR" + clearScreen, Error: "cannot read " + setTitle}}
	m.restore.previewError = "restore failed: " + clearScreen
	assertNeutralized(t, "restore preview", m.renderRestorePreview(), `ADDR\x1b[2J`, `cannot read \x1b]0;pwned\a`)

	m.viewState = ViewRestoreDisplay
	m.restore.result = RestoreDisplayResult{ArchivePath: archive, Error: "partly failed: " + archive}
	assertNeutralized(t, "restore result", m.renderRestoreDisplay(), `migration\x1b]0;pwned\a\x1b[2J.tar`)
}

func TestPolicyReviewAndEditorEscapeFileNamesAndCheckOutput(t *testing.T) {
	file := "policy" + clearScreen + rightToLeft + ".json"
	m := Model{width: 100, height: 40, viewState: ViewPolicyApplyReview}
	m.policies.apply.file = file
	m.policies.apply.applyErr = "Apply failed: " + setTitle
	m.policies.apply.warnings = []string{file + ": warning: route r1 " + clearScreen}
	m.policies.apply.diffLines = []string{file + ":", "  loosened  description: " + rightToLeft}
	assertNeutralized(t, "policy review", m.renderPolicyApplyReview(), `policy\x1b[2J\u202e.json:`, `Apply failed: \x1b]0;pwned\a`)

	m.policies.apply.err = "invalid: " + clearScreen
	m.policies.apply.problems = []string{"/transfer_policy/\x1b[2J: unknown member"}
	var lines []string
	for _, line := range m.policyEditMessages() {
		lines = append(lines, line.text)
	}
	assertNeutralized(t, "policy editor messages", strings.Join(lines, "\n"), `invalid: \x1b[2J`, `/transfer_policy/\x1b[2J: unknown member`)
}

func TestPolicyDocumentViewEscapesStoredText(t *testing.T) {
	m := Model{width: 100, height: 40, viewState: ViewPolicyDocument}
	m.policies.document = protocol.PolicyDocumentMessage{
		Success:  true,
		Key:      "default",
		Document: "{\n  \"description\": \"a\u009b2Jb" + rightToLeft + "\"\n}\n",
	}
	rendered := m.renderPolicyDocument()
	assertNeutralized(t, "policy document", rendered, `"description": "a\u009b2Jb\u202e"`)
	if strings.Contains(rendered, "\u009b") {
		t.Fatalf("policy document shows a raw C1 control:\n%s", rendered)
	}

	m.viewState = ViewPolicies
	m.policies.err = "denied " + clearScreen
	assertNeutralized(t, "policies screen", m.renderPolicies(), `denied \x1b[2J`)
}

func TestStatusBarAndErrorPopupEscapeErrors(t *testing.T) {
	m := Model{width: 200, height: 40, lastError: "save failed: " + clearScreen, lastWarning: "check " + rightToLeft}
	assertNeutralized(t, "status bar", m.renderStatusBar(), `save failed: \x1b[2J`, `check \u202e`)

	m.errorPopup = errorPopupState{title: "Error" + setTitle, message: "backup archive not found: /b/x" + clearScreen}
	assertNeutralized(t, "serious-error popup", m.renderErrorView(), `Error\x1b]0;pwned\a`, `/b/x\x1b[2J`)
}

// A screen that leaves outside text raw still reaches the terminal escaped.
func TestViewEscapesWhatAScreenLeavesRaw(t *testing.T) {
	m := Model{width: 100, height: 40, viewState: ViewImportDisplay, forms: formsState{
		importedAddress: "ADDR" + clearScreen + rightToLeft,
	}}
	assertNeutralized(t, "View", m.View(), `ADDR\x1b[2J\u202e`)
}
