// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	algoCrypto "github.com/algorand/go-algorand-sdk/v2/crypto"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestApplyInputModeTransforms_NormalizesAddressListParams(t *testing.T) {
	addr1 := algoCrypto.GenerateAccount().Address.String()
	addr2 := algoCrypto.GenerateAccount().Address.String()
	addr3 := algoCrypto.GenerateAccount().Address.String()
	addr4 := algoCrypto.GenerateAccount().Address.String()

	m := Model{
		dataDir: "/does/not/exist",
		genericLSigParams: map[string]string{
			"recipients": addr1 + "\n" + addr2 + ", " + addr3 + "\r\n" + addr4,
		},
		genericLSigParamModes: map[string]int{},
	}
	params := []lsigprovider.ParameterDef{
		{Name: "recipients", Type: "address[]"},
	}

	got, err := m.applyInputModeTransforms(params)
	if err != nil {
		t.Fatalf("applyInputModeTransforms returned error: %v", err)
	}

	wantRecipients := []string{addr1, addr2, addr3, addr4}
	sort.Strings(wantRecipients)
	want := map[string]string{"recipients": strings.Join(wantRecipients, ",")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("transformed params = %v, want %v", got, want)
	}
}

func TestApplyInputModeTransforms_ResolvesAddressListAliasesAndSets(t *testing.T) {
	tmpDir := t.TempDir()
	store := cache.NewStore(tmpDir)

	addr1 := algoCrypto.GenerateAccount().Address.String()
	addr2 := algoCrypto.GenerateAccount().Address.String()
	addr3 := algoCrypto.GenerateAccount().Address.String()

	aliasCache := cache.LoadAliasCacheFromStore(store)
	aliasCache.Aliases["alice"] = addr1
	if err := aliasCache.SaveCache(); err != nil {
		t.Fatalf("SaveCache(alias) returned error: %v", err)
	}

	setCache := cache.LoadSetCacheFromStore(store)
	setCache.Sets["friends"] = []string{addr2, addr3}
	if err := setCache.SaveCache(); err != nil {
		t.Fatalf("SaveCache(set) returned error: %v", err)
	}

	m := Model{
		dataDir: tmpDir,
		genericLSigParams: map[string]string{
			"recipients": "alice\n@friends",
		},
		genericLSigParamModes: map[string]int{},
	}
	params := []lsigprovider.ParameterDef{
		{Name: "recipients", Type: "address[]"},
	}

	got, err := m.applyInputModeTransforms(params)
	if err != nil {
		t.Fatalf("applyInputModeTransforms returned error: %v", err)
	}

	wantRecipients := []string{addr1, addr2, addr3}
	sort.Strings(wantRecipients)
	want := map[string]string{"recipients": strings.Join(wantRecipients, ",")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("transformed params = %v, want %v", got, want)
	}
}

func TestSplitAddressListValueAcceptsWhitespaceSeparators(t *testing.T) {
	got := splitAddressListValue("alice bob\n@friends,\tcarol")
	want := []string{"alice", "bob", "@friends", "carol"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitAddressListValue() = %#v, want %#v", got, want)
	}
}

func TestHandleParamInput_AddressListPreservesAliasCase(t *testing.T) {
	m := Model{
		genericLSigParams:     map[string]string{},
		genericLSigParamOrder: []string{"recipients"},
		generateFocus:         0,
	}

	got := m.appendToCurrentParam("alice\n@friends", []lsigprovider.ParameterDef{
		{Name: "recipients", Type: "address[]"},
	})
	if got.genericLSigParams["recipients"] != "alice\n@friends" {
		t.Fatalf("address[] input = %q, want %q", got.genericLSigParams["recipients"], "alice\n@friends")
	}

	m = Model{
		genericLSigParams:     map[string]string{},
		genericLSigParamOrder: []string{"recipients"},
		generateFocus:         0,
	}
	got = m.appendToCurrentParam("alice,bob", []lsigprovider.ParameterDef{
		{Name: "recipients", Type: "address[]"},
	})
	if got.genericLSigParams["recipients"] != "alice\nbob" {
		t.Fatalf("address[] comma input = %q, want %q", got.genericLSigParams["recipients"], "alice\nbob")
	}
}

func TestSelectParamDefaultsAndCyclesOptions(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:     "aplane.falcon1024-sentry-ed25519.v1",
		DisplayName: "Falcon-1024 / Ed25519 Sentry",
		CreationParams: []protocol.TemplateParamInfo{{
			Name:    "sentry",
			Label:   "Sentry",
			Type:    "select",
			Options: []string{"lab-att", "backup-att"},
			Default: "lab-att",
		}},
	}})

	m := Model{generateKeyType: 0}
	m = m.initGenericLSigParamsForKeyType("aplane.falcon1024-sentry-ed25519.v1")
	if got := m.genericLSigParams["sentry"]; got != "lab-att" {
		t.Fatalf("default sentry = %q, want lab-att", got)
	}

	m.generateFocus = 0
	next, cmd := m.handleGenerateParamsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'>'}})
	if cmd != nil {
		t.Fatalf("cycle command = %v, want nil", cmd)
	}
	m = next.(Model)
	if got := m.genericLSigParams["sentry"]; got != "backup-att" {
		t.Fatalf("cycled sentry = %q, want backup-att", got)
	}

	next, _ = m.handleGenerateParamsKeys(tea.KeyMsg{Type: tea.KeyLeft})
	m = next.(Model)
	if got := m.genericLSigParams["sentry"]; got != "lab-att" {
		t.Fatalf("left-cycled sentry = %q, want lab-att", got)
	}
}

func TestHandleParamInputBytesAcceptsDeclaredHexLength(t *testing.T) {
	m := Model{
		genericLSigParams:     map[string]string{},
		genericLSigParamOrder: []string{"sentry_public_key"},
		generateFocus:         0,
	}
	input := "D6FB74E10151AC3B0EAA7431B9B92C772C2A4A600C10B88CFD30169EA1AB4D0A"
	params := []lsigprovider.ParameterDef{{
		Name:      "sentry_public_key",
		Type:      "bytes",
		MaxLength: 64,
	}}

	got := m.appendToCurrentParam(input, params)
	if got.genericLSigParams["sentry_public_key"] != strings.ToLower(input) {
		t.Fatalf("bytes input = %q, want lowercase 64-char hex", got.genericLSigParams["sentry_public_key"])
	}

	got = got.appendToCurrentParam("ffff", params)
	if got.genericLSigParams["sentry_public_key"] != strings.ToLower(input) {
		t.Fatalf("bytes input exceeded max length: %q", got.genericLSigParams["sentry_public_key"])
	}
}

func TestHandleParamInput_AddressListCapsLineLength(t *testing.T) {
	m := Model{
		genericLSigParams:     map[string]string{},
		genericLSigParamOrder: []string{"recipients"},
		generateFocus:         0,
	}
	params := []lsigprovider.ParameterDef{{Name: "recipients", Type: "address[]"}}
	maxLineLen := getFieldWidthForType("address[]", 0) - 1

	got := m.appendToCurrentParam(strings.Repeat("A", maxLineLen+20), params)
	if gotLen := currentParamLineLength(got.genericLSigParams["recipients"]); gotLen != maxLineLen {
		t.Fatalf("address[] line length = %d, want %d", gotLen, maxLineLen)
	}

	got = got.appendToCurrentParam(" "+strings.Repeat("B", maxLineLen+20), params)
	lines := strings.Split(got.genericLSigParams["recipients"], "\n")
	if len(lines) != 2 {
		t.Fatalf("address[] lines = %#v, want two lines", lines)
	}
	for i, line := range lines {
		if len(line) != maxLineLen {
			t.Fatalf("line %d length = %d, want %d", i, len(line), maxLineLen)
		}
	}
}

func TestHandleParamInput_AddressListAutoScrollsAndPages(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:     "whitelist-test-v1",
		DisplayName: "Whitelist Test",
		CreationParams: []protocol.TemplateParamInfo{{
			Name: "recipients",
			Type: "address[]",
		}},
	}})

	m := Model{
		generateKeyType: 0,
		generateFocus:   0,
		genericLSigParams: map[string]string{
			"recipients": "",
		},
		genericLSigParamModes: map[string]int{
			"recipients": 0,
		},
		genericLSigParamScroll: map[string]int{
			"recipients": 0,
		},
	}
	params := []lsigprovider.ParameterDef{{Name: "recipients", Type: "address[]"}}
	m = m.appendToCurrentParam("addr1\naddr2\naddr3\naddr4\naddr5\naddr6\naddr7\naddr8", params)

	if got, want := m.genericLSigParamScroll["recipients"], 2; got != want {
		t.Fatalf("address[] auto-scroll = %d, want %d", got, want)
	}

	m = applyParamKey(t, m, tea.KeyMsg{Type: tea.KeyPgUp})
	if got, want := m.genericLSigParamScroll["recipients"], 0; got != want {
		t.Fatalf("address[] scroll after pgup = %d, want %d", got, want)
	}

	m = applyParamKey(t, m, tea.KeyMsg{Type: tea.KeyPgDown})
	if got, want := m.genericLSigParamScroll["recipients"], 2; got != want {
		t.Fatalf("address[] scroll after pgdown = %d, want %d", got, want)
	}

	m = applyParamKey(t, m, tea.KeyMsg{Type: tea.KeyUp})
	if got, want := m.genericLSigParamScroll["recipients"], 1; got != want {
		t.Fatalf("address[] scroll after up = %d, want %d", got, want)
	}

	m = applyParamKey(t, m, tea.KeyMsg{Type: tea.KeyDown})
	if got, want := m.genericLSigParamScroll["recipients"], 2; got != want {
		t.Fatalf("address[] scroll after down = %d, want %d", got, want)
	}

	m = applyParamKey(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	if got, want := m.generateFocus, 1; got != want {
		t.Fatalf("focus after j = %d, want %d", got, want)
	}
}

func TestGenerateFormShowsTemplateShortcutLegend(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:     "aplane.whitelist.v1",
		DisplayName: "Whitelist",
		Description: "Template-backed key type",
	}})

	m := Model{viewState: ViewGenerateForm, width: 100, height: 30}
	rendered := m.View()
	if !strings.Contains(rendered, "t: Template") {
		t.Fatalf("generate form missing template shortcut footer:\n%s", rendered)
	}
}

func TestGenerateFormTemplateShortcutOpensYAMLDetails(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:     "aplane.whitelist.v1",
		DisplayName: "Whitelist",
		Description: "Template-backed key type",
	}})

	m := Model{
		viewState:       ViewGenerateForm,
		generateKeyType: 0,
		libraryTemplates: []protocol.LibraryTemplateInfo{{
			KeyType:      "aplane.whitelist.v1",
			TemplateType: "generic",
			SourcePath:   "/tmp/keystore/library/templates/aplane.whitelist.v1.yaml",
		}},
	}

	next, cmd := m.handleGenerateFormKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'t'}})
	got := next.(Model)
	if got.viewState != ViewLibraryTemplateDetails {
		t.Fatalf("viewState after t = %v, want ViewLibraryTemplateDetails", got.viewState)
	}
	if !got.libraryDetailsLoading || got.libraryDetailsKeyType != "aplane.whitelist.v1" || got.libraryDetailsTemplateType != "generic" {
		t.Fatalf("library details state = loading:%v key:%q type:%q", got.libraryDetailsLoading, got.libraryDetailsKeyType, got.libraryDetailsTemplateType)
	}
	if cmd == nil {
		t.Fatal("template shortcut for YAML entry returned nil cmd, want show-template request")
	}
	closed, _ := got.handleLibraryTemplateDetailsKeys(tea.KeyMsg{Type: tea.KeyEsc})
	if closed.(Model).viewState != ViewGenerateForm {
		t.Fatalf("viewState after closing generate template details = %v, want ViewGenerateForm", closed.(Model).viewState)
	}
}

func TestGenerateFormTemplateShortcutSynthesizesDefaultCompiledProviderDetails(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:          "aplane.falcon1024.v1",
		DisplayName:      "Falcon-1024",
		Description:      "Default post-quantum signer",
		RequiresLogicSig: true,
	}})

	m := Model{viewState: ViewGenerateForm, generateKeyType: 0}

	next, cmd := m.handleGenerateFormKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'t'}})
	got := next.(Model)
	if cmd != nil {
		t.Fatalf("template shortcut for compiled provider returned cmd = %v, want nil", cmd)
	}
	if got.viewState != ViewLibraryTemplateDetails {
		t.Fatalf("viewState after t = %v, want ViewLibraryTemplateDetails", got.viewState)
	}
	if got.libraryDetailsLoading {
		t.Fatal("compiled provider details are loading, want synthesized details")
	}
	for _, want := range []string{"Compiled provider: falcon1024.v1", "Publisher: aplane", "Default post-quantum signer"} {
		rendered := got.renderLibraryTemplateDetails()
		if !strings.Contains(rendered, want) {
			t.Fatalf("compiled provider details missing %q:\n%s", want, rendered)
		}
	}
}

func TestGenerateFormTemplateShortcutReportsMissingTemplate(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:     "ed25519",
		DisplayName: "Ed25519",
	}})

	m := Model{viewState: ViewGenerateForm, generateKeyType: 0}

	next, cmd := m.handleGenerateFormKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'t'}})
	got := next.(Model)
	if cmd != nil {
		t.Fatalf("template shortcut for missing details returned cmd = %v, want nil", cmd)
	}
	if got.viewState != ViewGenerateForm {
		t.Fatalf("viewState after missing template = %v, want ViewGenerateForm", got.viewState)
	}
	if !strings.Contains(got.generateError, "no template details available") {
		t.Fatalf("generateError = %q, want missing template details", got.generateError)
	}
}

func TestHandleParamModalKeys_AddressListSpaceAndEnterStayInField(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{{
		KeyType:     "whitelist-test-v1",
		DisplayName: "Whitelist Test",
		CreationParams: []protocol.TemplateParamInfo{{
			Name: "recipients",
			Type: "address[]",
		}},
	}})

	m := Model{
		generateKeyType: 0,
		generateFocus:   0,
		genericLSigParams: map[string]string{
			"recipients": "alice",
		},
		genericLSigParamModes: map[string]int{
			"recipients": 0,
		},
	}

	next, cmd := m.handleGenerateParamsKeys(tea.KeyMsg{Type: tea.KeySpace})
	if cmd != nil {
		t.Fatal("space in address[] field returned command")
	}
	updated, ok := next.(Model)
	if !ok {
		t.Fatalf("handleGenerateParamsKeys(space) returned %T, want Model", next)
	}
	if got, want := updated.generateFocus, 0; got != want {
		t.Fatalf("focus after space = %d, want %d", got, want)
	}
	if got, want := updated.genericLSigParams["recipients"], "alice\n"; got != want {
		t.Fatalf("recipients after space = %q, want %q", got, want)
	}

	updated = applyParamKey(t, updated, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'b'}})
	updated = applyParamKey(t, updated, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'o'}})
	updated = applyParamKey(t, updated, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'b'}})
	if got, want := updated.genericLSigParams["recipients"], "alice\nbob"; got != want {
		t.Fatalf("recipients after typing next address = %q, want %q", got, want)
	}

	next, cmd = updated.handleGenerateParamsKeys(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Fatal("enter in address[] field returned command")
	}
	updated, ok = next.(Model)
	if !ok {
		t.Fatalf("handleGenerateParamsKeys(enter) returned %T, want Model", next)
	}
	if got, want := updated.generateFocus, 0; got != want {
		t.Fatalf("focus after enter = %d, want %d", got, want)
	}
	if got, want := updated.genericLSigParams["recipients"], "alice\nbob\n"; got != want {
		t.Fatalf("recipients after enter = %q, want %q", got, want)
	}
}

func applyParamKey(t *testing.T, m Model, msg tea.KeyMsg) Model {
	t.Helper()
	next, cmd := m.handleGenerateParamsKeys(msg)
	if cmd != nil {
		t.Fatalf("handleGenerateParamsKeys(%q) returned command", msg.String())
	}
	updated, ok := next.(Model)
	if !ok {
		t.Fatalf("handleGenerateParamsKeys(%q) returned %T, want Model", msg.String(), next)
	}
	return updated
}

func TestNewImportMnemonicInputIsMultiline(t *testing.T) {
	input := newImportMnemonicInput()
	if got, want := input.Height(), 4; got != want {
		t.Fatalf("mnemonic input height = %d, want %d", got, want)
	}
	if got, want := input.Width(), 62; got != want {
		t.Fatalf("mnemonic input width = %d, want %d", got, want)
	}
}

func TestHandleImportFormKeys_MnemonicCursorEditing(t *testing.T) {
	input := newImportMnemonicInput()
	_ = input.Focus()
	m := Model{
		importFocus:         1,
		importMnemonicInput: input,
	}

	m = applyImportKeys(t, m, keyRunes("alpha beta gamma"))
	for i := 0; i < len("gamma"); i++ {
		m = applyImportKey(t, m, tea.KeyMsg{Type: tea.KeyLeft})
	}
	m = applyImportKeys(t, m, keyRunes("fixed "))

	if got, want := m.importMnemonicInput.Value(), "alpha beta fixed gamma"; got != want {
		t.Fatalf("mnemonic input = %q, want %q", got, want)
	}
}

func TestSubmitImportValidatesMnemonicWordCountLocally(t *testing.T) {
	input := newImportMnemonicInput()
	input.SetValue("alpha beta gamma")
	m := Model{
		importKeyType:       0, // ed25519 expects 25 words
		importMnemonicInput: input,
	}

	next, cmd := m.submitImport()
	if cmd != nil {
		t.Fatal("submitImport returned command for invalid word count")
	}
	updated, ok := next.(Model)
	if !ok {
		t.Fatalf("submitImport returned %T, want Model", next)
	}
	if got, want := updated.importError, "Recovery phrase must contain 25 words, got 3"; got != want {
		t.Fatalf("importError = %q, want %q", got, want)
	}
}

func TestGetExpectedWordCountUsesDSAProviderForFalconTemplates(t *testing.T) {
	provider := &testWordCountDSA{keyType: "falcon1024-testtemplate-v1", family: "falcon1024-testtemplate", words: 24}
	keytypecatalog.Register(keytypecatalog.Entry{
		KeyType:      provider.keyType,
		Family:       provider.family,
		Availability: keytypecatalog.AvailabilityDefaultEnabled,
	})
	if !lsigprovider.Has(provider.keyType) {
		logicsigdsa.Register(provider)
	}

	index := -1
	for i := 0; i < getKeyTypeCount(); i++ {
		if getKeyTypeByIndex(i) == provider.keyType {
			index = i
			break
		}
	}
	if index < 0 {
		t.Fatalf("registered key type %q was not found in key type options", provider.keyType)
	}
	if got, want := getExpectedWordCount(index), 24; got != want {
		t.Fatalf("getExpectedWordCount(%d) = %d, want %d", index, got, want)
	}
}

type testWordCountDSA struct {
	keyType string
	family  string
	words   int
}

func (t *testWordCountDSA) KeyType() string          { return t.keyType }
func (t *testWordCountDSA) Family() string           { return t.family }
func (t *testWordCountDSA) Version() int             { return 1 }
func (t *testWordCountDSA) CryptoSignatureSize() int { return 0 }
func (t *testWordCountDSA) MnemonicScheme() string   { return "bip39" }
func (t *testWordCountDSA) MnemonicWordCount() int   { return t.words }
func (t *testWordCountDSA) SupportsMnemonicImport() bool {
	return false
}
func (t *testWordCountDSA) DisplayColor() string { return "" }
func (t *testWordCountDSA) GenerateKeypair([]byte) ([]byte, []byte, error) {
	return nil, nil, nil
}
func (t *testWordCountDSA) DeriveLsig(context.Context, []byte, map[string]string) ([]byte, string, error) {
	return nil, "", nil
}
func (t *testWordCountDSA) Sign([]byte, []byte) ([]byte, error) { return nil, nil }
func (t *testWordCountDSA) DisplayName() string                 { return "Test Word Count DSA" }
func (t *testWordCountDSA) Description() string                 { return "Test provider" }
func (t *testWordCountDSA) Category() string                    { return lsigprovider.CategoryDSALsig }
func (t *testWordCountDSA) CreationParams() []lsigprovider.ParameterDef {
	return nil
}
func (t *testWordCountDSA) ValidateCreationParams(map[string]string) error { return nil }
func (t *testWordCountDSA) RuntimeArgs() []lsigprovider.RuntimeArgDef      { return nil }
func (t *testWordCountDSA) BuildArgs([]byte, map[string][]byte) ([][]byte, error) {
	return nil, nil
}

func applyImportKeys(t *testing.T, m Model, msgs []tea.KeyMsg) Model {
	t.Helper()
	for _, msg := range msgs {
		m = applyImportKey(t, m, msg)
	}
	return m
}

func applyImportKey(t *testing.T, m Model, msg tea.KeyMsg) Model {
	t.Helper()
	next, _ := m.handleImportFormKeys(msg)
	updated, ok := next.(Model)
	if !ok {
		t.Fatalf("handleImportFormKeys returned %T, want Model", next)
	}
	return updated
}

func keyRunes(s string) []tea.KeyMsg {
	msgs := make([]tea.KeyMsg, 0, len(s))
	for _, r := range s {
		if r == ' ' {
			msgs = append(msgs, tea.KeyMsg{Type: tea.KeySpace})
			continue
		}
		msgs = append(msgs, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	return msgs
}
