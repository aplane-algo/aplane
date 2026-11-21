// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Helper functions for key type options and input field configuration.

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

var serverKeyTypes struct {
	sync.RWMutex
	items []protocol.KeyTypeInfo
}

func setServerKeyTypes(items []protocol.KeyTypeInfo) {
	serverKeyTypes.Lock()
	defer serverKeyTypes.Unlock()

	serverKeyTypes.items = append([]protocol.KeyTypeInfo(nil), items...)
	slices.SortStableFunc(serverKeyTypes.items, func(a, b protocol.KeyTypeInfo) int {
		return compareKeyTypesForSelection(a.KeyType, b.KeyType)
	})
}

// isNativeKeyType reports whether keyType is a protocol-native scheme, named
// bare (ed25519, falcon1024) rather than publisher.family.vN.
func isNativeKeyType(keyType string) bool {
	return !strings.Contains(keyType, ".")
}

// compareKeyTypesForSelection orders key type pickers in clusters: the
// protocol-native key types first, then every published key type, each
// alphabetical, then the cosigner key types in their own order, the
// post-quantum one first. Only a cosigner node lists cosigner key types, and
// they are all it lists, so its generate list starts with Falcon-1024.
func compareKeyTypesForSelection(a, b string) int {
	if rankA, rankB := keyTypeCluster(a), keyTypeCluster(b); rankA != rankB {
		return rankA - rankB
	}
	if witness.IsKeyType(a) {
		return slices.Index(witness.KeyTypes, a) - slices.Index(witness.KeyTypes, b)
	}
	return strings.Compare(a, b)
}

// keyTypeCluster is a key type's cluster in a picker: native, published, or
// cosigner.
func keyTypeCluster(keyType string) int {
	switch {
	case isNativeKeyType(keyType):
		return 0
	case witness.IsKeyType(keyType):
		return 2
	default:
		return 1
	}
}

func sortKeyTypesForSelection(keyTypes []string) []string {
	slices.SortStableFunc(keyTypes, compareKeyTypesForSelection)
	return keyTypes
}

// nativeKeyTypeCount is how many of keyTypes, in selection order, belong to
// the native cluster at the top.
func nativeKeyTypeCount(keyTypes []string) int {
	count := 0
	for _, keyType := range keyTypes {
		if isNativeKeyType(keyType) {
			count++
		}
	}
	return count
}

// separateKeyTypeClusters inserts a blank row between the native and the
// published key type clusters when both are present, and returns the rows
// with the selected index moved to match.
func separateKeyTypeClusters(rows []string, nativeCount, selected int) ([]string, int) {
	if nativeCount <= 0 || nativeCount >= len(rows) {
		return rows, selected
	}
	out := make([]string, 0, len(rows)+1)
	out = append(out, rows[:nativeCount]...)
	out = append(out, "")
	out = append(out, rows[nativeCount:]...)
	if selected >= nativeCount {
		selected++
	}
	return out, selected
}

// compiledGenerateKeyTypes is the generate list from the compiled registries,
// used before the signer has sent its own list.
func compiledGenerateKeyTypes() []string {
	types := append([]string(nil), keymgmt.GetValidKeyTypes()...)
	for _, template := range genericlsig.GetAll() {
		types = append(types, template.KeyType())
	}
	return sortKeyTypesForSelection(types)
}

// compiledImportKeyTypes is the mnemonic import list from the compiled
// registries, used before the signer has sent its own list.
func compiledImportKeyTypes() []string {
	return sortKeyTypesForSelection(append([]string(nil), keymgmt.GetMnemonicImportKeyTypesWithActivated(nil)...))
}

// generateKeyTypeIDs is the generate list's key types in display order.
func generateKeyTypeIDs() []string {
	if types := getServerKeyTypes(); len(types) > 0 {
		ids := make([]string, len(types))
		for i, info := range types {
			ids[i] = info.KeyType
		}
		return ids
	}
	return compiledGenerateKeyTypes()
}

// keyTypeTakesBoundary reports whether a key type's requests take the boundary
// grammar, from the signer's inventory. A per-key type that takes none, such as a
// plain host, uses the parameter form. known is false when inventory doesn't hold
// the type, which says nothing about what it is.
func keyTypeTakesBoundary(keyType string) (takesBoundary, known bool) {
	info, known := findServerKeyType(keyType)
	return info.PerKeyContract && info.BoundarySchema == boundary.SchemaV1, known
}

// importKeyTypeIDs is the mnemonic import list's key types in display order.
func importKeyTypeIDs() []string {
	if types := getServerImportKeyTypes(); len(types) > 0 {
		ids := make([]string, len(types))
		for i, info := range types {
			ids[i] = info.KeyType
		}
		return ids
	}
	return compiledImportKeyTypes()
}

func getServerKeyTypes() []protocol.KeyTypeInfo {
	serverKeyTypes.RLock()
	defer serverKeyTypes.RUnlock()
	return append([]protocol.KeyTypeInfo(nil), serverKeyTypes.items...)
}

func findServerKeyType(keyType string) (protocol.KeyTypeInfo, bool) {
	for _, info := range getServerKeyTypes() {
		if info.KeyType == keyType {
			return info, true
		}
	}
	return protocol.KeyTypeInfo{}, false
}

func getServerImportKeyTypes() []protocol.KeyTypeInfo {
	var out []protocol.KeyTypeInfo
	for _, info := range getServerKeyTypes() {
		if info.MnemonicImport {
			out = append(out, info)
		}
	}
	return out
}

// importKeyTypeOptions returns the mnemonic import key type display strings,
// in selection order (native key types first, then published ones).
func importKeyTypeOptions() []string {
	if types := getServerImportKeyTypes(); len(types) > 0 {
		options := make([]string, len(types))
		for i, info := range types {
			if info.MnemonicWordCount > 0 {
				options[i] = fmt.Sprintf("%s (%d words)", displayKeyType(info.KeyType), info.MnemonicWordCount)
			} else {
				options[i] = displayKeyType(info.KeyType)
			}
		}
		return options
	}

	types := compiledImportKeyTypes()
	options := make([]string, len(types))
	for i, keyType := range types {
		meta, err := algorithm.GetMetadata(keyType)
		if err == nil && meta != nil {
			options[i] = fmt.Sprintf("%s (%d words)", displayKeyType(keyType), meta.MnemonicWordCount())
		} else {
			options[i] = displayKeyType(keyType)
		}
	}
	return options
}

func getKeyTypeSelectionLabel(keyType string) string {
	if info, ok := findServerKeyType(keyType); ok {
		if info.DisplayName != "" {
			return terminalSafe(info.DisplayName)
		}
		if info.Family != "" {
			return terminalSafe(info.Family)
		}
		return displayKeyType(info.KeyType)
	}
	if spec := getParamSpecForKeyType(keyType); spec != nil && spec.DisplayName != "" {
		return spec.DisplayName
	}
	if meta, err := algorithm.GetMetadata(keyType); err == nil && meta != nil {
		return algorithm.DisplayLabel(meta)
	}
	if template := genericlsig.Get(keyType); template != nil {
		return "generic LogicSig"
	}
	return displayKeyType(keyType)
}

type paramSpec struct {
	DisplayName string
	Description string
	Params      []lsigprovider.ParameterDef
	Validate    func(map[string]string) error
	// Sections group the fields on screen, in order; none is one group.
	Sections []paramSection
	// OptionLabel names a choice field's value for the screen; nil shows the
	// value itself.
	OptionLabel func(name, value string) string
	// Overlay marks the overlay choices form (overlay_form.go).
	Overlay bool
}

// paramSection is a titled group of fields starting at Start.
type paramSection struct {
	Start int
	Title string
}

// sectionAt is the title of the group field index belongs to, and whether the
// group starts there.
func (s *paramSpec) sectionAt(index int) (string, bool) {
	title, starts := "", false
	for _, section := range s.Sections {
		if section.Start > index {
			break
		}
		title, starts = section.Title, section.Start == index
	}
	return title, starts
}

// optionLabel names value for the screen.
func (s *paramSpec) optionLabel(name, value string) string {
	if s == nil || s.OptionLabel == nil {
		return terminalSafe(value)
	}
	return terminalSafe(s.OptionLabel(name, value))
}

// validateParams checks creation parameter values against params.
func validateParams(params []lsigprovider.ParameterDef) func(map[string]string) error {
	return func(values map[string]string) error {
		normalized, err := lsigprovider.NormalizeCreationParams(values, params)
		if err != nil {
			return err
		}
		return generictemplate.ValidateParameterValues(normalized, params)
	}
}

func getParamSpecForKeyType(keyType string) *paramSpec {
	if keyType == "" {
		return nil
	}

	if info, ok := findServerKeyType(keyType); ok && len(info.CreationParams) > 0 {
		params := protocolParamInfosToDefs(info.CreationParams)
		// A template's names and labels are its author's text, so the spec
		// carries them escaped for every form and details screen that shows
		// them.
		return &paramSpec{
			DisplayName: terminalSafe(info.DisplayName),
			Description: terminalSafe(info.Description),
			Params:      params,
			Validate:    validateParams(params),
		}
	}

	// Use unified lsigprovider registry
	provider := lsigprovider.Get(keyType)
	if provider == nil {
		return nil
	}

	params := provider.CreationParams()
	if len(params) == 0 {
		return nil
	}

	return &paramSpec{
		DisplayName: provider.DisplayName(),
		Description: provider.Description(),
		Params:      params,
		Validate:    provider.ValidateCreationParams,
	}
}

// getImportKeyTypeByIndex returns the import list's key type at index, or ""
// when there is none.
func getImportKeyTypeByIndex(index int) string {
	return keyTypeAt(importKeyTypeIDs(), index)
}

// getKeyTypeByIndex returns the generate list's key type at index, or "" when
// there is none. The list holds both cryptographic key types (versioned) and
// generic LogicSig templates.
func getKeyTypeByIndex(index int) string {
	return keyTypeAt(generateKeyTypeIDs(), index)
}

func keyTypeAt(ids []string, index int) string {
	if index >= 0 && index < len(ids) {
		return ids[index]
	}
	return ""
}

func getExpectedImportWordCount(keyTypeIndex int) int {
	keyType := getImportKeyTypeByIndex(keyTypeIndex)
	return getExpectedWordCountForKeyType(keyType)
}

func getExpectedWordCountForKeyType(keyType string) int {
	if keyType == "" {
		return 25 // default for ed25519
	}
	if info, ok := findServerKeyType(keyType); ok {
		if info.MnemonicWordCount > 0 {
			return info.MnemonicWordCount
		}
		return 0
	}
	if dsa := logicsigdsa.Get(keyType); dsa != nil {
		return dsa.MnemonicWordCount()
	}
	meta, err := algorithm.GetMetadata(keyType)
	if err == nil && meta != nil {
		return meta.MnemonicWordCount()
	}
	return 25 // default
}

// protocolParamInfosToDefs converts the daemon's parameter list for a form,
// with its display text escaped. What a field sends, its name and options,
// is kept as the template wrote it.
func protocolParamInfosToDefs(params []protocol.TemplateParamInfo) []lsigprovider.ParameterDef {
	defs := make([]lsigprovider.ParameterDef, len(params))
	for i, p := range params {
		defs[i] = lsigprovider.ParameterDef{
			Name:        p.Name,
			Label:       terminalSafe(p.Label),
			Description: terminalSafe(p.Description),
			Type:        p.Type,
			Required:    p.Required,
			MaxLength:   p.MaxLength,
			InputModes:  protocolInputModesToDefs(p.InputModes),
			Options:     append([]string(nil), p.Options...),
			MinItems:    p.MinItems,
			MaxItems:    p.MaxItems,
			Example:     terminalSafe(p.Example),
			Placeholder: terminalSafe(p.Placeholder),
			Min:         p.Min,
			Max:         p.Max,
			Default:     p.Default,
		}
	}
	return defs
}

func protocolInputModesToDefs(modes []protocol.InputModeInfo) []lsigprovider.InputMode {
	if len(modes) == 0 {
		return nil
	}
	out := make([]lsigprovider.InputMode, len(modes))
	for i, mode := range modes {
		out[i] = lsigprovider.InputMode{
			Name:       mode.Name,
			Label:      terminalSafe(mode.Label),
			Transform:  mode.Transform,
			ByteLength: mode.ByteLength,
			InputType:  mode.InputType,
		}
	}
	return out
}

// keyListVisibleHeight returns the number of visible key rows based on terminal height.
// Used by key list rendering, scroll handling, and key selection.
func (m Model) keyListVisibleHeight() int {
	reservedLines := 8 // Reserve lines for filter, scroll indicators, count, and spacing.
	h := m.windowBodyHeight() - reservedLines
	if h < 3 {
		h = 3
	}
	return h
}

func scrollMoreAboveLine(count int) string {
	return scrollMoreLine(count, "▲", "above")
}

func scrollMoreBelowLine(count int) string {
	return scrollMoreLine(count, "▼", "below")
}

func scrollMoreLine(count int, arrow, direction string) string {
	if count <= 0 {
		return ""
	}
	return subtitleStyle.Render(fmt.Sprintf("  %s %d more %s", arrow, count, direction))
}

const keyAddressShortWidth = 23 // 10 leading chars + "..." + 10 trailing chars

func formatKeyAddress(address, keyType string, maxWidth int, useKeyTypeColor bool) string {
	width := keyAddressShortWidth
	if maxWidth > 0 && maxWidth < width {
		width = maxWidth
	}
	address = ellipsizeMiddle(address, width)
	if !useKeyTypeColor {
		return address
	}
	return styledAddress(address, keyType)
}

// tableWidth is the width list rows are laid out for: the window, or MinWidth
// before the first size message.
func (m Model) tableWidth() int {
	if m.width > 0 {
		return m.width
	}
	return MinWidth
}

func keyAddressWidth(rowWidth int, prefix, suffix string) int {
	if rowWidth <= 0 {
		return 0
	}
	width := rowWidth - len(prefix) - len(suffix)
	if width < 4 {
		return 4
	}
	return width
}

// padRight pads s with spaces to width columns, as the terminal draws them,
// and leaves a string as wide or wider as it is: "%-*s" counted in columns.
func padRight(s string, width int) string {
	return s + strings.Repeat(" ", max(width-ansi.StringWidth(s), 0))
}

// ellipsizeMiddle cuts s to width columns, as the terminal draws them, in
// the middle: its start, "...", then its end, when width has room for more
// than the dots.
func ellipsizeMiddle(s string, width int) string {
	if width <= 0 {
		return ""
	}
	total := ansi.StringWidth(s)
	if total <= width {
		return s
	}
	if width <= 3 {
		return ansi.Truncate(s, width, "")
	}
	prefix := (width - 3) / 2
	suffix := width - 3 - prefix
	// TruncateLeft keeps whole a cluster the cut falls inside, however many
	// columns it takes, so the cut moves right until the end fits.
	cut := total - suffix
	end := ansi.TruncateLeft(s, cut, "")
	for ansi.StringWidth(end) > suffix {
		cut++
		end = ansi.TruncateLeft(s, cut, "")
	}
	return ansi.Truncate(s, prefix, "") + "..." + end
}

// pagerWidth is the width a full-screen text pager draws in.
func (m Model) pagerWidth() int {
	if m.width < 20 {
		return 80
	}
	return m.width
}

// pagerScrollKeys names a text pager's scroll keys, which its footer adds
// when its text does not fit.
const pagerScrollKeys = "up/down/pgup/pgdown: Scroll"

// pagerScrollFooter is a full-screen text pager's footer when its text does
// not fit.
const pagerScrollFooter = "Esc/q close | " + pagerScrollKeys

// pagerVisibleLines is how many lines of text a full-screen pager shows: the
// window body under the pager's footer at its tallest, scrollFooter (the
// footer names the scroll keys only when the text does not fit, so the fit
// cannot be measured under the footer it decides), less the rows of chrome
// drawn above and below the text, each ending in a newline, and a row for
// each scroll marker. The body is measured under the status bar as drawn, so
// a long error takes its rows from the text. The renderer and the key
// handler both use it, so the furthest the keys scroll is the end of the
// text in view.
func (m Model) pagerVisibleLines(chrome, scrollFooter string) int {
	if m.height <= 0 {
		return 20
	}
	body := m.windowBodyHeightUnder(renderedBlockHeight(m.renderFooterText(scrollFooter)))
	if visible := body - strings.Count(chrome, "\n") - 2; visible > 1 {
		return visible
	}
	return 1
}

// pagerFooter is a full-screen text pager's footer: it names the scroll keys
// only when the text does not fit.
func pagerFooter(lines, visible int) string {
	if lines > visible {
		return pagerScrollFooter
	}
	return "Esc/q close"
}

// pagerOffset is the line a text pager of visible rows draws from: offset,
// held where the window lies within the text and is full where the text
// allows. A window resized or text replaced under an offset draws from here.
func pagerOffset(offset, lines, visible int) int {
	return max(0, min(offset, lines-visible))
}

// scrollPager applies a scroll key to a text pager's offset: up/down and
// k/j move a line, pgup/pgdown a page. Any other key leaves it.
func scrollPager(offset *int, key string, lines, visible int) {
	step := 0
	switch key {
	case "up", "k":
		step = -1
	case "down", "j":
		step = 1
	case "pgup":
		step = -visible
	case "pgdown":
		step = visible
	default:
		return
	}
	*offset = pagerOffset(pagerOffset(*offset, lines, visible)+step, lines, visible)
}

// writePagerLines writes the lines of a text pager in view from offset, with
// a marker for the lines above and below them. render draws one line.
func writePagerLines[T any](sb *strings.Builder, lines []T, offset, visible int, render func(T) string) {
	offset = pagerOffset(offset, len(lines), visible)
	end := min(offset+visible, len(lines))
	if offset > 0 {
		sb.WriteString(scrollMoreAboveLine(offset))
		sb.WriteString("\n")
	}
	for _, line := range lines[offset:end] {
		sb.WriteString(render(line))
		sb.WriteString("\n")
	}
	if end < len(lines) {
		sb.WriteString(scrollMoreBelowLine(len(lines) - end))
		sb.WriteString("\n")
	}
}

// wrappedRows is how many rows s takes in a popup body width columns wide:
// each of its lines wraps on its own, and an empty line is a row.
func wrappedRows(s string, width int) int {
	rows := 0
	for _, line := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
		rows += max(1, renderedBlockHeight(lipgloss.NewStyle().Width(width).Render(line)))
	}
	return rows
}

// keyDetailsParametersHeading heads the parameters on Key Details.
const keyDetailsParametersHeading = "═══ Parameters ═══\n\n"

// detailsVisibleLines is how many parameter rows (detailsParameterRows) Key
// Details shows: 5, 8 or 12 by terminal height, and never more than the
// popup has room for under the rows drawn above and below them and the two
// scroll markers.
func (m Model) detailsVisibleLines() int {
	lines := 8
	switch {
	case m.height > 30:
		lines = 12
	case m.height < 20:
		lines = 5
	}
	if m.height <= 0 {
		return lines
	}
	width := m.popupBodyWidth(keyDetailsPopupWidth)
	room := m.popupContentHeight() - wrappedRows(m.keyDetailsHeader()+keyDetailsParametersHeading, width) -
		wrappedRows(m.keyDetailsTrailer(), width) - 2
	return max(1, min(lines, room))
}

// getPlaceholderForType returns a placeholder string for the given parameter type.
func getPlaceholderForType(paramType string) string {
	switch paramType {
	case "address":
		return "(enter 58-char Algorand address)"
	case "address[]":
		return "(enter one address per line)"
	case "uint64":
		return "(enter number)"
	case "string":
		return "(enter value)"
	case "select":
		return "(select value)"
	default:
		return "(enter value)"
	}
}

// getFieldWidthForType returns the display width for an input field based on type.
func getFieldWidthForType(paramType string, maxLength int) int {
	switch paramType {
	case "address":
		return 60 // 58 chars + cursor + margin
	case "address[]":
		return 62
	case "uint64":
		return 20 // plenty for large numbers
	case "bytes":
		if maxLength > 0 {
			return maxLength + 2
		}
		return 66 // 32 bytes of hex plus cursor and margin
	case "string":
		if maxLength > 0 {
			return maxLength + 2
		}
		return 40
	case "select":
		return 40
	default:
		return 40
	}
}

// getMaxInputLengthForType returns the maximum input length for a parameter type.
func getMaxInputLengthForType(paramType string, maxLength int) int {
	switch paramType {
	case "address":
		return 58
	case "address[]":
		if maxLength > 0 {
			return maxLength
		}
		return 4096
	case "uint64":
		return 20 // Max uint64 is 20 digits
	case "bytes":
		if maxLength > 0 {
			return maxLength
		}
		return 4096
	case "string":
		if maxLength > 0 {
			return maxLength
		}
		return 256
	case "select":
		if maxLength > 0 {
			return maxLength
		}
		return 256
	default:
		return 256
	}
}

func isMultilineParamType(paramType string) bool {
	return paramType == "address[]"
}

func getFieldHeightForType(paramType string) int {
	if isMultilineParamType(paramType) {
		return 6
	}
	return 1
}
