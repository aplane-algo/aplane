// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/protocol"
)

// columnOf is the column, as the terminal draws it, where sub starts in
// line, or -1.
func columnOf(line, sub string) int {
	i := strings.Index(line, sub)
	if i < 0 {
		return -1
	}
	return lipgloss.Width(line[:i])
}

// checkColumnAligned fails unless marker starts at the same column on every
// line of view that holds it, of which there must be at least want, and no
// line is wider than width.
func checkColumnAligned(t *testing.T, name, view, marker string, want, width int) {
	t.Helper()
	column, rows := -1, 0
	for _, line := range strings.Split(view, "\n") {
		if lipgloss.Width(line) > width {
			t.Errorf("%s: line wider than %d: %q", name, width, line)
		}
		c := columnOf(line, marker)
		if c < 0 {
			continue
		}
		rows++
		if column < 0 {
			column = c
		} else if c != column {
			t.Errorf("%s: %q at column %d, want %d: %q", name, marker, c, column, line)
		}
	}
	if rows < want {
		t.Errorf("%s: %q on %d rows, want %d:\n%s", name, marker, rows, want, view)
	}
}

// User text is padded and cut in columns, as the terminal draws it, so a
// name of two-column characters keeps its row inside the window and the
// columns after it in line.
func TestRowsPadUserTextInColumns(t *testing.T) {
	const witnessKey = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	var backups []BackupInfo
	for i := range 30 {
		name := fmt.Sprintf("backup-%02d.tar.gz", i)
		if i%2 == 0 {
			name = fmt.Sprintf("田中のバックアップ・サーバー移行前の控え-%02d.tar.gz", i)
		}
		backups = append(backups, BackupInfo{FileName: name, Size: 72000})
	}
	for _, standalone := range []bool{false, true} {
		m := backupsModel(backups...)
		m.standalone, m.restore.selectedBackup = standalone, 29
		m = sizedForTest(t, m, MinWidth, MinHeight)
		view := stripANSI(m.View())
		name := fmt.Sprintf("backups standalone %v", standalone)
		checkBodyFits(t, name, m)
		checkColumnAligned(t, name, view, backup.FormatFileSize(72000), 5, MinWidth)
		if !strings.Contains(view, "> ") || !strings.Contains(view, "backup-29.tar.gz") {
			t.Errorf("%s: the selected backup is not on screen:\n%s", name, view)
		}
	}

	clients := clientsState{keys: []protocol.EnrolledKeyInfo{
		{Fingerprint: "SHA256:Abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG", Label: "田中のノートPC", KeyType: "ssh-ed25519", Connected: true},
		{Fingerprint: "SHA256:Abcdefghijklmnopqrstuvwxyz0123456789ABCDEFH", Label: "ops-laptop", KeyType: "ssh-ed25519", Connected: true},
	}}
	for _, width := range []int{MinWidth, 120} {
		m := sizedForTest(t, Model{viewState: ViewEnrolledClients, connectionState: ConnectionConnected, clients: clients}, width, MinHeight)
		view := stripANSI(m.View())
		name := fmt.Sprintf("clients at %d columns", width)
		checkColumnAligned(t, name, view, "  "+clientConnectedFlag, 2, width)
		// A label is quoted in ASCII, so one stored before labels were
		// ASCII shows as escapes, whole where its column has room.
		if width == 120 && !strings.Contains(view, `"\u7530\u4e2d\u306e\u30ce\u30fc\u30c8PC"  `) {
			t.Errorf("%s: the label is not shown whole, escaped:\n%s", name, view)
		}
	}

	manager := sizedForTest(t, Model{viewState: ViewCosignerReferences, cosigner: cosignerState{loaded: true, references: []CosignerReferenceInfo{
		{Name: "田中の署名者", ComponentKey: witnessKey, KeyType: "aplane.falcon1024.v1"},
		{Name: "ops", ComponentKey: witnessKey, KeyType: "ed25519"},
	}}}, MinWidth, MinHeight)
	checkColumnAligned(t, "cosigner manager", stripANSI(manager.View()), "abcdef0123...", 2, MinWidth)

	picker := sizedForTest(t, Model{viewState: ViewCosignerPicker, cosigner: cosignerState{choices: []cosignerChoice{
		{PrimaryAlias: "田中の署名者", WitnessKeyID: witnessKey}, {PrimaryAlias: "ops", WitnessKeyID: witnessKey},
	}}}, MinWidth, MinHeight)
	checkColumnAligned(t, "cosigner picker", stripANSI(picker.View()), "abcdef0123...", 2, MinWidth)

	policies := sizedForTest(t, Model{viewState: ViewPolicies, policies: policiesState{policy: protocol.PolicyMessage{NodeRole: "signer",
		Keys: []protocol.PolicyKeyStatusWire{{Key: "田中のキー", Status: adminproto.PolicyKeyOwn}, {Key: "ABC", Status: adminproto.PolicyKeyOwn}}}}}, MinWidth, MinHeight)
	checkColumnAligned(t, "policies", stripANSI(policies.View()), "  own policy", 2, MinWidth)
	if view := stripANSI(policies.View()); !strings.Contains(view, "> 田中のキー  own policy") {
		t.Errorf("policies: the key is cut though it fits:\n%s", view)
	}

	library := sizedForTest(t, Model{viewState: ViewTemplateLibrary, library: libraryState{templates: []protocol.LibraryTemplateInfo{
		{FileName: "田中のテンプレート.yaml", TemplateType: "generic"}, {FileName: "ops.yaml", TemplateType: "generic"},
	}}}, MinWidth, MinHeight)
	checkColumnAligned(t, "library", stripANSI(library.View()), "generic", 2, MinWidth)
}

// The width helpers count columns: a path breaks into lines that fit, text
// wraps into lines that fit, and a field line is cut or padded to its width.
func TestWidthHelpersCountColumns(t *testing.T) {
	path := "/home/田中/.local/share/aplane/apsigner-データ/identities/既定/cosigners/田中の署名者の参照ファイル.json"
	lines := strings.Split(wrapPath(path, 20), "\n")
	if strings.Join(lines, "") != path {
		t.Errorf("wrapPath lost part of the path: %q", lines)
	}
	for _, line := range lines {
		if lipgloss.Width(line) > 20 {
			t.Errorf("wrapPath line %q is %d columns", line, lipgloss.Width(line))
		}
	}
	for _, line := range strings.Split(wrapText("送金先 田中のアドレス 承認済み "+strings.Repeat("漢字", 30), 20), "\n") {
		if lipgloss.Width(line) > 20 {
			t.Errorf("wrapText line %q is %d columns", line, lipgloss.Width(line))
		}
	}
	if got := wrapText("送金先 田中のアドレス", 12); got != "送金先\n  田中のアド\n  レス" {
		t.Errorf("wrapText = %q, want a break at the space, then inside the word", got)
	}
	for _, tc := range []struct {
		in    string
		width int
		want  string
	}{
		{"漢字漢字", 5, "漢字 "},
		{"漢字", 6, "漢字  "},
		{"ab", 4, "ab  "},
	} {
		if got := fixedWidthFieldLine(tc.in, tc.width); got != tc.want {
			t.Errorf("fixedWidthFieldLine(%q, %d) = %q, want %q", tc.in, tc.width, got, tc.want)
		}
	}
}
