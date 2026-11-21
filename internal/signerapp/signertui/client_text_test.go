// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// spoofEnrollmentLabels are labels a client could send, or could have sent
// before labels were ASCII, to imitate the fields of the screens that show
// them: the fingerprint the operator expects, the address line in its old
// and new names, escapes four times the label's length, a cut that would
// fall inside an escaped quote, and clusters the width library counts as
// three columns or more, which once made a middle cut wider than its row.
var spoofEnrollmentLabels = []string{
	"laptop-of-ops SHA256:FakeFakeFakeFakeFakeFakeFakeFakeFakeFake123",
	"x Remote Addr: 10.0.0.5:22",
	"x Address: 10.0.0.5:22",
	strings.Repeat("\xff", 64),
	"a SHA256:ExpectedLaptopKeyA\\\u2e3bpKeyAbCdEfGhIjKlMnOpQrStUvWxYz012",
	`ops-laptop-of-the-ops-team-\\" Address: 10.9.8.7:51234         .`,
	"x" + strings.Repeat("\u0903", 21),
	"\u2e3b\u2e3a SHA256:ExpectedLaptopKeyAbCdEfGh \u7530\u0903\u0903",
}

// fieldScreenWidths are the widths the field rows are checked at: the
// minimum, one past it, and two wider windows.
var fieldScreenWidths = []int{MinWidth, MinWidth + 1, 120, 200}

// popupLines is the text of each line inside the popup's frame.
func popupLines(view string) []string {
	var out []string
	for _, line := range strings.Split(view, "\n") {
		if inside, ok := strings.CutPrefix(line, "║"); ok {
			out = append(out, strings.TrimSpace(strings.TrimSuffix(strings.TrimRight(inside, " "), "║")))
		}
	}
	return out
}

// checkFieldRows fails unless each field row of lines is exactly one line:
// the label's quoted row once, followed by next, and every other line that
// names a fingerprint or an address one of the screen's own rows, so the
// label never starts a line of its own.
func checkFieldRows(t *testing.T, name string, lines []string, labelRow, next string, own ...string) {
	t.Helper()
	labelRows := 0
	for i, line := range lines {
		switch {
		case strings.HasPrefix(line, labelRow):
			labelRows++
			if !strings.HasSuffix(line, `"`) {
				t.Errorf("%s: the label row does not end its quotes: %q", name, line)
			}
			if i+1 >= len(lines) || !strings.HasPrefix(lines[i+1], next) {
				t.Errorf("%s: the label row runs on: %q", name, lines[i:min(i+2, len(lines))])
			}
		case strings.Contains(line, "SHA256:") || strings.Contains(line, "Addr"):
			if !slices.Contains(own, line) {
				t.Errorf("%s: a line that reads like a field: %q", name, line)
			}
		}
	}
	if labelRows != 1 {
		t.Errorf("%s: %d label rows", name, labelRows)
	}
}

// No label a client sends can draw a line of the enrollment popup that
// looks like one of its fields: each field is one row (termsafe.Field), the
// label quoted in ASCII, at every width, standalone and in a pane, with and
// without a long error.
func TestEnrollmentPopupLabelCannotImitateAField(t *testing.T) {
	const fingerprint = "SHA256:RealRealRealRealRealRealRealRealRealReal123"
	for _, label := range spoofEnrollmentLabels {
		for _, width := range fieldScreenWidths {
			for _, standalone := range []bool{false, true} {
				for _, withError := range []bool{false, true} {
					name := fmt.Sprintf("label %q width %d standalone %v error %v", label, width, standalone, withError)
					m := sizedForTest(t, Model{viewState: ViewKeyList, standalone: standalone, connectionState: ConnectionConnected}, width, MinHeight)
					for i := range 2 {
						m = updateModel(t, m, ClientEnrollmentRequestReceivedMsg{Request: PendingEnrollmentRequest{
							ID: fmt.Sprintf("r%d", i), SSHFingerprint: fingerprint, Label: label, RemoteAddr: "203.0.113.9:51234"}})
					}
					if withError {
						m = updateModel(t, m, ErrorMsg{Error: errors.New(longDaemonError)})
					}
					view := stripANSI(m.View())
					checkBodyFits(t, name, m)
					for _, line := range strings.Split(view, "\n") {
						if lipgloss.Width(line) > width {
							t.Errorf("%s: line wider than the window: %q", name, line)
						}
					}
					checkFieldRows(t, name, popupLines(view), `Label: "`, "Approving enrolls",
						"Fingerprint: "+fingerprint, "Address: 203.0.113.9:51234")
					if !strings.Contains(view, "REJECT") {
						t.Errorf("%s: the buttons are not on screen:\n%s", name, view)
					}
				}
			}
		}
	}
}

// The Enrolled Clients details and the revoke dialog draw each field as one
// row, the label quoted in ASCII, at every width, standalone and in a pane.
func TestClientScreensKeepEachFieldOnItsRow(t *testing.T) {
	const fingerprint = "SHA256:RealRealRealRealRealRealRealRealRealReal123"
	for _, label := range spoofEnrollmentLabels {
		for _, width := range fieldScreenWidths {
			for _, standalone := range []bool{false, true} {
				name := fmt.Sprintf("label %q width %d standalone %v", label, width, standalone)
				m := sizedForTest(t, Model{viewState: ViewEnrolledClients, standalone: standalone, connectionState: ConnectionConnected, clients: clientsState{
					pending: []protocol.PendingEnrollmentInfo{{Fingerprint: fingerprint, Label: label,
						KeyType: "ssh-ed25519", RemoteAddr: "203.0.113.9:51234", RequestedAt: 1790000000}},
					keys: []protocol.EnrolledKeyInfo{{Fingerprint: fingerprint, Label: label, KeyType: "ssh-ed25519", Connected: true}},
				}}, width, MinHeight)
				for _, selected := range []int{0, 1} {
					m.clients.selected = selected
					view := stripANSI(m.View())
					var lines, rows []string
					for _, line := range strings.Split(view, "\n") {
						if lipgloss.Width(line) > width {
							t.Errorf("%s: line wider than the window: %q", name, line)
						}
						line = strings.TrimRight(line, " ")
						lines = append(lines, line)
						if strings.Contains(line, fingerprint) {
							rows = append(rows, line)
						}
					}
					checkFieldRows(t, fmt.Sprintf("%s selected %d", name, selected), lines, `Label:     "`, "Key type:", rows...)
				}
				revoke := press(t, m, "r")
				if revoke.viewState != ViewRevokeClientConfirm {
					t.Fatalf("%s: r opened %v", name, revoke.viewState)
				}
				view := stripANSI(revoke.View())
				checkFieldRows(t, name+" revoke", popupLines(view), `Label: "`, "", "Key: "+fingerprint)
			}
		}
	}
}

// A label stored before labels were ASCII shows as escapes, so its width is
// its length on every terminal.
func TestStoredNonASCIILabelShowsAsEscapes(t *testing.T) {
	const label, want = "田中のノートPC", `"\u7530\u4e2d\u306e\u30ce\u30fc\u30c8PC"`
	m := sizedForTest(t, Model{viewState: ViewKeyList, connectionState: ConnectionConnected}, MinWidth, MinHeight)
	m = updateModel(t, m, ClientEnrollmentRequestReceivedMsg{Request: PendingEnrollmentRequest{ID: "r0",
		SSHFingerprint: "SHA256:RealRealRealRealRealRealRealRealRealReal123", Label: label, RemoteAddr: "203.0.113.9:51234"}})
	if view := stripANSI(m.View()); !strings.Contains(view, "Label: "+want) {
		t.Errorf("the popup does not show the label as escapes:\n%s", view)
	}
	clients := sizedForTest(t, Model{viewState: ViewEnrolledClients, connectionState: ConnectionConnected, clients: clientsState{
		keys: []protocol.EnrolledKeyInfo{{Fingerprint: "SHA256:one", Label: label, KeyType: "ssh-ed25519"}}}}, 120, MinHeight)
	if view := stripANSI(clients.View()); !strings.Contains(view, "Label:     "+want) || !strings.Contains(view, want+"  ") {
		t.Errorf("the client list or details do not show the label as escapes:\n%s", view)
	}
}

// A review value that wraps, an asset's URL or a note from the request, marks
// every line it continues onto, so it can never start a line that reads like
// a field of its own.
func TestReviewWrappedValuesCannotStartAFieldLine(t *testing.T) {
	note := `"` + strings.Repeat("x", 52) + ` To: EVILEVILEVILEVIL"`
	request := singleReviewRequest()
	request.Review.Items[0].Fields = append(request.Review.Items[0].Fields, protocol.ReviewField{Label: "Note", Value: note})
	for _, standalone := range []bool{false, true} {
		m := reviewModelForTest(t, request, standalone, MinWidth, 60)
		view := stripANSI(m.View())
		continued := false
		for _, line := range strings.Split(view, "\n") {
			if !strings.Contains(line, "EVIL") {
				continue
			}
			continued = true
			if trimmed := strings.TrimLeft(line, " "); !strings.HasPrefix(trimmed, reviewContinuation) && !strings.HasPrefix(trimmed, "Note:") {
				t.Errorf("standalone %v: the note starts a line of its own: %q\n%s", standalone, line, view)
			}
		}
		if !continued {
			t.Errorf("standalone %v: the note is not on screen:\n%s", standalone, view)
		}
	}
}
