// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// spoofEnrollmentLabels are labels a client could send to imitate the
// enrollment popup's fields: the fingerprint the operator expects, the
// address line in its old and new names, and a label whose escapes are four
// times its length.
var spoofEnrollmentLabels = []string{
	"laptop-of-ops SHA256:FakeFakeFakeFakeFakeFakeFakeFakeFakeFake123",
	"x Remote Addr: 10.0.0.5:22",
	"x Address: 10.0.0.5:22",
	strings.Repeat("\xff", 64),
}

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

// No label a client sends can draw a line of the enrollment popup that
// looks like one of its fields: the label is quoted and escaped on its one
// line, and the fingerprint and address keep their names on theirs, at
// 80x24, standalone and in a pane, with and without a long error.
func TestEnrollmentPopupLabelCannotImitateAField(t *testing.T) {
	const fingerprint = "SHA256:RealRealRealRealRealRealRealRealRealReal123"
	for _, label := range spoofEnrollmentLabels {
		for _, standalone := range []bool{false, true} {
			for _, withError := range []bool{false, true} {
				name := fmt.Sprintf("label %q standalone %v error %v", label, standalone, withError)
				m := sizedForTest(t, Model{viewState: ViewKeyList, standalone: standalone, connectionState: ConnectionConnected}, MinWidth, MinHeight)
				for i := range 2 {
					m = updateModel(t, m, ClientEnrollmentRequestReceivedMsg{Request: PendingEnrollmentRequest{
						ID: fmt.Sprintf("r%d", i), SSHFingerprint: fingerprint, Label: label, RemoteAddr: "203.0.113.9:51234"}})
				}
				if withError {
					m = updateModel(t, m, ErrorMsg{Error: errors.New(longDaemonError)})
				}
				view := stripANSI(m.View())
				checkFitsMinSize(t, view)
				checkBodyFits(t, name, m)
				labelLines := 0
				for _, line := range popupLines(view) {
					switch {
					case strings.HasPrefix(line, `Label: "`):
						labelLines++
					case strings.Contains(line, "SHA256:") && line != "Fingerprint: "+fingerprint,
						strings.Contains(line, "Addr") && line != "Address: 203.0.113.9:51234":
						t.Errorf("%s: a line that reads like a field: %q\n%s", name, line, view)
					}
				}
				if labelLines != 1 || !strings.Contains(view, "Fingerprint: "+fingerprint) || !strings.Contains(view, "REJECT") {
					t.Errorf("%s: %d label lines, or the fingerprint or the buttons are not on screen:\n%s", name, labelLines, view)
				}
			}
		}
	}
}

// The Enrolled Clients details show a client's label quoted and escaped on
// its one line.
func TestClientDetailsQuoteTheLabel(t *testing.T) {
	for _, label := range spoofEnrollmentLabels {
		m := sizedForTest(t, Model{viewState: ViewEnrolledClients, connectionState: ConnectionConnected, clients: clientsState{
			pending: []protocol.PendingEnrollmentInfo{{Fingerprint: "SHA256:RealRealRealRealRealRealRealRealRealReal123", Label: label,
				KeyType: "ssh-ed25519", RemoteAddr: "203.0.113.9:51234", RequestedAt: 1790000000}}}}, MinWidth, MinHeight)
		view := stripANSI(m.View())
		checkFitsMinSize(t, view)
		details := 0
		for _, line := range strings.Split(view, "\n") {
			if strings.HasPrefix(line, `Label:     "`) {
				details++
			}
		}
		if details != 1 {
			t.Errorf("label %q: %d quoted label lines:\n%s", label, details, view)
		}
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
