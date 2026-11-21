// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const testWitnessKeyID = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRST"

func testCosignerReferences() []CosignerReferenceInfo {
	return []CosignerReferenceInfo{
		{
			Name:         "west",
			ComponentKey: testWitnessKeyID,
			KeyType:      "aplane.falcon1024.v1",
			PublicKeyHex: "deadbeefcafebabe",
			ImportedAt:   "2026-09-01T12:00:00Z",
		},
		{
			Name:         "alpha",
			ComponentKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
			KeyType:      "aplane.falcon1024.v1",
		},
		{
			Name:         "east",
			ComponentKey: testWitnessKeyID,
			KeyType:      "aplane.falcon1024.v1",
		},
	}
}

func TestKeyListCosignerShortcutOpensManagerOnlyOnSigner(t *testing.T) {
	signer := Model{
		viewState: ViewKeyList,
		admin:     adminPanelState{settings: &AdminSettings{NodeRole: "signer"}},
	}
	nextModel, cmd := signer.handleKeyListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	next := nextModel.(Model)
	if next.viewState != ViewCosignerReferences {
		t.Fatalf("signer viewState = %v, want %v", next.viewState, ViewCosignerReferences)
	}
	if cmd == nil {
		t.Fatal("signer cosigner manager did not request a reference refresh")
	}

	cosigner := Model{
		viewState: ViewKeyList,
		admin:     adminPanelState{settings: &AdminSettings{NodeRole: "cosigner"}},
	}
	nextModel, cmd = cosigner.handleKeyListKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	next = nextModel.(Model)
	if next.viewState != ViewKeyList {
		t.Fatalf("cosigner viewState = %v, want %v", next.viewState, ViewKeyList)
	}
	if cmd != nil {
		t.Fatal("cosigner node unexpectedly requested signer reference data")
	}
	if next.lastError != "" {
		t.Fatalf("cosigner error = %q, want none", next.lastError)
	}
}

func TestCosignerManagerSortsAliasesAndKeepsPublicKeyOutOfViews(t *testing.T) {
	m := Model{
		width:    120,
		height:   30,
		cosigner: cosignerState{references: testCosignerReferences()},
	}

	references := m.sortedCosignerReferences()
	if got := []string{references[0].Name, references[1].Name, references[2].Name}; strings.Join(got, ",") != "alpha,east,west" {
		t.Fatalf("sorted aliases = %v", got)
	}

	list := stripANSI(m.renderCosignerReferences())
	if !strings.Contains(list, "alpha") || !strings.Contains(list, "east") || !strings.Contains(list, "west") {
		t.Fatalf("manager list missing aliases:\n%s", list)
	}
	if strings.Contains(list, "deadbeefcafebabe") || strings.Contains(list, testWitnessKeyID) {
		t.Fatalf("manager list exposed raw public material or an unabridged ID:\n%s", list)
	}

	m.cosigner.detailsName = "west"
	details := stripANSI(m.renderCosignerReferenceDetails())
	if !strings.Contains(details, groupedWitnessKeyID(testWitnessKeyID)) {
		t.Fatalf("details missing full grouped witness ID:\n%s", details)
	}
	if !strings.Contains(details, "Aliases:  east, west") {
		t.Fatalf("details missing aliases for shared authority:\n%s", details)
	}
	if strings.Contains(details, "deadbeefcafebabe") {
		t.Fatalf("details exposed raw public key:\n%s", details)
	}
	if want := "Public key SHA-256: 3f8a286ab667f1b60da3a12c138461dac343cab1eb3928c433a8062a61d417f8"; !strings.Contains(details, want) {
		t.Fatalf("details missing %q:\n%s", want, details)
	}
}

func TestCosignerManagerRemovalDefaultsToCancelAndReportsResult(t *testing.T) {
	m := Model{
		viewState: ViewCosignerReferenceDetails,
		cosigner: cosignerState{
			references:  testCosignerReferences(),
			detailsName: "west",
		},
	}

	nextModel, _ := m.handleCosignerReferenceDetailsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	next := nextModel.(Model)
	if next.viewState != ViewCosignerRemoveConfirm || next.cosigner.removeFocus != 0 {
		t.Fatalf("remove confirmation = view %v focus %d", next.viewState, next.cosigner.removeFocus)
	}

	nextModel, cmd := next.handleCosignerRemoveConfirmKeys(tea.KeyMsg{Type: tea.KeyEnter})
	next = nextModel.(Model)
	if next.viewState != ViewCosignerReferenceDetails || cmd != nil {
		t.Fatalf("default confirmation did not cancel: view %v cmd nil=%v", next.viewState, cmd == nil)
	}

	next.viewState = ViewCosignerRemoveConfirm
	nextModel, cmd = next.handleCosignerRemoveConfirmKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	next = nextModel.(Model)
	if next.viewState != ViewCosignerRemoving || cmd == nil {
		t.Fatalf("explicit removal = view %v cmd nil=%v", next.viewState, cmd == nil)
	}

	nextModel, _ = next.Update(CosignerRemoveResultMsg{ID: next.operation.id, Success: true, Name: "west", Removed: true})
	next = nextModel.(Model)
	if next.viewState != ViewCosignerReferences || next.cosigner.managerStatus != "Removed west" {
		t.Fatalf("removal result = view %v status %q", next.viewState, next.cosigner.managerStatus)
	}
}

func TestManagerCosignerImportReturnsToManager(t *testing.T) {
	m := Model{
		viewState: ViewCosignerImporting,
		operation: pendingOperation{id: "cosigner-import-1", view: ViewCosignerImporting},
		cosigner: cosignerState{
			returnView:   ViewCosignerReferences,
			envelopeJSON: "sensitive public envelope",
		},
	}
	nextModel, _ := m.Update(CosignerImportResultMsg{
		ID:      "cosigner-import-1",
		Success: true,
		Reference: CosignerReferenceInfo{
			Name:         "west",
			ComponentKey: testWitnessKeyID,
		},
	})
	next := nextModel.(Model)
	if next.viewState != ViewCosignerReferences {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewCosignerReferences)
	}
	if next.cosigner.pendingWitnessID != "" || next.cosigner.pendingKeyType != "" {
		t.Fatal("manager import incorrectly queued cosigned-key generation")
	}
	if next.cosigner.envelopeJSON != "" {
		t.Fatal("manager import retained the public envelope")
	}
}

func TestCosignerImportSuggestsSanitizedFilenameStem(t *testing.T) {
	m := Model{cosigner: cosignerState{
		importPath:  "/operator/exports/Lab Cosigner #1.cos.json",
		importFocus: 0,
	}}
	nextModel, _ := m.handleCosignerImportFormKeys(tea.KeyMsg{Type: tea.KeyTab})
	next := nextModel.(Model)
	if next.cosigner.importName != "lab-cosigner-1" {
		t.Fatalf("suggested name = %q", next.cosigner.importName)
	}
	if next.cosigner.importFocus != 1 {
		t.Fatalf("import focus = %d, want 1", next.cosigner.importFocus)
	}
}

func TestGenerateAccountFromReferencePreselectsCosigner(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{
		{
			KeyType: "ordinary.v1",
		},
		{
			KeyType:                   "cosigned.v1",
			DisplayName:               "Cosigned",
			CosignerComponentKeyTypes: []string{"witness.v1"},
			CreationParams: []protocol.TemplateParamInfo{
				{Name: "cosigner", Label: "Cosigner", Type: "select", Required: true},
				{Name: "recipients", Label: "Recipients", Type: "address[]", Required: true},
			},
		},
	})
	m := Model{
		viewState: ViewCosignerReferenceDetails,
		cosigner: cosignerState{detailsName: "lab", references: []CosignerReferenceInfo{{
			Name: "lab", ComponentKey: testWitnessID1, KeyType: "witness.v1",
		}}},
	}

	nextModel, cmd := m.handleCosignerReferenceDetailsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'g'}})
	next := nextModel.(Model)
	if cmd != nil {
		t.Fatalf("cmd = %v, want nil", cmd)
	}
	if next.viewState != ViewGenerateParams {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewGenerateParams)
	}
	if next.forms.generateKeyType != 0 || next.forms.genericLSigParams["cosigner"] != testWitnessID1 {
		t.Fatalf("generation selection = index %d params %#v", next.forms.generateKeyType, next.forms.genericLSigParams)
	}
	if !next.cosigner.generateFromManager {
		t.Fatal("manager generation continuation was not recorded")
	}

	nextModel, _ = next.handleGenerateParamsKeys(tea.KeyMsg{Type: tea.KeyEsc})
	next = nextModel.(Model)
	if next.viewState != ViewCosignerReferenceDetails || next.cosigner.generateFromManager {
		t.Fatalf("cancel = view %v continuation %v", next.viewState, next.cosigner.generateFromManager)
	}
}

func TestGenerateAccountFromReferenceChoosesAmongCompatibleTypes(t *testing.T) {
	defer setServerKeyTypes(nil)
	setServerKeyTypes([]protocol.KeyTypeInfo{
		{
			KeyType:                   "cosigned-one.v1",
			CosignerComponentKeyTypes: []string{"witness.v1"},
			CreationParams:            []protocol.TemplateParamInfo{{Name: "cosigner", Type: "select"}},
		},
		{KeyType: "wrong.v1", CosignerComponentKeyTypes: []string{"witness.v2"}},
		{
			KeyType:                   "cosigned-two.v1",
			CosignerComponentKeyTypes: []string{"witness.v1"},
			CreationParams:            []protocol.TemplateParamInfo{{Name: "cosigner", Type: "select"}},
		},
	})
	m := Model{
		viewState: ViewCosignerReferenceDetails,
		cosigner: cosignerState{detailsName: "lab", references: []CosignerReferenceInfo{{
			Name: "lab", ComponentKey: testWitnessID1, KeyType: "witness.v1",
		}}},
	}

	nextModel, _ := m.beginDetailsCosignerGeneration()
	next := nextModel.(Model)
	if next.viewState != ViewCosignerGenerateType {
		t.Fatalf("viewState = %v, want %v", next.viewState, ViewCosignerGenerateType)
	}
	// Selection order is alphabetical: cosigned-one, cosigned-two, wrong.
	if got := next.cosigner.generateTypeIndices; len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("compatible indices = %v", got)
	}

	nextModel, _ = next.handleCosignerGenerateTypeKeys(tea.KeyMsg{Type: tea.KeyDown})
	next = nextModel.(Model)
	nextModel, _ = next.handleCosignerGenerateTypeKeys(tea.KeyMsg{Type: tea.KeyEnter})
	next = nextModel.(Model)
	if next.viewState != ViewGenerateParams || next.forms.generateKeyType != 1 {
		t.Fatalf("selected generation = view %v index %d", next.viewState, next.forms.generateKeyType)
	}
	if next.forms.genericLSigParams["cosigner"] != testWitnessID1 {
		t.Fatalf("cosigner selector = %q", next.forms.genericLSigParams["cosigner"])
	}
}

func TestCosignerDetailsHaveNoClientRouteActions(t *testing.T) {
	t.Setenv("APCLIENT_DATA", t.TempDir())
	m := Model{width: 120, height: 40, viewState: ViewCosignerReferenceDetails, cosigner: cosignerState{references: testCosignerReferences(), detailsName: "alpha"}}
	view := m.renderCosignerReferenceDetails()
	for _, label := range []string{"Client routes", "Live route", "Verify route"} {
		if strings.Contains(view, label) {
			t.Fatalf("details expose client routing: %s", label)
		}
	}
	next, cmd := m.handleCosignerReferenceDetailsKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'v'}})
	if cmd != nil || next.(Model).viewState != ViewCosignerReferenceDetails {
		t.Fatal("v still starts route verification")
	}
}

// The manager lists the reference files that are not valid references after
// the references, and a note below the list counts them, at the minimum window
// size too. Every one is reachable by scrolling.
func TestCosignerManagerReportsInvalidReferenceFiles(t *testing.T) {
	var references []CosignerReferenceInfo
	for i := 0; i < 12; i++ {
		references = append(references, CosignerReferenceInfo{Name: fmt.Sprintf("ref-%02d", i), ComponentKey: testWitnessKeyID, KeyType: "aplane.falcon1024.v1"})
	}
	var invalid []InvalidCosignerReferenceInfo
	for _, name := range []string{"bad", "Lab", "my ref", "._lab", "x"} {
		invalid = append(invalid, InvalidCosignerReferenceInfo{
			Path: "/var/lib/apsigner/identities/default/cosigners/" + name + ".json", Name: name, Reason: "unsupported schema \"wrong\"",
		})
	}
	m := sizedForTest(t, Model{viewState: ViewCosignerReferences, cosigner: cosignerState{loaded: true, references: references, invalid: invalid}}, MinWidth, MinHeight)
	const note = "5 reference file(s) are not valid references; select one to clear it."
	view := stripANSI(m.View())
	checkFitsMinSize(t, view)
	for _, want := range []string{note, "> ref-00"} {
		if !strings.Contains(view, want) {
			t.Errorf("%q missing from:\n%s", want, view)
		}
	}
	for range len(references) + len(invalid) - 1 {
		m = press(t, m, "down")
	}
	view = stripANSI(m.View())
	checkFitsMinSize(t, view)
	for _, want := range []string{note, `  bad.json: unsupported schema "wrong"`, `  my ref.json: unsupported schema "wrong"`, `> x.json: unsupported schema "wrong"`} {
		if !strings.Contains(view, want) {
			t.Errorf("%q missing from:\n%s", want, view)
		}
	}
}

// invalidCosignerReferencesModel is the manager at the minimum window size
// with two references and, listed after them, two reference files that are
// not valid references: one remove clears, and one only deleting it does.
func invalidCosignerReferencesModel(t *testing.T) Model {
	t.Helper()
	const dir = "/var/lib/apsigner/identities/default/cosigners/"
	return sizedForTest(t, Model{viewState: ViewCosignerReferences, connectionState: ConnectionConnected, cosigner: cosignerState{
		loaded: true,
		references: []CosignerReferenceInfo{
			{Name: "alpha", ComponentKey: testWitnessKeyID, KeyType: "aplane.falcon1024.v1"},
			{Name: "west", ComponentKey: testWitnessKeyID, KeyType: "aplane.falcon1024.v1"},
		},
		invalid: []InvalidCosignerReferenceInfo{
			{Path: dir + "bad.json", Name: "bad", Reason: `unsupported schema "wrong"`, Removable: true},
			{Path: dir + "my ref.json", Name: "my ref", Reason: `"my ref" is not a reference name`},
		},
	}}, MinWidth, MinHeight)
}

// checkFitsMinSize fails when view is taller or wider than the minimum window.
func checkFitsMinSize(t *testing.T, view string) {
	t.Helper()
	lines := strings.Split(strings.TrimRight(view, "\n"), "\n")
	if len(lines) > MinHeight {
		t.Errorf("view is %d lines, more than the %d-line window:\n%s", len(lines), MinHeight, view)
	}
	for _, line := range lines {
		if lipgloss.Width(line) > MinWidth {
			t.Errorf("line wider than the window: %q", line)
		}
	}
}

// sentCosignerRemovals connects m to a pipe and returns the name of each
// cosigner reference removal it sends.
func sentCosignerRemovals(t *testing.T, m *Model) <-chan string {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = serverConn.Close() })
	client := NewAdminClient(&queueConnector{conns: []io.ReadWriteCloser{clientConn}})
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(client.Disconnect)
	m.adminClient = client
	sent := make(chan string, 8)
	go func() {
		reader := bufio.NewReader(serverConn)
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				return
			}
			var msg protocol.RemoveCosignerReferenceMessage
			if json.Unmarshal(line, &msg) == nil && msg.Type == protocol.MsgTypeRemoveCosignerReference {
				sent <- msg.Name
			}
		}
	}()
	return sent
}

// A reference file that is not a valid reference is a row of the list. One
// that remove clears is removed through the same confirmation as a
// reference, which defaults to Cancel.
func TestCosignerManagerRemovesARemovableInvalidReferenceFile(t *testing.T) {
	m := invalidCosignerReferencesModel(t)
	removals := sentCosignerRemovals(t, &m)
	m = press(t, m, "down", "down")
	view := stripANSI(m.View())
	checkFitsMinSize(t, view)
	for _, want := range []string{`> bad.json: unsupported schema "wrong"`, "enter: Clear"} {
		if !strings.Contains(view, want) {
			t.Errorf("%q missing from:\n%s", want, view)
		}
	}

	m = press(t, m, "enter")
	if m.viewState != ViewCosignerRemoveConfirm || m.cosigner.removeFocus != 0 {
		t.Fatalf("enter = view %v focus %d, want the remove confirmation on Cancel", m.viewState, m.cosigner.removeFocus)
	}
	view = stripANSI(m.View())
	checkFitsMinSize(t, view)
	for _, want := range []string{"REMOVE COSIGNER REFERENCE", "bad.json", `unsupported schema "wrong"`, "CANCEL", "REMOVE"} {
		if !strings.Contains(view, want) {
			t.Errorf("%q missing from:\n%s", want, view)
		}
	}
	if m = press(t, m, "enter"); m.viewState != ViewCosignerReferences {
		t.Fatalf("Cancel = view %v, want the list", m.viewState)
	}

	m = press(t, m, "enter")
	next, cmd := m.handleKeyPress(browserKey("y"))
	m = next.(Model)
	if m.viewState != ViewCosignerRemoving {
		t.Fatalf("y = view %v, want removing", m.viewState)
	}
	runSends(cmd)
	select {
	case name := <-removals:
		if name != "bad" {
			t.Fatalf("removal sent for %q, want bad", name)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no removal was sent")
	}
	m = updateModel(t, m, CosignerRemoveResultMsg{ID: m.operation.id, Success: true, Name: "bad", Removed: true})
	if m.viewState != ViewCosignerReferences || m.cosigner.managerStatus != "Removed bad" {
		t.Fatalf("result = view %v status %q", m.viewState, m.cosigner.managerStatus)
	}
}

// A file remove does not reach is not offered for removal: choosing it says
// to delete the file.
func TestCosignerManagerSaysToDeleteAnInvalidFileRemoveDoesNotReach(t *testing.T) {
	m := invalidCosignerReferencesModel(t)
	m = press(t, m, "down", "down", "down")
	next, cmd := m.handleKeyPress(browserKey("enter"))
	m = next.(Model)
	if m.viewState != ViewCosignerReferences || cmd != nil {
		t.Fatalf("enter = view %v cmd nil=%v, want the list and no request", m.viewState, cmd == nil)
	}
	view := stripANSI(m.View())
	checkFitsMinSize(t, view)
	want := "Remove does not reach this file; delete it to clear it: /var/lib/apsigner/identities/default/cosigners/my ref.json"
	if flat := strings.Join(strings.Fields(view), " "); !strings.Contains(flat, want) {
		t.Errorf("%q missing from:\n%s", want, view)
	}
}

// The remove confirmation removes what it opened on. A list that arrives
// while it is open, here with a reference that sorts into the rows, moves the
// rows under the cursor but not the confirmation's target, for a reference
// file and for a reference alike.
func TestCosignerRemoveConfirmationKeepsItsTargetAcrossAList(t *testing.T) {
	zeta := CosignerReferenceInfo{Name: "zeta", ComponentKey: testWitnessKeyID, KeyType: "aplane.falcon1024.v1"}
	aaa := CosignerReferenceInfo{Name: "aaa", ComponentKey: testWitnessKeyID, KeyType: "aplane.falcon1024.v1"}
	for _, tc := range []struct {
		name     string
		open     []string
		added    CosignerReferenceInfo
		want     string
		wantText string
	}{
		{name: "reference file", open: []string{"down", "down", "enter"}, added: zeta, want: "bad", wantText: "bad.json"},
		{name: "reference", open: []string{"down", "enter", "d"}, added: aaa, want: "west", wantText: "Remove alias west"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := invalidCosignerReferencesModel(t)
			removals := sentCosignerRemovals(t, &m)
			m = press(t, m, tc.open...)
			if m.viewState != ViewCosignerRemoveConfirm {
				t.Fatalf("view %v, want the remove confirmation", m.viewState)
			}
			references := append(append([]CosignerReferenceInfo(nil), m.cosigner.references...), tc.added)
			m = updateModel(t, m, CosignerReferencesMsg{References: references, Invalid: m.cosigner.invalid})
			view := stripANSI(m.View())
			checkFitsMinSize(t, view)
			if !strings.Contains(view, tc.wantText) || strings.Contains(view, tc.added.Name) {
				t.Fatalf("after the list the confirmation shows:\n%s", view)
			}
			next, cmd := m.handleKeyPress(browserKey("y"))
			m = next.(Model)
			runSends(cmd)
			select {
			case name := <-removals:
				if name != tc.want {
					t.Fatalf("removal sent for %q, want %q", name, tc.want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no removal was sent")
			}
		})
	}
}

// A target the list no longer holds is not removed: the confirmation says so
// and y returns to the list without a request.
func TestCosignerRemoveConfirmationDropsATargetNoLongerListed(t *testing.T) {
	m := invalidCosignerReferencesModel(t)
	m = press(t, m, "down", "down", "enter")
	m = updateModel(t, m, CosignerReferencesMsg{References: m.cosigner.references, Invalid: m.cosigner.invalid[1:]})
	if view := stripANSI(m.View()); !strings.Contains(view, "Cosigner reference is no longer available") {
		t.Fatalf("confirmation after its target went:\n%s", view)
	}
	next, cmd := m.handleKeyPress(browserKey("y"))
	if got := next.(Model); got.viewState != ViewCosignerReferences || cmd != nil {
		t.Fatalf("y = view %v cmd nil=%v, want the list and no request", got.viewState, cmd == nil)
	}
}

// The hint for a reference file remove does not reach keeps all of its path on
// screen at the minimum window size, with a full list and a deep data
// directory, a long file name with spaces included. The list gives up rows
// for it, and the selected row stays in view.
func TestCosignerDeleteHintKeepsItsPathOnScreenAtMinSize(t *testing.T) {
	for _, tc := range []struct{ dir, name string }{
		{"/home/operator-with-a-long-name/.local/share/aplane/apsigner-data/identities/default/cosigners/", "a-really-long-file-name-for-a-cosigner-reference"},
		{"/home/operator/.aplane/apsigner/identities/default/cosigners/", "copy of the west cosigner reference from the old machine before the move"},
	} {
		var references []CosignerReferenceInfo
		for i := 0; i < 12; i++ {
			references = append(references, CosignerReferenceInfo{Name: fmt.Sprintf("ref-%02d", i), ComponentKey: testWitnessKeyID, KeyType: "aplane.falcon1024.v1"})
		}
		var invalid []InvalidCosignerReferenceInfo
		for _, name := range []string{"bad", "Lab", "my ref", "._lab", tc.name} {
			invalid = append(invalid, InvalidCosignerReferenceInfo{Path: tc.dir + name + ".json", Name: name, Reason: `unsupported schema "wrong"`})
		}
		m := sizedForTest(t, Model{viewState: ViewCosignerReferences, cosigner: cosignerState{loaded: true, references: references, invalid: invalid}}, MinWidth, MinHeight)
		for range len(references) + len(invalid) - 1 {
			m = press(t, m, "down")
		}
		m = press(t, m, "enter")
		view := stripANSI(m.View())
		checkFitsMinSize(t, view)
		flat := strings.Join(strings.Fields(view), "")
		path := strings.Join(strings.Fields(tc.dir+tc.name+".json"), "")
		if !strings.Contains(flat, path) || !strings.Contains(flat, "deleteittoclearit:") || !strings.Contains(view, "> "+tc.name[:8]) {
			t.Errorf("%s: the hint's path or the selected row is not all on screen:\n%s", tc.name, view)
		}
	}
}

// The hint is about the selected row, so moving to another row clears it.
func TestCosignerDeleteHintClearsWhenTheCursorMoves(t *testing.T) {
	m := invalidCosignerReferencesModel(t)
	m = press(t, m, "down", "down", "down", "enter")
	if !strings.Contains(stripANSI(m.View()), "delete it to clear it") {
		t.Fatalf("no hint after enter:\n%s", stripANSI(m.View()))
	}
	if m = press(t, m, "down"); !strings.Contains(stripANSI(m.View()), "delete it to clear it") {
		t.Fatalf("the hint went though the cursor stayed on the last row:\n%s", stripANSI(m.View()))
	}
	if m = press(t, m, "up"); strings.Contains(stripANSI(m.View()), "delete it to clear it") {
		t.Fatalf("the hint stayed after the cursor moved:\n%s", stripANSI(m.View()))
	}
}

// After a failed list the rows shown are the last list read, and the manager
// says so whenever it shows any, reference files included.
func TestCosignerManagerMarksAStaleListOfReferenceFilesOnly(t *testing.T) {
	m := sizedForTest(t, Model{viewState: ViewCosignerReferences, cosigner: cosignerState{loaded: true, listErr: "store busy",
		invalid: []InvalidCosignerReferenceInfo{{Path: "/data/cosigners/bad.json", Name: "bad", Reason: `unsupported schema "wrong"`, Removable: true}},
	}}, MinWidth, MinHeight)
	if view := stripANSI(m.View()); !strings.Contains(view, "Showing the last list read.") {
		t.Fatalf("a stale list of reference files is not marked:\n%s", view)
	}
}

// The details screen shows the reference it opened on. A list that arrives
// while it is open, here with a reference that sorts ahead of it, moves the
// rows under the cursor but not the details, before and after a cancelled
// removal; a reference the list no longer holds is no longer available.
func TestCosignerReferenceDetailsKeepTheirReferenceAcrossAList(t *testing.T) {
	aaa := CosignerReferenceInfo{Name: "aaa", ComponentKey: testWitnessKeyID, KeyType: "aplane.falcon1024.v1"}
	m := invalidCosignerReferencesModel(t)
	m = press(t, m, "down", "enter")
	if m.viewState != ViewCosignerReferenceDetails {
		t.Fatalf("view %v, want the details", m.viewState)
	}
	references := append(append([]CosignerReferenceInfo(nil), m.cosigner.references...), aaa)
	m = updateModel(t, m, CosignerReferencesMsg{References: references, Invalid: m.cosigner.invalid})
	for _, step := range [][]string{nil, {"d", "esc"}} {
		m = press(t, m, step...)
		view := stripANSI(m.View())
		checkFitsMinSize(t, view)
		if m.viewState != ViewCosignerReferenceDetails || !strings.Contains(view, "Name:     west") {
			t.Fatalf("after %v: view %v shows:\n%s", step, m.viewState, view)
		}
	}
	m = updateModel(t, m, CosignerReferencesMsg{References: references[:1], Invalid: m.cosigner.invalid})
	if view := stripANSI(m.View()); !strings.Contains(view, "Cosigner reference is no longer available") {
		t.Fatalf("details after their reference went:\n%s", view)
	}
}

// fullInvalidCosignerReferencesModel is the manager at the minimum window
// size with 12 references and 5 reference files in dir that remove does not
// reach, the last named name, with the cursor on that last row.
func fullInvalidCosignerReferencesModel(t *testing.T, dir, name string, standalone bool) Model {
	t.Helper()
	var references []CosignerReferenceInfo
	for i := 0; i < 12; i++ {
		references = append(references, CosignerReferenceInfo{Name: fmt.Sprintf("ref-%02d", i), ComponentKey: testWitnessKeyID, KeyType: "aplane.falcon1024.v1"})
	}
	var invalid []InvalidCosignerReferenceInfo
	for _, file := range []string{"bad", "Lab", "my ref", "._lab", name} {
		invalid = append(invalid, InvalidCosignerReferenceInfo{Path: dir + file + ".json", Name: file, Reason: `unsupported schema "wrong"`})
	}
	m := sizedForTest(t, Model{standalone: standalone, viewState: ViewCosignerReferences, connectionState: ConnectionConnected,
		cosigner: cosignerState{loaded: true, references: references, invalid: invalid}}, MinWidth, MinHeight)
	for range len(references) + len(invalid) - 1 {
		m = press(t, m, "down")
	}
	return m
}

// When the status and a list error need more room than the manager keeps
// below its list, the list gives up rows, so the window cuts none of it: with
// a status left by an earlier removal, with a failed re-list, and with a file
// name longer than a line. Each case takes rows from the list, and the hint's
// path and the selected row stay on screen, in a pane and standalone.
func TestCosignerManagerGivesUpRowsForALongStatus(t *testing.T) {
	const (
		deepDir = "/home/operator-with-a-long-name/.local/share/aplane/apsigner-data/identities/default/cosigners/"
		spaced  = "copy of the west cosigner reference from the old machine before the move"
		// Short, so the status bar's copy of it fits the window too.
		listError = "store busy; try again"
	)
	long := strings.Repeat("x", 100)
	for _, tc := range []struct {
		name, dir, file string
		after           func(Model) Model
	}{
		{"status from an earlier removal", deepDir, spaced, func(m Model) Model {
			m.cosigner.managerStatus = "Removed bad"
			return m
		}},
		{"failed re-list", deepDir, "a-really-long-file-name-for-a-cosigner-reference", func(m Model) Model {
			return updateModel(t, m, CosignerReferencesMsg{Error: listError})
		}},
		{"file name longer than a line", deepDir, long, func(m Model) Model { return m }},
	} {
		for _, standalone := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s standalone %v", tc.name, standalone), func(t *testing.T) {
				m := fullInvalidCosignerReferencesModel(t, tc.dir, tc.file, standalone)
				m = tc.after(press(t, m, "enter"))
				quiet := m
				quiet.cosigner.managerStatus, quiet.cosigner.deleteHint, quiet.cosigner.listErr = "", "", ""
				if m.cosignerManagerVisibleRows() >= quiet.cosignerManagerVisibleRows() {
					t.Fatalf("the list keeps %d rows, as many as with no status: the case does not need more room", m.cosignerManagerVisibleRows())
				}
				view := stripANSI(m.View())
				checkFitsMinSize(t, view)
				flat := strings.Join(strings.Fields(view), "")
				path := strings.Join(strings.Fields(tc.dir+tc.file+".json"), "")
				if !strings.Contains(flat, path) || !strings.Contains(view, "> "+tc.file[:8]) {
					t.Errorf("the hint's path or the selected row is not all on screen:\n%s", view)
				}
			})
		}
	}
}

// The hint stays only while the selected row is still the file it names. The
// operator deletes the file and refreshes, so the cursor lands on bad.json;
// a reference sorted ahead of the rows, as an import adds, moves another row
// under the cursor. A list that leaves the file under the cursor keeps it.
func TestCosignerDeleteHintFollowsItsRowAcrossAList(t *testing.T) {
	aaa := CosignerReferenceInfo{Name: "aaa", ComponentKey: testWitnessKeyID, KeyType: "aplane.falcon1024.v1"}
	for _, tc := range []struct {
		name     string
		list     func(Model) CosignerReferencesMsg
		wantHint bool
	}{
		{"file deleted", func(m Model) CosignerReferencesMsg {
			return CosignerReferencesMsg{References: m.cosigner.references, Invalid: m.cosigner.invalid[:1]}
		}, false},
		{"rows moved", func(m Model) CosignerReferencesMsg {
			return CosignerReferencesMsg{References: append(append([]CosignerReferenceInfo(nil), m.cosigner.references...), aaa), Invalid: m.cosigner.invalid}
		}, false},
		{"same rows", func(m Model) CosignerReferencesMsg {
			return CosignerReferencesMsg{References: m.cosigner.references, Invalid: m.cosigner.invalid}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := invalidCosignerReferencesModel(t)
			m = press(t, m, "down", "down", "down", "enter", "r")
			if !strings.Contains(stripANSI(m.View()), "delete it to clear it") {
				t.Fatalf("no hint after enter:\n%s", stripANSI(m.View()))
			}
			m = updateModel(t, m, tc.list(m))
			view := stripANSI(m.View())
			checkFitsMinSize(t, view)
			if got := strings.Contains(view, "delete it to clear it"); got != tc.wantHint {
				t.Fatalf("hint shown %v, want %v, with the cursor on row %d:\n%s", got, tc.wantHint, m.cosigner.managerSelected, view)
			}
		})
	}
}
