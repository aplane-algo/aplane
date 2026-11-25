// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// secretFields are the Model's secret-bearing fields, by path, each with a way
// to fill it and, for a byte buffer, to read it.
var secretFields = map[string]struct {
	fill   func(*Model)
	buffer func(Model) []byte // nil for the import form's text area
}{
	"Model.auth.passphraseInput": {
		func(m *Model) { m.auth.passphraseInput = SensitiveBytes("login secret") },
		func(m Model) []byte { return m.auth.passphraseInput }},
	"Model.backup.exportPassphrase": {
		func(m *Model) { m.backup.exportPassphrase = SensitiveBytes("export secret") },
		func(m Model) []byte { return m.backup.exportPassphrase }},
	"Model.backup.confirmPassphrase": {
		func(m *Model) { m.backup.confirmPassphrase = SensitiveBytes("confirm secret") },
		func(m Model) []byte { return m.backup.confirmPassphrase }},
	"Model.restore.passphrase": {
		func(m *Model) { m.restore.passphrase = []byte("restore secret") },
		func(m Model) []byte { return m.restore.passphrase }},
	"Model.mnemonicExport.passphrase": {
		func(m *Model) { m.mnemonicExport.passphrase = SensitiveBytes("phrase export secret") },
		func(m Model) []byte { return m.mnemonicExport.passphrase }},
	"Model.mnemonicExport.words": {
		func(m *Model) { m.mnemonicExport.words = SensitiveBytes("revealed words") },
		func(m Model) []byte { return m.mnemonicExport.words }},
	"Model.sourceTokens.token": {
		func(m *Model) { m.sourceTokens.token = SensitiveBytes("source token") },
		func(m Model) []byte { return m.sourceTokens.token }},
	"Model.backups.imp.passphrase": {
		func(m *Model) { m.backups.imp.passphrase = []byte("import secret") },
		func(m Model) []byte { return m.backups.imp.passphrase }},
	"Model.forms.importMnemonicInput": {
		func(m *Model) {
			m.forms.importMnemonicInput = newImportMnemonicInput()
			m.forms.importMnemonicInput.SetValue("w01 w02 w03")
		}, nil},
}

// notSecretFields are the Model's other byte buffers and text areas.
var notSecretFields = []string{
	"Model.adminClient.stream.reader.buf", // clears what it has read itself
	"Model.policies.apply.edit.input",     // a policy document
}

// Every byte buffer and text area of the Model is a secret the session's end
// must clear or is known not to be one, so a new field is not missed. It looks
// into every struct of this module, however often the Model holds one. A byte
// array is a hash, and not typed input.
func TestEveryInputOfTheModelIsClassified(t *testing.T) {
	var found []string
	within := make(map[reflect.Type]bool) // the structs around the current field
	modelPackage := reflect.TypeOf(Model{}).PkgPath()
	module, _, _ := strings.Cut(modelPackage, "/internal/")
	var walk func(path string, typ reflect.Type)
	walk = func(path string, typ reflect.Type) {
		switch typ.Kind() {
		case reflect.Slice:
			if typ.Elem().Kind() == reflect.Uint8 {
				found = append(found, path)
				return
			}
			walk(path+"[]", typ.Elem())
		case reflect.Pointer:
			walk(path, typ.Elem())
		case reflect.Array, reflect.Map:
			walk(path+"[]", typ.Elem())
		case reflect.Struct:
			switch {
			case typ.String() == "textarea.Model" || typ.String() == "textinput.Model":
				found = append(found, path)
			case strings.HasPrefix(typ.PkgPath(), module+"/") && !within[typ]:
				within[typ] = true
				for i := range typ.NumField() {
					walk(path+"."+typ.Field(i).Name, typ.Field(i).Type)
				}
				delete(within, typ)
			}
		}
	}
	walk("Model", reflect.TypeOf(Model{}))

	want := slices.Clone(notSecretFields)
	for path := range secretFields {
		want = append(want, path)
	}
	slices.Sort(want)
	slices.Sort(found)
	if !slices.Equal(found, want) {
		t.Fatalf("the Model's inputs are\n%q\nand the classified ones\n%q", found, want)
	}
}

// filledSecrets is an unlocked model on view with every secret field filled, and
// the buffers they hold.
func filledSecrets(view ViewState) (Model, map[string][]byte) {
	m := activityReadyModel()
	m.viewState = view
	buffers := make(map[string][]byte)
	for path, field := range secretFields {
		field.fill(&m)
		if field.buffer != nil {
			buffers[path] = field.buffer(m)
		}
	}
	m.heldResult = ImportResultMsg{Success: true, Address: "ADDR", KeyType: "ed25519"}
	return m, buffers
}

func assertSecretsCleared(t *testing.T, m Model, buffers map[string][]byte, kept ...string) {
	t.Helper()
	for path, field := range secretFields {
		if slices.Contains(kept, path) {
			if len(field.buffer(m)) == 0 || allZero(buffers[path]) {
				t.Errorf("%s was cleared", path)
			}
			continue
		}
		if field.buffer == nil {
			if value := m.forms.importMnemonicInput.Value(); value != "" {
				t.Errorf("%s still holds %q", path, value)
			}
			continue
		}
		if left := field.buffer(m); len(left) != 0 || !allZero(buffers[path]) {
			t.Errorf("%s holds %q, its buffer %q", path, left, buffers[path])
		}
	}
}

// A lock, a recovery and every end of the session clear every secret the model
// holds. A held result, which holds none, lasts across a lock or a recovery but
// not past the session.
func TestEveryTransitionClearsEverySecret(t *testing.T) {
	lock, recovery, end := "lock", "recovery", "session end"
	for name, tt := range map[string]struct {
		msg  tea.Msg
		kind string
	}{
		"locked status":    {SignerStatusMsg{State: "locked"}, lock},
		"manual lock":      {LockIdentityResultMsg{Success: true}, lock},
		"recovery status":  {SignerStatusMsg{State: "recovery"}, recovery},
		"unlock recovery":  {UnlockResultMsg{Success: true, Code: protocol.ResultCodeRecoveryBlocked}, recovery},
		"auth required":    {AuthRequiredMsg{}, end},
		"login timeout":    {AuthResultMsg{Code: protocol.ErrCodeLoginTimeout}, end},
		"disconnected":     {DisconnectedMsg{}, end},
		"idle disconnect":  {localIdleDisconnectedMsg{Reason: localIdleDisconnectReason}, end},
		"reconnecting":     {ReconnectingMsg{}, end},
		"displaced":        {DisplacedMsg{Reason: "replaced"}, end},
		"second time over": {SignerStatusMsg{State: "recovery"}, recovery},
	} {
		t.Run(name, func(t *testing.T) {
			m, buffers := filledSecrets(ViewKeyList)
			m = updateModel(t, m, tt.msg)
			if name == "second time over" {
				m = updateModel(t, m, tt.msg)
			}
			assertSecretsCleared(t, m, buffers)
			if held := m.heldResult != nil; held != (tt.kind != end) {
				t.Errorf("held result kept = %v after a %s", held, tt.kind)
			}
		})
	}
	t.Run("uncertain policy apply", func(t *testing.T) {
		m, buffers := filledSecrets(ViewPolicyApplyReview)
		m.policies.apply.pendingApplyID = "apply-1"
		m = updateModel(t, m, PolicyApplyResultMsg{Result: protocol.ApplyPolicyResultMessage{
			BaseMessage: protocol.BaseMessage{ID: "apply-1"}, CommitUncertain: true, Error: "commit uncertain"}})
		if m.viewState != ViewStoreRecovery {
			t.Fatalf("view %v, want the recovery screen", m.viewState)
		}
		assertSecretsCleared(t, m, buffers)
	})
	t.Run("shutdown", func(t *testing.T) {
		m, buffers := filledSecrets(ViewKeyList)
		m.Shutdown()
		for path, buffer := range buffers {
			if !allZero(buffer) {
				t.Errorf("%s left %q", path, buffer)
			}
		}
	})
	// The lock state clears them by itself, whoever enters it.
	t.Run("locked state alone", func(t *testing.T) {
		m, buffers := filledSecrets(ViewKeyList)
		m.backups.imp.phase = importUploading
		m.applySignerLockedState()
		assertSecretsCleared(t, m, buffers)
	})
}

// A backup import goes on through a recovery: the recovery keeps its passphrase
// until the commit sends it, and clears it if the import fails first.
func TestRecoveryKeepsTheActiveImportsPassphrase(t *testing.T) {
	const importPassphrase = "Model.backups.imp.passphrase"
	upload := func(t *testing.T) (Model, map[string][]byte, string, int64) {
		t.Helper()
		m, _, size := importFixture(t)
		m, begin := startImport(t, m)
		m, cmd := update(t, m, beginReply(begin, "upload-1"))
		for path, field := range secretFields {
			if path != importPassphrase {
				field.fill(&m)
			}
		}
		buffers := make(map[string][]byte)
		for path, field := range secretFields {
			if field.buffer != nil {
				buffers[path] = field.buffer(m)
			}
		}
		m, _ = update(t, m, SignerStatusMsg{State: "recovery"})
		assertSecretsCleared(t, m, buffers, importPassphrase)
		return m, buffers, sentRequest(cmd, "backup-import-append"), size
	}

	t.Run("committed", func(t *testing.T) {
		copies := watchSecretCopies(t)
		m, buffers, appendID, size := upload(t)
		m, cmd := update(t, m, appendReply(appendID, size))
		if sentRequest(cmd, "backup-import-commit") == "" {
			t.Fatalf("the upload did not commit: %v", sentRequestIDs(cmd))
		}
		if len(*copies) == 0 || len((*copies)[0]) != len("secret") {
			t.Fatalf("the commit sent %d secrets, want the passphrase", len(*copies))
		}
		assertSecretsCleared(t, m, buffers)
	})
	t.Run("failed", func(t *testing.T) {
		m, buffers, appendID, _ := upload(t)
		m, _ = update(t, m, AppendBackupImportResultMsg{Result: protocol.AppendBackupImportResultMessage{
			BaseMessage: protocol.BaseMessage{ID: appendID}, Error: "refused"}})
		if m.backups.imp.phase != importIdle || m.backups.imp.err != "Import failed: refused" {
			t.Fatalf("after a refusal: phase %v, error %q", m.backups.imp.phase, m.backups.imp.err)
		}
		assertSecretsCleared(t, m, buffers)
	})
	// On the form, a failed import keeps the passphrase for another try.
	t.Run("failed on the form", func(t *testing.T) {
		m, _, _ := importFixture(t)
		m, begin := startImport(t, m)
		m, cmd := update(t, m, beginReply(begin, "upload-1"))
		m, _ = update(t, m, AppendBackupImportResultMsg{Result: protocol.AppendBackupImportResultMessage{
			BaseMessage: protocol.BaseMessage{ID: sentRequest(cmd, "backup-import-append")}, Error: "refused"}})
		if m.viewState != ViewBackupImport || string(m.backups.imp.passphrase) != "secret" {
			t.Fatalf("view %v, passphrase %q, want the form as it was", m.viewState, m.backups.imp.passphrase)
		}
	})
}
