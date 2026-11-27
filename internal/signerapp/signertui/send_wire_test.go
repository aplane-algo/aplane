// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"bufio"
	"io"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	tea "github.com/charmbracelet/bubbletea"
)

// clockID matches the clock reading in a request ID the client names itself.
var clockID = regexp.MustCompile(`("id":"[a-z-]+)-[0-9]{12,}"`)

// Every send command writes exactly this message. IDs the client names from
// the clock are shown with the reading as T.
func TestSendCommandsWriteTheirMessages(t *testing.T) {
	doc := adminproto.PolicyDocument{Key: "default", Document: `{"schema":"aplane.policy.v1"}`}
	tests := []struct {
		name string
		cmd  func(Model) tea.Cmd
		want string
	}{
		{"auth", func(m Model) tea.Cmd { return m.sendAuthCmd([]byte("pass")) }, `{"kind":"request","type":"auth","id":"auth-T","passphrase":"pass","protocol_version":11}`},
		{"unlock", func(m Model) tea.Cmd { return m.sendUnlockCmd([]byte("pass")) }, `{"kind":"request","type":"unlock","id":"unlock-T","passphrase":"pass"}`},
		{"lock", func(m Model) tea.Cmd { return m.sendLockIdentityCmd("why") }, `{"kind":"request","type":"lock_identity","id":"lock-T","reason":"why"}`},
		{"sign approve", func(m Model) tea.Cmd { return m.sendSignResponseCmd("sign-1", true) }, `{"kind":"request","type":"sign_response","id":"sign-1","approved":true}`},
		{"sign reject", func(m Model) tea.Cmd { return m.sendSignResponseCmd("sign-2", false) }, `{"kind":"request","type":"sign_response","id":"sign-2","approved":false,"reason":"rejected by user"}`},
		{"approve enrollment", func(m Model) tea.Cmd { return m.sendApproveEnrollmentCmd("fp", "label") }, `{"kind":"request","type":"approve_enrollment","id":"approve-T","fingerprint":"fp","label":"label"}`},
		{"reject enrollment", func(m Model) tea.Cmd { return m.sendRejectEnrollmentCmd("fp") }, `{"kind":"request","type":"reject_enrollment","id":"reject-T","fingerprint":"fp"}`},
		{"list pending", func(m Model) tea.Cmd { return m.sendListPendingEnrollmentsCmd("pending-1") }, `{"kind":"request","type":"list_pending_enrollments","id":"pending-1"}`},
		{"import client key", func(m Model) tea.Cmd { return m.sendImportClientKeyCmd("ssh-ed25519 AAAA", "label") }, `{"kind":"request","type":"import_client_key","id":"import-client-T","public_key":"ssh-ed25519 AAAA","label":"label"}`},
		{"displace confirm", func(m Model) tea.Cmd { return m.sendDisplaceConfirmCmd() }, `{"kind":"request","type":"displace_confirm","id":""}`},
		{"list keys", func(m Model) tea.Cmd { return m.sendListKeysCmd() }, `{"kind":"request","type":"list_keys","id":"list-T"}`},
		{"generate", func(m Model) tea.Cmd { return m.sendGenerateKeyCmd("kt", map[string]string{"a": "b"}, "gen-1") }, `{"kind":"request","type":"generate_key","id":"gen-1","key_type":"kt","parameters":{"a":"b"}}`},
		{"generate no params", func(m Model) tea.Cmd { return m.sendGenerateKeyCmd("kt", nil, "gen-2") }, `{"kind":"request","type":"generate_key","id":"gen-2","key_type":"kt"}`},
		{"backup", func(m Model) tea.Cmd { return m.sendBackupCmd([]byte("pass"), "backup-1") }, `{"kind":"request","type":"backup","id":"backup-1","export_passphrase":"pass"}`},
		{"list backups", func(m Model) tea.Cmd { return m.sendListBackupsCmd() }, `{"kind":"request","type":"list_backups","id":"list-backups-T"}`},
		{"preview restore", func(m Model) tea.Cmd { return m.sendPreviewRestoreCmd("a.tar.gz", []byte("pass"), "preview-1") }, `{"kind":"request","type":"preview_restore","id":"preview-1","archive_path":"a.tar.gz","export_passphrase":"pass"}`},
		{"restore", func(m Model) tea.Cmd {
			return m.sendRestoreBackupCmd("a.tar.gz", []string{"ADDR1", "ADDR2"}, []byte("pass"), true, "restore-1")
		}, `{"kind":"request","type":"restore_backup","id":"restore-1","archive_path":"a.tar.gz","addresses":["ADDR1","ADDR2"],"export_passphrase":"pass","replace_existing":true}`},
		{"restore no addresses", func(m Model) tea.Cmd {
			return m.sendRestoreBackupCmd("a.tar.gz", nil, []byte("pass"), false, "restore-2")
		}, `{"kind":"request","type":"restore_backup","id":"restore-2","archive_path":"a.tar.gz","export_passphrase":"pass"}`},
		{"rollback", func(m Model) tea.Cmd { return m.sendRollbackRestoreCmd("rollback-1") }, `{"kind":"request","type":"rollback_restore","id":"rollback-1"}`},
		{"reconcile", func(m Model) tea.Cmd { return m.sendReconcileStoreCmd("reconcile-1") }, `{"kind":"request","type":"reconcile_store","id":"reconcile-1"}`},
		{"prepare generate", func(m Model) tea.Cmd { return m.sendPrepareGenerateKeyCmd("kt", map[string]string{"a": "b"}, "prep-1") }, `{"kind":"request","type":"prepare_generate_key","id":"prep-1","key_type":"kt","parameters":{"a":"b"}}`},
		{"reviewed generate", func(m Model) tea.Cmd {
			return m.sendReviewedGenerateKeyCmd(PrepareGenerateResultMessage{
				KeyType: "kt", Parameters: map[string]string{"a": "b"}, ReviewFingerprint: "fpr", BoundaryDigest: "dig",
			}, "gen-3")
		}, `{"kind":"request","type":"generate_key","id":"gen-3","key_type":"kt","expected_fingerprint":"fpr","expected_boundary_digest":"dig","parameters":{"a":"b"}}`},
		{"delete key", func(m Model) tea.Cmd { return m.sendDeleteKeyCmd("ADDR", "del-1") }, `{"kind":"request","type":"delete_key","id":"del-1","address":"ADDR"}`},
		{"list enrolled", func(m Model) tea.Cmd { return m.sendListEnrolledKeysCmd("enrolled-1") }, `{"kind":"request","type":"list_enrolled_keys","id":"enrolled-1"}`},
		{"revoke", func(m Model) tea.Cmd { return m.sendRevokeEnrolledKeyCmd("fp") }, `{"kind":"request","type":"revoke_enrolled_key","id":"revoke-T","fingerprint":"fp"}`},
		{"revoke all", func(m Model) tea.Cmd { return m.sendRevokeAllEnrolledKeysCmd() }, `{"kind":"request","type":"revoke_all_enrolled_keys","id":"revoke-all-T"}`},
		{"import key", func(m Model) tea.Cmd { return m.sendImportKeyCmd("kt", "word word", nil, "import-1") }, `{"kind":"request","type":"import_key","id":"import-1","key_type":"kt","mnemonic":"word word"}`},
		{"import key params", func(m Model) tea.Cmd {
			return m.sendImportKeyCmd("kt", "word word", map[string]string{"a": "b"}, "import-2")
		}, `{"kind":"request","type":"import_key","id":"import-2","key_type":"kt","mnemonic":"word word","parameters":{"a":"b"}}`},
		{"get settings", func(m Model) tea.Cmd { return m.sendGetAdminSettingsCmd() }, `{"kind":"request","type":"get_admin_settings","id":"admin-T"}`},
		{"update setting", func(m Model) tea.Cmd { return m.sendUpdateAdminSettingCmd("k", "v") }, `{"kind":"request","type":"update_admin_setting","id":"admin-set-T","key":"k","value":"v"}`},
		{"key details", func(m Model) tea.Cmd { return m.sendGetKeyDetailsCmd("ADDR", "details-1") }, `{"kind":"request","type":"get_key_details","id":"details-1","address":"ADDR"}`},
		{"list library", func(m Model) tea.Cmd { return m.sendListLibraryTemplatesCmd() }, `{"kind":"request","type":"list_library_templates","id":"tmpl-list-T"}`},
		{"install library", func(m Model) tea.Cmd { return m.sendInstallLibraryTemplateCmd("kt", "tt", "install-1") }, `{"kind":"request","type":"install_library_template","id":"install-1","key_type":"kt","template_type":"tt"}`},
		{"show library", func(m Model) tea.Cmd { return m.sendShowLibraryTemplateCmd("kt", "tt", "show-1") }, `{"kind":"request","type":"show_library_template","id":"show-1","key_type":"kt","template_type":"tt"}`},
		{"show installed", func(m Model) tea.Cmd { return m.sendShowInstalledTemplateCmd("kt", "show-2") }, `{"kind":"request","type":"show_installed_template","id":"show-2","key_type":"kt"}`},
		{"activate", func(m Model) tea.Cmd { return m.sendActivateKeyTypeCmd("kt", "act-1") }, `{"kind":"request","type":"activate_key_type","id":"act-1","key_type":"kt"}`},
		{"deactivate", func(m Model) tea.Cmd { return m.sendDeactivateKeyTypeCmd("kt", "deact-1") }, `{"kind":"request","type":"deactivate_key_type","id":"deact-1","key_type":"kt"}`},
		{"list key types", func(m Model) tea.Cmd { return m.sendListKeyTypesCmd() }, `{"kind":"request","type":"list_key_types","id":"keytypes-T"}`},
		{"list cosigners", func(m Model) tea.Cmd { return m.sendListCosignerReferencesCmd() }, `{"kind":"request","type":"list_cosigner_references","id":"cosigner-references-T"}`},
		{"import cosigner", func(m Model) tea.Cmd { return m.sendImportCosignerReferenceCmd("name", `{"x":1}`, "cos-1") }, `{"kind":"request","type":"import_cosigner_reference","id":"cos-1","name":"name","envelope_json":"{\"x\":1}"}`},
		{"remove cosigner", func(m Model) tea.Cmd { return m.sendRemoveCosignerReferenceCmd("name", "cos-2") }, `{"kind":"request","type":"remove_cosigner_reference","id":"cos-2","name":"name"}`},
		{"export cosigner", func(m Model) tea.Cmd { return m.sendExportCosignerPublicCmd("WID", "cos-3") }, `{"kind":"request","type":"export_cosigner_public","id":"cos-3","witness_key_id":"WID"}`},
		{"get policy", func(m Model) tea.Cmd { return m.sendGetPolicyCmd("policy-1") }, `{"kind":"request","type":"get_policy","id":"policy-1"}`},
		{"get policy document", func(m Model) tea.Cmd { return m.sendGetPolicyDocumentCmd("default", "", "doc-1") }, `{"kind":"request","type":"get_policy_document","id":"doc-1","key":"default"}`},
		{"get policy document at", func(m Model) tea.Cmd { return m.sendGetPolicyDocumentCmd("default", "snap", "doc-2") }, `{"kind":"request","type":"get_policy_document","id":"doc-2","key":"default","expected_snapshot_sha256":"snap"}`},
		{"get policy context", func(m Model) tea.Cmd { return m.sendGetPolicyContextCmd("ctx-1") }, `{"kind":"request","type":"get_policy_context","id":"ctx-1"}`},
		{"check policy", func(m Model) tea.Cmd { return m.sendCheckPolicyCmd(doc, "check-1") }, `{"kind":"request","type":"check_policy","id":"check-1","documents":[{"key":"default","document":"{\"schema\":\"aplane.policy.v1\"}"}]}`},
		{"apply policy", func(m Model) tea.Cmd { return m.sendApplyPolicyCmd(doc, "set", "snap", "apply-1") }, `{"kind":"request","type":"apply_policy","id":"apply-1","documents":[{"key":"default","document":"{\"schema\":\"aplane.policy.v1\"}"}],"expected_policy_set_sha256":"set","expected_snapshot_sha256":"snap"}`},
		{"list source tokens", func(m Model) tea.Cmd { return m.sendSourceTokenListCmd("default", "tokens-1") }, `{"kind":"request","type":"source_token_list","id":"tokens-1","selector":"default"}`},
		{"set source token", func(m Model) tea.Cmd {
			return m.sendSourceTokenSetCmd("default", "screening", []byte("tok"), "tokens-2")
		}, `{"kind":"request","type":"source_token_set","id":"tokens-2","selector":"default","source":"screening","token":"tok"}`},
		{"remove source token", func(m Model) tea.Cmd { return m.sendSourceTokenRemoveCmd("default", "screening", "tokens-3") }, `{"kind":"request","type":"source_token_remove","id":"tokens-3","selector":"default","source":"screening"}`},
		{"delete backup", func(m Model) tea.Cmd { return m.sendDeleteBackupCmd("del-b-1", "a.tar.gz") }, `{"kind":"request","type":"delete_backup","id":"del-b-1","archive_path":"a.tar.gz"}`},
		{"commit backup import", func(m Model) tea.Cmd {
			return m.sendCommitBackupImportCmd("commit-1", "up-1", "a.tar.gz", 10, "sum", []byte("pass"))
		}, `{"kind":"request","type":"commit_backup_import","id":"commit-1","upload_id":"up-1","file_name":"a.tar.gz","expected_size":10,"expected_sha256":"sum","export_passphrase":"pass"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, written := wireClient(t)
			got := clockID.ReplaceAllString(written(tt.cmd(Model{adminClient: client})), `$1-T"`)
			if got != tt.want+"\n" {
				t.Fatalf("wrote %s\nwant  %s", got, tt.want)
			}
		})
	}
}

// wireClient is a connected client, and written runs a command of its and
// returns the line it wrote.
func wireClient(t *testing.T) (client *IPCClient, written func(tea.Cmd) string) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = serverConn.Close() })
	client = NewAdminClient(&queueConnector{conns: []io.ReadWriteCloser{clientConn}})
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(client.Disconnect)
	lines := make(chan string, 1)
	go func() {
		line, err := bufio.NewReader(serverConn).ReadString('\n')
		if err != nil {
			line = "read error: " + err.Error()
		}
		lines <- line
	}()
	return client, func(cmd tea.Cmd) string {
		t.Helper()
		if msg := cmd(); msg != nil {
			t.Fatalf("command returned %#v", msg)
		}
		select {
		case line := <-lines:
			return line
		case <-time.After(2 * time.Second):
			t.Fatal("nothing written")
			return ""
		}
	}
}
