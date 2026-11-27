// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"slices"
	"strconv"
	"testing"
)

// codeWireValues are the codes as clients and scripts read them. Changing or
// removing one changes the wire: see the AdminProtocolVersion rule in
// docs/ARCH_ADMIN.md ("Transport notes").
var codeWireValues = map[string]string{
	"ErrCodeInvalidMessageFormat":               "invalid_message_format",
	"ErrCodeExpectedAuthMessage":                "expected_auth_message",
	"ErrCodeInvalidAuthMessage":                 "invalid_auth_message",
	"ErrCodeAuthenticationFailed":               "authentication_failed",
	"ErrCodeInvalidPassphrase":                  "invalid_passphrase",
	"ErrCodeUnlockFailed":                       "unlock_failed",
	"ErrCodeInvalidRequest":                     "invalid_request",
	"ErrCodeUnknownMessageType":                 "unknown_message_type",
	"ErrCodeNoRuntimeBound":                     "no_runtime_bound",
	"ErrCodeAuthorizationDenied":                "authorization_denied",
	"ErrCodeSignerLocked":                       "signer_locked",
	"ErrCodeKeyNotFound":                        "key_not_found",
	"ErrCodeSourceTokenNotSet":                  "source_token_not_set",
	"ErrCodeNodeFailClosed":                     "node_fail_closed",
	"ErrCodeLoginTimeout":                       "login_timeout",
	"ErrCodeInternal":                           "internal_error",
	"ResultCodeBackupFailed":                    "backup_failed",
	"ResultCodeListBackupsFailed":               "list_backups_failed",
	"ResultCodeDeleteBackupFailed":              "delete_backup_failed",
	"ResultCodeBackupImportBeginFailed":         "backup_import_begin_failed",
	"ResultCodeBackupImportAppendFailed":        "backup_import_append_failed",
	"ResultCodeBackupImportCommitFailed":        "backup_import_commit_failed",
	"ResultCodeBackupImportAbortFailed":         "backup_import_abort_failed",
	"ResultCodeBackupExportReadFailed":          "backup_export_read_failed",
	"ResultCodeRestorePreviewFailed":            "restore_preview_failed",
	"ResultCodeRestoreRateLimited":              "restore_rate_limited",
	"ResultCodeRestoreFailed":                   "restore_failed",
	"ResultCodeRestoreConflict":                 "restore_conflict",
	"ResultCodeRestoreRollbackFailed":           "restore_rollback_failed",
	"ResultCodeRestoreRollbackRefused":          "restore_rollback_refused",
	"ResultCodeRestoreRollbackDiverged":         "restore_rollback_diverged",
	"ResultCodeRestoreAuditFailed":              "restore_audit_failed",
	"ResultCodeQuarantinePruneFailed":           "quarantine_prune_failed",
	"ResultCodeAbandonedDiscardFailed":          "abandoned_discard_failed",
	"ResultCodeAbandonedAuditFailed":            "abandoned_discard_audit_failed",
	"ResultCodeQuarantineAuditFailed":           "quarantine_audit_failed",
	"ResultCodeArchiveListFailed":               "archive_list_failed",
	"ResultCodeArchivePruneFailed":              "archive_prune_failed",
	"ResultCodeArchiveAuditFailed":              "archive_audit_failed",
	"ResultCodeAuditUnavailable":                "audit_unavailable",
	"ResultCodeAuditWriteFailed":                "audit_write_failed",
	"ResultCodeConfirmationRequired":            "confirmation_required",
	"ResultCodeRecoveryBlocked":                 "recovery_blocked",
	"ResultCodePassphraseChangeFailed":          "passphrase_change_failed",
	"ResultCodePassphraseHelperError":           "passphrase_helper_error",
	"ResultCodeAppliedNotSaved":                 "applied_not_saved",
	"ResultCodeStoreBusy":                       "store_busy",
	"ResultCodeListFailed":                      "list_failed",
	"ResultCodeReadFailed":                      "read_failed",
	"ResultCodeNotFound":                        "not_found",
	"ResultCodeInvalidWitnessKeyID":             "invalid_witness_key_id",
	"ResultCodeExportFailed":                    "export_failed",
	"ResultCodeEncodeFailed":                    "encode_failed",
	"ResultCodeInspectFailed":                   "inspect_failed",
	"ResultCodeInvalidTemplateType":             "invalid_template_type",
	"ResultCodeInstallFailed":                   "install_failed",
	"ResultCodeReloadFailed":                    "reload_failed",
	"ResultCodeActivationFailed":                "activation_failed",
	"ResultCodeLibraryReadFailed":               "library_read_failed",
	"ResultCodeLibraryEntryNotFound":            "library_entry_not_found",
	"ResultCodeTemplateStateFailed":             "template_state_failed",
	"ResultCodeTemplateNotFound":                "template_not_found",
	"ResultCodeDecryptFailed":                   "decrypt_failed",
	"ResultCodeInvalidTemplate":                 "invalid_template",
	"ResultCodeImportFailed":                    "import_failed",
	"ResultCodeRemoveFailed":                    "remove_failed",
	"ResultCodeKeyTypeInUse":                    "key_type_in_use",
	"ResultCodeDeactivationFailed":              "deactivation_failed",
	"ResultCodeExpectedPolicySetSHA256Required": "expected_policy_set_sha256_required",
	"ResultCodeExpectedSnapshotSHA256Required":  "expected_snapshot_sha256_required",
	"ResultCodePolicyUnavailable":               "policy_unavailable",
	"ResultCodeInvalidPolicyRequest":            "invalid_policy_request",
	"ResultCodePolicySetTooLarge":               "policy_set_too_large",
	"ResultCodePolicyContextUnavailable":        "policy_context_unavailable",
	"ResultCodePolicyCheckFailed":               "policy_check_failed",
	"ResultCodePolicyVerifyFailed":              "policy_verify_failed",
	"ResultCodePolicySnapshotChanged":           "policy_snapshot_changed",
	"ResultCodePolicyValidationFailed":          "policy_validation_failed",
	"ResultCodePolicyCommitUncertain":           "policy_commit_uncertain",
	"ResultCodePolicySaveFailed":                "policy_save_failed",
	"ResultCodePolicyApplyFailed":               "policy_apply_failed",
	"ResultCodePolicyReloadFailed":              "policy_reload_failed",
	"ResultCodePolicyDocumentNotFound":          "policy_document_not_found",
	"ResultCodePolicyExportStale":               "policy_export_stale",
	"ResultCodeASAUnknownNetwork":               "unknown_network",
	"ResultCodeASALookupFailed":                 "lookup_failed",
	"ResultCodeASAConfirmationStale":            "confirmation_stale",
	"ResultCodeASABuiltin":                      "asa_builtin",
	"ResultCodeASAAlreadyConfirmed":             "asa_already_confirmed",
	"ResultCodeASAReferenced":                   "asa_referenced",
	"ResultCodeASAAddFailed":                    "asa_add_failed",
	"ResultCodeASARemoveFailed":                 "asa_remove_failed",
	"ResultCodeASACommitUncertain":              "asa_commit_uncertain",
	"ResultCodeASAReloadFailed":                 "asa_reload_failed",
}

// Every code keeps its wire value, and a new one is added to the table.
func TestCodesKeepTheirWireValues(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "error_codes.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]string)
	for _, decl := range parsed.Decls {
		consts, ok := decl.(*ast.GenDecl)
		if !ok || consts.Tok != token.CONST {
			continue
		}
		for _, spec := range consts.Specs {
			for i, name := range spec.(*ast.ValueSpec).Names {
				lit, ok := spec.(*ast.ValueSpec).Values[i].(*ast.BasicLit)
				if !ok {
					t.Fatalf("%s is not a string literal", name.Name)
				}
				if got[name.Name], err = strconv.Unquote(lit.Value); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(got)) {
		if want, ok := codeWireValues[name]; !ok || got[name] != want {
			t.Errorf("%s = %q, the table has %q", name, got[name], want)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(codeWireValues)) {
		if _, ok := got[name]; !ok {
			t.Errorf("%s is gone", name)
		}
	}
}
