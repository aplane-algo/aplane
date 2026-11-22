// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

// refusedInRecovery are the admin requests the session refuses as locked
// while the signer is in recovery, before their service is called. Each is
// sent with an empty payload.
var refusedInRecovery = []string{
	"activate_key_type", "backup", "change_store_passphrase", "deactivate_key_type",
	"delete_backup", "delete_key", "export_key", "generate_key",
	"get_key_details", "import_cosigner_reference", "import_installed_template", "import_key",
	"install_library_template", "list_installed_templates", "list_keys", "list_library_templates",
	"prepare_generate_key", "remove_cosigner_reference", "remove_installed_template", "show_installed_template",
	"show_library_template",
}

// answeredInRecovery are the admin requests the session does not refuse as
// locked while the signer is in recovery. Several are then refused by their
// service: a policy apply, an ASA set change and a source token request each
// require an unlocked signer under the store mutation lock.
//
// Of these, the requests that read what a reload publishes are:
//   - get_policy, get_policy_context, get_policy_document and check_policy,
//     which read the policy and the ASA set, and the key maps to mark each
//     per-key document as held or not;
//   - list_asa_set and lookup_asa, which read the ASA set;
//   - unlock, reconcile_store, restore_backup and rollback_restore, whose
//     answers carry the key count, as the status the session is pushed does;
//   - export_cosigner_public and list_key_types, which read the generation
//     the runtime is bound to, and list_key_types the provider registry.
//
// The store inspection requests read the store root themselves and not the
// runtime's binding. None reads the source token index: source_token_list
// answers only an unlocked signer, and check_policy reads token names only
// while unlocked. The reload redesign makes recovery publish no keys, so the
// held marking and the key counts are what it changes here.
var answeredInRecovery = []string{
	"abort_backup_import", "add_asa", "append_backup_import", "apply_policy",
	"approve_enrollment", "begin_backup_import", "check_policy", "commit_backup_import",
	"discard_abandoned_generations", "export_cosigner_public", "get_admin_settings", "get_cosigner_reference",
	"get_policy", "get_policy_context", "get_policy_document", "import_client_key",
	"list_asa_set", "list_backups", "list_cosigner_references", "list_deleted_archive",
	"list_enrolled_keys", "list_generations", "list_key_types", "list_pending_enrollments",
	"lock_identity", "lookup_asa", "preview_restore", "prune_deleted_archive",
	"prune_generation_quarantine", "read_backup_chunk", "reconcile_store", "reject_enrollment",
	"remove_asa", "restore_backup", "revoke_all_enrolled_keys", "revoke_enrolled_key",
	"rollback_restore", "sign_response", "source_token_list", "source_token_remove",
	"source_token_set", "unlock", "update_admin_setting",
}

func TestWhichAdminRequestsASessionInRecoveryIsAnswered(t *testing.T) {
	var refused, answered []string
	for msgType, handle := range dispatchTable {
		ir := productruntime.New(productruntime.Config{})
		ir.SetUnlocked()
		ir.EnterRecovery(nil)
		svc := &stubServices{runtime: ir}
		conn := &queueConn{}
		session := NewSession(conn, SessionDeps{
			Product: svc, Settings: svc, Keys: svc, Backups: svc, Templates: svc,
			Inspection: &inspectionStub{}, Authorizer: &recordingAuthorizer{}, Audit: &mutationAudit{},
		}, OriginLocal)
		session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)

		handle(session, []byte(fmt.Sprintf(`{"type":%q,"kind":"request","id":"r"}`, msgType)), "r")
		locked := false
		for _, msg := range decodeAdminProtoWrites(t, conn) {
			locked = locked || msg.Code == protocol.ErrCodeSignerLocked
		}
		if locked {
			refused = append(refused, msgType)
		} else {
			answered = append(answered, msgType)
		}
	}
	sort.Strings(refused)
	sort.Strings(answered)
	if got, want := strings.Join(refused, " "), strings.Join(refusedInRecovery, " "); got != want {
		t.Errorf("refused as locked in recovery:\n got: %s\nwant: %s", got, want)
	}
	if got, want := strings.Join(answered, " "), strings.Join(answeredInRecovery, " "); got != want {
		t.Errorf("reach their service in recovery:\n got: %s\nwant: %s", got, want)
	}
}
