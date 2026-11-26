// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/templatespec"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

// Template install and import never compare a recorded fingerprint leniently:
// reinstalling a template rewrites its record with the fingerprint the current
// code computes, whatever the record held. The reload that follows every
// install reads all records, so installing another template succeeds only
// while every other record holds exactly its template's fingerprint. When one
// does not, that reload finds an external edit, a content defect, and enters
// recovery: the install answers recovery_blocked and rolls its own files
// back.
func TestTemplateInstallAndImportWithARecordedFingerprint(t *testing.T) {
	const (
		succeeds = true
		fails    = false
	)
	for _, test := range []struct {
		name    string
		record  func(live string) string
		another bool
	}{
		{name: "matching", record: func(live string) string { return live }, another: succeeds},
		{name: "mismatching", record: func(string) string { return "1:" + strings.Repeat("b", 64) }, another: fails},
		{name: "unversioned", record: func(live string) string { return strings.TrimPrefix(live, "1:") }, another: fails},
		{name: "version 0", record: func(live string) string { return "0:" + strings.TrimPrefix(live, "1:") }, another: fails},
		{name: "noncanonical prefix", record: func(live string) string { return "01:" + strings.TrimPrefix(live, "1:") }, another: fails},
		{name: "cross-version", record: func(live string) string { return "2:" + strings.TrimPrefix(live, "1:") }, another: fails},
		{name: "malformed hash", record: func(live string) string { return live[:len(live)-1] }, another: fails},
	} {
		for _, operation := range []string{"reimport", "import another", "install another"} {
			t.Run(test.name+"/"+operation, func(t *testing.T) {
				server, cleanup := setupTestSigner(t)
				defer cleanup()
				family := fmt.Sprintf("fingerprint-recorded-%d", time.Now().UnixNano())
				keyType := testTemplateKeyType(family)
				templateYAML := renderGenericTemplateYAML(family, 1, "Recorded", "recorded fingerprint")
				live, err := generictemplate.SemanticFingerprint(templateYAML)
				if err != nil {
					t.Fatal(err)
				}
				otherFamily := family + "-other"
				otherKeyType := testTemplateKeyType(otherFamily)
				otherYAML := renderGenericTemplateYAML(otherFamily, 1, "Other", "another template")
				t.Cleanup(func() {
					lsigprovider.Unregister(keyType)
					lsigprovider.Unregister(otherKeyType)
				})

				templates := server.adminServices().templateApp()
				if result := templates.ImportInstalledTemplate(adminproto.ImportInstalledTemplateRequest{TemplateYAML: templateYAML}); !result.Success {
					t.Fatalf("ImportInstalledTemplate() = %+v", result)
				}
				recorded := test.record(live)
				if err := keytypestate.Put(mustActiveKeyPaths(t, server), keytypestate.Record{
					KeyType:     keyType,
					Source:      keytypestate.SourceYAMLGeneric,
					State:       keytypestate.StateEnabled,
					Fingerprint: recorded,
				}); err != nil {
					t.Fatal(err)
				}

				var success, alreadyExists bool
				var code, message, installed string
				switch operation {
				case "reimport":
					result := templates.ImportInstalledTemplate(adminproto.ImportInstalledTemplateRequest{TemplateYAML: templateYAML})
					success, alreadyExists, code, message, installed = result.Success, result.AlreadyExists, result.Code, result.Error, keyType
				case "import another":
					result := templates.ImportInstalledTemplate(adminproto.ImportInstalledTemplateRequest{TemplateYAML: otherYAML})
					success, alreadyExists, code, message, installed = result.Success, result.AlreadyExists, result.Code, result.Error, otherKeyType
				case "install another":
					writeLibraryTemplateForTest(t, server, "other.yaml", otherYAML)
					result := templates.InstallLibraryTemplate(adminproto.InstallLibraryTemplateRequest{
						KeyType:      otherKeyType,
						TemplateType: string(templatespec.TemplateTypeGeneric),
					})
					success, alreadyExists, code, message, installed = result.Success, result.AlreadyExists, result.Code, result.Error, otherKeyType
				}

				rec, ok, err := keytypestate.Get(mustActiveKeyPaths(t, server), keyType)
				if err != nil || !ok {
					t.Fatalf("keytypestate.Get(%s) = (%+v, %v, %v)", keyType, rec, ok, err)
				}
				if operation == "reimport" {
					if !success || !alreadyExists || code != "" || message != "" {
						t.Fatalf("reimport = (success %v, already exists %v, %q, %q), want an idempotent success", success, alreadyExists, code, message)
					}
					if rec.Fingerprint != live {
						t.Fatalf("record fingerprint = %q, want the reinstall to record %q", rec.Fingerprint, live)
					}
					return
				}
				if rec.Fingerprint != recorded {
					t.Fatalf("record fingerprint = %q, want %q kept", rec.Fingerprint, recorded)
				}
				if test.another == succeeds {
					if !success || alreadyExists || code != "" || message != "" {
						t.Fatalf("%s = (success %v, already exists %v, %q, %q), want a fresh success", operation, success, alreadyExists, code, message)
					}
					if lsigprovider.Get(installed) == nil {
						t.Fatalf("%s is not registered", installed)
					}
					return
				}
				wantMessage := "generation validation failed: 0 malformed key file(s) and 1 template/key-type defect(s) in the selected generation: key type " + keyType
				if success || code != protocol.ResultCodeRecoveryBlocked || message != wantMessage {
					t.Fatalf("%s = (success %v, %q, %q), want recovery_blocked with %q", operation, success, code, message, wantMessage)
				}
				if !server.productRuntime().IsRecovery() {
					t.Fatalf("state = %v after a reload that found an external edit, want recovery", server.productRuntime().GetState())
				}
				if lsigprovider.Get(installed) != nil {
					t.Fatalf("%s is registered after a failed install", installed)
				}
				if _, ok, err := keytypestate.Get(mustActiveKeyPaths(t, server), installed); err != nil || ok {
					t.Fatalf("record for %s after a failed install = (%v, %v), want none", installed, ok, err)
				}
			})
		}
	}
}
