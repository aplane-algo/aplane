// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templateadmin

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
)

const gatedTestKeyType = "test.approval-gated.v1"

// gatedProvider is a compiled type whose generation needs current approval.
type gatedProvider struct{ *composeddsa.ComposedDSA }

func (gatedProvider) GenerationRequiresCurrentApproval() bool { return true }

func registerGatedProvider(t *testing.T) {
	t.Helper()
	spec, err := composeddsa.ParseTemplateSpec([]byte(`
schema_version: 2
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: test
family: approval-gated
version: 1
display_name: Approval Gated
max_opcode_cost: 20000
bounded:
  contract: bounded1
  spend_effects: [pay]
  max_fee: 10000
teal: |
  pushint 1
  assert
`))
	if err != nil {
		t.Fatal(err)
	}
	composed, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	keytypecatalog.Register(keytypecatalog.Entry{
		KeyType: gatedTestKeyType, Family: "test.approval-gated", Availability: keytypecatalog.AvailabilityLibrary,
	})
	logicsigdsa.RegisterIfAbsent(gatedProvider{composed})
	t.Cleanup(func() { lsigprovider.Unregister(gatedTestKeyType) })
}

func libraryEntry(t *testing.T, svc Service, keyType string) adminproto.LibraryTemplateInfo {
	t.Helper()
	result := svc.ListLibraryTemplates()
	if result.Error != "" {
		t.Fatalf("ListLibraryTemplates() error = %s", result.Error)
	}
	for _, item := range result.Templates {
		if item.KeyType == keyType {
			return item
		}
	}
	t.Fatalf("library has no %s", keyType)
	return adminproto.LibraryTemplateInfo{}
}

func TestExplicitEnablementRenewsApprovalWithoutADisableCycle(t *testing.T) {
	registerGatedProvider(t)
	svc, ir, _ := setupServiceWithReloadCounter(t)
	if result := svc.ActivateKeyType(adminproto.ActivateKeyTypeRequest{KeyType: gatedTestKeyType}); !result.Success {
		t.Fatalf("ActivateKeyType() = %+v", result)
	}
	if entry := libraryEntry(t, svc, gatedTestKeyType); !entry.Enabled || entry.NeedsApproval {
		t.Fatalf("after enabling: %+v", entry)
	}

	record, ok, err := keytypestate.Get(ir.KeyPaths(), gatedTestKeyType)
	if err != nil || !ok {
		t.Fatalf("read record: %v, %v", ok, err)
	}
	approved := record.Fingerprint
	record.Fingerprint = "1:" + strings.Repeat("a", 64)
	if err := keytypestate.Put(ir.KeyPaths(), record); err != nil {
		t.Fatal(err)
	}
	if entry := libraryEntry(t, svc, gatedTestKeyType); !entry.Enabled || !entry.NeedsApproval {
		t.Fatalf("after a definition change: %+v", entry)
	}

	if result := svc.ActivateKeyType(adminproto.ActivateKeyTypeRequest{KeyType: gatedTestKeyType}); !result.Success {
		t.Fatalf("ActivateKeyType() = %+v", result)
	}
	if entry := libraryEntry(t, svc, gatedTestKeyType); !entry.Enabled || entry.NeedsApproval {
		t.Fatalf("after renewal: %+v", entry)
	}
	record, _, err = keytypestate.Get(ir.KeyPaths(), gatedTestKeyType)
	if err != nil {
		t.Fatal(err)
	}
	if record.Fingerprint != approved {
		t.Fatalf("record = %q, want the current fingerprint %q", record.Fingerprint, approved)
	}
}

func TestOtherLibraryTypesNeverNeedApproval(t *testing.T) {
	svc, _, _ := setupServiceWithReloadCounter(t)
	const keyType = "aplane.falcon1024-cosigner1024.v1"
	if result := svc.ActivateKeyType(adminproto.ActivateKeyTypeRequest{KeyType: keyType}); !result.Success {
		t.Fatalf("ActivateKeyType() = %+v", result)
	}
	if entry := libraryEntry(t, svc, keyType); entry.NeedsApproval {
		t.Fatalf("%+v", entry)
	}
}
