// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/addressderive"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
)

// registerBaseForTest registers a base for the duration of one test, then puts back
// whatever entry it replaced. Tests register stubs under production names such as
// "aplane.falcon1024.v1"; without the restore, a stub outlives its test and later
// tests in this binary see it in place of the real base.
func registerBaseForTest(t testing.TB, reg BaseRegistration) {
	t.Helper()
	key := keytypecatalog.Canonicalize(reg.BaseKeyType)
	baseRegistry.mu.RLock()
	previous, had := baseRegistry.bases[key]
	baseRegistry.mu.RUnlock()
	RegisterBase(reg)
	t.Cleanup(func() {
		baseRegistry.mu.Lock()
		defer baseRegistry.mu.Unlock()
		if had {
			baseRegistry.bases[key] = previous
		} else {
			delete(baseRegistry.bases, key)
		}
	})
}

type testDeriver struct{}

func (testDeriver) DeriveAddress(string, map[string]string) (string, error) {
	return "addr", nil
}

func TestRegisterBaseAndLookupBase(t *testing.T) {
	registerBaseForTest(t, BaseRegistration{
		BaseKeyType:       " TEST-BASE-v1 ",
		FamilyName:        "test-base",
		Version:           1,
		Ops:               testOps{},
		NewAddressDeriver: func(string) addressderive.Deriver { return testDeriver{} },
	})

	reg, ok := LookupBase("test-base-v1")
	if !ok {
		t.Fatal("LookupBase() did not find registered base")
	}
	if reg.BaseKeyType != "test-base-v1" {
		t.Fatalf("BaseKeyType = %q, want test-base-v1", reg.BaseKeyType)
	}
	if reg.FamilyName != "test-base" {
		t.Fatalf("FamilyName = %q, want test-base", reg.FamilyName)
	}
	if reg.Version != 1 {
		t.Fatalf("Version = %d, want 1", reg.Version)
	}
	if reg.Ops == nil {
		t.Fatal("Ops is nil")
	}
	if reg.NewAddressDeriver == nil {
		t.Fatal("NewAddressDeriver is nil")
	}
}

func TestRegisterBaseRequiresOps(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("RegisterBase() did not panic")
		}
	}()
	RegisterBase(BaseRegistration{
		BaseKeyType:       "missing-ops-v1",
		FamilyName:        "missing-ops",
		Version:           1,
		NewAddressDeriver: func(string) addressderive.Deriver { return testDeriver{} },
	})
}

// Signing resolves an account's construction from its durable base_key_type, so a
// catalog name served by ops that render a different construction would create
// accounts the signer checks against the wrong construction.
func TestRegisterBaseRequiresOpsToRenderTheNamedConstruction(t *testing.T) {
	deriver := func(string) addressderive.Deriver { return testDeriver{} }
	t.Run("mismatch panics", func(t *testing.T) {
		defer func() {
			recovered := recover()
			if recovered == nil {
				t.Fatal("RegisterBase() did not panic")
			}
			if err, _ := recovered.(error); err == nil || !strings.Contains(err.Error(), `names construction "ed25519", but its ops render "falcon1024"`) {
				t.Fatalf("panic = %v", recovered)
			}
		}()
		RegisterBase(BaseRegistration{
			BaseKeyType: "aplane.ed25519.v1", FamilyName: "aplane.ed25519", Version: 1,
			Ops: testOps{construction: sigconstruction.Falcon1024()}, NewAddressDeriver: deriver,
		})
	})
	t.Run("ops with no construction under a catalog name panic", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("RegisterBase() did not panic")
			}
		}()
		RegisterBase(BaseRegistration{
			BaseKeyType: " APLANE.FALCON1024.V1 ", FamilyName: "aplane.falcon1024", Version: 1,
			Ops: testOps{}, NewAddressDeriver: deriver,
		})
	})
	t.Run("matching construction registers", func(t *testing.T) {
		registerBaseForTest(t, BaseRegistration{
			BaseKeyType: "aplane.ed25519.v1", FamilyName: "aplane.ed25519", Version: 1,
			Ops: testOps{construction: sigconstruction.Ed25519()}, NewAddressDeriver: deriver,
		})
	})
	t.Run("a name outside the catalog constrains nothing", func(t *testing.T) {
		registerBaseForTest(t, BaseRegistration{
			BaseKeyType: "test.uncataloged-base.v1", FamilyName: "uncataloged", Version: 1,
			Ops: testOps{construction: sigconstruction.Falcon1024()}, NewAddressDeriver: deriver,
		})
	})
}
