// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/addressderive"
)

type testDeriver struct{}

func (testDeriver) DeriveAddress(string, map[string]string) (string, error) {
	return "addr", nil
}

func TestRegisterBaseAndLookupBase(t *testing.T) {
	RegisterBase(BaseRegistration{
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
