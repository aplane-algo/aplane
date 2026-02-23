// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package keys

import (
	"testing"
)

func TestValidatePathComponent(t *testing.T) {
	// Valid values should not panic
	valid := []string{"default", "user-123", "org_tenant", "a"}
	for _, v := range valid {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("validatePathComponent(%q) panicked unexpectedly: %v", v, r)
				}
			}()
			validatePathComponent("test", v)
		}()
	}

	// Invalid values should panic
	invalid := []string{"", "..", "foo/..", "../etc", "a/b", `a\b`, "foo/bar"}
	for _, v := range invalid {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("validatePathComponent(%q) did not panic", v)
				}
			}()
			validatePathComponent("test", v)
		}()
	}
}

func TestKeysDirRejectsTraversal(t *testing.T) {
	SetKeystorePath("/tmp/test-keystore")
	defer SetKeystorePath("")

	defer func() {
		if r := recover(); r == nil {
			t.Error("KeysDir with traversal identity did not panic")
		}
	}()
	KeysDir("../../etc")
}
