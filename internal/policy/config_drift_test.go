// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"reflect"
	"testing"
)

// storedConfigOnlyFields are the fields StoredConfig adds beyond the shared
// role-domain block; they intentionally do not recurse into StoredRoleConfig.
var storedConfigOnlyFields = map[string]bool{
	"ClientSigning": true,
	"Sentry":        true,
	"KeyOverrides":  true,
}

// TestStoredRoleConfigMirrorsStoredConfig guards the deliberate duplication
// between StoredConfig and StoredRoleConfig: the role struct must remain an
// exact field/type/yaml-tag subset of the full struct. When this fails, a
// policy field was added to one struct but not the other — update both, their
// Clone methods, and the toStoredConfig/toStoredRoleConfig converters.
func TestStoredRoleConfigMirrorsStoredConfig(t *testing.T) {
	role := reflect.TypeOf(StoredRoleConfig{})
	full := reflect.TypeOf(StoredConfig{})

	fullFields := make(map[string]reflect.StructField, full.NumField())
	for i := 0; i < full.NumField(); i++ {
		f := full.Field(i)
		fullFields[f.Name] = f
	}

	for i := 0; i < role.NumField(); i++ {
		rf := role.Field(i)
		ff, ok := fullFields[rf.Name]
		if !ok {
			t.Errorf("StoredRoleConfig.%s has no StoredConfig counterpart", rf.Name)
			continue
		}
		if rf.Type != ff.Type {
			t.Errorf("StoredRoleConfig.%s type %s differs from StoredConfig's %s", rf.Name, rf.Type, ff.Type)
		}
		if rf.Tag.Get("yaml") != ff.Tag.Get("yaml") {
			t.Errorf("StoredRoleConfig.%s yaml tag %q differs from StoredConfig's %q", rf.Name, rf.Tag.Get("yaml"), ff.Tag.Get("yaml"))
		}
	}

	for name := range fullFields {
		if _, onRole := role.FieldByName(name); !onRole && !storedConfigOnlyFields[name] {
			t.Errorf("StoredConfig.%s is missing from StoredRoleConfig and not declared in storedConfigOnlyFields", name)
		}
	}
}
