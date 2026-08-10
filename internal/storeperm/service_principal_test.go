// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeperm

import "testing"

func TestParseServicePrincipalMetadata(t *testing.T) {
	metadata, err := parseServicePrincipalMetadata([]byte(`{"schema_version":1,"uid":123,"gid":456}`))
	if err != nil {
		t.Fatal(err)
	}
	if metadata.UID != 123 || metadata.GID != 456 {
		t.Fatalf("metadata = %#v, want uid 123 gid 456", metadata)
	}
}

func TestParseServicePrincipalMetadataRejectsUnsafeValues(t *testing.T) {
	for _, data := range []string{
		`{"schema_version":2,"uid":123,"gid":456}`,
		`{"schema_version":1,"uid":0,"gid":456}`,
		`{"schema_version":1,"uid":123,"gid":-1}`,
		`{"schema_version":1,"uid":123,"gid":456,"extra":true}`,
		`{"schema_version":1,"uid":123,"gid":456} {}`,
	} {
		if _, err := parseServicePrincipalMetadata([]byte(data)); err == nil {
			t.Fatalf("parseServicePrincipalMetadata(%s) error = nil", data)
		}
	}
}
