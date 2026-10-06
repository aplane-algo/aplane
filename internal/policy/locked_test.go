// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"strings"
	"testing"
)

func TestLockedCosignerDocumentHasNoRoutesAndNoAllowances(t *testing.T) {
	const key = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"
	document, err := LockedCosignerDocumentV1(key)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := DecodeCosignerPolicyV1([]byte(document), key)
	if err != nil {
		t.Fatalf("locked document does not decode: %v", err)
	}
	if doc.Key != key || len(doc.Routes) != 0 || len(doc.RekeyPolicy) != 0 {
		t.Fatalf("locked document = %+v, want the key with no routes and no rekey edges", doc)
	}
	// A note that the key is locked would outlive the lock once routes exist.
	if doc.Description != "" {
		t.Fatalf("locked document carries the description %q", doc.Description)
	}
	if _, err := doc.Compile(nil); err != nil {
		t.Fatalf("locked document does not compile: %v", err)
	}
	// Readable as it stands: the editor shows these bytes.
	if !strings.Contains(document, "\n  \"transfer_policy\": {\n    \"routes\": []\n  }\n") || !strings.HasSuffix(document, "}\n") {
		t.Fatalf("locked document is not laid out for editing:\n%s", document)
	}
	if _, err := LockedCosignerDocumentV1("not-a-witness-key-id"); err == nil {
		t.Fatal("locked document accepted an invalid Witness Key ID")
	}
}
