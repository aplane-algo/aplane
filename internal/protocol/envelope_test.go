// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestMarshalAdminMessageBoundsDocumentGrowth pins that a policy document at
// most doubles on the wire, so a 1 MiB document always fits one frame.
func TestMarshalAdminMessageBoundsDocumentGrowth(t *testing.T) {
	const size = 1 << 20
	for name, document := range map[string]string{
		"html":           strings.Repeat("<>&", size/3),
		"quotes":         strings.Repeat(`"`, size),
		"newlines":       strings.Repeat("\n", size),
		"line separator": strings.Repeat(" ", size/3),
	} {
		t.Run(name, func(t *testing.T) {
			data, err := MarshalAdminMessage(PolicyDocumentMessage{
				BaseMessage: BaseMessage{Type: MsgTypePolicyDocument, ID: "doc"},
				Success:     true,
				Document:    document,
			})
			if err != nil {
				t.Fatal(err)
			}
			if limit := 2*len(document) + 256; len(data) > limit || len(data) > MaxAdminMessageBytes {
				t.Fatalf("%d-byte document encodes to %d bytes", len(document), len(data))
			}
			var decoded PolicyDocumentMessage
			if err := json.Unmarshal(data, &decoded); err != nil || decoded.Document != document {
				t.Fatalf("round trip changed the document: %v", err)
			}
		})
	}
	data, err := MarshalAdminMessage(PolicyDocumentMessage{BaseMessage: BaseMessage{Type: MsgTypePolicyDocument}, Document: "<a&b>"})
	if err != nil || !strings.Contains(string(data), `"document":"<a&b>"`) {
		t.Fatalf("HTML characters escaped: %s, %v", data, err)
	}
}
