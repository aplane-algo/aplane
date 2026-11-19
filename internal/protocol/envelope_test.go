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

// The inferred kind is added to the first encoding in place of a decode and
// re-encode through a map, which left unzeroed copies of every passphrase
// and recovery phrase a message carried. Members therefore keep their struct
// order and the kind comes last.
func TestMarshalAdminMessageAppendsInferredKindWithoutReencoding(t *testing.T) {
	data, err := MarshalAdminMessage(UnlockMessage{
		BaseMessage: BaseMessage{Type: MsgTypeUnlock, ID: "unlock-1"},
		Passphrase:  NewSensitiveBytes("secret"),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"type":"unlock","id":"unlock-1","passphrase":"secret","kind":"request"}`
	if string(data) != want {
		t.Fatalf("MarshalAdminMessage() = %s, want %s", data, want)
	}

	data, err = MarshalAdminMessage(UnlockMessage{
		BaseMessage: BaseMessage{Kind: MessageKindRequest, Type: MsgTypeUnlock, ID: "unlock-2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"kind":"request","type":"unlock","id":"unlock-2","passphrase":""}`; string(data) != want {
		t.Fatalf("MarshalAdminMessage(with kind) = %s, want %s", data, want)
	}
}

func TestAppendObjectKindHandlesEmptyObjectAndRejectsNonObject(t *testing.T) {
	got, err := appendObjectKind([]byte(`{}`), MessageKindNotification)
	if err != nil || string(got) != `{"kind":"notification"}` {
		t.Fatalf("appendObjectKind({}) = %s, %v", got, err)
	}
	if _, err := appendObjectKind([]byte(`[]`), MessageKindRequest); err == nil {
		t.Fatal("appendObjectKind accepted a non-object")
	}
}
