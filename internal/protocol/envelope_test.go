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

// The inferred kind is populated structurally on a shallow copy of the message
// before encoding once, so no intermediate JSON buffer or cloned secret slice
// is allocated and the encoded JSON places kind in its BaseMessage position.
func TestMarshalAdminMessageSetsInferredKindStructurally(t *testing.T) {
	secret := NewSensitiveBytes("secret")
	msg := UnlockMessage{
		BaseMessage: BaseMessage{Type: MsgTypeUnlock, ID: "unlock-1"},
		Passphrase:  secret,
	}
	data, err := MarshalAdminMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"kind":"request","type":"unlock","id":"unlock-1","passphrase":"secret"}`
	if string(data) != want {
		t.Fatalf("MarshalAdminMessage(value) = %s, want %s", data, want)
	}

	// Pointer callers get the same encoding without mutating the caller's struct.
	ptrMsg := &UnlockMessage{
		BaseMessage: BaseMessage{Type: MsgTypeUnlock, ID: "unlock-1"},
		Passphrase:  secret,
	}
	data, err = MarshalAdminMessage(ptrMsg)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != want {
		t.Fatalf("MarshalAdminMessage(pointer) = %s, want %s", data, want)
	}
	if ptrMsg.Kind != "" {
		t.Fatalf("MarshalAdminMessage mutated caller Kind to %q", ptrMsg.Kind)
	}

	// Direct BaseMessage values also receive inferred kind.
	baseData, err := MarshalAdminMessage(BaseMessage{Type: MsgTypeStatus, ID: "st-1"})
	if err != nil {
		t.Fatal(err)
	}
	if wantBase := `{"kind":"notification","type":"status","id":"st-1"}`; string(baseData) != wantBase {
		t.Fatalf("MarshalAdminMessage(BaseMessage) = %s, want %s", baseData, wantBase)
	}

	// Explicit kind is preserved, and unknown/empty types encode without kind.
	data, err = MarshalAdminMessage(UnlockMessage{
		BaseMessage: BaseMessage{Kind: MessageKindRequest, Type: MsgTypeUnlock, ID: "unlock-2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"kind":"request","type":"unlock","id":"unlock-2","passphrase":""}`; string(data) != want {
		t.Fatalf("MarshalAdminMessage(with kind) = %s, want %s", data, want)
	}

	unknownData, err := MarshalAdminMessage(BaseMessage{Type: "unknown_future_type", ID: "u-1"})
	if err != nil {
		t.Fatal(err)
	}
	if wantUnknown := `{"type":"unknown_future_type","id":"u-1"}`; string(unknownData) != wantUnknown {
		t.Fatalf("MarshalAdminMessage(unknown type) = %s, want %s", unknownData, wantUnknown)
	}
}
