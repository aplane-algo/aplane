// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"

	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestProtocolKeyDetailsMessageIncludesPublicKey(t *testing.T) {
	msg := ProtocolKeyDetailsMessage("details-1", adminproto.GetKeyDetailsResult{
		Success:      true,
		Address:      "ADDR",
		KeyType:      "aplane.witness-falcon1024.v1",
		PublicKeyHex: "aabbccdd",
	})

	if msg.Type != protocol.MsgTypeKeyDetails || msg.ID != "details-1" {
		t.Fatalf("message identity = (%q, %q), want (%q, details-1)", msg.Type, msg.ID, protocol.MsgTypeKeyDetails)
	}
	if msg.PublicKeyHex != "aabbccdd" {
		t.Fatalf("PublicKeyHex = %q, want aabbccdd", msg.PublicKeyHex)
	}
}
