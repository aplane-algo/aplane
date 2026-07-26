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

func TestProtocolReviewRecoveredResultCopiesTypedSourceContext(t *testing.T) {
	autoApprove := false
	result := adminproto.ReviewRecoveredResult{
		Success:               true,
		SourceSettingsStatus:  protocol.RecoverySourceSettingsStatusUnverified,
		SourceUserAutoApprove: &autoApprove,
		SourceGenesisHashMappings: []adminproto.RecoveryGenesisHashMapping{{
			GenesisHash: "REREREREREREREREREREREREREREREREREREREREREQ=",
			Network:     "private-network",
		}},
		SourceSettingsWarning: "warning",
	}
	message := ProtocolReviewRecoveredResultMessage("review-1", result)
	if message.SourceSettingsStatus != protocol.RecoverySourceSettingsStatusUnverified ||
		message.SourceUserAutoApprove == nil ||
		*message.SourceUserAutoApprove ||
		len(message.SourceGenesisHashMappings) != 1 ||
		message.SourceGenesisHashMappings[0].Network != "private-network" ||
		message.SourceSettingsWarning != "warning" {
		t.Fatalf("protocol review source context = %+v", message)
	}
	autoApprove = true
	result.SourceGenesisHashMappings[0].Network = "changed"
	if *message.SourceUserAutoApprove ||
		message.SourceGenesisHashMappings[0].Network != "private-network" {
		t.Fatal("protocol review aliases admin result source context")
	}
}
