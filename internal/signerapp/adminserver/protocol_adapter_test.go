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

func TestProtocolChangeStorePassphraseResultPreservesFailureRecoveryState(t *testing.T) {
	msg := ProtocolChangeStorePassphraseResultMessage(
		"change-1",
		adminproto.ChangeStorePassphraseResult{
			PriorGenerations: 2,
			HelperWarning:    "helper still has old passphrase",
			RootCommitted:    true,
			RotationPending:  true,
			Code:             "passphrase_change_failed",
			Error:            "injected completion failure",
		},
	)
	if msg.Success ||
		msg.PriorGenerations != 2 ||
		msg.HelperWarning == "" ||
		!msg.RootCommitted ||
		!msg.RotationPending ||
		msg.Code != "passphrase_change_failed" {
		t.Fatalf("failure recovery state was not preserved: %#v", msg)
	}
}

func TestProtocolReviewRecoveredResultCopiesTypedSourceContext(t *testing.T) {
	autoApprove := false
	result := adminproto.ReviewRecoveredResult{
		Success:                      true,
		UnattendedSigningAckRequired: true,
		ArchiveCreatedAtUnix:         1_700_000_000,
		SourceUserAutoApprove:        &autoApprove,
		SourceGenesisHashMappings: []adminproto.RecoveryGenesisHashMapping{{
			GenesisHash: "REREREREREREREREREREREREREREREREREREREREREQ=",
			Network:     "private-network",
		}},
		SecurityChanges: []adminproto.RecoveryPolicyChange{{
			Path: "reject_rekey",
		}},
	}
	message := ProtocolReviewRecoveredResultMessage("review-1", result)
	if message.ArchiveCreatedAtUnix != 1_700_000_000 {
		t.Fatalf("ArchiveCreatedAtUnix = %d, want the archive packaging time copied to the wire",
			message.ArchiveCreatedAtUnix)
	}
	if message.SourceUserAutoApprove == nil ||
		*message.SourceUserAutoApprove ||
		len(message.SourceGenesisHashMappings) != 1 ||
		message.SourceGenesisHashMappings[0].Network != "private-network" ||
		message.UnattendedSigningAckRequired == nil ||
		!*message.UnattendedSigningAckRequired ||
		len(message.SecurityChanges) != 1 ||
		message.SecurityChanges[0].Path != "reject_rekey" {
		t.Fatalf("protocol review source context = %+v", message)
	}
	autoApprove = true
	result.SourceGenesisHashMappings[0].Network = "changed"
	if *message.SourceUserAutoApprove ||
		message.SourceGenesisHashMappings[0].Network != "private-network" {
		t.Fatal("protocol review aliases admin result source context")
	}
}
