// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
)

// The ASA set decides which assets policy documents may name, so it is policy
// context: reading it takes policy.view and changing it policy.update.

func (s *Session) HandleListASASet(msg *protocol.ListASASetMessage) {
	if !s.authorize(msg.ID, auth.ActionPolicyView, auth.Resource{Type: "asa_set"}) {
		return
	}
	_ = s.WriteJSON(ProtocolASASetMessage(msg.ID, s.settingsServices.ListASASet()))
}

func (s *Session) HandleLookupASA(msg *protocol.LookupASAMessage) {
	if !s.authorize(msg.ID, auth.ActionPolicyView, auth.Resource{Type: "asa_set"}) {
		return
	}
	result := s.settingsServices.LookupASA(adminproto.LookupASARequest{Network: msg.Network, AssetID: msg.AssetID})
	_ = s.WriteJSON(protocol.LookupASAResultMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeLookupASAResult, ID: msg.ID},
		Success:     result.Success,
		Asset:       protocolASAObservation(result.Asset),
		Code:        result.Code,
		Error:       result.Error,
	})
}

func (s *Session) HandleAddASA(msg *protocol.AddASAMessage) {
	if !s.authorize(msg.ID, auth.ActionPolicyUpdate, auth.Resource{Type: "asa_set"}) {
		return
	}
	result := s.settingsServices.AddASA(adminproto.AddASARequest{Confirmed: AdminASAObservation(msg.Confirmed)})
	_ = s.WriteJSON(protocol.AddASAResultMessage{
		BaseMessage:     protocol.BaseMessage{Type: protocol.MsgTypeAddASAResult, ID: msg.ID},
		Success:         result.Success,
		Asset:           protocolASAInfo(result.Asset),
		GenerationID:    result.GenerationID,
		CommitUncertain: result.CommitUncertain,
		Code:            result.Code,
		Error:           result.Error,
	})
}

func (s *Session) HandleRemoveASA(msg *protocol.RemoveASAMessage) {
	if !s.authorize(msg.ID, auth.ActionPolicyUpdate, auth.Resource{Type: "asa_set"}) {
		return
	}
	result := s.settingsServices.RemoveASA(adminproto.RemoveASARequest{Network: msg.Network, GenesisHash: msg.GenesisHash, AssetID: msg.AssetID})
	out := protocol.RemoveASAResultMessage{
		BaseMessage:     protocol.BaseMessage{Type: protocol.MsgTypeRemoveASAResult, ID: msg.ID},
		Success:         result.Success,
		GenerationID:    result.GenerationID,
		CommitUncertain: result.CommitUncertain,
		BlockingOmitted: result.BlockingOmitted,
		Code:            result.Code,
		Error:           result.Error,
	}
	for _, ref := range result.Blocking {
		out.Blocking = append(out.Blocking, protocol.ASAReference{Document: ref.Document, Pointer: ref.Pointer})
	}
	_ = s.WriteJSON(out)
}

// ProtocolASASetMessage projects the effective ASA set onto the wire.
func ProtocolASASetMessage(id string, result adminproto.ListASASetResult) protocol.ASASetMessage {
	msg := protocol.ASASetMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeASASet, ID: id},
		Assets:      []protocol.ASAInfo{},
		Code:        result.Code,
		Error:       result.Error,
	}
	for _, a := range result.Assets {
		msg.Assets = append(msg.Assets, protocolASAInfo(a))
	}
	return msg
}

func protocolASAInfo(a adminproto.ASAInfo) protocol.ASAInfo {
	return protocol.ASAInfo{
		Network: a.Network, GenesisHash: a.GenesisHash, AssetID: a.AssetID,
		Name: a.Name, UnitName: a.UnitName, Decimals: a.Decimals, Origin: a.Origin, Shadowed: a.Shadowed,
		Creator: a.Creator, ConfirmedAt: a.ConfirmedAt, NetworkAtConfirmation: a.NetworkAtConfirmation,
	}
}

func protocolASAObservation(o adminproto.ASAObservation) protocol.ASAObservation {
	return protocol.ASAObservation{
		Network: o.Network, GenesisHash: o.GenesisHash, AssetID: o.AssetID,
		Name: o.Name, UnitName: o.UnitName, Decimals: o.Decimals, Total: o.Total,
		DefaultFrozen: o.DefaultFrozen, URL: o.URL, Creator: o.Creator,
		Manager: o.Manager, Reserve: o.Reserve, Freeze: o.Freeze, Clawback: o.Clawback,
	}
}

// AdminASAObservation is the inverse of protocolASAObservation, for the
// confirmation a client sends back.
func AdminASAObservation(o protocol.ASAObservation) adminproto.ASAObservation {
	return adminproto.ASAObservation{
		Network: o.Network, GenesisHash: o.GenesisHash, AssetID: o.AssetID,
		Name: o.Name, UnitName: o.UnitName, Decimals: o.Decimals, Total: o.Total,
		DefaultFrozen: o.DefaultFrozen, URL: o.URL, Creator: o.Creator,
		Manager: o.Manager, Reserve: o.Reserve, Freeze: o.Freeze, Clawback: o.Clawback,
	}
}

// ProtocolPolicyContextMessage projects the node's policy context onto the
// wire.
func ProtocolPolicyContextMessage(id string, view adminproto.PolicyContextView) protocol.PolicyContextMessage {
	msg := protocol.PolicyContextMessage{
		BaseMessage:     protocol.BaseMessage{Type: protocol.MsgTypePolicyContext, ID: id},
		Success:         view.Success,
		NodeRole:        view.NodeRole,
		RulesVersion:    view.RulesVersion,
		ContextSHA256:   view.ContextSHA256,
		PolicySetSHA256: view.PolicySetSHA256,
		SnapshotSHA256:  view.SnapshotSHA256,
		Code:            view.Code,
		Error:           view.Error,
	}
	for _, n := range view.Networks {
		msg.Networks = append(msg.Networks, protocol.PolicyNetwork{Network: n.Network, GenesisHash: n.GenesisHash})
	}
	for _, a := range view.Assets {
		msg.Assets = append(msg.Assets, protocolASAInfo(a))
	}
	return msg
}
