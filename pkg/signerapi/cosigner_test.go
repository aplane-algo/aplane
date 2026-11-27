// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerapi

import (
	"strings"
	"testing"
)

func TestComponentRequestValidateKindsAndClosedPartition(t *testing.T) {
	validBounded := ComponentRequest{
		GroupBytesHex: []string{"5458aa", "5458bb", "5458cc"},
		Targets: []ComponentTarget{{
			TargetIndex: 0, Kind: ComponentTargetKindBase,
			AuthAddress: "BOUNDED", LsigArgs: map[string]string{"preimage": "aa"},
		}},
		ContextualPositions: []ComponentContextPosition{{TargetIndex: 1}},
		DummyPositions:      []ComponentDummyPosition{{TargetIndex: 2}},
	}
	tests := []struct {
		name    string
		request ComponentRequest
		wantErr string
	}{
		{name: "bounded base", request: validBounded},
		{name: "the retired user kind", request: ComponentRequest{
			GroupBytesHex: []string{"5458aa"},
			Targets:       []ComponentTarget{{TargetIndex: 0, Kind: "user", AuthAddress: "USER"}},
		}, wantErr: "unsupported component kind"},
		{name: "the retired bounded-base kind", request: ComponentRequest{
			GroupBytesHex: []string{"5458aa"},
			Targets:       []ComponentTarget{{TargetIndex: 0, Kind: "bounded-base", AuthAddress: "USER"}},
		}, wantErr: "unsupported component kind"},
		{name: "cosigner", request: ComponentRequest{
			GroupBytesHex: []string{"5458aa"},
			Targets:       []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindCosigner, ComponentKey: "COSIGNER"}},
		}},
		{name: "mixed kinds fail closed", request: ComponentRequest{
			GroupBytesHex: []string{"5458aa", "5458bb"},
			Targets: []ComponentTarget{
				{TargetIndex: 0, Kind: ComponentTargetKindCosigner, ComponentKey: "COSIGNER"},
				{TargetIndex: 1, Kind: ComponentTargetKindBase, AuthAddress: "BOUNDED"},
			},
		}, wantErr: "mixed component target kinds"},
		{name: "bounded discriminator forbids cosigner key", request: ComponentRequest{
			GroupBytesHex: []string{"5458aa"},
			Targets: []ComponentTarget{{
				TargetIndex: 0, Kind: ComponentTargetKindBase,
				AuthAddress: "BOUNDED", ComponentKey: "COSIGNER",
			}},
		}, wantErr: "forbids component_key"},
		{name: "cosigner discriminator forbids authorizer", request: ComponentRequest{
			GroupBytesHex: []string{"5458aa"},
			Targets: []ComponentTarget{{
				TargetIndex: 0, Kind: ComponentTargetKindCosigner,
				ComponentKey: "COSIGNER", AuthAddress: "USER",
			}},
		}, wantErr: "forbids auth_address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.wantErr == "" && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("Validate() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// Validate is the only check on a cosigner request's target indices before
// the signer indexes the decoded group by them, so each refusal is pinned.
func TestComponentRequestValidateRefusesBadTargetIndices(t *testing.T) {
	cosigner := func(indices ...int) []ComponentTarget {
		targets := make([]ComponentTarget, len(indices))
		for i, index := range indices {
			targets[i] = ComponentTarget{TargetIndex: index, Kind: ComponentTargetKindCosigner, ComponentKey: "COSIGNER"}
		}
		return targets
	}
	group := []string{"5458aa", "5458bb", "5458cc"}
	tests := []struct {
		name    string
		request ComponentRequest
		wantErr string
	}{
		{name: "every position covered", request: ComponentRequest{
			GroupBytesHex: group, Targets: cosigner(2, 0),
			ContextualPositions: []ComponentContextPosition{{TargetIndex: 1}},
		}},
		{name: "targets before a declared dummy", request: ComponentRequest{
			GroupBytesHex: group, Targets: cosigner(0, 1),
			DummyPositions: []ComponentDummyPosition{{TargetIndex: 2}},
		}},
		{name: "no targets", request: ComponentRequest{GroupBytesHex: group},
			wantErr: "targets array is empty"},
		{name: "index past the group", request: ComponentRequest{GroupBytesHex: group, Targets: cosigner(0, 1, 3)},
			wantErr: "target 3: target_index 3 is outside original prefix"},
		{name: "negative index", request: ComponentRequest{GroupBytesHex: group, Targets: cosigner(-1)},
			wantErr: "target 1: target_index -1 is outside original prefix"},
		{name: "duplicate index", request: ComponentRequest{GroupBytesHex: group, Targets: cosigner(0, 1, 0)},
			wantErr: "target 3: duplicate or overlapping target_index 0"},
		{name: "contextual position on a target", request: ComponentRequest{
			GroupBytesHex: group, Targets: cosigner(0, 1, 2),
			ContextualPositions: []ComponentContextPosition{{TargetIndex: 1}},
		}, wantErr: "contextual position 1: duplicate or overlapping target_index 1"},
		{name: "position left uncovered", request: ComponentRequest{GroupBytesHex: group, Targets: cosigner(0, 2)},
			wantErr: "original group position 1 is not covered"},
		{name: "index inside the dummy suffix", request: ComponentRequest{
			GroupBytesHex: group, Targets: cosigner(0, 2),
			ContextualPositions: []ComponentContextPosition{{TargetIndex: 1}},
			DummyPositions:      []ComponentDummyPosition{{TargetIndex: 2}},
		}, wantErr: "target 2: target_index 2 is outside original prefix"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v, want none", err)
				}
				return
			}
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("Validate() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestComponentRequestGroupSignRequestPreservesApprovalMetadata(t *testing.T) {
	targetInfo := &AppCallInfo{Mode: "abi", Method: "increment(uint64)void"}
	contextInfo := &AppCallInfo{Mode: "raw"}
	request := ComponentRequest{
		GroupBytesHex: []string{"5458aa", "5458bb", "5458cc"},
		Targets: []ComponentTarget{{
			TargetIndex: 0, Kind: ComponentTargetKindBase,
			AuthAddress: "BOUNDED", AppCallInfo: targetInfo,
		}},
		ContextualPositions: []ComponentContextPosition{{TargetIndex: 1, AppCallInfo: contextInfo}},
		DummyPositions:      []ComponentDummyPosition{{TargetIndex: 2}},
	}

	group := request.GroupSignRequest()
	if len(group.Requests) != 2 {
		t.Fatalf("group request length = %d, want original prefix length 2", len(group.Requests))
	}
	if group.Requests[0].AppCallInfo != targetInfo || group.Requests[1].AppCallInfo != contextInfo {
		t.Fatalf("app-call metadata = %#v/%#v, want target/context metadata", group.Requests[0].AppCallInfo, group.Requests[1].AppCallInfo)
	}
}

func TestComponentResponseValidateForRequestRejectsOutOfGroupIndex(t *testing.T) {
	request := ComponentRequest{
		GroupBytesHex: []string{"5458aa"},
		Targets: []ComponentTarget{{
			TargetIndex: 0, Kind: ComponentTargetKindCosigner, ComponentKey: "COSIGNER",
		}},
	}
	response := ComponentResponse{
		RequestID: "request-1",
		Components: []Component{{
			TargetIndex: 1, Kind: ComponentTargetKindCosigner,
			Signature: "aa", SignatureScheme: "aplane.falcon1024.v1",
		}},
	}

	if err := response.ValidateForRequest(request); err == nil || !strings.Contains(err.Error(), "indices or kinds") {
		t.Fatalf("ValidateForRequest() error = %v, want out-of-group rejection", err)
	}
}

// A base component names the path the signer classified, from the closed
// set; the client skips the cosigner on a listed rekey only.
func TestComponentResponseNamesTheHostPath(t *testing.T) {
	component := Component{
		TargetIndex: 0, Kind: ComponentTargetKindBase, AuthAddress: "BOUNDED",
		BaseSignatures: []string{"aa"}, AssemblyReceipt: "bb", SignatureScheme: "aplane.falcon1024.v1",
	}
	for path, needsCosigner := range map[string]bool{ComponentPathSpend: true, ComponentPathSpendingRekey: true, ComponentPathListedRekey: false} {
		component.Path = path
		if err := (ComponentResponse{RequestID: "request-1", Components: []Component{component}}).Validate(); err != nil {
			t.Fatalf("path %s: Validate() error = %v", path, err)
		}
		if component.NeedsCosigner() != needsCosigner {
			t.Fatalf("path %s: NeedsCosigner() = %v", path, !needsCosigner)
		}
	}
	for _, path := range []string{"", "admin_rekey"} {
		component.Path = path
		if err := (ComponentResponse{RequestID: "request-1", Components: []Component{component}}).Validate(); err == nil || !strings.Contains(err.Error(), "unknown bounded path") {
			t.Fatalf("path %q: Validate() error = %v", path, err)
		}
	}
	cosigner := Component{TargetIndex: 0, Kind: ComponentTargetKindCosigner, Signature: "aa", SignatureScheme: "aplane.witness-falcon1024.v1", Path: ComponentPathSpend}
	if err := (ComponentResponse{RequestID: "request-1", Components: []Component{cosigner}}).Validate(); err == nil {
		t.Fatal("a cosigner component with a path validated")
	}
}
