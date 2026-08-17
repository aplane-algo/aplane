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
			TargetIndex: 0, Kind: ComponentTargetKindBoundedBase,
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
		{name: "user", request: ComponentRequest{
			GroupBytesHex: []string{"5458aa"},
			Targets:       []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindUser, AuthAddress: "USER"}},
		}},
		{name: "sentry", request: ComponentRequest{
			GroupBytesHex: []string{"5458aa"},
			Targets:       []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindSentry, ComponentKey: "SENTRY"}},
		}},
		{name: "mixed kinds fail closed", request: ComponentRequest{
			GroupBytesHex: []string{"5458aa", "5458bb"},
			Targets: []ComponentTarget{
				{TargetIndex: 0, Kind: ComponentTargetKindUser, AuthAddress: "USER"},
				{TargetIndex: 1, Kind: ComponentTargetKindBoundedBase, AuthAddress: "BOUNDED"},
			},
		}, wantErr: "mixed component target kinds"},
		{name: "bounded discriminator forbids sentry key", request: ComponentRequest{
			GroupBytesHex: []string{"5458aa"},
			Targets: []ComponentTarget{{
				TargetIndex: 0, Kind: ComponentTargetKindBoundedBase,
				AuthAddress: "BOUNDED", ComponentKey: "SENTRY",
			}},
		}, wantErr: "forbids component_key"},
		{name: "sentry discriminator forbids authorizer", request: ComponentRequest{
			GroupBytesHex: []string{"5458aa"},
			Targets: []ComponentTarget{{
				TargetIndex: 0, Kind: ComponentTargetKindSentry,
				ComponentKey: "SENTRY", AuthAddress: "USER",
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
