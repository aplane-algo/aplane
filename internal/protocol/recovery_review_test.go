// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import "testing"

func TestIsRecoveryArchiveSourceLimitation(t *testing.T) {
	tests := []struct {
		name    string
		setting string
		want    bool
	}{
		{name: "approval default", setting: RecoverySourceSettingUserAutoApprove, want: true},
		{name: "genesis mappings", setting: RecoverySourceSettingGenesisHashMappings, want: true},
		{name: "legacy node role", setting: RecoverySourceSettingNodeRole},
		{name: "future setting remains visible", setting: "source.future_setting"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRecoveryArchiveSourceLimitation(tt.setting); got != tt.want {
				t.Fatalf("IsRecoveryArchiveSourceLimitation(%q) = %v, want %v", tt.setting, got, tt.want)
			}
		})
	}
}
