// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

const (
	// RecoverySourceSettingUserAutoApprove identifies source approval-default
	// metadata conservatively reported unknown by protocol v3.
	RecoverySourceSettingUserAutoApprove = "source.user_auto_approve"
	// RecoverySourceSettingGenesisHashMappings identifies source custom-network
	// metadata conservatively reported unknown by protocol v3.
	RecoverySourceSettingGenesisHashMappings = "source.genesis_hash_mappings"
	// RecoverySourceSettingNodeRole identifies source-role metadata unavailable
	// from archives that predate manifest.json.
	RecoverySourceSettingNodeRole = "source.node_role"

	// RecoverySourceSettingsStatusMissing means no usable source-settings
	// sidecar was present.
	RecoverySourceSettingsStatusMissing = "missing"
	// RecoverySourceSettingsStatusUnverified means the archive carried a
	// valid but unauthenticated source-settings projection.
	RecoverySourceSettingsStatusUnverified = "unverified"
	// RecoverySourceSettingsStatusInvalid means source-settings metadata was
	// present but unusable.
	RecoverySourceSettingsStatusInvalid = "invalid"
)

// IsRecoveryArchiveSourceLimitation reports whether setting is a constant
// protocol-v3 compatibility caveat rather than a per-batch finding.
// Unknown values return false so newer findings remain visible to older
// renderers.
func IsRecoveryArchiveSourceLimitation(setting string) bool {
	switch setting {
	case RecoverySourceSettingUserAutoApprove,
		RecoverySourceSettingGenesisHashMappings:
		return true
	default:
		return false
	}
}
