// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

const (
	// RecoverySourceSettingUserAutoApprove identifies source approval-default
	// metadata that current backup archives do not carry.
	RecoverySourceSettingUserAutoApprove = "source.user_auto_approve"
	// RecoverySourceSettingGenesisHashMappings identifies source custom-network
	// metadata that current backup archives do not carry.
	RecoverySourceSettingGenesisHashMappings = "source.genesis_hash_mappings"
	// RecoverySourceSettingNodeRole identifies source-role metadata unavailable
	// from archives that predate manifest.json.
	RecoverySourceSettingNodeRole = "source.node_role"
)

// IsRecoveryArchiveSourceLimitation reports whether setting is a constant
// limitation of the current backup archive rather than a per-batch finding.
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
