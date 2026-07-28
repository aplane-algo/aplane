// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/backup/recovered"
	"github.com/aplane-algo/aplane/internal/backup/sourcecontext"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const recoveredReviewFormatVersion = 3

// unattendedSigningWarning is emitted whenever the destination identity
// auto-approves unmatched signing requests. It is destination-derived and
// cannot be suppressed by archive-reported source context.
const unattendedSigningWarning = "you are activating into an auto-approving identity"

// ReviewRecovered validates one inactive batch against current destination
// policy, approval mode, and active credential conflicts.
func (s Service) ReviewRecovered(ir *identity.Runtime, restoreID string) adminproto.ReviewRecoveredResult {
	var result adminproto.ReviewRecoveredResult
	err := s.Deps.WithIdentityMutation(ir.ID(), func() error {
		return ir.WithMasterKey(func(masterKey []byte) error {
			var reviewErr error
			result, reviewErr = s.reviewRecoveredWithMasterKey(ir, restoreID, masterKey)
			return reviewErr
		})
	})
	if err != nil {
		return adminproto.ReviewRecoveredResult{
			RestoreID: restoreID,
			Code:      protocol.ResultCodeReviewRecoveredFailed,
			Error:     err.Error(),
		}
	}
	result.Success = true
	return result
}

func (s Service) reviewRecoveredWithMasterKey(
	ir *identity.Runtime,
	restoreID string,
	masterKey []byte,
) (adminproto.ReviewRecoveredResult, error) {
	if err := recovered.ValidateRestoreID(restoreID); err != nil {
		return adminproto.ReviewRecoveredResult{}, err
	}
	batch, err := recovered.LoadBatch(s.Deps.KeyPaths(), ir.ID(), restoreID, masterKey)
	if err != nil {
		return adminproto.ReviewRecoveredResult{}, err
	}
	defer crypto.ZeroBytes(batch.SourcePolicyYAML)

	entries := make([]adminproto.RecoveredReviewEntry, 0, len(batch.Entries))
	selectors := make([]string, 0, len(batch.Entries))
	for _, meta := range batch.Entries {
		entry, err := recovered.LoadEntry(s.Deps.KeyPaths(), ir.ID(), restoreID, meta, masterKey)
		if err != nil {
			return adminproto.ReviewRecoveredResult{}, err
		}
		entries = append(entries, adminproto.RecoveredReviewEntry{
			Selector: entry.Selector,
			Category: entry.Category,
			KeyType:  entry.KeyType,
		})
		selectors = append(selectors, entry.Selector)
		entry.ZeroSecrets()
	}

	destinationPolicy, destinationDigest, err := loadDestinationRestorePolicy(
		s.Deps.KeyPaths().Root(),
		ir.ID(),
		ir.NodeRole(),
		masterKey,
	)
	if err != nil {
		return adminproto.ReviewRecoveredResult{}, err
	}
	destinationProjection, err := policy.NormalizeForRestoreDiff(
		destinationPolicy,
		string(ir.NodeRole()),
		selectors,
	)
	if err != nil {
		return adminproto.ReviewRecoveredResult{}, err
	}
	comparison, err := compareRecoveredSourcePolicy(batch, ir.NodeRole(), selectors, destinationProjection)
	if err != nil {
		return adminproto.ReviewRecoveredResult{}, err
	}

	conflicts, err := activeRecoveredConflicts(s.Deps.KeyPaths(), ir.ID(), entries)
	if err != nil {
		return adminproto.ReviewRecoveredResult{}, err
	}
	unknowns := recoveredUnknownSourceSettings(batch)
	sourceSettings := projectRecoveredSourceSettings(batch)
	approvalMode, warning := destinationApprovalMode(ir)
	changes := make([]adminproto.RecoveryPolicyChange, len(comparison.Changes))
	for i, change := range comparison.Changes {
		changes[i] = adminproto.RecoveryPolicyChange{
			Category:    string(change.Category),
			Selector:    change.Selector,
			Path:        change.Path,
			Source:      change.Source,
			Destination: change.Destination,
		}
	}

	token, err := recoveredReviewToken(recoveredReviewTokenInput{
		FormatVersion:           recoveredReviewFormatVersion,
		RestoreID:               batch.RestoreID,
		ArchiveSHA256:           batch.ArchiveSHA256,
		SourcePolicyStatus:      string(batch.SourcePolicyStatus),
		SourcePolicySHA256:      batch.SourcePolicySHA256,
		SourceSettingsStatus:    sourceSettings.Status,
		SourceSettingsSHA256:    batch.SourceSettingsSHA256,
		DestinationPolicySHA256: destinationDigest,
		DestinationApprovalMode: string(approvalMode),
		Entries:                 entries,
		ActiveConflicts:         conflicts,
		PolicyComparisonFormat:  recoveredReviewFormatVersion,
	})
	if err != nil {
		return adminproto.ReviewRecoveredResult{}, err
	}
	return adminproto.ReviewRecoveredResult{
		RestoreID:                    batch.RestoreID,
		ArchiveChecksum:              batch.ArchiveSHA256,
		SourceNodeRole:               batch.SourceNodeRole,
		SourcePolicyStatus:           string(batch.SourcePolicyStatus),
		SourcePolicySHA256:           batch.SourcePolicySHA256,
		DestinationPolicySHA256:      destinationDigest,
		DestinationApprovalMode:      approvalMode,
		UnattendedSigningWarning:     warning,
		PolicyComparison:             string(comparison.Status),
		SecurityChanges:              changes,
		ChangedPaths:                 slices.Clone(comparison.ChangedPaths),
		UnknownSourceSettings:        unknowns,
		SourceSettingsStatus:         sourceSettings.Status,
		SourceUserAutoApprove:        sourceSettings.UserAutoApprove,
		SourceGenesisHashMappings:    sourceSettings.GenesisHashMappings,
		SourceSettingsWarning:        sourceSettings.Warning,
		Entries:                      entries,
		ActiveConflicts:              conflicts,
		ReviewToken:                  token,
		UnattendedSigningAckRequired: warning != "",
	}, nil
}

type recoveredSourceSettingsReview struct {
	Status              string
	UserAutoApprove     *bool
	GenesisHashMappings []adminproto.RecoveryGenesisHashMapping
	Warning             string
}

func projectRecoveredSourceSettings(batch *recovered.Batch) recoveredSourceSettingsReview {
	if batch == nil {
		return recoveredSourceSettingsReview{Status: string(sourcecontext.StatusMissing)}
	}
	status := batch.SourceSettingsStatus
	if status == "" {
		status = sourcecontext.StatusMissing
	}
	var userAutoApprove *bool
	if batch.SourceUserAutoApprove != nil {
		value := *batch.SourceUserAutoApprove
		userAutoApprove = &value
	}
	mappings := make([]adminproto.RecoveryGenesisHashMapping, len(batch.SourceGenesisHashMappings))
	for i, mapping := range batch.SourceGenesisHashMappings {
		mappings[i] = adminproto.RecoveryGenesisHashMapping{
			GenesisHash: mapping.GenesisHash,
			Network:     mapping.Network,
		}
	}
	return recoveredSourceSettingsReview{
		Status:              string(status),
		UserAutoApprove:     userAutoApprove,
		GenesisHashMappings: mappings,
		Warning:             batch.SourceSettingsWarning,
	}
}

func recoveredUnknownSourceSettings(batch *recovered.Batch) []string {
	unknowns := []string{
		protocol.RecoverySourceSettingUserAutoApprove,
		protocol.RecoverySourceSettingGenesisHashMappings,
	}
	if batch != nil && batch.SourceNodeRole == recovered.SourceNodeRoleUnknown {
		unknowns = append(unknowns, protocol.RecoverySourceSettingNodeRole)
	}
	return unknowns
}

func loadDestinationRestorePolicy(
	dataRoot, identityID string,
	role noderole.Role,
	masterKey []byte,
) (*policy.Config, string, error) {
	var (
		stored    *policy.StoredConfig
		effective *policy.Config
		encoded   []byte
		err       error
	)
	switch role {
	case noderole.RoleSigner:
		stored, err = policy.LoadVerifiedStoredConfigWithMasterKey(dataRoot, identityID, masterKey)
		if err == nil {
			effective, err = stored.ApplySigning(nil)
		}
		if err == nil {
			encoded, err = policy.MarshalStoredConfig(stored)
		}
	case noderole.RoleSentry:
		stored, err = policy.LoadVerifiedSentryConfigWithMasterKey(dataRoot, identityID, masterKey)
		if err == nil {
			effective, err = stored.ApplySentry(nil)
		}
		if err == nil {
			encoded, err = policy.MarshalStoredSentryConfig(stored)
		}
	default:
		err = fmt.Errorf("unsupported destination node role %q", role)
	}
	if err != nil {
		return nil, "", fmt.Errorf("load destination policy for recovery review: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return effective, hex.EncodeToString(sum[:]), nil
}

func compareRecoveredSourcePolicy(
	batch *recovered.Batch,
	destinationRole noderole.Role,
	selectors []string,
	destination policy.RestorePolicyProjection,
) (policy.RestorePolicyComparison, error) {
	if batch.SourcePolicyStatus != recovered.SourcePolicyUnverified ||
		batch.SourceNodeRole != string(destinationRole) {
		return policy.RestorePolicyComparison{Status: policy.RestoreComparisonUnavailable}, nil
	}

	var (
		stored    *policy.StoredConfig
		effective *policy.Config
		err       error
	)
	switch destinationRole {
	case noderole.RoleSigner:
		stored, err = policy.ParseStoredConfig(batch.SourcePolicyYAML)
		if err == nil {
			effective, err = stored.ApplySigning(nil)
		}
	case noderole.RoleSentry:
		stored, err = policy.ParseStoredSentryConfig(batch.SourcePolicyYAML)
		if err == nil {
			effective, err = stored.ApplySentry(nil)
		}
	default:
		return policy.RestorePolicyComparison{}, fmt.Errorf("unsupported destination node role %q", destinationRole)
	}
	if err != nil {
		return policy.RestorePolicyComparison{Status: policy.RestoreComparisonUnavailable}, nil
	}
	source, err := policy.NormalizeForRestoreDiff(effective, string(destinationRole), selectors)
	if err != nil {
		return policy.RestorePolicyComparison{}, err
	}
	return policy.DiffForRestore(source, destination), nil
}

// destinationApprovalMode reports the destination's own unmatched-request
// approval behavior and the warning it requires.
//
// The warning depends only on verified destination state. Archive-reported
// source context is unauthenticated and must never suppress it: a source that
// claims it also auto-approved, an archive with no source settings, and an
// archive whose policy failed to parse all produce the same warning here.
func destinationApprovalMode(ir *identity.Runtime) (adminproto.DestinationApprovalMode, string) {
	if ir.NodeRole() != noderole.RoleSigner {
		return adminproto.DestinationApprovalNotApplicable, ""
	}
	if ir.Config().UserAutoApprove() {
		return adminproto.DestinationApprovalAutoApproveFallback, unattendedSigningWarning
	}
	return adminproto.DestinationApprovalManualDefault, ""
}

func activeRecoveredConflicts(
	paths storepaths.Paths,
	identityID string,
	entries []adminproto.RecoveredReviewEntry,
) ([]adminproto.RecoveredActiveConflict, error) {
	var conflicts []adminproto.RecoveredActiveConflict
	for _, entry := range entries {
		path, exists, err := keys.ManagedCredentialDestination(
			paths,
			identityID,
			entry.Selector,
			entry.Category,
		)
		if err != nil {
			return nil, err
		}
		if !exists {
			continue
		}
		fingerprint, err := conflictFingerprint(path)
		if err != nil {
			return nil, fmt.Errorf("fingerprint active credential %s: %w", entry.Selector, err)
		}
		conflicts = append(conflicts, adminproto.RecoveredActiveConflict{
			Selector: entry.Selector,
			Category: entry.Category,
			KeyType:  entry.KeyType,
			SHA256:   fingerprint,
		})
	}
	slices.SortFunc(conflicts, func(a, b adminproto.RecoveredActiveConflict) int {
		return strings.Compare(a.Selector, b.Selector)
	})
	return conflicts, nil
}

type recoveredReviewTokenInput struct {
	FormatVersion           int                                  `json:"format_version"`
	RestoreID               string                               `json:"restore_id"`
	ArchiveSHA256           string                               `json:"archive_sha256"`
	SourcePolicyStatus      string                               `json:"source_policy_status"`
	SourcePolicySHA256      string                               `json:"source_policy_sha256"`
	SourceSettingsStatus    string                               `json:"source_settings_status"`
	SourceSettingsSHA256    string                               `json:"source_settings_sha256"`
	DestinationPolicySHA256 string                               `json:"destination_policy_sha256"`
	DestinationApprovalMode string                               `json:"destination_approval_mode"`
	Entries                 []adminproto.RecoveredReviewEntry    `json:"entries"`
	ActiveConflicts         []adminproto.RecoveredActiveConflict `json:"active_conflicts"`
	PolicyComparisonFormat  int                                  `json:"policy_comparison_format"`
}

func recoveredReviewToken(input recoveredReviewTokenInput) (string, error) {
	encoded, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("marshal recovered review token input: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func conflictFingerprint(path string) (string, error) {
	checksum, _, err := backup.FileSHA256(path)
	if err != nil {
		return "", err
	}
	return strings.ToLower(checksum), nil
}
