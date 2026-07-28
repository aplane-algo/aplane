// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
)

const (
	applyUsage    = "usage: apstore restore apply <backup-id|name> [--address ADDRESS ...] [--overwrite] [--acknowledge-unattended-signing]"
	activateUsage = "usage: apstore restore activate <restore-id> [--replace-existing] [--acknowledge-unattended-signing]"
)

func cmdRestoreManaged(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apstore restore <preview|apply|list|review|activate|rollback|purge>")
	}
	switch args[0] {
	case "preview":
		if len(args) != 2 {
			return fmt.Errorf("usage: apstore restore preview <backup-id|name>")
		}
		return cmdRestorePreviewManaged(args[1])
	case "apply":
		return cmdRestoreApplyManaged(args[1:])
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("usage: apstore restore list")
		}
		return cmdRestoreListRecovered()
	case "review":
		if len(args) != 2 {
			return fmt.Errorf("usage: apstore restore review <restore-id>")
		}
		return cmdRestoreReviewRecovered(args[1])
	case "activate":
		return cmdRestoreActivateRecovered(args[1:])
	case "rollback":
		if len(args) != 2 {
			return fmt.Errorf("usage: apstore restore rollback <restore-id>")
		}
		return cmdRestoreRollbackRecovered(args[1])
	case "purge":
		if len(args) != 2 {
			return fmt.Errorf("usage: apstore restore purge <restore-id>")
		}
		return cmdRestorePurgeRecovered(args[1])
	default:
		return fmt.Errorf("usage: apstore restore <preview|apply|list|review|activate|rollback|purge>")
	}
}

func cmdRestorePreviewManaged(name string) error {
	exportPassphrase, err := promptPassphrase("Enter export passphrase (to decrypt backup files): ")
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(exportPassphrase)

	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()

	result, err := requestRestorePreview(client, name, exportPassphrase)
	if err != nil {
		return err
	}
	if err := renderRestorePreviewResult(result); err != nil {
		return err
	}
	return nil
}

func cmdRestoreApplyManaged(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", applyUsage)
	}
	name := args[0]
	var addresses []string
	overwrite := false
	unattendedAck := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--overwrite":
			overwrite = true
		case "--acknowledge-unattended-signing":
			unattendedAck = true
		case "--address":
			if i+1 >= len(args) {
				return fmt.Errorf("%s", applyUsage)
			}
			addresses = append(addresses, args[i+1])
			i++
		default:
			return fmt.Errorf("unknown restore apply option: %s", args[i])
		}
	}
	exportPassphrase, err := promptPassphrase("Enter export passphrase (to decrypt backup files): ")
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(exportPassphrase)

	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()

	var recoveredResult protocol.RecoverBackupResultMessage
	err = client.request(protocol.RecoverBackupMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypeRecoverBackup, ID: newApstoreRequestID("restore-recover")},
		ArchivePath:      name,
		Addresses:        addresses,
		ExportPassphrase: protocol.SensitiveBytes(exportPassphrase),
	}, &recoveredResult)
	if err != nil {
		return err
	}
	if !recoveredResult.Success {
		return resultError("backup recovery failed", recoveredResult.Code, recoveredResult.Error)
	}
	logInfof("recovered inactive batch: %s (%d entries)", recoveredResult.RestoreID, recoveredResult.EntryCount)
	return reviewAndActivateRecovered(client, recoveredResult.RestoreID, overwrite, unattendedAck)
}

func cmdRestoreListRecovered() error {
	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()
	var result protocol.RecoveredListMessage
	if err := client.request(protocol.ListRecoveredMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListRecovered, ID: newApstoreRequestID("restore-list")},
	}, &result); err != nil {
		return err
	}
	if result.Error != "" {
		return resultError("list recovered batches failed", result.Code, result.Error)
	}
	if len(result.Batches) == 0 {
		logInfof("no inactive recovered batches")
		return nil
	}
	for _, batch := range result.Batches {
		fmt.Printf("%s  %d entries  %s  %s\n",
			batch.RestoreID,
			batch.EntryCount,
			batch.SourcePolicyStatus,
			batch.ArchiveName,
		)
	}
	return nil
}

func cmdRestoreReviewRecovered(restoreID string) error {
	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()
	review, err := requestRecoveredReview(client, restoreID)
	if err != nil {
		return err
	}
	printRecoveredReview(review)
	return nil
}

func cmdRestoreActivateRecovered(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", activateUsage)
	}
	restoreID := args[0]
	replaceExisting := false
	unattendedAck := false
	for _, arg := range args[1:] {
		switch arg {
		case "--replace-existing":
			replaceExisting = true
		case "--acknowledge-unattended-signing":
			unattendedAck = true
		default:
			return fmt.Errorf("unknown restore activate option: %s", arg)
		}
	}
	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()
	return reviewAndActivateRecovered(client, restoreID, replaceExisting, unattendedAck)
}

func cmdRestoreRollbackRecovered(restoreID string) error {
	if !confirmYesNo("Roll back this incomplete activation to its exact prior state?") {
		return fmt.Errorf("rollback cancelled")
	}
	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()
	var result protocol.RollbackRecoveredResultMessage
	if err := client.request(protocol.RollbackRecoveredMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRollbackRecovered, ID: newApstoreRequestID("restore-rollback")},
		RestoreID:   restoreID,
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("recovered activation rollback failed", result.Code, result.Error)
	}
	logInfof("rolled back incomplete activation: %s", restoreID)
	return nil
}

func cmdRestorePurgeRecovered(restoreID string) error {
	if !confirmYesNo("Permanently purge this inactive recovered batch?") {
		return fmt.Errorf("purge cancelled")
	}
	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()
	var result protocol.PurgeRecoveredResultMessage
	if err := client.request(protocol.PurgeRecoveredMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypePurgeRecovered, ID: newApstoreRequestID("restore-purge")},
		RestoreID:   restoreID,
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("purge recovered batch failed", result.Code, result.Error)
	}
	logInfof("purged inactive recovered batch: %s", restoreID)
	return nil
}

// reviewAndActivateRecovered activates one reviewed batch. preAcknowledged
// carries --acknowledge-unattended-signing: it replaces the interactive prompt
// with explicit operator intent recorded on the command line, so restore stays
// scriptable against an auto-approving destination. It does not bypass the
// requirement; the server still enforces the acknowledgement against its own
// pinned review.
func reviewAndActivateRecovered(
	client apstoreAdminRequester,
	restoreID string,
	replaceExisting bool,
	preAcknowledged bool,
) error {
	review, err := requestRecoveredReview(client, restoreID)
	if err != nil {
		return err
	}
	printRecoveredReview(review)
	if len(review.ActiveConflicts) > 0 && !replaceExisting {
		return fmt.Errorf("%d active credential conflict(s); review and retry with --replace-existing", len(review.ActiveConflicts))
	}
	unattendedAck := false
	if recoveredUnattendedSigningAckRequired(review) {
		if !preAcknowledged &&
			!confirmYesNo("I acknowledge this identity auto-approves unmatched signing requests?") {
			return fmt.Errorf("activation cancelled; recovered batch %s remains inactive", restoreID)
		}
		unattendedAck = true
	}
	review.AcknowledgeUnattendedSigning = unattendedAck
	return activateRecovered(client, review, replaceExisting)
}

func recoveredUnattendedSigningAckRequired(
	review protocol.ReviewRecoveredResultMessage,
) bool {
	if review.UnattendedSigningAckRequired == nil {
		return review.DestinationApprovalMode == "auto_approve_fallback"
	}
	return *review.UnattendedSigningAckRequired
}

func requestRecoveredReview(
	client apstoreAdminRequester,
	restoreID string,
) (protocol.ReviewRecoveredResultMessage, error) {
	var review protocol.ReviewRecoveredResultMessage
	err := client.request(protocol.ReviewRecoveredMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeReviewRecovered, ID: newApstoreRequestID("restore-review")},
		RestoreID:   restoreID,
	}, &review)
	if err != nil {
		return review, err
	}
	if !review.Success {
		return review, resultError("review recovered batch failed", review.Code, review.Error)
	}
	return review, nil
}

func activateRecovered(
	client apstoreAdminRequester,
	review protocol.ReviewRecoveredResultMessage,
	replaceExisting bool,
) error {
	var result protocol.ActivateRecoveredResultMessage
	err := client.request(protocol.ActivateRecoveredMessage{
		BaseMessage:                  protocol.BaseMessage{Type: protocol.MsgTypeActivateRecovered, ID: newApstoreRequestID("restore-activate")},
		RestoreID:                    review.RestoreID,
		ReviewToken:                  review.ReviewToken,
		AcknowledgeUnattendedSigning: review.AcknowledgeUnattendedSigning,
		ReplaceExisting:              replaceExisting,
	}, &result)
	if err != nil {
		return err
	}
	if !result.Success {
		return resultError("activate recovered batch failed", result.Code, result.Error)
	}
	for _, warning := range result.Warnings {
		logWarnf("%s", warning)
	}
	logInfof("activated recovered batch: %s", review.RestoreID)
	if result.KeyCount > 0 {
		logInfof("key count: %d", result.KeyCount)
	}
	return nil
}

func printRecoveredReview(review protocol.ReviewRecoveredResultMessage) {
	logInfof("destination approval mode: %s", review.DestinationApprovalMode)
	if review.UnattendedSigningWarning != "" {
		logWarnf("%s", review.UnattendedSigningWarning)
	}
	logInfof("policy comparison: %s", review.PolicyComparison)
	fmt.Print(formatRecoveredReviewSections(review))
	for _, conflict := range review.ActiveConflicts {
		logWarnf("active conflict: %s (%s, %s)", conflict.Selector, conflict.Category, conflict.KeyType)
	}
}

func formatRecoveredReviewSections(review protocol.ReviewRecoveredResultMessage) string {
	var sb strings.Builder
	sb.WriteString("Policy differences (informational)\n")
	if review.PolicyComparison == string(policy.RestoreComparisonUnavailable) {
		// An empty change list here means "could not compare", never "no
		// differences" — rendering "none" would read as an all-clear the
		// comparison never established.
		sb.WriteString("  comparison unavailable: the source policy could not be compared\n")
	} else if len(review.SecurityChanges) == 0 {
		sb.WriteString("  none\n")
	}
	for _, change := range review.SecurityChanges {
		scope := change.Selector
		if scope == "" {
			scope = "default"
		}
		fmt.Fprintf(&sb, "  [%s] %s %s: %s -> %s\n",
			change.Category,
			scope,
			change.Path,
			change.Source,
			change.Destination,
		)
	}
	var batchUnknowns []string
	for _, unknown := range review.UnknownSourceSettings {
		if protocol.IsRecoveryArchiveSourceLimitation(unknown) {
			continue
		}
		batchUnknowns = append(batchUnknowns, unknown)
	}
	if len(batchUnknowns) > 0 {
		sb.WriteString("\nSource metadata unavailable for this archive\n")
	}
	for _, unknown := range batchUnknowns {
		fmt.Fprintf(&sb, "  [unknown source] %s\n", unknown)
	}
	appendRecoveredSourceContext(&sb, review)
	return sb.String()
}

// appendRecoveredSourceContext renders what the archive reported about its
// source node, under a heading that names the provenance.
//
// It deliberately says nothing when the archive reports nothing. That backups
// are unsigned, and that archive-reported context therefore governs nothing,
// holds for every restore; USER_STORE_MGMT.md carries the explanation rather
// than repeating it on each review.
func appendRecoveredSourceContext(sb *strings.Builder, review protocol.ReviewRecoveredResultMessage) {
	switch review.SourceSettingsStatus {
	case protocol.RecoverySourceSettingsStatusUnverified:
		sb.WriteString("\nReported by the backup archive\n")
		fmt.Fprintf(sb, "  approval default: %s\n", recoveredSourceApprovalLabel(review.SourceUserAutoApprove))
		if len(review.SourceGenesisHashMappings) == 0 {
			sb.WriteString("  custom genesis-hash mappings: none\n")
		} else {
			sb.WriteString("  custom genesis-hash mappings:\n")
			for _, mapping := range review.SourceGenesisHashMappings {
				fmt.Fprintf(sb, "    %s: %s\n", mapping.Network, mapping.GenesisHash)
			}
		}
	case protocol.RecoverySourceSettingsStatusInvalid:
		warning := review.SourceSettingsWarning
		if warning == "" {
			warning = "Archive source-settings metadata is invalid."
		}
		fmt.Fprintf(sb, "\n%s\n", warning)
	}
}

func recoveredSourceApprovalLabel(value *bool) string {
	if value == nil {
		return "not applicable"
	}
	if *value {
		return "auto approve"
	}
	return "manual review"
}

func requestRestorePreview(client apstoreAdminRequester, name string, exportPassphrase []byte) (protocol.RestorePreviewMessage, error) {
	var result protocol.RestorePreviewMessage
	err := client.request(protocol.PreviewRestoreMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypePreviewRestore, ID: newApstoreRequestID("restore-preview")},
		ArchivePath:      name,
		ExportPassphrase: protocol.SensitiveBytes(exportPassphrase),
	}, &result)
	return result, err
}

func renderRestorePreviewResult(result protocol.RestorePreviewMessage) error {
	if result.Error != "" || len(result.Errors) > 0 {
		printRestorePreview(result)
		if result.Error != "" {
			return resultError("restore preview failed", result.Code, result.Error)
		}
		return fmt.Errorf("restore preview found %d error(s)", len(result.Errors))
	}
	printRestorePreview(result)
	return nil
}

func promptPassphrase(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	passphrase, err := readPassword()
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}
	fmt.Println()
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase cannot be empty")
	}
	return passphrase, nil
}

func printRestorePreview(result protocol.RestorePreviewMessage) {
	if result.ArchivePath != "" {
		logInfof("restore preview: %s", result.ArchivePath)
	}
	for _, key := range result.Keys {
		status := "new"
		if key.AlreadyExists {
			status = "exists"
		}
		if key.Error != "" {
			status = "error: " + key.Error
		}
		parts := []string{key.Address}
		if key.KeyType != "" {
			parts = append(parts, displayKeyType(key.KeyType))
		}
		parts = append(parts, status)
		fmt.Printf("  %s\n", strings.Join(parts, "  "))
	}
	for _, item := range result.Errors {
		if item.Address != "" {
			logErrorf("%s: %s", item.Address, item.Error)
		} else {
			logErrorf("%s", item.Error)
		}
	}
}
