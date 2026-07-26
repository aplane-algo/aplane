// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/protocol"
)

const archiveSourceSettingsLimitation = "Backup archives do not record the source node's " +
	"approval default or custom genesis-hash mappings."

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
		return fmt.Errorf("usage: apstore restore apply <backup-id|name> [--address ADDRESS ...] [--overwrite]")
	}
	name := args[0]
	var addresses []string
	overwrite := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--overwrite":
			overwrite = true
		case "--address":
			if i+1 >= len(args) {
				return fmt.Errorf("usage: apstore restore apply <backup-id|name> [--address ADDRESS ...] [--overwrite]")
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
	return reviewAndActivateRecovered(client, recoveredResult.RestoreID, overwrite)
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
		return fmt.Errorf("usage: apstore restore activate <restore-id> [--replace-existing]")
	}
	restoreID := args[0]
	replaceExisting := false
	for _, arg := range args[1:] {
		if arg != "--replace-existing" {
			return fmt.Errorf("unknown restore activate option: %s", arg)
		}
		replaceExisting = true
	}
	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()
	return reviewAndActivateRecovered(client, restoreID, replaceExisting)
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

func reviewAndActivateRecovered(
	client apstoreAdminRequester,
	restoreID string,
	replaceExisting bool,
) error {
	review, err := requestRecoveredReview(client, restoreID)
	if err != nil {
		return err
	}
	printRecoveredReview(review)
	if review.State == "activation_incomplete" {
		if replaceExisting != review.ReplaceExisting {
			return fmt.Errorf("resume options must match recorded replace_existing=%t", review.ReplaceExisting)
		}
		if !confirmYesNo("Resume the exact recorded activation?") {
			return fmt.Errorf("activation resume cancelled")
		}
		return activateRecovered(client, review, review.ReplaceExisting)
	}
	if len(review.ActiveConflicts) > 0 && !replaceExisting {
		return fmt.Errorf("%d active credential conflict(s); review and retry with --replace-existing", len(review.ActiveConflicts))
	}
	if !confirmYesNo("I acknowledge the destination policy transition and want to activate?") {
		return fmt.Errorf("activation cancelled; recovered batch %s remains inactive", restoreID)
	}
	unattendedAck := false
	if review.DestinationApprovalMode == string("auto_approve_fallback") {
		if !confirmYesNo("I acknowledge this identity can sign unattended?") {
			return fmt.Errorf("activation cancelled; recovered batch %s remains inactive", restoreID)
		}
		unattendedAck = true
	}
	review.AcknowledgePolicyTransition = true
	review.AcknowledgeUnattendedSigning = unattendedAck
	return activateRecovered(client, review, replaceExisting)
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
		AcknowledgePolicyTransition:  review.AcknowledgePolicyTransition,
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
	logInfof("recovery state: %s", review.State)
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
	sb.WriteString("Security-bearing policy differences\n")
	if len(review.SecurityChanges) == 0 {
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
		sb.WriteString("\n")
		sb.WriteString("Source metadata unavailable for this archive\n")
	}
	for _, unknown := range batchUnknowns {
		fmt.Fprintf(&sb, "  [unknown source] %s\n", unknown)
	}
	appendRecoveredSourceContext(&sb, review)
	return sb.String()
}

func appendRecoveredSourceContext(
	sb *strings.Builder,
	review protocol.ReviewRecoveredResultMessage,
) {
	switch review.SourceSettingsStatus {
	case protocol.RecoverySourceSettingsStatusUnverified:
		sb.WriteString("\n")
		sb.WriteString("Unverified archive-reported source context\n")
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
		sb.WriteString("\n")
		if review.SourceSettingsWarning == "" {
			sb.WriteString("WARNING: archive source-settings metadata is invalid.\n")
		} else {
			fmt.Fprintf(sb, "WARNING: %s\n", review.SourceSettingsWarning)
		}
		sb.WriteString(archiveSourceSettingsLimitation)
		sb.WriteString("\n")
	default:
		sb.WriteString("\n")
		sb.WriteString(archiveSourceSettingsLimitation)
		sb.WriteString("\n")
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
