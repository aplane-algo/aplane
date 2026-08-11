// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/protocol"
)

const applyUsage = "usage: apstore restore apply <backup-id|name> [--address ADDRESS ...] [--replace-existing]"

func cmdRestoreManaged(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apstore restore <preview|apply|rollback|reconcile>")
	}
	switch args[0] {
	case "preview":
		if len(args) != 2 {
			return fmt.Errorf("usage: apstore restore preview <backup-id|name>")
		}
		return cmdRestorePreviewManaged(args[1])
	case "apply":
		return cmdRestoreApplyManaged(args[1:])
	case "rollback":
		if len(args) != 1 {
			return fmt.Errorf("usage: apstore restore rollback")
		}
		return cmdRestoreRollback()
	case "reconcile":
		if len(args) != 1 {
			return fmt.Errorf("usage: apstore restore reconcile")
		}
		return cmdRestoreReconcile()
	default:
		return fmt.Errorf("usage: apstore restore <preview|apply|rollback|reconcile>")
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
	replaceExisting := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--replace-existing":
			replaceExisting = true
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

	logInfof("restored credentials will use the destination's current policy and configuration")
	var result protocol.RestoreBackupResultMessage
	err = client.request(protocol.RestoreBackupMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypeRestoreBackup, ID: newApstoreRequestID("restore")},
		ArchivePath:      name,
		Addresses:        addresses,
		ExportPassphrase: protocol.SensitiveBytes(exportPassphrase),
		ReplaceExisting:  replaceExisting,
	}, &result)
	if err != nil {
		return err
	}
	if !result.Success {
		for _, conflict := range result.Conflicts {
			logWarnf("credential conflict: %s (%s, %s): %s", conflict.Selector, conflict.Category, conflict.KeyType, conflict.Reason)
		}
		return resultError("credential restore failed", result.Code, result.Error)
	}
	logInfof("restored %d credential(s); %d already identical", len(result.Restored), len(result.Identical))
	if result.GenerationID != "" {
		logInfof("generation: %s", result.GenerationID)
	}
	return nil
}

func cmdRestoreRollback() error {
	if !confirmYesNo("Roll back the latest clean credential restore?") {
		return fmt.Errorf("rollback cancelled")
	}
	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()
	var result protocol.RollbackRestoreResultMessage
	if err := client.request(protocol.RollbackRestoreMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRollbackRestore, ID: newApstoreRequestID("restore-rollback")},
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("credential restore rollback failed", result.Code, result.Error)
	}
	logInfof("rolled back latest credential restore into generation %s", result.GenerationID)
	return nil
}

func cmdRestoreReconcile() error {
	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()
	var result protocol.ReconcileStoreResultMessage
	if err := client.request(protocol.ReconcileStoreMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeReconcileStore, ID: newApstoreRequestID("store-reconcile")},
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("store reconciliation failed", result.Code, result.Error)
	}
	logInfof("store reconciled: generation %s, state %s", result.GenerationID, result.State)
	return nil
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
	_, _ = fmt.Fprint(backupPassphrasePromptOutput, prompt)
	passphrase, err := readPassword()
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}
	_, _ = fmt.Fprintln(backupPassphrasePromptOutput)
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

// formatArchiveTime renders an archive's packaging time from the sealed
// manifest. UTC keeps it comparable against a backup inventory taken on
// another host.
func formatArchiveTime(unix int64) string {
	if unix <= 0 {
		return "unknown"
	}
	return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04:05 UTC")
}
