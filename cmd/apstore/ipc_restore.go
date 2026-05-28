// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/protocol"
)

func cmdRestoreManaged(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apstore restore <preview|apply>")
	}
	switch args[0] {
	case "preview":
		if len(args) != 2 {
			return fmt.Errorf("usage: apstore restore preview <backup-id|name>")
		}
		return cmdRestorePreviewManaged(args[1])
	case "apply":
		return cmdRestoreApplyManaged(args[1:])
	default:
		return fmt.Errorf("usage: apstore restore <preview|apply>")
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

	preview, err := requestRestorePreview(client, name, exportPassphrase)
	if err != nil {
		return err
	}
	if err := renderRestorePreviewResult(preview); err != nil {
		return err
	}
	if !confirmYesNo("Apply restore through apsigner?") {
		return fmt.Errorf("restore cancelled")
	}

	var result protocol.RestoreBackupResultMessage
	err = client.request(protocol.RestoreBackupMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypeRestoreBackup, ID: newApstoreRequestID("restore-apply")},
		ArchivePath:      name,
		Addresses:        addresses,
		Overwrite:        overwrite,
		ExportPassphrase: protocol.SensitiveBytes(exportPassphrase),
	}, &result)
	if err != nil {
		return err
	}
	printRestoreResult(result)
	if !result.Success {
		return resultError("restore failed", result.Code, result.Error)
	}
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

func printRestoreResult(result protocol.RestoreBackupResultMessage) {
	for _, key := range result.Restored {
		label := key.Address
		if key.KeyType != "" {
			label += " (" + displayKeyType(key.KeyType) + ")"
		}
		logInfof("restored: %s", label)
	}
	for _, key := range result.Skipped {
		logWarnf("skipped %s: %s", key.Address, key.Error)
	}
	for _, item := range result.Errors {
		if item.Address != "" {
			logErrorf("%s: %s", item.Address, item.Error)
		} else {
			logErrorf("%s", item.Error)
		}
	}
	for _, item := range result.Warnings {
		if item.Address != "" {
			logWarnf("%s: %s", item.Address, item.Warning)
		} else {
			logWarnf("%s", item.Warning)
		}
	}
	if result.KeyCount > 0 {
		logInfof("key count: %d", result.KeyCount)
	}
}
