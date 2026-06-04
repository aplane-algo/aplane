// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keymgmt"
)

func cmdKey(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apstore key <export-public>")
	}
	switch args[0] {
	case "export-public":
		return cmdKeyExportPublic(args[1:])
	default:
		return fmt.Errorf("usage: apstore key <export-public>")
	}
}

func cmdKeyExportPublic(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return fmt.Errorf("usage: apstore key export-public <component-key> [output-json]")
	}
	componentKey, err := keytypes.NormalizeComponentKeySelector(args[0])
	if err != nil {
		return fmt.Errorf("invalid component key selector: %w", err)
	}

	masterKey, err := readStoreMasterKey()
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(masterKey)

	keyFile := keystorePaths().KeyFilePath(productIdentityID(), componentKey)
	info, err := keymgmt.DetectKeyInfoFromFileWithMasterKey(keyFile, masterKey)
	if err != nil {
		return fmt.Errorf("failed to read key file %s: %w", keyFile, err)
	}
	envelope, err := keymgmt.BuildAttestorPublicKeyExport(componentKey, info)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode public key envelope: %w", err)
	}
	data = append(data, '\n')

	if len(args) == 1 {
		_, err := os.Stdout.Write(data)
		return err
	}
	outputPath := args[1]
	if outputPath == "" {
		return fmt.Errorf("output path is required")
	}
	if err := os.WriteFile(outputPath, data, 0o600); err != nil {
		return fmt.Errorf("failed to write public key envelope: %w", err)
	}
	logInfof("attestor public key envelope written: %s", outputPath)
	return nil
}
