// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/attestor/attrefs"
	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
)

func cmdSentry(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apstore sentry <export-public|import-public|list|show|remove>")
	}
	switch args[0] {
	case "export-public":
		return cmdSentryExportPublic(args[1:])
	case "import-public":
		if len(args) != 3 {
			return fmt.Errorf("usage: apstore sentry import-public <export-json> <name>")
		}
		return cmdSentryImport(args[1], args[2])
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("usage: apstore sentry list")
		}
		return cmdSentryList()
	case "show":
		if len(args) != 2 {
			return fmt.Errorf("usage: apstore sentry show <name>")
		}
		return cmdSentryShow(args[1])
	case "remove":
		if len(args) != 2 {
			return fmt.Errorf("usage: apstore sentry remove <name>")
		}
		return cmdSentryRemove(args[1])
	default:
		return fmt.Errorf("usage: apstore sentry <export-public|import-public|list|show|remove>")
	}
}

func cmdSentryExportPublic(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return fmt.Errorf("usage: apstore sentry export-public <component-key> [output-json]")
	}
	componentKey, err := keytypes.NormalizeComponentKeySelector(args[0])
	if err != nil {
		return fmt.Errorf("invalid component key selector: %w", err)
	}

	envelope, ok, err := apkeys.ReadComponentPublicMetadata(keystorePaths(), productIdentityID(), componentKey)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("component public metadata for %s not found; regenerate the sentry component key or run a metadata backfill before exporting", componentKey)
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
	logInfof("sentry public key envelope written: %s", outputPath)
	return nil
}

func cmdSentryImport(path, name string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read sentry public key export: %w", err)
	}
	rec, err := attrefs.Import(keystorePaths(), productIdentityID(), name, data)
	if err != nil {
		return err
	}
	logInfof("sentry reference %s imported for %s", rec.Name, rec.KeyType)
	return nil
}

func cmdSentryList() error {
	records, err := attrefs.List(keystorePaths(), productIdentityID())
	if err != nil {
		return err
	}
	if len(records) == 0 {
		logInfof("no sentry references found")
		return nil
	}
	logInfof("found %d sentry reference(s)", len(records))
	for _, rec := range records {
		fmt.Printf("  %s  (%s, %s)\n", rec.Name, rec.KeyType, rec.ComponentKey)
	}
	return nil
}

func cmdSentryShow(name string) error {
	rec, ok, err := attrefs.Get(keystorePaths(), productIdentityID(), name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("sentry reference %q not found", name)
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode sentry reference: %w", err)
	}
	data = append(data, '\n')
	_, err = os.Stdout.Write(data)
	return err
}

func cmdSentryRemove(name string) error {
	removed, err := attrefs.Delete(keystorePaths(), productIdentityID(), name)
	if err != nil {
		return err
	}
	if removed {
		logInfof("sentry reference %s removed", name)
	} else {
		logInfof("sentry reference %s was already absent", name)
	}
	return nil
}
