// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/witness"
)

const maxSentryPublicEnvelopeBytes = 64 * 1024

func cmdSentry(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apstore sentry <export|import|list|show|remove>")
	}
	switch args[0] {
	case "export":
		return cmdSentryExport(args[1:])
	case "import":
		if len(args) != 3 {
			return fmt.Errorf("usage: apstore sentry import <export-json> <name>")
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
		return fmt.Errorf("usage: apstore sentry <export|import|list|show|remove>")
	}
}

func cmdSentryExport(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return fmt.Errorf("usage: apstore sentry export <sentry-key-id> [output-json]")
	}
	componentKey, err := witness.NormalizeID(args[0])
	if err != nil {
		return fmt.Errorf("invalid Witness Key ID: %w", err)
	}

	client, err := newApstoreReadOnlyAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()
	result, err := requestInspectionWithRetry(client, func() any {
		return protocol.ExportSentryPublicMessage{
			BaseMessage:  protocol.BaseMessage{Type: protocol.MsgTypeExportSentryPublic, ID: newApstoreRequestID("sentry-export")},
			WitnessKeyID: componentKey,
		}
	}, func(result *protocol.ExportSentryPublicResultMessage) string { return result.Code })
	if err != nil {
		return err
	}
	if !result.Success {
		return codedError{code: result.Code, message: result.Error}
	}
	data := []byte(result.EnvelopeJSON)

	if len(args) == 1 {
		_, err := os.Stdout.Write(data)
		return err
	}
	outputPath := args[1]
	if outputPath == "" {
		return fmt.Errorf("output path is required")
	}
	if err := fsutil.WriteFileDurableWithProfile(outputPath, data, fsutil.PrivateStoreFileProfile); err != nil {
		return fmt.Errorf("failed to write public key envelope: %w", err)
	}
	logInfof("sentry public key envelope written: %s", outputPath)
	return nil
}

func cmdSentryImport(path, name string) error {
	data, _, err := fsutil.ReadRegularFileLimited(path, maxSentryPublicEnvelopeBytes)
	if err != nil {
		return fmt.Errorf("failed to read sentry public key export: %w", err)
	}
	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()
	var result protocol.ImportSentryReferenceResultMessage
	if err := client.request(protocol.ImportSentryReferenceMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeImportSentryReference, ID: newApstoreRequestID("sentry-import")},
		Name:        name, EnvelopeJSON: string(data),
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return codedError{code: result.Code, message: result.Error}
	}
	logInfof("sentry reference %s imported for %s", result.Reference.Name, result.Reference.KeyType)
	return nil
}

func cmdSentryList() error {
	client, err := newApstoreReadOnlyAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()
	result, err := requestInspectionWithRetry(client, func() any {
		return protocol.ListSentryReferencesMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListSentryReferences, ID: newApstoreRequestID("sentry-list")},
		}
	}, func(result *protocol.SentryReferencesListMessage) string { return result.Code })
	if err != nil {
		return err
	}
	if result.Error != "" {
		return codedError{code: result.Code, message: result.Error}
	}
	if len(result.References) == 0 {
		logInfof("no sentry references found")
		return nil
	}
	logInfof("found %d sentry reference(s)", len(result.References))
	for _, rec := range result.References {
		fmt.Printf("  %s  (%s, %s)\n", rec.ComponentKey, rec.KeyType, sentryReferenceListLabel(rec))
	}
	return nil
}

func sentryReferenceListLabel(rec protocol.SentryReferenceInfo) string {
	if rec.Source == "client_discovery" {
		if rec.EndpointAlias != "" {
			return "endpoint: " + rec.EndpointAlias
		}
		return "source: " + rec.Source
	}
	if rec.Name != "" {
		return "name: " + rec.Name
	}
	if rec.Source != "" {
		return "source: " + rec.Source
	}
	return "source: unknown"
}

func cmdSentryShow(name string) error {
	client, err := newApstoreReadOnlyAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()
	result, err := requestInspectionWithRetry(client, func() any {
		return protocol.GetSentryReferenceMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeGetSentryReference, ID: newApstoreRequestID("sentry-show")},
			Name:        name,
		}
	}, func(result *protocol.SentryReferenceMessage) string { return result.Code })
	if err != nil {
		return err
	}
	if !result.Success {
		return codedError{code: result.Code, message: result.Error}
	}
	data, err := json.MarshalIndent(result.Reference, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode sentry reference: %w", err)
	}
	data = append(data, '\n')
	_, err = os.Stdout.Write(data)
	return err
}

func cmdSentryRemove(name string) error {
	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()
	var result protocol.RemoveSentryReferenceResultMessage
	if err := client.request(protocol.RemoveSentryReferenceMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRemoveSentryReference, ID: newApstoreRequestID("sentry-remove")},
		Name:        name,
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return codedError{code: result.Code, message: result.Error}
	}
	if result.Removed {
		logInfof("sentry reference %s removed", name)
	} else {
		logInfof("sentry reference %s was already absent", name)
	}
	return nil
}
