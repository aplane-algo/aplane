// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/protocol"

	"gopkg.in/yaml.v3"
)

func cmdTemplates() error {
	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()

	var result protocol.InstalledTemplatesMessage
	err = client.request(protocol.ListInstalledTemplatesMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListInstalledTemplates, ID: newApstoreRequestID("template-list")},
	}, &result)
	if err != nil {
		return err
	}
	if result.Error != "" {
		return resultError("template list failed", result.Code, result.Error)
	}
	if len(result.Templates) == 0 {
		logInfof("no installed templates found")
		return nil
	}
	logInfof("found %d installed template(s)", len(result.Templates))
	for _, item := range result.Templates {
		status := "disabled"
		if item.Enabled {
			status = "enabled"
		}
		fmt.Printf("  %s  (%s, %s, %s)\n", displayKeyType(item.KeyType), backup.FormatFileSize(item.Size), item.TemplateType, status)
	}
	return nil
}

func cmdShowTemplate(keyType string, showSensitiveTemplate bool) error {
	if !showSensitiveTemplate {
		return fmt.Errorf("refusing to show decrypted template YAML without --show-sensitive-template")
	}
	keyType = canonicalKeyType(keyType)

	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()

	var result protocol.ShowInstalledTemplateResultMessage
	err = client.request(protocol.ShowInstalledTemplateMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeShowInstalledTemplate, ID: newApstoreRequestID("template-show")},
		KeyType:     keyType,
	}, &result)
	if err != nil {
		return err
	}
	if !result.Success {
		return resultError("template show failed", result.Code, result.Error)
	}
	logInfof("template: %s (%s)", displayKeyType(result.KeyType), result.TemplateType)
	fmt.Println(string(result.TemplateYAML))
	result.TemplateYAML.Zero()
	return nil
}

func cmdImportTemplate(yamlPath string) error {
	templateYAML, err := os.ReadFile(yamlPath)
	if err != nil {
		return fmt.Errorf("failed to read template YAML: %w", err)
	}

	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()

	var result protocol.ImportInstalledTemplateResultMessage
	err = client.request(protocol.ImportInstalledTemplateMessage{
		BaseMessage:  protocol.BaseMessage{Type: protocol.MsgTypeImportInstalledTemplate, ID: newApstoreRequestID("template-import")},
		TemplateYAML: protocol.SensitiveBytes(templateYAML),
	}, &result)
	if err != nil {
		return err
	}
	if !result.Success {
		return resultError("template import failed", result.Code, result.Error)
	}
	if templateUsesDefaultOpcodeCeiling(templateYAML) {
		logWarnf(
			"template declares no max_opcode_cost; using the default single-transaction opcode ceiling (%d for every consensus version currently supported by APlane)",
			lsigresource.SingleTransactionOpcodeCeiling,
		)
	}
	if result.AlreadyExists {
		logInfof("%s template %s is already installed", result.TemplateType, displayKeyType(result.KeyType))
		return nil
	}
	logInfof("%s template %s imported", result.TemplateType, displayKeyType(result.KeyType))
	return nil
}

func templateUsesDefaultOpcodeCeiling(templateYAML []byte) bool {
	var header struct {
		MaxOpcodeCost *uint64 `yaml:"max_opcode_cost"`
	}
	return yaml.Unmarshal(templateYAML, &header) == nil && header.MaxOpcodeCost == nil
}

func cmdRemoveTemplate(keyType string) error {
	keyType = canonicalKeyType(keyType)
	if !confirmRemoveTemplate(keyType) {
		return fmt.Errorf("template removal cancelled")
	}

	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()

	var result protocol.RemoveInstalledTemplateResultMessage
	err = client.request(protocol.RemoveInstalledTemplateMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRemoveInstalledTemplate, ID: newApstoreRequestID("template-remove")},
		KeyType:     keyType,
	}, &result)
	if err != nil {
		return err
	}
	if !result.Success {
		return resultError("template remove failed", result.Code, result.Error)
	}
	if result.Removed {
		logInfof("template %s removed", displayKeyType(result.KeyType))
		return nil
	}
	logInfof("template %s was already absent", displayKeyType(result.KeyType))
	return nil
}
