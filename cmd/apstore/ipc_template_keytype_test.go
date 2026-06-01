// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestCmdShowTemplateRequiresSensitiveFlag(t *testing.T) {
	err := cmdShowTemplate("example-template-v1", false)
	if err == nil {
		t.Fatal("cmdShowTemplate() error = nil, want sensitive flag refusal")
	}
	if !strings.Contains(err.Error(), "--show-sensitive-template") {
		t.Fatalf("cmdShowTemplate() error = %v, want sensitive flag context", err)
	}
}

func TestCmdTemplateShowRequiresSensitiveFlag(t *testing.T) {
	err := cmdTemplate([]string{"show", "example-template-v1"})
	if err == nil {
		t.Fatal("cmdTemplate(show) error = nil, want usage error")
	}
	if !strings.Contains(err.Error(), "--show-sensitive-template") {
		t.Fatalf("cmdTemplate(show) error = %v, want sensitive flag context", err)
	}
}

func TestCmdTemplateListUsesIPC(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		installedTemplatesResult: protocol.InstalledTemplatesMessage{
			Templates: []protocol.InstalledTemplateInfo{
				{
					KeyType:      "escrow-v1",
					TemplateType: "generic",
					Size:         123,
					Enabled:      true,
				},
				{
					KeyType:      "falcon-escrow-v1",
					TemplateType: "composed",
					Size:         456,
					Enabled:      false,
				},
			},
		},
	}
	withFakeApstoreAdminClient(t, fake)

	output, err := withCapturedStdout(func() error {
		return cmdTemplate([]string{"list"})
	})
	if err != nil {
		t.Fatalf("cmdTemplate(list) error = %v", err)
	}
	if len(fake.requests) != 1 || fake.requests[0] != protocol.MsgTypeListInstalledTemplates {
		t.Fatalf("requests = %v, want list_installed_templates", fake.requests)
	}
	for _, want := range []string{
		"escrow-v1",
		"generic",
		"enabled",
		"falcon-escrow-v1",
		"composed",
		"disabled",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("template list output = %q, want %q", output, want)
		}
	}
	if !fake.closed {
		t.Fatal("admin client was not closed")
	}
}

func TestCmdTemplateShowUsesIPC(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		showTemplateResult: protocol.ShowInstalledTemplateResultMessage{
			Success:      true,
			KeyType:      "escrow-v1",
			TemplateType: "generic",
			TemplateYAML: protocol.SensitiveBytes("schema_version: 1\n"),
		},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := cmdTemplate([]string{"show", "escrow-v1", "--show-sensitive-template"}); err != nil {
		t.Fatalf("cmdTemplate(show) error = %v", err)
	}
	if len(fake.requests) != 1 || fake.requests[0] != protocol.MsgTypeShowInstalledTemplate {
		t.Fatalf("requests = %v, want show_installed_template", fake.requests)
	}
	if fake.showTemplateRequest.KeyType != "escrow-v1" {
		t.Fatalf("show key type = %q, want escrow-v1", fake.showTemplateRequest.KeyType)
	}
	if !fake.closed {
		t.Fatal("admin client was not closed")
	}
}

func TestCmdTemplateShowCanonicalizesDefaultPublisherAlias(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		showTemplateResult: protocol.ShowInstalledTemplateResultMessage{
			Success:      true,
			KeyType:      "aplane.whitelist.v1",
			TemplateType: "generic",
			TemplateYAML: protocol.SensitiveBytes("schema_version: 1\n"),
		},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := cmdTemplate([]string{"show", "whitelist.v1", "--show-sensitive-template"}); err != nil {
		t.Fatalf("cmdTemplate(show alias) error = %v", err)
	}
	if fake.showTemplateRequest.KeyType != "aplane.whitelist.v1" {
		t.Fatalf("show key type = %q, want aplane.whitelist.v1", fake.showTemplateRequest.KeyType)
	}
}

func TestCmdTemplateImportUsesIPC(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "template.yaml")
	templateYAML := []byte("schema_version: 1\nfamily: escrow\nversion: 1\n")
	if err := os.WriteFile(templatePath, templateYAML, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	fake := &fakeApstoreAdminRequester{
		importTemplateResult: protocol.ImportInstalledTemplateResultMessage{
			Success:      true,
			KeyType:      "escrow-v1",
			TemplateType: "generic",
		},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := cmdTemplate([]string{"import", templatePath}); err != nil {
		t.Fatalf("cmdTemplate(import) error = %v", err)
	}
	if len(fake.requests) != 1 || fake.requests[0] != protocol.MsgTypeImportInstalledTemplate {
		t.Fatalf("requests = %v, want import_installed_template", fake.requests)
	}
	if string(fake.importTemplateRequest.TemplateYAML) != string(templateYAML) {
		t.Fatalf("imported YAML = %q, want %q", string(fake.importTemplateRequest.TemplateYAML), string(templateYAML))
	}
	if !fake.closed {
		t.Fatal("admin client was not closed")
	}
}

func TestCmdTemplateImportReportsIPCFailure(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "template.yaml")
	if err := os.WriteFile(templatePath, []byte("not: a valid template\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	fake := &fakeApstoreAdminRequester{
		importTemplateResult: protocol.ImportInstalledTemplateResultMessage{
			Success: false,
			Code:    "invalid_template",
			Error:   "missing template_type",
		},
	}
	withFakeApstoreAdminClient(t, fake)

	err := cmdTemplate([]string{"import", templatePath})
	if err == nil {
		t.Fatal("cmdTemplate(import) error = nil, want invalid template failure")
	}
	if !strings.Contains(err.Error(), "missing template_type") {
		t.Fatalf("cmdTemplate(import) error = %v, want invalid template context", err)
	}
	if len(fake.requests) != 1 || fake.requests[0] != protocol.MsgTypeImportInstalledTemplate {
		t.Fatalf("requests = %v, want import_installed_template", fake.requests)
	}
}

func TestCmdTemplateImportAllowsAlreadyInstalledTemplate(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "template.yaml")
	templateYAML := []byte("schema_version: 1\nfamily: escrow\nversion: 1\n")
	if err := os.WriteFile(templatePath, templateYAML, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	fake := &fakeApstoreAdminRequester{
		importTemplateResult: protocol.ImportInstalledTemplateResultMessage{
			Success:       true,
			KeyType:       "escrow-v1",
			TemplateType:  "generic",
			AlreadyExists: true,
		},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := cmdTemplate([]string{"import", templatePath}); err != nil {
		t.Fatalf("cmdTemplate(import existing) error = %v", err)
	}
	if string(fake.importTemplateRequest.TemplateYAML) != string(templateYAML) {
		t.Fatalf("imported YAML = %q, want %q", string(fake.importTemplateRequest.TemplateYAML), string(templateYAML))
	}
}

func TestCmdTemplateRemoveUsesIPC(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		removeTemplateResult: protocol.RemoveInstalledTemplateResultMessage{
			Success: true,
			KeyType: "escrow-v1",
			Removed: true,
		},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := withTestStdin("y\n", func() error {
		return cmdTemplate([]string{"remove", "escrow-v1"})
	}); err != nil {
		t.Fatalf("cmdTemplate(remove) error = %v", err)
	}
	if len(fake.requests) != 1 || fake.requests[0] != protocol.MsgTypeRemoveInstalledTemplate {
		t.Fatalf("requests = %v, want remove_installed_template", fake.requests)
	}
	if fake.removeTemplateRequest.KeyType != "escrow-v1" {
		t.Fatalf("remove key type = %q, want escrow-v1", fake.removeTemplateRequest.KeyType)
	}
	if !fake.closed {
		t.Fatal("admin client was not closed")
	}
}

func TestCmdTemplateRemoveCanonicalizesDefaultPublisherAlias(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		removeTemplateResult: protocol.RemoveInstalledTemplateResultMessage{
			Success: true,
			KeyType: "aplane.whitelist.v1",
			Removed: true,
		},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := withTestStdin("y\n", func() error {
		return cmdTemplate([]string{"remove", "whitelist.v1"})
	}); err != nil {
		t.Fatalf("cmdTemplate(remove alias) error = %v", err)
	}
	if fake.removeTemplateRequest.KeyType != "aplane.whitelist.v1" {
		t.Fatalf("remove key type = %q, want aplane.whitelist.v1", fake.removeTemplateRequest.KeyType)
	}
}

func TestCmdTemplateRemoveHandlesAlreadyAbsentResult(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		removeTemplateResult: protocol.RemoveInstalledTemplateResultMessage{
			Success: true,
			KeyType: "escrow-v1",
			Removed: false,
		},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := withTestStdin("y\n", func() error {
		return cmdTemplate([]string{"remove", "escrow-v1"})
	}); err != nil {
		t.Fatalf("cmdTemplate(remove absent) error = %v", err)
	}
	if len(fake.requests) != 1 || fake.requests[0] != protocol.MsgTypeRemoveInstalledTemplate {
		t.Fatalf("requests = %v, want remove_installed_template", fake.requests)
	}
}

func TestCmdTemplateRemoveCancelledBeforeIPC(t *testing.T) {
	fake := &fakeApstoreAdminRequester{}
	withFakeApstoreAdminClient(t, fake)

	err := withTestStdin("n\n", func() error {
		return cmdTemplate([]string{"remove", "escrow-v1"})
	})
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("cmdTemplate(remove) error = %v, want cancellation", err)
	}
	if len(fake.requests) != 0 {
		t.Fatalf("requests = %v, want none", fake.requests)
	}
}

func TestCmdKeyTypeActivateUsesIPC(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		activateResult: protocol.ActivateKeyTypeResultMessage{
			Success: true,
			KeyType: "aplane.ecdsak1.v1",
		},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := cmdKeyType([]string{"activate", "aplane.ecdsak1.v1"}); err != nil {
		t.Fatalf("cmdKeyType(activate) error = %v", err)
	}
	if len(fake.requests) != 1 || fake.requests[0] != protocol.MsgTypeActivateKeyType {
		t.Fatalf("requests = %v, want activate_keytype", fake.requests)
	}
	if fake.activateRequest.KeyType != "aplane.ecdsak1.v1" {
		t.Fatalf("activate key type = %q, want aplane.ecdsak1.v1", fake.activateRequest.KeyType)
	}
	if !fake.closed {
		t.Fatal("admin client was not closed")
	}
}

func TestCmdKeyTypeActivateCanonicalizesDefaultPublisherAlias(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		activateResult: protocol.ActivateKeyTypeResultMessage{
			Success: true,
			KeyType: "aplane.ecdsak1.v1",
		},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := cmdKeyType([]string{"activate", "ecdsak1.v1"}); err != nil {
		t.Fatalf("cmdKeyType(activate alias) error = %v", err)
	}
	if fake.activateRequest.KeyType != "aplane.ecdsak1.v1" {
		t.Fatalf("activate key type = %q, want aplane.ecdsak1.v1", fake.activateRequest.KeyType)
	}
}

func TestCmdKeyTypeDeactivateUsesIPC(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		deactivateResult: protocol.DeactivateKeyTypeResultMessage{
			Success: true,
			KeyType: "aplane.ecdsak1.v1",
			Removed: true,
		},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := withTestStdin("y\n", func() error {
		return cmdKeyType([]string{"deactivate", "aplane.ecdsak1.v1"})
	}); err != nil {
		t.Fatalf("cmdKeyType(deactivate) error = %v", err)
	}
	if len(fake.requests) != 1 || fake.requests[0] != protocol.MsgTypeDeactivateKeyType {
		t.Fatalf("requests = %v, want deactivate_keytype", fake.requests)
	}
	if fake.deactivateRequest.KeyType != "aplane.ecdsak1.v1" {
		t.Fatalf("deactivate key type = %q, want aplane.ecdsak1.v1", fake.deactivateRequest.KeyType)
	}
	if !fake.closed {
		t.Fatal("admin client was not closed")
	}
}

func TestCmdKeyTypeDeactivateCanonicalizesDefaultPublisherAlias(t *testing.T) {
	fake := &fakeApstoreAdminRequester{
		deactivateResult: protocol.DeactivateKeyTypeResultMessage{
			Success: true,
			KeyType: "aplane.ecdsak1.v1",
			Removed: true,
		},
	}
	withFakeApstoreAdminClient(t, fake)

	if err := withTestStdin("y\n", func() error {
		return cmdKeyType([]string{"deactivate", "ecdsak1.v1"})
	}); err != nil {
		t.Fatalf("cmdKeyType(deactivate alias) error = %v", err)
	}
	if fake.deactivateRequest.KeyType != "aplane.ecdsak1.v1" {
		t.Fatalf("deactivate key type = %q, want aplane.ecdsak1.v1", fake.deactivateRequest.KeyType)
	}
}

func TestCmdKeyTypeDeactivateCancelledBeforeIPC(t *testing.T) {
	fake := &fakeApstoreAdminRequester{}
	withFakeApstoreAdminClient(t, fake)

	err := withTestStdin("n\n", func() error {
		return cmdKeyType([]string{"deactivate", "aplane.ecdsak1.v1"})
	})
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("cmdKeyType(deactivate) error = %v, want cancellation", err)
	}
	if len(fake.requests) != 0 {
		t.Fatalf("requests = %v, want none", fake.requests)
	}
}
