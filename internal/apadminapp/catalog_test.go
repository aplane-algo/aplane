// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/protocol"
)

type fakeRequester struct {
	requests []any
	timeouts []time.Duration
	handle   func(any, any) error
}

func (f *fakeRequester) Request(message, result any) error {
	return f.RequestWithTimeout(message, result, DefaultTimeout)
}

func (f *fakeRequester) RequestWithTimeout(message, result any, timeout time.Duration) error {
	return f.requestWithTimeout(message, result, timeout)
}

func (f *fakeRequester) requestWithTimeout(message, result any, timeout time.Duration) error {
	f.requests = append(f.requests, message)
	f.timeouts = append(f.timeouts, timeout)
	if f.handle == nil {
		return nil
	}
	return f.handle(message, result)
}

func TestCatalogAuthModePinsPublicReads(t *testing.T) {
	readOnly := [][]string{
		{"sentry", "export", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"sentry", "list"},
		{"sentry", "show", "lab"},
		{"endpoint", "export", "--host", "127.0.0.1"},
		{"generations", "list"},
	}
	for _, command := range readOnly {
		mode, err := CatalogAuthMode(command[0], command[1:])
		if err != nil {
			t.Fatalf("CatalogAuthMode(%v) error = %v", command, err)
		}
		if mode != AuthReadOnly {
			t.Fatalf("CatalogAuthMode(%v) = %v, want read-only", command, mode)
		}
	}

	mutating := [][]string{
		{"template", "list"},
		{"template", "import", "template.yaml"},
		{"keytype", "enable", "aplane.ed25519.v1"},
		{"sentry", "import", "sentry.json", "lab"},
		{"sentry", "remove", "lab"},
	}
	for _, command := range mutating {
		mode, err := CatalogAuthMode(command[0], command[1:])
		if err != nil {
			t.Fatalf("CatalogAuthMode(%v) error = %v", command, err)
		}
		if mode != AuthUnlock {
			t.Fatalf("CatalogAuthMode(%v) = %v, want unlock", command, mode)
		}
	}
}

func TestCatalogAuthModeRejectsMalformedBeforeConnection(t *testing.T) {
	for _, command := range [][]string{
		{"template", "show", "example.v1"},
		{"keytype", "disable"},
		{"sentry", "import", "only.json"},
		{"endpoint", "export", "--bogus"},
		{"generations", "prune"},
	} {
		if _, err := CatalogAuthMode(command[0], command[1:]); err == nil {
			t.Fatalf("CatalogAuthMode(%v) error = nil", command)
		}
	}
}

func TestCatalogTemplateListSeparatesRowsFromStatus(t *testing.T) {
	requester := &fakeRequester{handle: func(message, result any) error {
		if _, ok := message.(protocol.ListInstalledTemplatesMessage); !ok {
			return fmt.Errorf("request = %T", message)
		}
		out := result.(*protocol.InstalledTemplatesMessage)
		out.Templates = []protocol.InstalledTemplateInfo{{KeyType: "aplane.ed25519.v1", Size: 42, TemplateType: "compiled", Enabled: true}}
		return nil
	}}
	var stdout, stderr bytes.Buffer
	err := (Catalog{Client: requester, Streams: Streams{Stdout: &stdout, Stderr: &stderr}}).Run("template", []string{"list"})
	if err != nil {
		t.Fatal(err)
	}
	if stdout.String() == "" || bytes.Contains(stdout.Bytes(), []byte("found 1")) {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if !bytes.Contains(stderr.Bytes(), []byte("found 1 installed")) {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCatalogDestructiveCommandDefaultsToCancellation(t *testing.T) {
	requester := &fakeRequester{}
	err := (Catalog{Client: requester}).Run("keytype", []string{"disable", "aplane.ed25519.v1"})
	if err == nil {
		t.Fatal("disable error = nil, want cancellation")
	}
	if len(requester.requests) != 0 {
		t.Fatalf("requests = %d, want none", len(requester.requests))
	}
}

func TestCatalogGenerationListRetriesIdentityBusy(t *testing.T) {
	now := time.Unix(100, 0)
	attempt := 0
	requester := &fakeRequester{handle: func(message, result any) error {
		if _, ok := message.(protocol.ListGenerationsMessage); !ok {
			return fmt.Errorf("request = %T", message)
		}
		attempt++
		out := result.(*protocol.GenerationsListMessage)
		if attempt == 1 {
			out.Code = protocol.ResultCodeIdentityBusy
		} else {
			out.Current = "gen-2"
		}
		return nil
	}}
	var stderr bytes.Buffer
	catalog := Catalog{
		Client: requester, Streams: Streams{Stderr: &stderr},
		Now:   func() time.Time { return now },
		Sleep: func(d time.Duration) { now = now.Add(d) },
	}
	if err := catalog.Run("generations", []string{"list"}); err != nil {
		t.Fatal(err)
	}
	if attempt != 2 || !bytes.Contains(stderr.Bytes(), []byte("current: gen-2")) {
		t.Fatalf("attempts=%d stderr=%q", attempt, stderr.String())
	}
}

func TestCatalogTemplateShowUsesCanonicalKeyTypeAndExactYAML(t *testing.T) {
	requester := &fakeRequester{handle: func(message, result any) error {
		request, ok := message.(protocol.ShowInstalledTemplateMessage)
		if !ok {
			return fmt.Errorf("request = %T", message)
		}
		if request.KeyType != "aplane.ed25519.v1" {
			return fmt.Errorf("key type = %q", request.KeyType)
		}
		out := result.(*protocol.ShowInstalledTemplateResultMessage)
		*out = protocol.ShowInstalledTemplateResultMessage{
			Success: true, KeyType: request.KeyType, TemplateType: "compiled",
			TemplateYAML: protocol.SensitiveBytes("key_type: aplane.ed25519.v1\n"),
		}
		return nil
	}}
	var stdout bytes.Buffer
	if err := (Catalog{Client: requester, Streams: Streams{Stdout: &stdout}}).Run(
		"template", []string{"show", " APLANE.Ed25519.V1 ", "--show-sensitive-template"},
	); err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); got != "key_type: aplane.ed25519.v1\n\n" {
		t.Fatalf("stdout = %q", got)
	}
}

func TestCatalogTemplateImportReadsLocalFileAndPreservesBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "template.yaml")
	want := []byte("key_type: example.template.v1\nmax_fee: 1000\n")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	requester := &fakeRequester{handle: func(message, result any) error {
		request, ok := message.(protocol.ImportInstalledTemplateMessage)
		if !ok {
			return fmt.Errorf("request = %T", message)
		}
		if !bytes.Equal(request.TemplateYAML, want) {
			return fmt.Errorf("template bytes = %q", request.TemplateYAML)
		}
		out := result.(*protocol.ImportInstalledTemplateResultMessage)
		*out = protocol.ImportInstalledTemplateResultMessage{Success: true, KeyType: "example.template.v1", TemplateType: "generic"}
		return nil
	}}
	var stderr bytes.Buffer
	if err := (Catalog{Client: requester, Streams: Streams{Stderr: &stderr}}).Run("template", []string{"import", path}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "no max_opcode_cost") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCatalogTemplateAndKeyTypeMutationsPreserveStructuredFailures(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
		result  func(any) error
		code    string
	}{
		{
			name: "template in use", command: "template", args: []string{"remove", "example.v1"}, code: protocol.ResultCodeKeyTypeInUse,
			result: func(out any) error {
				*out.(*protocol.RemoveInstalledTemplateResultMessage) = protocol.RemoveInstalledTemplateResultMessage{Success: false, Code: protocol.ResultCodeKeyTypeInUse, Error: "key still uses template"}
				return nil
			},
		},
		{
			name: "key type deactivation", command: "keytype", args: []string{"disable", "ed25519"}, code: protocol.ResultCodeDeactivationFailed,
			result: func(out any) error {
				*out.(*protocol.DeactivateKeyTypeResultMessage) = protocol.DeactivateKeyTypeResultMessage{Success: false, Code: protocol.ResultCodeDeactivationFailed, Error: "cannot disable"}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requester := &fakeRequester{handle: func(_ any, out any) error { return tt.result(out) }}
			err := (Catalog{Client: requester, Confirm: func(string) bool { return true }}).Run(tt.command, tt.args)
			if got := protocol.CodeForError(err); got != tt.code {
				t.Fatalf("error code = %q error=%v, want %q", got, err, tt.code)
			}
		})
	}
}

func TestCatalogKeyTypeEnableCanonicalizesAlias(t *testing.T) {
	requester := &fakeRequester{handle: func(message, result any) error {
		request := message.(protocol.ActivateKeyTypeMessage)
		if request.KeyType != "aplane.ed25519.v1" {
			return fmt.Errorf("key type = %q", request.KeyType)
		}
		*result.(*protocol.ActivateKeyTypeResultMessage) = protocol.ActivateKeyTypeResultMessage{Success: true, KeyType: request.KeyType}
		return nil
	}}
	if err := (Catalog{Client: requester}).Run("keytype", []string{"enable", " APLANE.Ed25519.V1 "}); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogSentryImportListShowAndRemoveRequests(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentry.json")
	if err := os.WriteFile(path, []byte(`{"schema":"aplane.sentry-public.v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	requester := &fakeRequester{handle: func(message, result any) error {
		switch request := message.(type) {
		case protocol.ImportSentryReferenceMessage:
			if request.Name != "Lab-Sentry" || !strings.Contains(request.EnvelopeJSON, "aplane.sentry-public.v1") {
				return fmt.Errorf("import = %#v", request)
			}
			*result.(*protocol.ImportSentryReferenceResultMessage) = protocol.ImportSentryReferenceResultMessage{
				Success: true, Reference: protocol.SentryReferenceInfo{Name: "lab-sentry", KeyType: "aplane.witness-falcon1024.v1"},
			}
		case protocol.ListSentryReferencesMessage:
			*result.(*protocol.SentryReferencesListMessage) = protocol.SentryReferencesListMessage{References: []protocol.SentryReferenceInfo{{Name: "lab-sentry", ComponentKey: "KEY", KeyType: "TYPE"}}}
		case protocol.GetSentryReferenceMessage:
			*result.(*protocol.SentryReferenceMessage) = protocol.SentryReferenceMessage{Success: true, Reference: protocol.SentryReferenceInfo{Name: request.Name, ComponentKey: "KEY"}}
		case protocol.RemoveSentryReferenceMessage:
			*result.(*protocol.RemoveSentryReferenceResultMessage) = protocol.RemoveSentryReferenceResultMessage{Success: true, Removed: true, Name: request.Name}
		default:
			return fmt.Errorf("request = %T", message)
		}
		return nil
	}}
	var stdout bytes.Buffer
	catalog := Catalog{Client: requester, Streams: Streams{Stdout: &stdout}}
	if err := catalog.Run("sentry", []string{"import", path, "Lab-Sentry"}); err != nil {
		t.Fatal(err)
	}
	if err := catalog.Run("sentry", []string{"list"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "KEY  (TYPE, name: lab-sentry)") {
		t.Fatalf("list stdout = %q", stdout.String())
	}
	stdout.Reset()
	if err := catalog.Run("sentry", []string{"show", "lab-sentry"}); err != nil {
		t.Fatal(err)
	}
	var shown protocol.SentryReferenceInfo
	if err := json.Unmarshal(stdout.Bytes(), &shown); err != nil || shown.Name != "lab-sentry" {
		t.Fatalf("show = %#v err=%v output=%q", shown, err, stdout.String())
	}
	if err := catalog.Run("sentry", []string{"remove", "lab-sentry"}); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogEndpointExportPrecedenceAndDefaults(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		settings   protocol.AdminSettingsMessage
		wantURL    string
		wantSigner int
		wantErr    string
	}{
		{
			name: "host uses configured ports", args: []string{"export", "--host", "signer.example"},
			settings: protocol.AdminSettingsMessage{SSHPort: 2223, SignerPort: 12345},
			wantURL:  "ssh://signer.example:2223", wantSigner: 12345,
		},
		{
			name: "explicit URL wins", args: []string{"export", "--host", "ignored.example", "--url", "https://signer.example:8443"},
			settings: protocol.AdminSettingsMessage{EndpointAdvertiseURL: "ssh://advertised:22"},
			wantURL:  "https://signer.example:8443",
		},
		{
			name: "advertised URL", args: []string{"export"},
			settings: protocol.AdminSettingsMessage{EndpointAdvertiseURL: "ssh://advertised.example:2200", SignerPort: 1111},
			wantURL:  "ssh://advertised.example:2200", wantSigner: 1111,
		},
		{
			name: "default ports", args: []string{"export", "--host", "127.0.0.1"},
			wantURL: "ssh://127.0.0.1:" + fmt.Sprint(config.DefaultSSHPort), wantSigner: config.DefaultRESTPort,
		},
		{name: "missing routing", args: []string{"export"}, wantErr: "advertise_url"},
		{name: "self rejected", args: []string{"export", "--url", "self"}, wantErr: "not allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requester := &fakeRequester{handle: func(message, result any) error {
				if _, ok := message.(protocol.GetAdminSettingsMessage); !ok {
					return fmt.Errorf("request = %T", message)
				}
				*result.(*protocol.AdminSettingsMessage) = tt.settings
				return nil
			}}
			var stdout bytes.Buffer
			err := (Catalog{Client: requester, Streams: Streams{Stdout: &stdout}}).Run("endpoint", tt.args)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var envelope endpointrefs.Envelope
			if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
				t.Fatalf("output = %q: %v", stdout.String(), err)
			}
			if envelope.URL != tt.wantURL || envelope.SignerPort != tt.wantSigner {
				t.Fatalf("envelope = %#v, want URL=%q signer=%d", envelope, tt.wantURL, tt.wantSigner)
			}
		})
	}
}

func TestCatalogEndpointExportRefusesSymlinkOutput(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target.json")
	link := filepath.Join(t.TempDir(), "endpoint.json")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	requester := &fakeRequester{handle: func(_ any, result any) error {
		*result.(*protocol.AdminSettingsMessage) = protocol.AdminSettingsMessage{EndpointAdvertiseURL: "ssh://example:22"}
		return nil
	}}
	err := (Catalog{Client: requester}).Run("endpoint", []string{"export", "--out", link})
	if err == nil {
		t.Fatal("endpoint export error = nil, want symlink refusal")
	}
	data, readErr := os.ReadFile(target)
	if readErr != nil || string(data) != "keep" {
		t.Fatalf("target = %q err=%v", data, readErr)
	}
}
