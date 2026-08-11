// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestCmdEndpointExportStdout(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, _ []byte) {
		withEndpointExportSettings(t, endpointExportSettings{})
		out, err := withCapturedStdout(func() error {
			return cmdEndpoint([]string{
				"export",
				"--url", "ssh://127.0.0.1:2223",
				"--signer-port", "11270",
			})
		})
		if err != nil {
			t.Fatalf("cmdEndpoint(export) error = %v", err)
		}
		if strings.Contains(out, "Enter store passphrase") {
			t.Fatalf("stdout contains passphrase prompt: %q", out)
		}

		env, err := endpointrefs.Parse([]byte(out))
		if err != nil {
			t.Fatalf("endpoint envelope parse error = %v\n%s", err, out)
		}
		if strings.Contains(out, `"alias"`) ||
			strings.Contains(out, `"kind"`) ||
			strings.Contains(out, `"role"`) ||
			strings.Contains(out, `"schema_version"`) ||
			strings.Contains(out, `"sentry_public_keys"`) {
			t.Fatalf("endpoint envelope contains non-connection fields: %s", out)
		}
		if env.SignerPort != 11270 {
			t.Fatalf("SignerPort = %d, want 11270", env.SignerPort)
		}
	})
}

func TestCmdEndpointExportHostDerivesSSHURLFromConfig(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, _ []byte) {
		withEndpointExportSettings(t, endpointExportSettings{SSHPort: 2223, SignerPort: 12345})

		out, err := withCapturedStdout(func() error {
			return cmdEndpoint([]string{
				"export",
				"--host", "sentry.example",
			})
		})
		if err != nil {
			t.Fatalf("cmdEndpoint(export --host) error = %v", err)
		}
		env, err := endpointrefs.Parse([]byte(out))
		if err != nil {
			t.Fatalf("endpoint envelope parse error = %v\n%s", err, out)
		}
		if env.URL != "ssh://sentry.example:2223" {
			t.Fatalf("URL = %q, want derived ssh URL", env.URL)
		}
		if env.SignerPort != 12345 {
			t.Fatalf("SignerPort = %d, want config signer port", env.SignerPort)
		}
	})
}

func TestCmdEndpointExportURLOverridesHost(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, _ []byte) {
		withEndpointExportSettings(t, endpointExportSettings{
			SSHPort: 2223, SignerPort: 12345, AdvertiseURL: "ssh://configured.example:2223",
		})

		out, err := withCapturedStdout(func() error {
			return cmdEndpoint([]string{
				"export",
				"--host", "ignored.example",
				"--url", "ssh://explicit.example:2200",
			})
		})
		if err != nil {
			t.Fatalf("cmdEndpoint(export --url --host) error = %v", err)
		}
		env, err := endpointrefs.Parse([]byte(out))
		if err != nil {
			t.Fatalf("endpoint envelope parse error = %v\n%s", err, out)
		}
		if env.URL != "ssh://explicit.example:2200" {
			t.Fatalf("URL = %q, want explicit URL", env.URL)
		}
		if env.SignerPort != 12345 {
			t.Fatalf("SignerPort = %d, want config signer port for ssh URL", env.SignerPort)
		}
	})
}

func TestCmdEndpointExportUsesConfiguredAdvertiseURL(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, _ []byte) {
		withEndpointExportSettings(t, endpointExportSettings{
			SSHPort: 2223, SignerPort: 12345, AdvertiseURL: "ssh://configured.example:2223",
		})

		out, err := withCapturedStdout(func() error {
			return cmdEndpoint([]string{
				"export",
			})
		})
		if err != nil {
			t.Fatalf("cmdEndpoint(export) error = %v", err)
		}
		env, err := endpointrefs.Parse([]byte(out))
		if err != nil {
			t.Fatalf("endpoint envelope parse error = %v\n%s", err, out)
		}
		if env.URL != "ssh://configured.example:2223" {
			t.Fatalf("URL = %q, want configured advertise URL", env.URL)
		}
		if env.SignerPort != 12345 {
			t.Fatalf("SignerPort = %d, want config signer port for configured ssh URL", env.SignerPort)
		}
	})
}

func TestCmdEndpointExportRequiresHostURLOrConfiguredAdvertiseURL(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, _ []byte) {
		withEndpointExportSettings(t, endpointExportSettings{})

		err := cmdEndpoint([]string{
			"export",
		})
		if err == nil {
			t.Fatal("cmdEndpoint(export) error = nil, want missing advertise URL error")
		}
		if !strings.Contains(err.Error(), "endpoint.advertise_url") {
			t.Fatalf("cmdEndpoint(export) error = %v, want advertise_url guidance", err)
		}
	})
}

func TestCmdEndpointExportHostUsesDefaultPortsWhenConfigUnset(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, _ []byte) {
		withEndpointExportSettings(t, endpointExportSettings{})

		out, err := withCapturedStdout(func() error {
			return cmdEndpoint([]string{
				"export",
				"--host", "127.0.0.1",
			})
		})
		if err != nil {
			t.Fatalf("cmdEndpoint(export --host defaults) error = %v", err)
		}
		env, err := endpointrefs.Parse([]byte(out))
		if err != nil {
			t.Fatalf("endpoint envelope parse error = %v\n%s", err, out)
		}
		if env.URL != "ssh://127.0.0.1:1127" {
			t.Fatalf("URL = %q, want default SSH URL", env.URL)
		}
		if env.SignerPort != apconfig.DefaultRESTPort {
			t.Fatalf("SignerPort = %d, want default REST port", env.SignerPort)
		}
	})
}

func TestCmdEndpointExportRejectsSelfURL(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, _ []byte) {
		withEndpointExportSettings(t, endpointExportSettings{})
		err := cmdEndpoint([]string{
			"export",
			"--url", "self",
		})
		if err == nil {
			t.Fatal("cmdEndpoint(export self) error = nil, want rejection")
		}
		if !strings.Contains(err.Error(), "not allowed") {
			t.Fatalf("cmdEndpoint(export self) error = %v, want not allowed", err)
		}
	})
}

func TestCmdEndpointExportRefusesSymlinkOutput(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, _ []byte) {
		withEndpointExportSettings(t, endpointExportSettings{})
		dir := t.TempDir()
		sentinel := filepath.Join(dir, "sentinel")
		if err := os.WriteFile(sentinel, []byte("unchanged"), 0o600); err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(dir, "endpoint.json")
		if err := os.Symlink(sentinel, output); err != nil {
			t.Fatal(err)
		}
		err := cmdEndpoint([]string{"export", "--url", "ssh://127.0.0.1:2223", "--out", output})
		if err == nil || !strings.Contains(err.Error(), "refusing to replace symlink") {
			t.Fatalf("cmdEndpoint(export symlink) error = %v, want symlink rejection", err)
		}
		got, readErr := os.ReadFile(sentinel)
		if readErr != nil || string(got) != "unchanged" {
			t.Fatalf("sentinel = %q, err = %v", got, readErr)
		}
	})
}

func TestLoadEndpointExportSettingsUsesAdminIPC(t *testing.T) {
	fake := &fakeApstoreAdminRequester{requestFunc: func(msg any, out any) error {
		request, ok := msg.(protocol.GetAdminSettingsMessage)
		if !ok || request.Type != protocol.MsgTypeGetAdminSettings {
			t.Fatalf("settings request = %#v", msg)
		}
		response, ok := out.(*protocol.AdminSettingsMessage)
		if !ok {
			t.Fatalf("settings output = %T", out)
		}
		*response = protocol.AdminSettingsMessage{
			SSHPort: 2223, SignerPort: 12345, EndpointAdvertiseURL: "ssh://configured.example:2223",
		}
		return nil
	}}
	withFakeApstoreAdminClient(t, fake)
	settings, err := loadEndpointExportSettings()
	if err != nil {
		t.Fatalf("loadEndpointExportSettings() error = %v", err)
	}
	if settings.SSHPort != 2223 || settings.SignerPort != 12345 || settings.AdvertiseURL != "ssh://configured.example:2223" {
		t.Fatalf("settings = %#v", settings)
	}
	if !fake.closed {
		t.Fatal("admin IPC client was not closed")
	}
}

func withEndpointExportSettings(t *testing.T, settings endpointExportSettings) {
	t.Helper()
	previous := endpointExportSettingsForCommand
	endpointExportSettingsForCommand = func() (endpointExportSettings, error) {
		return settings, nil
	}
	t.Cleanup(func() { endpointExportSettingsForCommand = previous })
}
