// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"strings"
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
)

func TestCmdEndpointExportStdout(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, _ []byte) {
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
		config.SSH.Port = 2223
		config.SignerPort = 12345

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
		config.SSH.Port = 2223
		config.SignerPort = 12345

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

func TestCmdEndpointExportHostUsesDefaultPortsWhenConfigUnset(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, _ []byte) {
		config.SSH.Port = 0
		config.SignerPort = 0

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
