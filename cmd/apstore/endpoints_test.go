// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"strings"
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
)

func TestCmdEndpointsExportStdout(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, _ []byte) {
		out, err := withCapturedStdout(func() error {
			return cmdEndpoints([]string{
				"export",
				"--url", "ssh://127.0.0.1:2223",
				"--signer-port", "11270",
			})
		})
		if err != nil {
			t.Fatalf("cmdEndpoints(export) error = %v", err)
		}
		if strings.Contains(out, "Enter store passphrase") {
			t.Fatalf("stdout contains passphrase prompt: %q", out)
		}

		env, err := endpointrefs.Parse([]byte(out))
		if err != nil {
			t.Fatalf("endpoint envelope parse error = %v\n%s", err, out)
		}
		if strings.Contains(out, `"alias"`) || strings.Contains(out, `"role"`) || strings.Contains(out, `"attestor_public_keys"`) {
			t.Fatalf("endpoint envelope contains non-connection fields: %s", out)
		}
		if env.SignerPort != 11270 {
			t.Fatalf("SignerPort = %d, want 11270", env.SignerPort)
		}
	})
}

func TestCmdEndpointsExportHostDerivesSSHURLFromConfig(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, _ []byte) {
		config.SSH.Port = 2223
		config.SignerPort = 12345

		out, err := withCapturedStdout(func() error {
			return cmdEndpoints([]string{
				"export",
				"--host", "attestor.example",
			})
		})
		if err != nil {
			t.Fatalf("cmdEndpoints(export --host) error = %v", err)
		}
		env, err := endpointrefs.Parse([]byte(out))
		if err != nil {
			t.Fatalf("endpoint envelope parse error = %v\n%s", err, out)
		}
		if env.URL != "ssh://attestor.example:2223" {
			t.Fatalf("URL = %q, want derived ssh URL", env.URL)
		}
		if env.SignerPort != 12345 {
			t.Fatalf("SignerPort = %d, want config signer port", env.SignerPort)
		}
	})
}

func TestCmdEndpointsExportURLOverridesHost(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, _ []byte) {
		config.SSH.Port = 2223
		config.SignerPort = 12345

		out, err := withCapturedStdout(func() error {
			return cmdEndpoints([]string{
				"export",
				"--host", "ignored.example",
				"--url", "ssh://explicit.example:2200",
			})
		})
		if err != nil {
			t.Fatalf("cmdEndpoints(export --url --host) error = %v", err)
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

func TestCmdEndpointsExportHostUsesDefaultPortsWhenConfigUnset(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, _ []byte) {
		config.SSH.Port = 0
		config.SignerPort = 0

		out, err := withCapturedStdout(func() error {
			return cmdEndpoints([]string{
				"export",
				"--host", "127.0.0.1",
			})
		})
		if err != nil {
			t.Fatalf("cmdEndpoints(export --host defaults) error = %v", err)
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

func TestCmdEndpointsExportRejectsSelfURL(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, _ []byte) {
		err := cmdEndpoints([]string{
			"export",
			"--url", "self",
		})
		if err == nil {
			t.Fatal("cmdEndpoints(export self) error = nil, want rejection")
		}
		if !strings.Contains(err.Error(), "not allowed") {
			t.Fatalf("cmdEndpoints(export self) error = %v, want not allowed", err)
		}
	})
}
