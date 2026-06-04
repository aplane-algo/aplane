// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"strings"
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
)

func TestCmdEndpointsExportAttestationStdout(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, passphrase []byte) {
		result, publicKeyHex := generateTestAttestorComponentKey(t, passphrase)

		out, err := withCapturedStdout(func() error {
			return cmdEndpoints([]string{
				"export",
				"--alias", "attestor-local",
				"--role", "attestation",
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
		if env.Alias != "attestor-local" || env.Role != endpointrefs.RoleAttestation {
			t.Fatalf("envelope alias/role = %q/%q, want attestor-local/attestation", env.Alias, env.Role)
		}
		if env.SignerPort != 11270 {
			t.Fatalf("SignerPort = %d, want 11270", env.SignerPort)
		}
		if len(env.AttestorPublicKeys) != 1 {
			t.Fatalf("AttestorPublicKeys len = %d, want 1", len(env.AttestorPublicKeys))
		}
		got := env.AttestorPublicKeys[0]
		if got.ComponentKey != result.Address || got.PublicKeyHex != publicKeyHex {
			t.Fatalf("attestor key = %#v, want %s/%s", got, result.Address, publicKeyHex)
		}
	})
}

func TestCmdEndpointsExportHostDerivesSSHURLFromConfig(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, passphrase []byte) {
		config.SSH.Port = 2223
		config.SignerPort = 12345
		generateTestAttestorComponentKey(t, passphrase)

		out, err := withCapturedStdout(func() error {
			return cmdEndpoints([]string{
				"export",
				"--alias", "attestor-local",
				"--role", "attestation",
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
				"--alias", "primary",
				"--role", "signing",
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
				"--alias", "primary",
				"--role", "signing",
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

func TestCmdEndpointsExportSigningOmitsAttestorKeys(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, passphrase []byte) {
		generateTestAttestorComponentKey(t, passphrase)

		out, err := withCapturedStdout(func() error {
			return cmdEndpoints([]string{
				"export",
				"--alias", "primary",
				"--role", "signing",
				"--url", "ssh://signer.example:2222",
			})
		})
		if err != nil {
			t.Fatalf("cmdEndpoints(export signing) error = %v", err)
		}
		env, err := endpointrefs.Parse([]byte(out))
		if err != nil {
			t.Fatalf("endpoint envelope parse error = %v\n%s", err, out)
		}
		if len(env.AttestorPublicKeys) != 0 {
			t.Fatalf("AttestorPublicKeys = %#v, want empty", env.AttestorPublicKeys)
		}
	})
}

func TestCmdEndpointsExportRejectsSelfURL(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, _ []byte) {
		err := cmdEndpoints([]string{
			"export",
			"--alias", "attestor-local",
			"--role", "attestation",
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

func TestCmdEndpointsExportRequiresPublicMetadata(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, passphrase []byte) {
		result, _ := generateTestAttestorComponentKey(t, passphrase)
		if err := os.Remove(apkeys.ComponentPublicMetadataPath(keystorePaths(), productIdentityID(), result.Address)); err != nil {
			t.Fatalf("Remove(public metadata) error = %v", err)
		}

		err := cmdEndpoints([]string{
			"export",
			"--alias", "attestor-local",
			"--role", "attestation",
			"--url", "ssh://127.0.0.1:2223",
		})
		if err == nil {
			t.Fatal("cmdEndpoints(export missing metadata) error = nil, want failure")
		}
		if !strings.Contains(err.Error(), "no public attestor component metadata") {
			t.Fatalf("cmdEndpoints(export missing metadata) error = %v, want missing metadata", err)
		}
	})
}
