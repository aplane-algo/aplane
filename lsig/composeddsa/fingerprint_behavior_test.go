// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/tealtemplate"
)

// fingerprintBaseConfig is a representative composed-DSA config used to probe
// the behavior-only compatibility fingerprint.
func fingerprintBaseConfig() Config {
	return Config{
		KeyType:      "aplane.falcon1024-whitelist.v1",
		BaseKeyType:  "aplane.falcon1024.v1",
		FamilyName:   "aplane.falcon1024",
		Version:      1,
		DisplayName:  "Falcon Whitelist",
		Description:  "test",
		Ops:          testOps{},
		TemplateMode: "strict",
		SaltStyle:    lsigsalt.StylePushbytes,
		TEALSuffix:   "$owner_const\nlen\nint 32\n==\nassert\nint 1\nreturn\n",
		TemplateVars: []tealtemplate.TemplateVariable{{
			Name:      "owner_const",
			Source:    tealtemplate.SourceParameter,
			Parameter: "owner",
			Type:      "address",
			Constant:  tealtemplate.ConstantByte,
		}},
		Params: []lsigprovider.ParameterDef{
			{Name: "owner", Type: "address", Required: true},
		},
		RuntimeArgs: []lsigprovider.RuntimeArgDef{
			{Name: "preimage", Type: "bytes", Required: true, ByteLength: 32},
		},
	}
}

func TestComposedFingerprintCarriesVersionPrefix(t *testing.T) {
	got := NewComposedDSA(fingerprintBaseConfig()).CompatibilityFingerprint()
	if !strings.HasPrefix(got, "1:") {
		t.Fatalf("CompatibilityFingerprint() = %q, want a \"1:\" prefix", got)
	}
}

// TestComposedFingerprintIdentityRenameStable proves identity/display fields are
// excluded from the fingerprint: renaming key_type/family/version/display does
// not change the hash. This is the guard that no identity field leaks into the
// canonical spec.
func TestComposedFingerprintIdentityRenameStable(t *testing.T) {
	base := NewComposedDSA(fingerprintBaseConfig()).CompatibilityFingerprint()

	renamed := fingerprintBaseConfig()
	renamed.KeyType = "aplane.totally-renamed-whitelist.v9"
	renamed.FamilyName = "aplane.renamed-family"
	renamed.Version = 42
	renamed.DisplayName = "A Different Display Name"
	renamed.Description = "A different description entirely"

	if got := NewComposedDSA(renamed).CompatibilityFingerprint(); got != base {
		t.Fatalf("identity rename changed the fingerprint: %q != %q", got, base)
	}
}

// TestComposedFingerprintBaseRenameStable proves the base_primitive projection
// makes the fingerprint stable across pure base-identifier renames: two raw base
// key types that project to the same token produce the same fingerprint.
func TestComposedFingerprintBaseRenameStable(t *testing.T) {
	a := fingerprintBaseConfig()
	a.BaseKeyType = "custom.base.v1"
	b := fingerprintBaseConfig()
	b.BaseKeyType = "  CUSTOM.BASE.V1  " // same primitive, different spelling

	fa := NewComposedDSA(a).CompatibilityFingerprint()
	fb := NewComposedDSA(b).CompatibilityFingerprint()
	if fa != fb {
		t.Fatalf("base rename changed the fingerprint: %q != %q", fa, fb)
	}
}

// TestComposedFingerprintBehaviorSensitive proves each behavior-bearing field
// changes the fingerprint.
func TestComposedFingerprintBehaviorSensitive(t *testing.T) {
	base := NewComposedDSA(fingerprintBaseConfig()).CompatibilityFingerprint()

	mutate := func(name string, fn func(c *Config)) {
		cfg := fingerprintBaseConfig()
		fn(&cfg)
		if got := NewComposedDSA(cfg).CompatibilityFingerprint(); got == base {
			t.Fatalf("%s did not change the fingerprint", name)
		}
	}

	mutate("base_primitive token", func(c *Config) { c.BaseKeyType = "aplane.ed25519.v1" })
	mutate("teal suffix", func(c *Config) { c.TEALSuffix = "int 1\nreturn\n" })
	mutate("salt style", func(c *Config) { c.SaltStyle = lsigsalt.StyleTrailingBytecblock })
	mutate("template mode", func(c *Config) { c.TemplateMode = "generated"; c.TemplateVars = nil })
	mutate("template variables", func(c *Config) {
		c.TemplateVars = append(c.TemplateVars, tealtemplate.TemplateVariable{
			Name: "extra", Source: tealtemplate.SourceParameter, Parameter: "owner", Type: "address", Constant: tealtemplate.ConstantByte,
		})
	})
	mutate("parameters", func(c *Config) {
		c.Params = append(c.Params, lsigprovider.ParameterDef{Name: "extra", Type: "uint64"})
	})
	mutate("runtime args", func(c *Config) {
		c.RuntimeArgs = append(c.RuntimeArgs, lsigprovider.RuntimeArgDef{Name: "extra", Type: "string"})
	})
}
