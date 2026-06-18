// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package defaultkeytypes

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"
	librarytemplates "github.com/aplane-algo/aplane/library/templates"
	"github.com/aplane-algo/aplane/lsig"
)

func TestInstallForNewIdentityInstallsDefaultWhitelistTemplatesForSigner(t *testing.T) {
	lsig.RegisterClient()

	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	masterKey := bytes.Repeat([]byte{1}, 32)
	defer crypto.ZeroBytes(masterKey)

	if err := InstallForNewIdentity(paths, identityID, noderole.RoleSigner, masterKey, nil); err != nil {
		t.Fatalf("InstallForNewIdentity() error = %v", err)
	}

	for _, keyType := range []string{Falcon1024WhitelistKeyType, Ed25519WhitelistKeyType} {
		rec, ok, err := keytypestate.Get(paths, identityID, keyType)
		if err != nil {
			t.Fatalf("keytypestate.Get(%s) error = %v", keyType, err)
		}
		if !ok {
			t.Fatalf("default key type state %s missing", keyType)
		}
		if rec.Source != keytypestate.SourceYAMLComposed || rec.State != keytypestate.StateEnabled {
			t.Fatalf("%s state = (%s, %s), want (%s, %s)",
				keyType, rec.Source, rec.State, keytypestate.SourceYAMLComposed, keytypestate.StateEnabled)
		}
		if rec.Fingerprint == "" {
			t.Fatalf("default key type %s fingerprint missing", keyType)
		}
		if !templatestore.TemplateExistsForPaths(paths, identityID, keyType, templatestore.TemplateTypeComposed) {
			t.Fatalf("default template %s not installed", keyType)
		}
		installed, err := templatestore.LoadTemplateFromPath(
			templatestore.GetTemplateFilePathForPaths(paths, identityID, keyType, templatestore.TemplateTypeComposed),
			masterKey,
		)
		if err != nil {
			t.Fatalf("LoadTemplateFromPath(%s) error = %v", keyType, err)
		}
		bundled, err := librarytemplates.ReadFile(keyType + ".yaml")
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", keyType, err)
		}
		if string(installed) != string(bundled) {
			t.Fatalf("installed default template %s does not match bundled template", keyType)
		}
	}
}

func TestInstallForNewIdentitySkipsSentryRole(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	masterKey := bytes.Repeat([]byte{2}, 32)
	defer crypto.ZeroBytes(masterKey)

	if err := InstallForNewIdentity(paths, "default", noderole.RoleSentry, masterKey, nil); err != nil {
		t.Fatalf("InstallForNewIdentity() error = %v", err)
	}
	if rec, ok, err := keytypestate.Get(paths, "default", Falcon1024WhitelistKeyType); err != nil {
		t.Fatalf("keytypestate.Get() error = %v", err)
	} else if ok {
		t.Fatalf("sentry role installed signer default key type: %+v", rec)
	}
}

func TestInstallForNewIdentityIsIdempotent(t *testing.T) {
	lsig.RegisterClient()

	paths := storepaths.NewPaths(t.TempDir())
	masterKey := bytes.Repeat([]byte{3}, 32)
	defer crypto.ZeroBytes(masterKey)

	if err := InstallForNewIdentity(paths, "default", noderole.RoleSigner, masterKey, nil); err != nil {
		t.Fatalf("first InstallForNewIdentity() error = %v", err)
	}
	if err := InstallForNewIdentity(paths, "default", noderole.RoleSigner, masterKey, nil); err != nil {
		t.Fatalf("second InstallForNewIdentity() error = %v", err)
	}
	rec, ok, err := keytypestate.Get(paths, "default", Falcon1024WhitelistKeyType)
	if err != nil {
		t.Fatalf("keytypestate.Get() error = %v", err)
	}
	if !ok || strings.TrimSpace(rec.ActivatedAt) == "" {
		t.Fatalf("default state after idempotent install = %+v, present %v", rec, ok)
	}
}
