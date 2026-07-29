// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package defaultkeytypes

import (
	"bytes"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/genstore"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"
	librarytemplates "github.com/aplane-algo/aplane/library/templates"
	"github.com/aplane-algo/aplane/lsig"
)

func TestInstallForNewIdentityInstallsDefaultAllowlistTemplatesForSigner(t *testing.T) {
	lsig.RegisterClient()

	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForTest(t, paths, "default")
	identityID := "default"
	masterKey := bytes.Repeat([]byte{1}, 32)

	if err := InstallForNewIdentity(paths, identityID, noderole.RoleSigner, cryptotest.Keyring(t, masterKey), nil); err != nil {
		t.Fatalf("InstallForNewIdentity() error = %v", err)
	}

	for _, keyType := range []string{Falcon1024AllowlistKeyType} {
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
		templatePath, pathErr := templatestore.GetTemplateFilePathForPaths(paths, identityID, keyType, templatestore.TemplateTypeComposed)
		if pathErr != nil {
			t.Fatalf("GetTemplateFilePathForPaths(%s) error = %v", keyType, pathErr)
		}
		installed, err := templatestore.LoadTemplateFromPath(templatePath, cryptotest.Keyring(t, masterKey))
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
	mintFirstGenerationForTest(t, paths, "default")
	masterKey := bytes.Repeat([]byte{2}, 32)

	if err := InstallForNewIdentity(paths, "default", noderole.RoleSentry, cryptotest.Keyring(t, masterKey), nil); err != nil {
		t.Fatalf("InstallForNewIdentity() error = %v", err)
	}
	if rec, ok, err := keytypestate.Get(paths, "default", Falcon1024AllowlistKeyType); err != nil {
		t.Fatalf("keytypestate.Get() error = %v", err)
	} else if ok {
		t.Fatalf("sentry role installed signer default key type: %+v", rec)
	}
}

func TestInstallForNewIdentityIsIdempotent(t *testing.T) {
	lsig.RegisterClient()

	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForTest(t, paths, "default")
	masterKey := bytes.Repeat([]byte{3}, 32)

	if err := InstallForNewIdentity(paths, "default", noderole.RoleSigner, cryptotest.Keyring(t, masterKey), nil); err != nil {
		t.Fatalf("first InstallForNewIdentity() error = %v", err)
	}
	if err := InstallForNewIdentity(paths, "default", noderole.RoleSigner, cryptotest.Keyring(t, masterKey), nil); err != nil {
		t.Fatalf("second InstallForNewIdentity() error = %v", err)
	}
	rec, ok, err := keytypestate.Get(paths, "default", Falcon1024AllowlistKeyType)
	if err != nil {
		t.Fatalf("keytypestate.Get() error = %v", err)
	}
	if !ok || strings.TrimSpace(rec.ActivatedAt) == "" {
		t.Fatalf("default state after idempotent install = %+v, present %v", rec, ok)
	}
}

func mintFirstGenerationForTest(t *testing.T, paths storepaths.Paths, identityID string) {
	t.Helper()
	generationID, err := genstore.NewGenerationID(time.Unix(1_785_200_000, 0))
	if err != nil {
		t.Fatalf("NewGenerationID: %v", err)
	}
	if _, err := genstore.Mint(paths, identityID, genstore.MintRequest{
		GenerationID:    generationID,
		FirstGeneration: true,
		Operation:       "store-initialize",
		OperationID:     "init-" + generationID,
		CreatedAt:       time.Unix(1_785_200_000, 0),
	}); err != nil {
		t.Fatalf("Mint(first): %v", err)
	}
}
