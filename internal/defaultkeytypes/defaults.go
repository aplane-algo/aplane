// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package defaultkeytypes installs identity-local key types that are enabled
// automatically for new signer stores.
package defaultkeytypes

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatelibrary"
	"github.com/aplane-algo/aplane/internal/templatestore"
	librarytemplates "github.com/aplane-algo/aplane/library/templates"
)

const Falcon1024AllowlistKeyType = "aplane.falcon1024-allowlist.v1"

type bundledTemplate struct {
	fileName     string
	keyType      string
	templateType templatestore.TemplateType
}

var signerDefaultTemplates = []bundledTemplate{
	{
		fileName:     Falcon1024AllowlistKeyType + ".yaml",
		keyType:      Falcon1024AllowlistKeyType,
		templateType: templatestore.TemplateTypeComposed,
	},
}

// InstallForNewIdentity installs key types that should be available and enabled
// immediately after a new identity store is initialized.
//
// The caller must be in an initialization or identity-mutation context and must
// have already registered built-in LogicSig providers. Sentry nodes skip signer
// account key types.
func InstallForNewIdentity(paths storepaths.Paths, identityID string, role noderole.Role, masterKey []byte, logf func(format string, args ...any)) error {
	return InstallForNewIdentityActive(paths.LegacyActivePaths(identityID), role, masterKey, logf)
}

// InstallForNewIdentityActive is InstallForNewIdentity against resolved
// active-store paths — including a staged, not-yet-published generation
// during store initialization or migration.
func InstallForNewIdentityActive(active storepaths.ActivePaths, role noderole.Role, masterKey []byte, logf func(format string, args ...any)) error {
	if role != noderole.RoleSigner {
		return nil
	}

	for _, tmpl := range signerDefaultTemplates {
		if err := installBundledTemplate(active, tmpl, masterKey); err != nil {
			return err
		}
		log(logf, "enabled default key type: %s", tmpl.keyType)
	}
	return nil
}

func installBundledTemplate(active storepaths.ActivePaths, tmpl bundledTemplate, masterKey []byte) error {
	data, err := librarytemplates.ReadFile(tmpl.fileName)
	if err != nil {
		return fmt.Errorf("failed to read bundled template %s: %w", tmpl.fileName, err)
	}
	parsed, err := templatelibrary.ParseYAMLAs(tmpl.fileName, data, tmpl.templateType)
	if err != nil {
		return fmt.Errorf("failed to parse bundled template %s: %w", tmpl.fileName, err)
	}
	if parsed.KeyType != tmpl.keyType || parsed.TemplateType != tmpl.templateType {
		return fmt.Errorf("bundled template %s declared %s (%s), want %s (%s)",
			tmpl.fileName, parsed.KeyType, parsed.TemplateType, tmpl.keyType, tmpl.templateType)
	}
	if _, err := templatelibrary.InstallParsedActive(active, parsed, masterKey); err != nil {
		return fmt.Errorf("failed to install default key type %s: %w", tmpl.keyType, err)
	}
	return nil
}

func log(logf func(format string, args ...any), format string, args ...any) {
	if logf != nil {
		logf(format, args...)
	}
}
