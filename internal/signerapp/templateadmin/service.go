// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templateadmin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/aplane-algo/aplane/internal/crypto"
	"os"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatelibrary"
	"github.com/aplane-algo/aplane/internal/templatestore"
)

type Deps interface {
	KeyPaths() storepaths.Paths
	WithIdentityMutation(identityID string, fn func() error) error
	Logf(format string, args ...interface{})
}

type Service struct {
	Deps Deps
}

func (s Service) ListLibraryTemplates(ir *identity.Runtime) adminproto.ListLibraryTemplatesResult {
	items, err := templatelibrary.List(s.Deps.KeyPaths(), ir.ID())
	if err != nil {
		return adminproto.ListLibraryTemplatesResult{
			Code:  protocol.ResultCodeListFailed,
			Error: err.Error(),
		}
	}
	out := make([]adminproto.LibraryTemplateInfo, len(items))
	for i, item := range items {
		out[i] = adminproto.LibraryTemplateInfo{
			KeyType:      item.KeyType,
			TemplateType: item.TemplateType,
			DisplayName:  item.DisplayName,
			Description:  item.Description,
			SourcePath:   item.SourcePath,
			FileName:     item.FileName,
			Parameters:   creationParamInfos(item.Parameters),
			RuntimeArgs:  runtimeArgInfos(item.RuntimeArgs),
			Installed:    item.Installed,
			Enabled:      item.Enabled,
			Conflict:     item.Conflict,
			Invalid:      item.Invalid,
		}
	}
	return adminproto.ListLibraryTemplatesResult{Templates: out}
}

func (s Service) InstallLibraryTemplate(ir *identity.Runtime, req adminproto.InstallLibraryTemplateRequest) adminproto.InstallLibraryTemplateResult {
	keyType := keytypecatalog.Canonicalize(req.KeyType)
	templateType := templatestore.TemplateType(req.TemplateType)
	if templateType != templatestore.TemplateTypeGeneric && templateType != templatestore.TemplateTypeComposed {
		return adminproto.InstallLibraryTemplateResult{
			Success:      false,
			KeyType:      keyType,
			TemplateType: req.TemplateType,
			Code:         protocol.ResultCodeInvalidTemplateType,
			Error:        fmt.Sprintf("unsupported template type: %s", req.TemplateType),
		}
	}

	ref := templatelibrary.TemplateRef{KeyType: keyType, TemplateType: templateType}
	var installResult templatelibrary.InstallResult
	var out adminproto.InstallLibraryTemplateResult
	err := s.Deps.WithIdentityMutation(ir.ID(), func() error {
		if err := ir.WithKeyring(func(masterKey *crypto.Keyring) error {
			var installErr error
			installResult, installErr = templatelibrary.InstallFromLibrary(s.Deps.KeyPaths(), ir.ID(), ref, masterKey)
			return installErr
		}); err != nil {
			out = adminproto.InstallLibraryTemplateResult{
				Success:      false,
				KeyType:      keyType,
				TemplateType: req.TemplateType,
				Code:         protocol.ResultCodeInstallFailed,
				Error:        err.Error(),
			}
			return nil
		}

		reloadReport, reloadErr := ir.Reload()
		if reloadErr != nil {
			reloadErr = rollbackFailedTemplateInstall(s.Deps.KeyPaths(), ir.ID(), installResult, reloadErr)
			out = adminproto.InstallLibraryTemplateResult{
				Success:       false,
				KeyType:       installResult.KeyType,
				TemplateType:  string(installResult.TemplateType),
				AlreadyExists: installResult.AlreadyExists,
				Code:          protocol.ResultCodeReloadFailed,
				Error:         reloadErr.Error(),
			}
			return nil
		}

		if !templateAcceptedByReloadReport(reloadReport, installResult.KeyType, installResult.TemplateType) {
			err := fmt.Errorf("template %s was saved but did not activate on reload", installResult.KeyType)
			err = rollbackFailedTemplateInstall(s.Deps.KeyPaths(), ir.ID(), installResult, err)
			out = adminproto.InstallLibraryTemplateResult{
				Success:       false,
				KeyType:       installResult.KeyType,
				TemplateType:  string(installResult.TemplateType),
				AlreadyExists: installResult.AlreadyExists,
				Code:          protocol.ResultCodeActivationFailed,
				Error:         err.Error(),
			}
			return nil
		}

		return nil
	})
	if err != nil {
		return adminproto.InstallLibraryTemplateResult{
			Success:      false,
			KeyType:      keyType,
			TemplateType: req.TemplateType,
			Code:         protocol.ResultCodeInstallFailed,
			Error:        err.Error(),
		}
	}
	if out.Code != "" || out.Error != "" {
		return out
	}

	s.Deps.Logf("installed %s template via IPC: %s", installResult.TemplateType, installResult.KeyType)
	return adminproto.InstallLibraryTemplateResult{
		Success:       true,
		KeyType:       installResult.KeyType,
		TemplateType:  string(installResult.TemplateType),
		AlreadyExists: installResult.AlreadyExists,
	}
}

func (s Service) ListInstalledTemplates(ir *identity.Runtime) adminproto.ListInstalledTemplatesResult {
	var out []adminproto.InstalledTemplateInfo
	for _, templateType := range templatestore.ActiveTemplateTypes() {
		files, err := templatestore.ScanTemplateDirectoryForPaths(s.Deps.KeyPaths(), ir.ID(), templateType)
		if err != nil {
			return adminproto.ListInstalledTemplatesResult{
				Code:  protocol.ResultCodeListFailed,
				Error: err.Error(),
			}
		}
		for _, file := range files {
			var size int64
			if info, err := os.Stat(file.FilePath); err == nil {
				size = info.Size()
			}
			out = append(out, adminproto.InstalledTemplateInfo{
				KeyType:      file.KeyType,
				TemplateType: installedWireTemplateType(templateType),
				Size:         size,
				Enabled:      installedTemplateEnabled(s.Deps.KeyPaths(), ir.ID(), file.KeyType),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].KeyType == out[j].KeyType {
			return out[i].TemplateType < out[j].TemplateType
		}
		return out[i].KeyType < out[j].KeyType
	})
	return adminproto.ListInstalledTemplatesResult{Templates: out}
}

func (s Service) ShowLibraryTemplate(ir *identity.Runtime, req adminproto.ShowLibraryTemplateRequest) adminproto.ShowLibraryTemplateResult {
	keyType := keytypecatalog.Canonicalize(req.KeyType)
	templateType := templatestore.TemplateType(strings.ToLower(strings.TrimSpace(req.TemplateType)))
	if keyType == "" {
		return adminproto.ShowLibraryTemplateResult{
			Success: false,
			Code:    protocol.ErrCodeInvalidRequest,
			Error:   "key_type is required",
		}
	}
	if templateType != templatestore.TemplateTypeGeneric && templateType != templatestore.TemplateTypeComposed {
		return adminproto.ShowLibraryTemplateResult{
			Success:      false,
			KeyType:      keyType,
			TemplateType: req.TemplateType,
			Code:         protocol.ResultCodeInvalidTemplateType,
			Error:        fmt.Sprintf("library YAML view does not apply to template type %q (only generic and composed have YAML)", req.TemplateType),
		}
	}

	yaml, sourcePath, err := templatelibrary.FindLibraryYAML(s.Deps.KeyPaths(), templatelibrary.TemplateRef{KeyType: keyType, TemplateType: templateType})
	if err != nil {
		code := protocol.ResultCodeLibraryReadFailed
		if errors.Is(err, os.ErrNotExist) {
			code = protocol.ResultCodeLibraryEntryNotFound
		}
		return adminproto.ShowLibraryTemplateResult{
			Success:      false,
			KeyType:      keyType,
			TemplateType: string(templateType),
			Code:         code,
			Error:        err.Error(),
		}
	}
	sum := sha256.Sum256(yaml)
	var sourceModTime int64
	if info, err := os.Stat(sourcePath); err == nil {
		sourceModTime = info.ModTime().Unix()
	}
	return adminproto.ShowLibraryTemplateResult{
		Success:       true,
		KeyType:       keyType,
		TemplateType:  string(templateType),
		SourcePath:    sourcePath,
		SourceSHA256:  hex.EncodeToString(sum[:]),
		SourceModTime: sourceModTime,
		TemplateYAML:  yaml,
	}
}

func (s Service) ShowInstalledTemplate(ir *identity.Runtime, req adminproto.ShowInstalledTemplateRequest) adminproto.ShowInstalledTemplateResult {
	keyType := keytypecatalog.Canonicalize(req.KeyType)
	templateType, rec, ok, err := installedTemplateFromRecord(s.Deps.KeyPaths(), ir.ID(), keyType)
	if err != nil {
		return adminproto.ShowInstalledTemplateResult{
			Success: false,
			KeyType: keyType,
			Code:    protocol.ResultCodeTemplateStateFailed,
			Error:   err.Error(),
		}
	}
	if !ok {
		return adminproto.ShowInstalledTemplateResult{
			Success: false,
			KeyType: keyType,
			Code:    protocol.ResultCodeTemplateNotFound,
			Error:   fmt.Sprintf("template %s not found", req.KeyType),
		}
	}

	path, err := templatestore.GetTemplateFilePathForPaths(s.Deps.KeyPaths(), ir.ID(), keyType, templateType)
	if err != nil {
		return adminproto.ShowInstalledTemplateResult{
			Code:  protocol.ResultCodeTemplateStateFailed,
			Error: err.Error(),
		}
	}
	var data []byte
	err = ir.WithKeyring(func(masterKey *crypto.Keyring) error {
		var loadErr error
		data, loadErr = templatestore.LoadTemplateFromPath(path, masterKey)
		return loadErr
	})
	if err != nil {
		return adminproto.ShowInstalledTemplateResult{
			Success:      false,
			KeyType:      keyType,
			TemplateType: installedWireTemplateType(templateType),
			Code:         protocol.ResultCodeDecryptFailed,
			Error:        err.Error(),
		}
	}
	return adminproto.ShowInstalledTemplateResult{
		Success:      true,
		KeyType:      keyType,
		TemplateType: recordWireTemplateType(rec),
		TemplateYAML: data,
	}
}

func (s Service) ImportInstalledTemplate(ir *identity.Runtime, req adminproto.ImportInstalledTemplateRequest) adminproto.ImportInstalledTemplateResult {
	if err := templatelibrary.ValidateImportableSchema(req.TemplateYAML); err != nil {
		return adminproto.ImportInstalledTemplateResult{
			Success: false,
			Code:    protocol.ResultCodeInvalidTemplate,
			Error:   err.Error(),
		}
	}

	parsed, err := templatelibrary.ParseYAML("ipc-installed-template.yaml", req.TemplateYAML)
	if err != nil {
		return adminproto.ImportInstalledTemplateResult{
			Success: false,
			Code:    protocol.ResultCodeInvalidTemplate,
			Error:   err.Error(),
		}
	}

	var installResult templatelibrary.InstallResult
	var out adminproto.ImportInstalledTemplateResult
	err = s.Deps.WithIdentityMutation(ir.ID(), func() error {
		if err := ir.WithKeyring(func(masterKey *crypto.Keyring) error {
			var installErr error
			installResult, installErr = templatelibrary.InstallParsed(s.Deps.KeyPaths(), ir.ID(), parsed, masterKey)
			return installErr
		}); err != nil {
			out = adminproto.ImportInstalledTemplateResult{
				Success:      false,
				KeyType:      parsed.KeyType,
				TemplateType: string(parsed.TemplateType),
				Code:         protocol.ResultCodeImportFailed,
				Error:        err.Error(),
			}
			return nil
		}

		reloadReport, reloadErr := ir.Reload()
		if reloadErr != nil {
			reloadErr = rollbackFailedTemplateInstall(s.Deps.KeyPaths(), ir.ID(), installResult, reloadErr)
			out = adminproto.ImportInstalledTemplateResult{
				Success:       false,
				KeyType:       installResult.KeyType,
				TemplateType:  string(installResult.TemplateType),
				AlreadyExists: installResult.AlreadyExists,
				Code:          protocol.ResultCodeReloadFailed,
				Error:         reloadErr.Error(),
			}
			return nil
		}

		if !templateAcceptedByReloadReport(reloadReport, installResult.KeyType, installResult.TemplateType) {
			err := fmt.Errorf("template %s was saved but did not activate on reload", installResult.KeyType)
			err = rollbackFailedTemplateInstall(s.Deps.KeyPaths(), ir.ID(), installResult, err)
			out = adminproto.ImportInstalledTemplateResult{
				Success:       false,
				KeyType:       installResult.KeyType,
				TemplateType:  string(installResult.TemplateType),
				AlreadyExists: installResult.AlreadyExists,
				Code:          protocol.ResultCodeActivationFailed,
				Error:         err.Error(),
			}
			return nil
		}

		return nil
	})
	if err != nil {
		return adminproto.ImportInstalledTemplateResult{
			Success:      false,
			KeyType:      parsed.KeyType,
			TemplateType: string(parsed.TemplateType),
			Code:         protocol.ResultCodeImportFailed,
			Error:        err.Error(),
		}
	}
	if out.Code != "" || out.Error != "" {
		return out
	}

	s.Deps.Logf("imported %s template via IPC: %s", installResult.TemplateType, installResult.KeyType)
	return adminproto.ImportInstalledTemplateResult{
		Success:       true,
		KeyType:       installResult.KeyType,
		TemplateType:  string(installResult.TemplateType),
		AlreadyExists: installResult.AlreadyExists,
	}
}

func (s Service) RemoveInstalledTemplate(ir *identity.Runtime, req adminproto.RemoveInstalledTemplateRequest) adminproto.RemoveInstalledTemplateResult {
	keyType := keytypecatalog.Canonicalize(req.KeyType)
	templateType, rec, ok, stateErr := installedTemplateFromRecord(s.Deps.KeyPaths(), ir.ID(), keyType)
	if stateErr != nil {
		return adminproto.RemoveInstalledTemplateResult{
			Success: false,
			KeyType: keyType,
			Code:    protocol.ResultCodeTemplateStateFailed,
			Error:   stateErr.Error(),
		}
	}
	if !ok {
		return adminproto.RemoveInstalledTemplateResult{
			Success: false,
			KeyType: keyType,
			Code:    protocol.ResultCodeTemplateNotFound,
			Error:   fmt.Sprintf("template %s not found", req.KeyType),
		}
	}

	var removeResult templatelibrary.RemoveResult
	var out adminproto.RemoveInstalledTemplateResult
	err := s.Deps.WithIdentityMutation(ir.ID(), func() error {
		if err := ir.WithKeyring(func(masterKey *crypto.Keyring) error {
			var removeErr error
			removeResult, removeErr = templatelibrary.RemoveInstalledTemplate(s.Deps.KeyPaths(), ir.ID(), keyType, templateType, masterKey)
			return removeErr
		}); err != nil {
			return err
		}
		if removeResult.Removed {
			signertemplates.UnregisterProductProvider(removeResult.KeyType)
			if _, err := ir.Reload(); err != nil {
				out = adminproto.RemoveInstalledTemplateResult{
					Success:      false,
					KeyType:      removeResult.KeyType,
					TemplateType: string(removeResult.TemplateType),
					Removed:      true,
					Code:         protocol.ResultCodeReloadFailed,
					Error:        err.Error(),
				}
			}
		}
		return nil
	})
	if err != nil {
		code := protocol.ResultCodeRemoveFailed
		if errors.Is(err, keytypestate.ErrKeyTypeInUse) {
			code = protocol.ResultCodeKeyTypeInUse
		}
		return adminproto.RemoveInstalledTemplateResult{
			Success:      false,
			KeyType:      keyType,
			TemplateType: recordWireTemplateType(rec),
			Code:         code,
			Error:        err.Error(),
		}
	}
	if out.Code != "" || out.Error != "" {
		return out
	}

	s.Deps.Logf("removed installed template via IPC: %s", removeResult.KeyType)
	return adminproto.RemoveInstalledTemplateResult{
		Success:      true,
		KeyType:      removeResult.KeyType,
		TemplateType: recordWireTemplateType(rec),
		Removed:      removeResult.Removed,
	}
}

func (s Service) ActivateKeyType(ir *identity.Runtime, req adminproto.ActivateKeyTypeRequest) adminproto.ActivateKeyTypeResult {
	keyType := keytypecatalog.Canonicalize(req.KeyType)
	var out adminproto.ActivateKeyTypeResult
	err := s.Deps.WithIdentityMutation(ir.ID(), func() error {
		if templateType, _, ok, stateErr := installedTemplateFromRecord(s.Deps.KeyPaths(), ir.ID(), keyType); stateErr != nil {
			out = adminproto.ActivateKeyTypeResult{
				Success: false,
				KeyType: keyType,
				Code:    protocol.ResultCodeTemplateStateFailed,
				Error:   stateErr.Error(),
			}
			return nil
		} else if ok {
			out = s.enableInstalledTemplateKeyTypeLocked(ir, keyType, templateType)
			return nil
		}

		out = s.activateCompiledProviderKeyTypeLocked(ir, keyType)
		return nil
	})
	if err != nil {
		return adminproto.ActivateKeyTypeResult{
			Success: false,
			KeyType: keyType,
			Code:    protocol.ResultCodeActivationFailed,
			Error:   err.Error(),
		}
	}
	return out
}

func (s Service) enableInstalledTemplateKeyTypeLocked(ir *identity.Runtime, keyType string, templateType templatestore.TemplateType) adminproto.ActivateKeyTypeResult {
	installResult, err := templatelibrary.EnableInstalledTemplate(s.Deps.KeyPaths(), ir.ID(), keyType, templateType)
	if err != nil {
		return adminproto.ActivateKeyTypeResult{
			Success: false,
			KeyType: keyType,
			Code:    protocol.ResultCodeActivationFailed,
			Error:   err.Error(),
		}
	}
	reloadReport, reloadErr := ir.Reload()
	if reloadErr != nil {
		if !installResult.AlreadyExists {
			if rollbackErr := templatelibrary.RollbackTemplateStateChange(s.Deps.KeyPaths(), ir.ID(), installResult); rollbackErr != nil {
				reloadErr = fmt.Errorf("%w (rollback failed: %v)", reloadErr, rollbackErr)
			}
		}
		return adminproto.ActivateKeyTypeResult{
			Success: false,
			KeyType: installResult.KeyType,
			Code:    protocol.ResultCodeReloadFailed,
			Error:   reloadErr.Error(),
		}
	}
	if !templateAcceptedByReloadReport(reloadReport, installResult.KeyType, templateType) {
		err := fmt.Errorf("template %s was enabled but did not activate on reload", installResult.KeyType)
		if !installResult.AlreadyExists {
			if rollbackErr := templatelibrary.RollbackTemplateStateChange(s.Deps.KeyPaths(), ir.ID(), installResult); rollbackErr != nil {
				err = fmt.Errorf("%w (rollback failed: %v)", err, rollbackErr)
			}
		}
		return adminproto.ActivateKeyTypeResult{
			Success: false,
			KeyType: installResult.KeyType,
			Code:    protocol.ResultCodeActivationFailed,
			Error:   err.Error(),
		}
	}
	s.Deps.Logf("enabled %s template via IPC: %s", installResult.TemplateType, installResult.KeyType)
	return adminproto.ActivateKeyTypeResult{
		Success:       true,
		KeyType:       installResult.KeyType,
		AlreadyExists: installResult.AlreadyExists,
	}
}

func (s Service) activateCompiledProviderKeyTypeLocked(ir *identity.Runtime, keyType string) adminproto.ActivateKeyTypeResult {
	installResult, err := templatelibrary.ActivateCompiledProvider(s.Deps.KeyPaths(), ir.ID(), keyType)
	if err != nil {
		return adminproto.ActivateKeyTypeResult{
			Success: false,
			KeyType: keyType,
			Code:    protocol.ResultCodeActivationFailed,
			Error:   err.Error(),
		}
	}
	if _, err := ir.Reload(); err != nil {
		return adminproto.ActivateKeyTypeResult{
			Success: false,
			KeyType: installResult.KeyType,
			Code:    protocol.ResultCodeReloadFailed,
			Error:   err.Error(),
		}
	}
	s.Deps.Logf("activated compiled provider via IPC: %s", installResult.KeyType)
	return adminproto.ActivateKeyTypeResult{
		Success:       true,
		KeyType:       installResult.KeyType,
		AlreadyExists: installResult.AlreadyExists,
	}
}

func (s Service) DeactivateKeyType(ir *identity.Runtime, req adminproto.DeactivateKeyTypeRequest) adminproto.DeactivateKeyTypeResult {
	keyType := keytypecatalog.Canonicalize(req.KeyType)
	var removeResult templatelibrary.RemoveResult
	var disabledTemplate bool
	var out adminproto.DeactivateKeyTypeResult
	err := s.Deps.WithIdentityMutation(ir.ID(), func() error {
		if err := ir.WithKeyring(func(masterKey *crypto.Keyring) error {
			var removeErr error
			if templateType, _, ok, stateErr := installedTemplateFromRecord(s.Deps.KeyPaths(), ir.ID(), keyType); stateErr != nil {
				return stateErr
			} else if ok {
				disabledTemplate = true
				removeResult, removeErr = s.disableInstalledTemplateKeyTypeLocked(ir, keyType, templateType, masterKey)
			} else {
				removeResult, removeErr = s.deactivateCompiledProviderKeyTypeLocked(ir, keyType, masterKey)
			}
			return removeErr
		}); err != nil {
			return err
		}
		if disabledTemplate && removeResult.Removed {
			signertemplates.UnregisterProductProvider(removeResult.KeyType)
		}
		if _, err := ir.Reload(); err != nil {
			out = adminproto.DeactivateKeyTypeResult{
				Success: false,
				KeyType: removeResult.KeyType,
				Removed: removeResult.Removed,
				Code:    protocol.ResultCodeReloadFailed,
				Error:   err.Error(),
			}
		}
		return nil
	})
	if err != nil {
		code := protocol.ResultCodeDeactivationFailed
		if errors.Is(err, keytypestate.ErrKeyTypeInUse) {
			code = protocol.ResultCodeKeyTypeInUse
		}
		return adminproto.DeactivateKeyTypeResult{
			Success: false,
			KeyType: keyType,
			Code:    code,
			Error:   err.Error(),
		}
	}
	if out.Code != "" || out.Error != "" {
		return out
	}
	if disabledTemplate {
		s.Deps.Logf("disabled installed template via IPC: %s", removeResult.KeyType)
	} else {
		s.Deps.Logf("deactivated compiled provider via IPC: %s", removeResult.KeyType)
	}
	return adminproto.DeactivateKeyTypeResult{
		Success: true,
		KeyType: removeResult.KeyType,
		Removed: removeResult.Removed,
	}
}

func (s Service) disableInstalledTemplateKeyTypeLocked(ir *identity.Runtime, keyType string, templateType templatestore.TemplateType, masterKey *crypto.Keyring) (templatelibrary.RemoveResult, error) {
	return templatelibrary.DisableInstalledTemplate(s.Deps.KeyPaths(), ir.ID(), keyType, templateType, masterKey)
}

func (s Service) deactivateCompiledProviderKeyTypeLocked(ir *identity.Runtime, keyType string, masterKey *crypto.Keyring) (templatelibrary.RemoveResult, error) {
	return templatelibrary.DeactivateCompiledProvider(s.Deps.KeyPaths(), ir.ID(), keyType, masterKey)
}

func templateAcceptedByReloadReport(report *signertemplates.ReloadReport, keyType string, templateType templatestore.TemplateType) bool {
	if report == nil {
		return false
	}
	var accepted, rejected []string
	rejected = append(rejected, report.InvalidStateRecordKeyTypes...)
	switch templateType {
	case templatestore.TemplateTypeGeneric:
		accepted = append(accepted, report.GenericActivatedKeyTypes...)
		accepted = append(accepted, report.GenericIdempotentKeyTypes...)
		rejected = append(rejected, report.GenericConflictingKeyTypes...)
		rejected = append(rejected, report.GenericInvalidKeyTypes...)
	case templatestore.TemplateTypeComposed:
		accepted = append(accepted, report.ComposedActivatedKeyTypes...)
		accepted = append(accepted, report.ComposedIdempotentKeyTypes...)
		rejected = append(rejected, report.ComposedConflictingKeyTypes...)
		rejected = append(rejected, report.ComposedInvalidKeyTypes...)
	default:
		return false
	}
	for _, rejectedKeyType := range rejected {
		if rejectedKeyType == keyType {
			return false
		}
	}
	for _, acceptedKeyType := range accepted {
		if acceptedKeyType == keyType {
			return true
		}
	}
	return false
}

func rollbackFailedTemplateInstall(paths storepaths.Paths, identityID string, result templatelibrary.InstallResult, cause error) error {
	var rollbackErr error
	if !result.AlreadyExists {
		rollbackErr = templatelibrary.RollbackInstalledTemplateFile(paths, identityID, result.KeyType, result.TemplateType)
		signertemplates.UnregisterProductProvider(result.KeyType)
	}
	if result.StateChanged {
		if err := templatelibrary.RollbackTemplateStateChange(paths, identityID, result); err != nil {
			if rollbackErr != nil {
				rollbackErr = fmt.Errorf("%v; state rollback failed: %w", rollbackErr, err)
			} else {
				rollbackErr = err
			}
		}
	}
	if rollbackErr != nil {
		return fmt.Errorf("%w (rollback failed: %v)", cause, rollbackErr)
	}
	return cause
}

func installedTemplateFromRecord(paths storepaths.Paths, identityID, keyType string) (templatestore.TemplateType, keytypestate.Record, bool, error) {
	rec, ok, err := keytypestate.Get(paths, identityID, keyType)
	if err != nil {
		return "", keytypestate.Record{}, false, err
	}
	if !ok {
		return "", keytypestate.Record{}, false, nil
	}
	templateType, ok := templateTypeFromSource(rec.Source)
	if !ok {
		return "", keytypestate.Record{}, false, nil
	}
	if !templatestore.TemplateExistsForPaths(paths, identityID, rec.KeyType, templateType) {
		return "", keytypestate.Record{}, false, nil
	}
	return templateType, rec, true, nil
}

func templateTypeFromSource(source keytypestate.Source) (templatestore.TemplateType, bool) {
	switch source {
	case keytypestate.SourceYAMLGeneric:
		return templatestore.TemplateTypeGeneric, true
	case keytypestate.SourceYAMLComposed:
		return templatestore.TemplateTypeComposed, true
	default:
		return "", false
	}
}

func installedWireTemplateType(templateType templatestore.TemplateType) string {
	switch templateType {
	case templatestore.TemplateTypeComposed:
		wire, _ := adminproto.WireTemplateTypeFromSource(keytypestate.SourceYAMLComposed)
		return wire
	default:
		wire, _ := adminproto.WireTemplateTypeFromSource(keytypestate.SourceYAMLGeneric)
		return wire
	}
}

func recordWireTemplateType(rec keytypestate.Record) string {
	wire, ok := adminproto.WireTemplateTypeFromSource(rec.Source)
	if !ok {
		return ""
	}
	return wire
}

func installedTemplateEnabled(paths storepaths.Paths, identityID, keyType string) bool {
	rec, ok, err := keytypestate.Get(paths, identityID, keyType)
	return err == nil && ok && rec.State == keytypestate.StateEnabled
}

func creationParamInfos(params []lsigprovider.ParameterDef) []signerapi.CreationParamInfo {
	if len(params) == 0 {
		return nil
	}
	out := make([]signerapi.CreationParamInfo, len(params))
	for i, p := range params {
		out[i] = signerapi.CreationParamInfo{
			Name:        p.Name,
			Label:       p.Label,
			Description: p.Description,
			Type:        p.Type,
			Required:    p.Required,
			MaxLength:   p.MaxLength,
			InputModes:  creationInputModeInfos(p.InputModes),
			Options:     append([]string(nil), p.Options...),
			MinItems:    p.MinItems,
			MaxItems:    p.MaxItems,
			Example:     p.Example,
			Placeholder: p.Placeholder,
			Min:         p.Min,
			Max:         p.Max,
			Default:     p.Default,
		}
	}
	return out
}

func creationInputModeInfos(modes []lsigprovider.InputMode) []signerapi.InputModeInfo {
	if len(modes) == 0 {
		return nil
	}
	out := make([]signerapi.InputModeInfo, len(modes))
	for i, mode := range modes {
		out[i] = signerapi.InputModeInfo{
			Name:       mode.Name,
			Label:      mode.Label,
			Transform:  mode.Transform,
			ByteLength: mode.ByteLength,
			InputType:  mode.InputType,
		}
	}
	return out
}

func runtimeArgInfos(args []lsigprovider.RuntimeArgDef) []signerapi.RuntimeArgInfo {
	if len(args) == 0 {
		return nil
	}
	out := make([]signerapi.RuntimeArgInfo, len(args))
	for i, a := range args {
		out[i] = signerapi.RuntimeArgInfo{
			Name:        a.Name,
			Label:       a.Label,
			Description: a.Description,
			Type:        a.Type,
			Required:    a.Required,
			ByteLength:  a.ByteLength,
			MaxSize:     a.MaxSize,
		}
	}
	return out
}
