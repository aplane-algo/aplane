// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeadmin

import (
	"bytes"
	"fmt"

	"github.com/aplane-algo/aplane/internal/adminproto"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepass"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

type Deps interface {
	DataDir() string
	Config() *apconfig.ServerConfig
	KeyPaths() storepaths.Paths
	WithIdentityMutation(identityID string, fn func() error) error
	Logf(format string, args ...interface{})
}

type AuditLogger interface {
	LogStoreInitialized(identityID, metadataDir string)
	LogStoreInitializeFailed(identityID, reason string)
	LogPassphraseChanged(identityID string, keysMigrated, templatesMigrated int)
	LogPassphraseChangeFailed(identityID, reason string)
}

type UnlockIdentityFunc func(ir *identity.Runtime, passphrase []byte) (bool, int, string)

type Service struct {
	Deps           Deps
	AuditLog       AuditLogger
	UnlockIdentity UnlockIdentityFunc
}

func (s Service) InitializeStore(ir *identity.Runtime, req adminproto.InitializeStoreRequest) adminproto.InitializeStoreResult {
	if ir == nil {
		return adminproto.InitializeStoreResult{
			Code:  protocol.ErrCodeNoIdentityBound,
			Error: "product identity runtime unavailable",
		}
	}
	if len(req.Passphrase) == 0 {
		s.logStoreInitializeFailed(ir.ID(), "passphrase is required")
		return adminproto.InitializeStoreResult{
			Code:  protocol.ErrCodeInvalidPassphrase,
			Error: "passphrase is required",
		}
	}

	configSnapshot := *s.Deps.Config()
	unlockCfg, err := signerstartup.ResolveUnlockConfig(s.Deps.DataDir(), ir.ID(), &configSnapshot)
	if err != nil {
		s.logStoreInitializeFailed(ir.ID(), err.Error())
		return adminproto.InitializeStoreResult{
			Code:  "passphrase_helper_error",
			Error: err.Error(),
		}
	}
	passphraseCmdCfg := passphraseCommandConfigFromUnlock(unlockCfg)

	var helperWarning string
	var initResult storeinit.Result
	err = s.Deps.WithIdentityMutation(ir.ID(), func() error {
		var initErr error
		initResult, initErr = storeinit.Initialize(req.Passphrase, storeinit.Options{
			DataDir:    s.Deps.DataDir(),
			Paths:      s.Deps.KeyPaths(),
			IdentityID: ir.ID(),
			Logf:       s.Deps.Logf,
		})
		if initErr != nil {
			return initErr
		}
		if passphraseCmdCfg != nil {
			if err := apconfig.WritePassphrase(passphraseCmdCfg, req.Passphrase); err != nil {
				helperWarning = fmt.Sprintf("could not store passphrase via passphrase command helper: %v", err)
			}
		}
		success, _, errMsg := s.UnlockIdentity(ir, req.Passphrase)
		if !success {
			return fmt.Errorf("store initialized but signer unlock failed: %s", errMsg)
		}
		return nil
	})
	if err != nil {
		s.logStoreInitializeFailed(ir.ID(), err.Error())
		return adminproto.InitializeStoreResult{
			Code:  "initialize_store_failed",
			Error: err.Error(),
		}
	}
	s.logStoreInitialized(ir.ID(), initResult.MetadataDir)
	return adminproto.InitializeStoreResult{
		Success:       true,
		MetadataDir:   initResult.MetadataDir,
		HelperWarning: helperWarning,
	}
}

func (s Service) ChangeStorePassphrase(ir *identity.Runtime, req adminproto.ChangeStorePassphraseRequest) adminproto.ChangeStorePassphraseResult {
	if len(req.CurrentPassphrase) == 0 || len(req.NewPassphrase) == 0 {
		s.logPassphraseChangeFailed(ir.ID(), "current and new passphrases are required")
		return adminproto.ChangeStorePassphraseResult{
			Code:  "invalid_passphrase",
			Error: "current and new passphrases are required",
		}
	}
	if bytes.Equal(req.CurrentPassphrase, req.NewPassphrase) {
		s.logPassphraseChangeFailed(ir.ID(), "new passphrase must be different from current passphrase")
		return adminproto.ChangeStorePassphraseResult{
			Code:  "invalid_passphrase",
			Error: "new passphrase must be different from current passphrase",
		}
	}
	if err := storepass.VerifyCurrentPassphrase(s.Deps.KeyPaths(), ir.ID(), req.CurrentPassphrase); err != nil {
		s.logPassphraseChangeFailed(ir.ID(), err.Error())
		return adminproto.ChangeStorePassphraseResult{
			Code:  protocol.ErrCodeInvalidPassphrase,
			Error: err.Error(),
		}
	}

	configSnapshot := *s.Deps.Config()
	unlockCfg, err := signerstartup.ResolveUnlockConfig(s.Deps.DataDir(), ir.ID(), &configSnapshot)
	if err != nil {
		s.logPassphraseChangeFailed(ir.ID(), err.Error())
		return adminproto.ChangeStorePassphraseResult{
			Code:  "passphrase_helper_error",
			Error: err.Error(),
		}
	}
	passphraseCmdCfg := passphraseCommandConfigFromUnlock(unlockCfg)

	var rotation storepass.RotateResult
	err = s.Deps.WithIdentityMutation(ir.ID(), func() error {
		var rotateErr error
		rotation, rotateErr = storepass.Rotate(s.Deps.KeyPaths(), ir.ID(), req.CurrentPassphrase, req.NewPassphrase, storepass.RotateOptions{
			Logf: s.Deps.Logf,
			AfterSwap: func() error {
				if passphraseCmdCfg == nil {
					return nil
				}
				if err := apconfig.WritePassphrase(passphraseCmdCfg, req.NewPassphrase); err != nil {
					return fmt.Errorf("passphrase change aborted: helper write failed: %w", err)
				}
				return nil
			},
		})
		if rotateErr != nil {
			return rotateErr
		}
		if _, reloadErr := ir.ReloadWithPassphrase(req.NewPassphrase); reloadErr != nil {
			return fmt.Errorf("passphrase changed but identity reload failed: %w", reloadErr)
		}
		return nil
	})
	if err != nil {
		s.logPassphraseChangeFailed(ir.ID(), err.Error())
		return adminproto.ChangeStorePassphraseResult{
			Code:  "passphrase_change_failed",
			Error: err.Error(),
		}
	}
	s.logPassphraseChanged(ir.ID(), rotation.KeysMigrated, rotation.TemplatesMigrated)
	return adminproto.ChangeStorePassphraseResult{
		Success:                  true,
		KeysMigrated:             rotation.KeysMigrated,
		TemplatesMigrated:        rotation.TemplatesMigrated,
		PolicySidecarsMigrated:   rotation.PolicySidecarsMigrated,
		NodeRoleSidecarsMigrated: rotation.NodeRoleSidecarsMigrated,
	}
}

func passphraseCommandConfigFromUnlock(unlockCfg *identity.UnlockConfig) *apconfig.PassphraseCommandConfig {
	if unlockCfg == nil || !unlockCfg.HasPassphraseCommand() {
		return nil
	}
	return &apconfig.PassphraseCommandConfig{
		Argv: unlockCfg.PassphraseCommandArgv,
		Env:  unlockCfg.PassphraseCommandEnv,
	}
}

func (s Service) logStoreInitialized(identityID, metadataDir string) {
	if s.AuditLog != nil {
		s.AuditLog.LogStoreInitialized(identityID, metadataDir)
	}
}

func (s Service) logStoreInitializeFailed(identityID, reason string) {
	if s.AuditLog != nil {
		s.AuditLog.LogStoreInitializeFailed(identityID, reason)
	}
}

func (s Service) logPassphraseChanged(identityID string, keysMigrated, templatesMigrated int) {
	if s.AuditLog != nil {
		s.AuditLog.LogPassphraseChanged(identityID, keysMigrated, templatesMigrated)
	}
}

func (s Service) logPassphraseChangeFailed(identityID, reason string) {
	if s.AuditLog != nil {
		s.AuditLog.LogPassphraseChangeFailed(identityID, reason)
	}
}
