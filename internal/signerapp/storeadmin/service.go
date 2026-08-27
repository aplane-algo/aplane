// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeadmin

import (
	"bytes"
	"fmt"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"
	"github.com/aplane-algo/aplane/internal/signerapp/unlockconfig"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepass"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

type Deps interface {
	DataDir() string
	Config() *serverconfig.ServerConfig
	KeyPaths() storepaths.Paths
	WithStoreMutation(fn func() error) error
	Logf(format string, args ...interface{})
}

type AuditLogger interface {
	LogStoreInitialized(metadataDir string)
	LogStoreInitializeFailed(reason string)
	LogPassphraseChanged(keysMigrated, templatesMigrated int)
	LogPassphraseChangeFailed(reason string)
}

type UnlockIdentityFunc func(passphrase []byte) (bool, int, string, string)

type Service struct {
	Deps           Deps
	Runtime        *productruntime.Runtime
	AuditLog       AuditLogger
	UnlockIdentity UnlockIdentityFunc
}

func (s Service) InitializeStore(req adminproto.InitializeStoreRequest) adminproto.InitializeStoreResult {
	ir := s.Runtime
	if ir == nil {
		return adminproto.InitializeStoreResult{
			Code:  protocol.ErrCodeNoRuntimeBound,
			Error: "product runtime unavailable",
		}
	}
	if len(req.Passphrase) == 0 {
		s.logStoreInitializeFailed("passphrase is required")
		return adminproto.InitializeStoreResult{
			Code:  protocol.ErrCodeInvalidPassphrase,
			Error: "passphrase is required",
		}
	}

	configSnapshot := *s.Deps.Config()
	unlockCfg, err := signerstartup.ResolveUnlockConfig(s.Deps.DataDir(), &configSnapshot)
	if err != nil {
		s.logStoreInitializeFailed(err.Error())
		return adminproto.InitializeStoreResult{
			Code:  "passphrase_helper_error",
			Error: err.Error(),
		}
	}
	passphraseCmdCfg := passphraseCommandConfigFromUnlock(unlockCfg)

	var helperWarning string
	var initResult storeinit.Result
	err = s.Deps.WithStoreMutation(func() error {
		var initErr error
		initResult, initErr = storeinit.Initialize(req.Passphrase, storeinit.Options{
			DataDir: s.Deps.DataDir(),
			Paths:   s.Deps.KeyPaths(),
			Logf:    s.Deps.Logf,
		})
		if initErr != nil {
			return initErr
		}
		if passphraseCmdCfg != nil {
			if err := serverconfig.WritePassphrase(passphraseCmdCfg, req.Passphrase); err != nil {
				helperWarning = fmt.Sprintf("could not store passphrase via passphrase command helper: %v", err)
			}
		}
		return nil
	})
	// UnlockIdentity owns its own generation/rotation reconciliation
	// mutations. Invoke it only after releasing the non-reentrant identity
	// mutation lock used for initialization.
	if err == nil {
		success, _, errMsg, _ := s.UnlockIdentity(req.Passphrase)
		if !success {
			err = fmt.Errorf("store initialized but signer unlock failed: %s", errMsg)
		}
	}
	if err != nil {
		s.logStoreInitializeFailed(err.Error())
		return adminproto.InitializeStoreResult{
			Code:          "initialize_store_failed",
			Error:         err.Error(),
			HelperWarning: helperWarning,
		}
	}
	s.logStoreInitialized(initResult.MetadataDir)
	return adminproto.InitializeStoreResult{
		Success:       true,
		MetadataDir:   initResult.MetadataDir,
		HelperWarning: helperWarning,
	}
}

func (s Service) ChangeStorePassphrase(req adminproto.ChangeStorePassphraseRequest) adminproto.ChangeStorePassphraseResult {
	ir := s.Runtime
	if len(req.CurrentPassphrase) == 0 || len(req.NewPassphrase) == 0 {
		s.logPassphraseChangeFailed("current and new passphrases are required")
		return adminproto.ChangeStorePassphraseResult{
			Code:  "invalid_passphrase",
			Error: "current and new passphrases are required",
		}
	}
	if bytes.Equal(req.CurrentPassphrase, req.NewPassphrase) {
		s.logPassphraseChangeFailed("new passphrase must be different from current passphrase")
		return adminproto.ChangeStorePassphraseResult{
			Code:  "invalid_passphrase",
			Error: "new passphrase must be different from current passphrase",
		}
	}
	if err := storepass.VerifyCurrentPassphrase(s.Deps.KeyPaths(), req.CurrentPassphrase); err != nil {
		s.logPassphraseChangeFailed(err.Error())
		return adminproto.ChangeStorePassphraseResult{
			Code:  protocol.ErrCodeInvalidPassphrase,
			Error: err.Error(),
		}
	}

	configSnapshot := *s.Deps.Config()
	unlockCfg, err := signerstartup.ResolveUnlockConfig(s.Deps.DataDir(), &configSnapshot)
	if err != nil {
		s.logPassphraseChangeFailed(err.Error())
		return adminproto.ChangeStorePassphraseResult{
			Code:  "passphrase_helper_error",
			Error: err.Error(),
		}
	}
	passphraseCmdCfg := passphraseCommandConfigFromUnlock(unlockCfg)

	var rotation storepass.RotateResult
	err = s.Deps.WithStoreMutation(func() error {
		// Withdraw signing authority before freezing the selected generation.
		// A racing explicit Lock must still win.
		maintenance := ir.BeginStoreMaintenance()
		republish := false
		defer func() {
			ir.FinishStoreMaintenance(maintenance, republish)
		}()
		var rotateErr error
		rotation, rotateErr = storepass.Rotate(s.Deps.KeyPaths(), req.CurrentPassphrase, req.NewPassphrase, storepass.RotateOptions{
			Logf: s.Deps.Logf,
			ValidateCandidate: func(staged storepaths.GenPaths, successor *crypto.Keyring) error {
				return storevalidate.Candidate(storevalidate.Options{
					Paths: s.Deps.KeyPaths(), Candidate: staged, Keyring: successor,
					ExpectedRole: ir.NodeRole(), DataDir: s.Deps.DataDir(), Config: s.Deps.Config(),
				})
			},
			AfterRootCommit: func() error {
				if passphraseCmdCfg == nil {
					return nil
				}
				if err := serverconfig.WritePassphrase(passphraseCmdCfg, req.NewPassphrase); err != nil {
					return fmt.Errorf("helper write failed: %w", err)
				}
				return nil
			},
		})
		if rotateErr != nil {
			return rotateErr
		}
		if _, reloadErr := ir.ReloadWithPassphrase(req.NewPassphrase); reloadErr != nil {
			return fmt.Errorf("passphrase changed but runtime reload failed: %w", reloadErr)
		}
		// The root replacement is complete and reload has rebuilt every runtime
		// index under the new passphrase, so signing authority may be
		// published again before the mutation lock is released.
		republish = true
		return nil
	})
	if err != nil {
		// The root record is the durable truth. A post-commit reload or
		// durability-confirmation error is operational failure after a
		// successful passphrase cutover, not PASSPHRASE_CHANGE_FAILED.
		if rotation.RootCommitted {
			s.logPassphraseChanged(rotation.KeysMigrated, rotation.TemplatesMigrated)
		} else {
			s.logPassphraseChangeFailed(err.Error())
		}
		return adminproto.ChangeStorePassphraseResult{
			KeysMigrated:             rotation.KeysMigrated,
			TemplatesMigrated:        rotation.TemplatesMigrated,
			PolicySidecarsMigrated:   rotation.PolicySidecarsMigrated,
			NodeRoleSidecarsMigrated: rotation.NodeRoleSidecarsMigrated,
			PriorGenerations:         rotation.PriorGenerations,
			HelperWarning:            rotation.HelperWarning,
			RootCommitted:            rotation.RootCommitted,
			Code:                     "passphrase_change_failed",
			Error:                    err.Error(),
		}
	}
	s.logPassphraseChanged(rotation.KeysMigrated, rotation.TemplatesMigrated)
	return adminproto.ChangeStorePassphraseResult{
		Success:                  true,
		KeysMigrated:             rotation.KeysMigrated,
		TemplatesMigrated:        rotation.TemplatesMigrated,
		PolicySidecarsMigrated:   rotation.PolicySidecarsMigrated,
		NodeRoleSidecarsMigrated: rotation.NodeRoleSidecarsMigrated,
		PriorGenerations:         rotation.PriorGenerations,
		HelperWarning:            rotation.HelperWarning,
		RootCommitted:            rotation.RootCommitted,
	}
}

func passphraseCommandConfigFromUnlock(unlockCfg *unlockconfig.UnlockConfig) *serverconfig.PassphraseCommandConfig {
	if unlockCfg == nil || !unlockCfg.HasPassphraseCommand() {
		return nil
	}
	return &serverconfig.PassphraseCommandConfig{
		Argv: unlockCfg.PassphraseCommandArgv,
		Env:  unlockCfg.PassphraseCommandEnv,
	}
}

func (s Service) logStoreInitialized(metadataDir string) {
	if s.AuditLog != nil {
		s.AuditLog.LogStoreInitialized(metadataDir)
	}
}

func (s Service) logStoreInitializeFailed(reason string) {
	if s.AuditLog != nil {
		s.AuditLog.LogStoreInitializeFailed(reason)
	}
}

func (s Service) logPassphraseChanged(keysMigrated, templatesMigrated int) {
	if s.AuditLog != nil {
		s.AuditLog.LogPassphraseChanged(keysMigrated, templatesMigrated)
	}
}

func (s Service) logPassphraseChangeFailed(reason string) {
	if s.AuditLog != nil {
		s.AuditLog.LogPassphraseChangeFailed(reason)
	}
}
