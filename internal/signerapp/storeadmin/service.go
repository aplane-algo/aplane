// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeadmin

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"
	"github.com/aplane-algo/aplane/internal/signerapp/unlockconfig"
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
	LogPassphraseChanged(ctx context.Context, keysMigrated, templatesMigrated, policySidecarsMigrated, sourceTokenFilesMigrated int)
	LogPassphraseChangeFailed(ctx context.Context, reason string)
}

type Service struct {
	Deps     Deps
	Runtime  *productruntime.Runtime
	AuditLog AuditLogger
}

func (s Service) ChangeStorePassphrase(ctx context.Context, req adminproto.ChangeStorePassphraseRequest) adminproto.ChangeStorePassphraseResult {
	ir := s.Runtime
	if len(req.CurrentPassphrase) == 0 || len(req.NewPassphrase) == 0 {
		s.logPassphraseChangeFailed(ctx, "current and new passphrases are required")
		return adminproto.ChangeStorePassphraseResult{
			Code:  protocol.ErrCodeInvalidPassphrase,
			Error: "current and new passphrases are required",
		}
	}
	if bytes.Equal(req.CurrentPassphrase, req.NewPassphrase) {
		s.logPassphraseChangeFailed(ctx, "new passphrase must be different from current passphrase")
		return adminproto.ChangeStorePassphraseResult{
			Code:  protocol.ErrCodeInvalidPassphrase,
			Error: "new passphrase must be different from current passphrase",
		}
	}
	if err := storepass.VerifyCurrentPassphrase(s.Deps.KeyPaths(), req.CurrentPassphrase); err != nil {
		s.logPassphraseChangeFailed(ctx, err.Error())
		code := protocol.ErrCodeInvalidPassphrase
		if !errors.Is(err, crypto.ErrInvalidPassphrase) {
			// The current passphrase may be right: the store root or its
			// selected generation is damaged or unreadable.
			code = protocol.ResultCodePassphraseChangeFailed
		}
		return adminproto.ChangeStorePassphraseResult{
			Code:  code,
			Error: err.Error(),
		}
	}

	unlockCfg, err := signerstartup.ResolveUnlockConfig(s.Deps.DataDir())
	if err != nil {
		s.logPassphraseChangeFailed(ctx, err.Error())
		return adminproto.ChangeStorePassphraseResult{
			Code:  protocol.ResultCodePassphraseHelperError,
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
				return storevalidate.StandardCandidate(s.Deps.KeyPaths(), ir.NodeRole(), s.Deps.DataDir(), s.Deps.Config(), successor)(staged)
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
			s.logPassphraseChanged(ctx, rotation.KeysMigrated, rotation.TemplatesMigrated, rotation.PolicySidecarsMigrated, rotation.SourceTokenFilesMigrated)
		} else {
			s.logPassphraseChangeFailed(ctx, err.Error())
		}
		return adminproto.ChangeStorePassphraseResult{
			KeysMigrated:             rotation.KeysMigrated,
			TemplatesMigrated:        rotation.TemplatesMigrated,
			PolicySidecarsMigrated:   rotation.PolicySidecarsMigrated,
			SourceTokenFilesMigrated: rotation.SourceTokenFilesMigrated,
			PriorGenerations:         rotation.PriorGenerations,
			HelperWarning:            rotation.HelperWarning,
			RootCommitted:            rotation.RootCommitted,
			Code:                     protocol.ResultCodePassphraseChangeFailed,
			Error:                    err.Error(),
		}
	}
	s.logPassphraseChanged(ctx, rotation.KeysMigrated, rotation.TemplatesMigrated, rotation.PolicySidecarsMigrated, rotation.SourceTokenFilesMigrated)
	return adminproto.ChangeStorePassphraseResult{
		Success:                  true,
		KeysMigrated:             rotation.KeysMigrated,
		TemplatesMigrated:        rotation.TemplatesMigrated,
		PolicySidecarsMigrated:   rotation.PolicySidecarsMigrated,
		SourceTokenFilesMigrated: rotation.SourceTokenFilesMigrated,
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

func (s Service) logPassphraseChanged(ctx context.Context, keysMigrated, templatesMigrated, policySidecarsMigrated, sourceTokenFilesMigrated int) {
	if s.AuditLog != nil {
		s.AuditLog.LogPassphraseChanged(ctx, keysMigrated, templatesMigrated, policySidecarsMigrated, sourceTokenFilesMigrated)
	}
}

func (s Service) logPassphraseChangeFailed(ctx context.Context, reason string) {
	if s.AuditLog != nil {
		s.AuditLog.LogPassphraseChangeFailed(ctx, reason)
	}
}
