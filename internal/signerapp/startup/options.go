// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package startup

import (
	"fmt"
	"time"

	bootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// Options captures resolved signer startup inputs after bootstrap.
type Options struct {
	DataDir           string
	Config            serverconfig.ServerConfig
	PassphraseTimeout time.Duration
	Paths             storepaths.Paths
	IdentityID        string
}

// LoadOptions resolves the signer bootstrap state into a normalized startup
// model that can be passed through validation and runtime assembly.
func LoadOptions(dataDirFlag string, identityID string) (*Options, error) {
	startup, err := bootstrap.Load(dataDirFlag)
	if err != nil {
		return nil, err
	}

	return &Options{
		DataDir:           startup.DataDir,
		Config:            startup.Config,
		PassphraseTimeout: startup.PassphraseTimeout,
		Paths:             startup.Paths,
		IdentityID:        identityID,
	}, nil
}

// UnlockSource describes how the signer obtained its startup unlock state.
type UnlockSource string

const (
	UnlockSourceIPC               UnlockSource = "ipc"
	UnlockSourcePassphraseCommand UnlockSource = "passphrase_command"
	UnlockSourceTestPassphrase    UnlockSource = "TEST_PASSPHRASE"
)

// UnlockPlan captures the normalized startup unlock decision.
type UnlockPlan struct {
	StartLocked bool
	Passphrase  []byte
	Source      UnlockSource
}

// ValidateAndBuildUnlockPlan validates every startup precondition, including
// the single-product identity layout, before resolving a passphrase source.
// Keeping that order in one operation prevents an invalid store layout from
// invoking an operator-configured passphrase helper.
func ValidateAndBuildUnlockPlan(opts *Options, runtime *RuntimeState, testPassphrase string) (*ValidationInfo, *UnlockPlan, error) {
	info, err := Validate(&opts.Config, runtime, opts.Paths, opts.IdentityID)
	if err != nil {
		return nil, nil, fmt.Errorf("startup validation failed: %w", err)
	}

	plan, err := BuildUnlockPlan(opts, info.KeystoreExists, testPassphrase)
	if err != nil {
		return nil, nil, err
	}
	return info, plan, nil
}

// ResolveUnlockConfig returns the passphrase command config for an identity.
// It checks identity-scoped unlock.yaml first, then falls back to the
// process-global config for backward compatibility.
func ResolveUnlockConfig(dataDir, identityID string, config *serverconfig.ServerConfig) (*identity.UnlockConfig, error) {
	unlockCfg, err := identity.LoadUnlockConfig(dataDir, identityID)
	if err != nil {
		return nil, err
	}
	if unlockCfg != nil && unlockCfg.HasPassphraseCommand() {
		return unlockCfg, nil
	}

	if len(config.PassphraseCommandArgv) > 0 {
		return &identity.UnlockConfig{
			PassphraseCommandArgv: config.PassphraseCommandArgv,
			PassphraseCommandEnv:  config.PassphraseCommandEnv,
		}, nil
	}

	return nil, nil
}

// BuildUnlockPlan resolves whether startup begins locked or unlocked and, for
// headless/test startup, loads and verifies the passphrase before runtime
// construction begins.
func BuildUnlockPlan(opts *Options, keystoreExists bool, testPassphrase string) (*UnlockPlan, error) {
	if !keystoreExists {
		return &UnlockPlan{
			StartLocked: true,
			Source:      UnlockSourceIPC,
		}, nil
	}

	if testPassphrase != "" {
		passphrase := []byte(testPassphrase)
		if err := crypto.VerifyPassphraseWithKeyring(passphrase, opts.Paths.KeystoreMetadataDir()); err != nil {
			crypto.ZeroBytes(passphrase)
			return nil, fmt.Errorf("TEST_PASSPHRASE does not match existing keystore")
		}
		return &UnlockPlan{
			StartLocked: false,
			Passphrase:  passphrase,
			Source:      UnlockSourceTestPassphrase,
		}, nil
	}

	unlockCfg, err := ResolveUnlockConfig(opts.DataDir, opts.IdentityID, &opts.Config)
	if err != nil {
		return nil, fmt.Errorf("load identity unlock config: %w", err)
	}
	if unlockCfg == nil {
		return &UnlockPlan{
			StartLocked: true,
			Source:      UnlockSourceIPC,
		}, nil
	}

	cmdCfg := &serverconfig.PassphraseCommandConfig{
		Argv: unlockCfg.PassphraseCommandArgv,
		Env:  unlockCfg.PassphraseCommandEnv,
		Verb: "read",
	}
	passphrase, err := serverconfig.RunPassphraseCommand(cmdCfg, nil)
	if err != nil {
		return nil, err
	}
	if err := crypto.VerifyPassphraseWithKeyring(passphrase, opts.Paths.KeystoreMetadataDir()); err != nil {
		crypto.ZeroBytes(passphrase)
		return nil, fmt.Errorf("passphrase from passphrase command does not match existing keystore")
	}

	return &UnlockPlan{
		StartLocked: false,
		Passphrase:  passphrase,
		Source:      UnlockSourcePassphraseCommand,
	}, nil
}
