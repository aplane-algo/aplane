// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"io"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/protocol"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	"github.com/aplane-algo/aplane/internal/storeinit"
)

// cmdInitialize initializes a new keystore with a passphrase.
// When a passphrase_command_argv helper is configured, the passphrase is
// stored via the helper after keystore creation.
func cmdInitialize(args []string) error {
	role, err := parseInitializeRole(args)
	if err != nil {
		return err
	}

	logInfof("Keystore Initialization")
	logInfof("=======================")

	// Get passphrase
	logInfof("choose a strong passphrase; it will be used to encrypt all keys")
	logInfof("you will need this passphrase to unlock the signer")

	var passphrase []byte
	for {
		fmt.Print("Enter passphrase: ")
		p, err := readPassword()
		if err != nil {
			return fmt.Errorf("failed to read passphrase: %w", err)
		}
		fmt.Println()

		if len(p) == 0 {
			logWarnf("passphrase cannot be empty; try again")
			continue
		}

		fmt.Print("Confirm passphrase: ")
		confirm, err := readPassword()
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}
		fmt.Println()

		if !bytes.Equal(p, confirm) {
			crypto.ZeroBytes(p)
			crypto.ZeroBytes(confirm)
			logWarnf("passphrases do not match; try again")
			continue
		}

		passphrase = p
		crypto.ZeroBytes(confirm)
		break
	}

	// Create keystore metadata
	defer crypto.ZeroBytes(passphrase)

	result, err := initializeStoreForCommand(passphrase, role)
	if err != nil {
		return err
	}
	if !result.Success {
		return resultError("keystore initialization failed", result.Code, result.Error)
	}

	logInfof("keystore initialized successfully")
	logInfof("  keystore metadata: %s/.keystore", result.MetadataDir)
	if result.HelperWarning != "" {
		logWarnf("%s", result.HelperWarning)
		logWarnf("store the passphrase manually in your secrets backend")
	}
	logInfof("start apsigner to unlock and use this keystore")

	return nil
}

var initializeStoreForCommand = initializeStoreLocal

const initializeUsage = "usage: apstore initialize [--role signer|sentry]"

func parseInitializeRole(args []string) (noderole.Role, error) {
	fs := flag.NewFlagSet("apstore initialize", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	roleArg := fs.String("role", string(noderole.DefaultRole()), "node role")
	if err := fs.Parse(args); err != nil {
		return "", errors.New(initializeUsage)
	}
	if fs.NArg() != 0 {
		return "", errors.New(initializeUsage)
	}
	role, err := noderole.ParseRole(*roleArg)
	if err != nil {
		return "", fmt.Errorf("invalid initialize role: %w", err)
	}
	return role, nil
}

func initializeStoreLocal(passphrase []byte, role noderole.Role) (protocol.InitializeStoreResultMessage, error) {
	var result protocol.InitializeStoreResultMessage
	unlockCfg, err := signerstartup.ResolveUnlockConfig(dataDirectory, productIdentityID(), &config)
	if err != nil {
		return result, fmt.Errorf("failed to resolve passphrase helper config: %w", err)
	}

	initResult, err := storeinit.Initialize(passphrase, storeinit.Options{
		DataDir:    dataDirectory,
		Paths:      keystorePaths(),
		IdentityID: productIdentityID(),
		Role:       role,
		Logf:       logInfof,
		// New stores use generation-based active storage
		// (docs/ARCH_GENERATIONS.md); older binaries reject them via the
		// keystore metadata version gate.
	})
	if err != nil {
		return protocol.InitializeStoreResultMessage{
			Success: false,
			Code:    "initialize_store_failed",
			Error:   err.Error(),
		}, nil
	}

	var helperWarning string
	if unlockCfg != nil && unlockCfg.HasPassphraseCommand() {
		passphraseCmdCfg := &serverconfig.PassphraseCommandConfig{
			Argv: unlockCfg.PassphraseCommandArgv,
			Env:  unlockCfg.PassphraseCommandEnv,
		}
		if err := serverconfig.WritePassphrase(passphraseCmdCfg, passphrase); err != nil {
			helperWarning = fmt.Sprintf("could not store passphrase via passphrase command helper: %v", err)
		}
	}

	return protocol.InitializeStoreResultMessage{
		Success:       true,
		MetadataDir:   initResult.MetadataDir,
		HelperWarning: helperWarning,
	}, nil
}
