// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"context"
	"errors"
	"fmt"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/serverconfig"

	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/signerapp/storemut"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/aplane-algo/aplane/internal/productmode"
)

var (
	errBadRequest   = errors.New("bad request")
	errCacheRefresh = errors.New("failed to refresh signer key cache")
)

type GenericLSigGenerator struct {
	Config    *serverconfig.ServerConfig
	MakeAlgod func(string, string) (*algod.Client, error)
	AuditLog  AuditLogger
}

func (g GenericLSigGenerator) GenerateContext(ctx context.Context, ir *identity.Runtime, keyType string, parameters map[string]string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	template, err := genericlsig.GetOrError(keyType)
	if err != nil {
		return "", fmt.Errorf("%w: unknown generic lsig type: %s", errBadRequest, keyType)
	}
	if g.Config == nil {
		return "", fmt.Errorf("TEAL compilation requires algod.testnet.server to be configured in config.yaml")
	}

	algodCfg, err := g.Config.GetTEALCompileAlgod()
	if err != nil || algodCfg.Server == "" {
		return "", fmt.Errorf("TEAL compilation requires algod.%s.server to be configured in config.yaml", g.Config.TEALCompileNetwork)
	}

	makeAlgod := g.MakeAlgod
	if makeAlgod == nil {
		makeAlgod = algod.MakeClient
	}
	algodClient, err := makeAlgod(algodCfg.Server, algodCfg.Token)
	if err != nil {
		return "", fmt.Errorf("failed to create algod client: %v", err)
	}

	normalized, err := lsigprovider.NormalizeCreationParams(parameters, template.CreationParams())
	if err != nil {
		return "", fmt.Errorf("%w: parameter normalization failed: %v", errBadRequest, err)
	}
	parameters = normalized

	// Validate before TEAL generation so user parameter errors keep the admin
	// bad-request classification instead of becoming generic generation errors.
	if err := template.ValidateCreationParams(parameters); err != nil {
		return "", fmt.Errorf("%w: parameter validation failed: %v", errBadRequest, err)
	}

	tealSource, err := template.GenerateTEAL(parameters)
	if err != nil {
		return "", fmt.Errorf("TEAL generation failed: %v", err)
	}

	salted, err := template.CompileWithSalt(ctx, parameters, algodClient)
	if err != nil {
		return "", fmt.Errorf("%s generation failed: %v", template.DisplayName(), err)
	}
	bytecode := salted.Bytecode
	address := salted.Address.String()
	saltCounter := salted.Counter

	mut := storemut.New(productmode.IdentityID, ir.KeyPaths(), nil, nil)
	signingArgs := keys.StoreSigningArgs(template.RuntimeArgs())
	opcodeProfile, err := lsigprovider.ResolveOpcodeProfile(template, false)
	if err != nil {
		return "", fmt.Errorf("%w: invalid LogicSig opcode profile: %v", errBadRequest, err)
	}
	if err := ir.WithKeyring(func(mk *crypto.Keyring) error {
		return mut.SaveGenericLSig(keyType, parameters, bytecode, saltCounter, salted.CompilerAutoSalted, tealSource, signingArgs, opcodeProfile, mk)
	}); err != nil {
		if errors.Is(err, keystore.ErrStoreLocked) {
			return "", err
		}
		return "", fmt.Errorf("failed to save %s file: %w", template.DisplayName(), err)
	}

	if _, err := ir.Reload(); err != nil {
		if errors.Is(err, keystore.ErrStoreLocked) {
			return "", err
		}
		return "", fmt.Errorf("%w: %v", errCacheRefresh, err)
	}

	if g.AuditLog != nil {
		g.AuditLog.LogKeyGenerated(productmode.IdentityID, address, keyType)
	}

	return address, nil
}
