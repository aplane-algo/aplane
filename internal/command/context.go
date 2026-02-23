// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package command

import (
	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/util"
)

// Context provides command handlers with access to REPL state (serializable for plugins)
type Context struct {
	Network  string
	AlgodURL string

	SignerURL   string
	IsConnected bool

	Aliases   map[string]string
	WriteMode bool
	Simulate  bool

	WorkingDir string

	// RawArgs contains the raw argument string before quote-stripping.
	// Used by commands like 'js' that need to preserve quotes in their input.
	RawArgs string

	Internal *InternalContext
}

// InternalContext holds non-serializable state (not sent to plugins)
type InternalContext struct {
	REPLState interface{}
	PluginAPI *PluginAPI
}

type PluginAPI struct {
	algodClient  *algod.Client
	network      string
	caches       *Caches
	signerClient *util.SignerClient
	txnWriter    func(types.Transaction, string)
}

type Caches struct {
	ASA    *util.ASACache
	Signer *util.SignerCache
	Auth   *util.AuthAddressCache
	Alias  *util.AliasCache
}

func NewPluginAPI(
	algodClient *algod.Client,
	network string,
	asaCache *util.ASACache,
	signerCache *util.SignerCache,
	authCache *util.AuthAddressCache,
	aliasCache *util.AliasCache,
	signerClient *util.SignerClient,
	txnWriter func(types.Transaction, string),
) *PluginAPI {
	return &PluginAPI{
		algodClient: algodClient,
		network:     network,
		caches: &Caches{
			ASA:    asaCache,
			Signer: signerCache,
			Auth:   authCache,
			Alias:  aliasCache,
		},
		signerClient: signerClient,
		txnWriter:    txnWriter,
	}
}

func (ctx *Context) Algod() *algod.Client {
	if ctx.Internal == nil || ctx.Internal.PluginAPI == nil {
		return nil
	}
	return ctx.Internal.PluginAPI.algodClient
}

func (ctx *Context) NetworkName() string {
	if ctx.Internal == nil || ctx.Internal.PluginAPI == nil {
		return ctx.Network // Fallback to serializable field
	}
	return ctx.Internal.PluginAPI.network
}

func (ctx *Context) GetCaches() *Caches {
	if ctx.Internal == nil || ctx.Internal.PluginAPI == nil {
		return nil
	}
	return ctx.Internal.PluginAPI.caches
}

func (ctx *Context) Signer() *util.SignerClient {
	if ctx.Internal == nil || ctx.Internal.PluginAPI == nil {
		return nil
	}
	return ctx.Internal.PluginAPI.signerClient
}

// WriteTxnCallback returns the TxnWriter callback for writing transaction JSON,
// or nil if write mode is disabled.
func (ctx *Context) WriteTxnCallback() func(types.Transaction, string) {
	if ctx.Internal == nil || ctx.Internal.PluginAPI == nil {
		return nil
	}
	return ctx.Internal.PluginAPI.txnWriter
}

// GetOrFetchLSig gets an LSig from cache or auto-fetches from Signer
