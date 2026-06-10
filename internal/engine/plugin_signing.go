// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

// Plugin signing: mixed local/remote signing for external plugin transactions.

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/cache"
	apcrypto "github.com/aplane-algo/aplane/internal/crypto"

	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
)

// LocalSigner represents a plugin-controlled account that should be signed locally.
// This is used when a plugin generates ephemeral accounts or controls keys
// that aren't managed by the user's apsigner keystore.
type LocalSigner struct {
	Address   string // Algorand address
	SecretKey []byte // 64-byte Ed25519 secret key
}

// PluginSubmitResult is the engine-owned result for plugin transaction submission.
type PluginSubmitResult struct {
	TxIDs  []string
	Output string
}

func pluginAppCallInfo(txn types.Transaction) *signerapi.AppCallInfo {
	if txn.Type != types.ApplicationCallTx {
		return nil
	}
	return &signerapi.AppCallInfo{Mode: "raw"}
}

// SignAndSubmitWithLocalSigners handles mixed signing for external plugins.
// Transactions from localSigners are signed locally by apshell.
// All other transactions are sent to apsigner for signing via /plan -> local sign -> /sign.
//
// Flow:
//  1. /plan: server computes canonical group (dummies, fees, group ID) — no approval triggered
//  2. Client signs plugin-owned and dummy transactions locally using canonical bytes
//  3. /sign: server sees full group (passthrough for plugin-signed + dummies, sign-mode for server-managed),
//     runs policy + approval on full group, signs server-managed subset
//
// Edge case: if ALL transactions are plugin-owned (no server-managed), skip /plan and /sign
// entirely — do group building locally, sign everything locally, submit directly.
func (e *Engine) SignAndSubmitWithLocalSigners(txns []types.Transaction, localSigners []LocalSigner, lsigArgs []map[string][]byte) ([]string, error) {
	result, err := e.SignAndSubmitWithLocalSignersWithContext(context.Background(), txns, localSigners, lsigArgs)
	if result == nil {
		return nil, err
	}
	return result.TxIDs, err
}

func (e *Engine) SignAndSubmitWithLocalSignersWithContext(ctx context.Context, txns []types.Transaction, localSigners []LocalSigner, lsigArgs []map[string][]byte) (*PluginSubmitResult, error) {
	// Build lookup map for local signers
	localSignerKeys := make(map[string][]byte, len(localSigners))
	for _, signer := range localSigners {
		localSignerKeys[signer.Address] = signer.SecretKey
	}
	defer zeroLocalSignerKeys(localSignerKeys)

	// Check if all transactions are plugin-owned
	allPlugin := true
	for _, txn := range txns {
		if _, isLocal := localSignerKeys[txn.Sender.String()]; !isLocal {
			allPlugin = false
			break
		}
	}

	// Edge case: all-plugin group — no server-managed transactions
	if allPlugin {
		return e.SignAndSubmitAllLocalWithContext(ctx, txns, localSignerKeys)
	}

	// --- Phase 1: /plan — server computes canonical group ---

	planRequests := make([]signerapi.SignRequest, len(txns))
	for i, txn := range txns {
		sender := txn.Sender.String()
		txnHex := txnutil.EncodeWithPrefixHex(txn)

		if _, isLocal := localSignerKeys[sender]; isLocal {
			// Plugin-owned: foreign mode (TxnBytesHex only, no AuthAddress)
			planRequests[i] = signerapi.SignRequest{
				TxnBytesHex: txnHex,
			}
		} else {
			// Server-managed: sign mode
			effectiveSigner := sender
			if authAddr, exists := e.AuthCache.GetAuthAddress(sender); exists && authAddr != "" {
				effectiveSigner = authAddr
			}
			req := signerapi.SignRequest{
				AuthAddress: effectiveSigner,
				TxnSender:   sender,
				TxnBytesHex: txnHex,
				AppCallInfo: pluginAppCallInfo(txn),
			}
			if i < len(lsigArgs) && lsigArgs[i] != nil {
				req.LsigArgs = make(map[string]string, len(lsigArgs[i]))
				for name, value := range lsigArgs[i] {
					req.LsigArgs[name] = hex.EncodeToString(value)
				}
			}
			planRequests[i] = req
		}
	}

	planResp, err := e.RequestGroupPlanWithContext(ctx, planRequests)
	if err != nil {
		return nil, fmt.Errorf("group planning failed: %w", err)
	}

	// --- Decode canonical transactions from /plan response ---

	originalCount := len(txns)
	if len(planResp.Transactions) < originalCount {
		return nil, fmt.Errorf("group planning returned %d transaction(s), want at least %d", len(planResp.Transactions), originalCount)
	}
	canonicalTxns := make([]types.Transaction, len(planResp.Transactions))
	for i, txnHex := range planResp.Transactions {
		txn, err := txnutil.DecodePrefixedHex(txnHex)
		if err != nil {
			return nil, fmt.Errorf("failed to decode canonical transaction %d: %w", i, err)
		}
		canonicalTxns[i] = txn
	}

	// --- Phase 2: Sign plugin-owned and dummy transactions locally ---

	// Sign plugin-owned originals and dummy transactions locally, collect as passthrough
	type signedEntry struct {
		index   int
		stxnHex string
	}
	var localSigned []signedEntry

	for i, ctxn := range canonicalTxns {
		if i < originalCount {
			sender := ctxn.Sender.String()
			if secretKey, isLocal := localSignerKeys[sender]; isLocal {
				stxn, err := signing.SignWithRawKey(ctxn, secretKey, sender)
				if err != nil {
					return nil, fmt.Errorf("failed to sign local transaction %d for %s: %w", i, sender, err)
				}
				localSigned = append(localSigned, signedEntry{
					index:   i,
					stxnHex: hex.EncodeToString(msgpack.Encode(stxn)),
				})
			}
		} else {
			// Dummy transaction — sign locally
			stxn, err := signing.SignDummyTransaction(ctxn)
			if err != nil {
				return nil, fmt.Errorf("failed to sign dummy transaction %d: %w", i, err)
			}
			localSigned = append(localSigned, signedEntry{
				index:   i,
				stxnHex: hex.EncodeToString(msgpack.Encode(stxn)),
			})
		}
	}

	// Build index lookup for locally signed entries
	localSignedMap := make(map[int]string, len(localSigned))
	for _, entry := range localSigned {
		localSignedMap[entry.index] = entry.stxnHex
	}

	// --- Phase 3: /sign or /simulate — server signs its subset, sees full group ---

	signRequests := make([]signerapi.SignRequest, len(canonicalTxns))
	for i, ctxn := range canonicalTxns {
		if stxnHex, isLocalSigned := localSignedMap[i]; isLocalSigned {
			// Passthrough: plugin-signed or dummy-signed
			signRequests[i] = signerapi.SignRequest{
				SignedTxnHex: stxnHex,
			}
		} else {
			// Sign mode: server-managed (use canonical bytes from /plan)
			sender := ctxn.Sender.String()
			effectiveSigner := sender
			if authAddr, exists := e.AuthCache.GetAuthAddress(sender); exists && authAddr != "" {
				effectiveSigner = authAddr
			}
			req := signerapi.SignRequest{
				AuthAddress: effectiveSigner,
				TxnSender:   sender,
				TxnBytesHex: txnutil.EncodeWithPrefixHex(ctxn),
				AppCallInfo: pluginAppCallInfo(ctxn),
			}
			if i < len(lsigArgs) && lsigArgs[i] != nil {
				req.LsigArgs = make(map[string]string, len(lsigArgs[i]))
				for name, value := range lsigArgs[i] {
					req.LsigArgs[name] = hex.EncodeToString(value)
				}
			}
			signRequests[i] = req
		}
	}

	if e.Simulate {
		simResp, err := e.RequestGroupSimulateWithContext(ctx, signRequests)
		if err != nil {
			return nil, fmt.Errorf("server simulation failed: %w", err)
		}
		if simResp.Failed {
			return &PluginSubmitResult{TxIDs: simResp.TxIDs, Output: simResp.Output}, errorWithSubmissionOutput(signing.ErrSimulationFailed, simResp.Output)
		}
		return &PluginSubmitResult{TxIDs: simResp.TxIDs, Output: simResp.Output}, nil
	}

	signResp, err := e.RequestGroupSignWithContext(ctx, signRequests)
	if err != nil {
		return nil, fmt.Errorf("server signing failed: %w", err)
	}
	finalSignedTxns, err := decodeGroupSignResponse(signResp.Signed, len(signRequests))
	if err != nil {
		return nil, err
	}

	var output bytes.Buffer
	txIDs, err := signing.SubmitTransactionsWithContext(ctx, finalSignedTxns, e.AlgodClient, true, &output)
	return &PluginSubmitResult{TxIDs: txIDs, Output: output.String()}, errorWithSubmissionOutput(err, output.String())
}

// decodeGroupSignResponse validates a group-sign response against the request
// count and decodes each signed transaction. A truncated, padded, or partially
// empty response is rejected so a malformed signer reply can never submit an
// incomplete group.
func decodeGroupSignResponse(signed []string, want int) ([][]byte, error) {
	if len(signed) != want {
		return nil, fmt.Errorf("signer returned %d signed transaction(s), want %d", len(signed), want)
	}
	decoded := make([][]byte, len(signed))
	for i, hexStr := range signed {
		if hexStr == "" {
			return nil, fmt.Errorf("signer returned no signature for position %d", i+1)
		}
		signedBytes, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode signed transaction %d: %w", i+1, err)
		}
		decoded[i] = signedBytes
	}
	return decoded, nil
}

func (e *Engine) SignAndSubmitAllLocalWithContext(ctx context.Context, txns []types.Transaction, localSignerKeys map[string][]byte) (*PluginSubmitResult, error) {
	defer zeroLocalSignerKeys(localSignerKeys)

	// All plugin transactions are Ed25519 — no LSig budget needed, no dummies
	allTxns := txns

	// Assign group ID
	_, err := signing.AssignGroupID(allTxns)
	if err != nil {
		return nil, fmt.Errorf("failed to assign group ID: %w", err)
	}

	// Sign everything locally
	finalSignedTxns := make([][]byte, len(allTxns))
	finalSignedObjects := make([]types.SignedTxn, len(allTxns))
	for i, txn := range allTxns {
		sender := txn.Sender.String()
		secretKey, ok := localSignerKeys[sender]
		if !ok {
			return nil, fmt.Errorf("no local signer key for %s", sender)
		}
		stxn, err := signing.SignWithRawKey(txn, secretKey, sender)
		if err != nil {
			return nil, fmt.Errorf("failed to sign transaction %d for %s: %w", i, sender, err)
		}
		finalSignedObjects[i] = stxn
		finalSignedTxns[i] = msgpack.Encode(stxn)
	}

	if e.Simulate {
		var output bytes.Buffer
		txIDs, err := signing.SimulateSignedTransactionsWithContext(ctx, finalSignedObjects, e.AlgodClient, &output)
		return &PluginSubmitResult{TxIDs: txIDs, Output: output.String()}, errorWithSubmissionOutput(err, output.String())
	}

	var output bytes.Buffer
	txIDs, err := signing.SubmitTransactionsWithContext(ctx, finalSignedTxns, e.AlgodClient, true, &output)
	return &PluginSubmitResult{TxIDs: txIDs, Output: output.String()}, errorWithSubmissionOutput(err, output.String())
}

func zeroLocalSignerKeys(keys map[string][]byte) {
	for _, secretKey := range keys {
		apcrypto.ZeroBytes(secretKey)
	}
}

// BuildPluginContext constructs a jsonrpc.Context from the engine's caches.
// This provides plugins with account, asset, and address information.
func (e *Engine) BuildPluginContext() (jsonrpc.Context, error) {
	assets := buildPluginAssetContext(e.AsaCache.Assets)

	addressMap := make(map[string]string)
	for alias, address := range e.AliasCache.Aliases {
		addressMap[alias] = address
	}

	if err := e.EnsureSignerCache(); err != nil {
		return jsonrpc.Context{}, err
	}
	accounts := e.signerCacheAddresses()

	return jsonrpc.Context{
		Network:    e.Network,
		Accounts:   accounts,
		Assets:     assets,
		AddressMap: addressMap,
	}, nil
}

func buildPluginAssetContext(cacheAssets map[uint64]cache.ASAInfo) []jsonrpc.ContextAsset {
	assetIDs := make([]uint64, 0, len(cacheAssets))
	for assetID := range cacheAssets {
		assetIDs = append(assetIDs, assetID)
	}
	sort.Slice(assetIDs, func(i, j int) bool { return assetIDs[i] < assetIDs[j] })

	assets := make([]jsonrpc.ContextAsset, 0, len(assetIDs))
	for _, assetID := range assetIDs {
		asaInfo := cacheAssets[assetID]
		assets = append(assets, jsonrpc.ContextAsset{
			AssetID:  assetID,
			Name:     asaInfo.Name,
			UnitName: asaInfo.UnitName,
			Decimals: asaInfo.Decimals,
		})
	}

	return assets
}
