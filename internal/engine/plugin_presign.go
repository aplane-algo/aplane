// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

// Pre-sign planning: APlane canonicalizes an unsigned plugin-supplied group
// (/plan), verifies the plan preserved each plugin slot's artifact-bound fields,
// asks the plugin to sign the slots it owns over the canonical bytes (by reference,
// never exporting key material), then submits with apsigner signing the managed
// slots (/sign) — passthrough for plugin-signed and dummy slots.
//
// Scope: APlane-managed slots + plugin-callback-signed slots + budget dummies.
// Already-signed passthrough slots supplied in the draft (e.g. Mithras verifier
// LogicSigs) are a planned follow-on.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
)

// PluginSlotSigner signs the canonical (post-/plan) bytes for the plugin-owned
// slots. The dispatch layer supplies it (closing over the plugin manager's
// signTransactions callback). It must return exactly one signed entry per request.
type PluginSlotSigner func(requests []PluginSlotSignRequest) ([]PluginSlotSigned, error)

// PluginSlotSignRequest asks the plugin to sign one canonical slot it owns.
type PluginSlotSignRequest struct {
	Index     int
	Address   string
	SignerRef string
	Encoded   string // base64 canonical unsigned transaction msgpack
}

// PluginSlotSigned is one plugin-signed slot, keyed by request index.
type PluginSlotSigned struct {
	Index   int
	Encoded string // base64 signed transaction msgpack
}

// SignAndSubmitWithPluginSigners runs the pre-sign planning flow. pluginSignerRefs
// maps a slot sender address to its opaque signerRef; those slots are signed by the
// plugin via signSlots. All other slots are APlane-managed (apsigner sign-mode).
// pluginSlotSizes maps the same plugin-owned addresses to the byte size of the
// LogicSig the plugin will attach during the callback; it is forwarded to /plan as
// the foreign slot's lsig_size hint so the signer sizes the group's pooled LogicSig
// byte budget (and budget dummies) correctly. A nil/absent entry means size 0.
func (e *Engine) SignAndSubmitWithPluginSigners(
	ctx context.Context,
	txns []types.Transaction,
	pluginSignerRefs map[string]string,
	pluginSlotSizes map[string]int,
	signSlots PluginSlotSigner,
	lsigArgs []map[string][]byte,
) (*PluginSubmitResult, error) {
	if len(pluginSignerRefs) == 0 {
		return nil, fmt.Errorf("pre-sign planning requires at least one plugin signer")
	}
	managed := 0
	for _, txn := range txns {
		if _, owned := pluginSignerRefs[txn.Sender.String()]; !owned {
			managed++
		}
	}
	if managed == 0 {
		return nil, fmt.Errorf("pre-sign planning requires at least one APlane-managed slot; use pregrouped-signed for an all-plugin group")
	}
	// Every declared plugin signer must own a slot. Otherwise the plugin output is
	// malformed (presign-plan with no plugin-signed slot is just managed signing),
	// and the callback would silently no-op — reject instead of degrading.
	if err := assertPluginSignersMatched(txns, pluginSignerRefs); err != nil {
		return nil, err
	}

	// --- Phase 1: /plan — plugin slots foreign, managed slots sign-mode ---
	planRequests := make([]signerapi.SignRequest, len(txns))
	for i, txn := range txns {
		if _, owned := pluginSignerRefs[txn.Sender.String()]; owned {
			// Foreign slot (no key on this signer): declare its LogicSig byte size so
			// the planner counts it toward the pooled LogicSig budget and adds the
			// budget dummies the group needs to satisfy len(group)*1000 >= total
			// LogicSig bytes at submit. Without this the large verifier LogicSigs are
			// invisible to pool sizing and a Falcon-funded group overflows the pool.
			planRequests[i] = signerapi.SignRequest{
				TxnBytesHex: txnutil.EncodeWithPrefixHex(txn),
				LsigSize:    pluginSlotSizes[txn.Sender.String()],
			}
		} else {
			planRequests[i] = e.managedSignRequest(txn, lsigArgsAt(lsigArgs, i))
		}
	}

	planResp, err := e.RequestGroupPlanWithContext(ctx, planRequests)
	if err != nil {
		return nil, fmt.Errorf("group planning failed: %w", err)
	}
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

	// --- Guardrail: /plan must preserve EVERY original slot's artifact-bound fields ---
	// Only the group id and fee may change. For plugin-owned slots this protects the
	// plugin's HPKE envelope/proof. For APlane-managed slots it matters just as much:
	// a Falcon-funded Mithras deposit's funder payment + app-call carry HPKE-bound
	// fields (sender/firstValid/lastValid/lease/appId), so a re-stamp here would
	// silently mint an unspendable UTXO. The planner is not supposed to touch these
	// (it only pools fees and appends budget dummies), but enforce it rather than
	// trust an emergent property — a future planner change must not break deposits.
	for i := 0; i < originalCount; i++ {
		if err := assertSlotArtifactFieldsPreserved(txns[i], canonicalTxns[i]); err != nil {
			owner := "managed"
			if _, owned := pluginSignerRefs[txns[i].Sender.String()]; owned {
				owner = "plugin"
			}
			return nil, fmt.Errorf("plan modified %s slot %d: %w", owner, i, err)
		}
	}

	// --- Phase 2: gather plugin slots for the callback; sign dummies locally ---
	passthrough := make(map[int]string) // index -> signed txn hex
	var callbackReqs []PluginSlotSignRequest
	expected := make(map[int]types.Transaction)
	for i, ctxn := range canonicalTxns {
		if i < originalCount {
			if ref, owned := pluginSignerRefs[ctxn.Sender.String()]; owned {
				callbackReqs = append(callbackReqs, PluginSlotSignRequest{
					Index:     i,
					Address:   ctxn.Sender.String(),
					SignerRef: ref,
					Encoded:   base64.StdEncoding.EncodeToString(msgpack.Encode(ctxn)),
				})
				expected[i] = ctxn
			}
		} else {
			stxn, err := signing.SignDummyTransaction(ctxn)
			if err != nil {
				return nil, fmt.Errorf("failed to sign dummy transaction %d: %w", i, err)
			}
			passthrough[i] = hex.EncodeToString(msgpack.Encode(stxn))
		}
	}

	// --- Plugin signs its slots over the canonical bytes ---
	signed, err := signSlots(callbackReqs)
	if err != nil {
		return nil, fmt.Errorf("plugin signing failed: %w", err)
	}
	if len(signed) != len(callbackReqs) {
		return nil, fmt.Errorf("plugin returned %d signed slot(s), want %d", len(signed), len(callbackReqs))
	}
	for _, s := range signed {
		ctxn, ok := expected[s.Index]
		if !ok {
			return nil, fmt.Errorf("plugin signed unexpected slot %d", s.Index)
		}
		if _, dup := passthrough[s.Index]; dup {
			return nil, fmt.Errorf("plugin returned duplicate slot %d", s.Index)
		}
		signedHex, err := validatePluginSignedSlot(ctxn, s.Encoded)
		if err != nil {
			return nil, fmt.Errorf("plugin slot %d: %w", s.Index, err)
		}
		passthrough[s.Index] = signedHex
	}

	// --- Phase 3: /sign or /simulate — passthrough plugin+dummy, sign-mode managed ---
	signRequests := make([]signerapi.SignRequest, len(canonicalTxns))
	for i, ctxn := range canonicalTxns {
		if stxnHex, ok := passthrough[i]; ok {
			signRequests[i] = signerapi.SignRequest{SignedTxnHex: stxnHex}
			continue
		}
		signRequests[i] = e.managedSignRequest(ctxn, lsigArgsAt(lsigArgs, i))
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

// managedSignRequest builds an apsigner sign-mode request for a managed slot,
// resolving the auth address and attaching lsig args.
func (e *Engine) managedSignRequest(txn types.Transaction, lsigArgs map[string][]byte) signerapi.SignRequest {
	sender := txn.Sender.String()
	effectiveSigner := sender
	if authAddr, exists := e.AuthCache.GetAuthAddress(sender); exists && authAddr != "" {
		effectiveSigner = authAddr
	}
	req := signerapi.SignRequest{
		AuthAddress: effectiveSigner,
		TxnSender:   sender,
		TxnBytesHex: txnutil.EncodeWithPrefixHex(txn),
		AppCallInfo: pluginAppCallInfo(txn),
	}
	if len(lsigArgs) > 0 {
		req.LsigArgs = make(map[string]string, len(lsigArgs))
		for name, value := range lsigArgs {
			req.LsigArgs[name] = hex.EncodeToString(value)
		}
	}
	return req
}

func lsigArgsAt(lsigArgs []map[string][]byte, i int) map[string][]byte {
	if i < len(lsigArgs) {
		return lsigArgs[i]
	}
	return nil
}

// assertPluginSignersMatched verifies every declared plugin signer owns at least
// one transaction in the group (matched by sender). Senders are preserved by
// /plan, so this is checked up front on the draft.
func assertPluginSignersMatched(txns []types.Transaction, refs map[string]string) error {
	for addr := range refs {
		matched := false
		for _, txn := range txns {
			if txn.Sender.String() == addr {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("declared plugin signer %s matches no transaction in the group", addr)
		}
	}
	return nil
}

// assertSlotArtifactFieldsPreserved verifies /plan changed nothing on a slot except
// the group ID and fee. Any other change (sender, validity window, lease, genesis,
// amount, app id, args) could silently break a plugin slot's HPKE envelope or proof,
// or a managed funder slot's HPKE binding, so it is rejected. Applies to both
// plugin-owned and APlane-managed slots — only fee pooling and the group id are
// legitimate planning mutations.
func assertSlotArtifactFieldsPreserved(draft, canonical types.Transaction) error {
	d, c := draft, canonical
	d.Group, c.Group = types.Digest{}, types.Digest{}
	d.Fee, c.Fee = 0, 0
	if !bytes.Equal(msgpack.Encode(d), msgpack.Encode(c)) {
		return fmt.Errorf("an artifact-bound field changed during planning (only group id and fee may change)")
	}
	return nil
}

// validatePluginSignedSlot decodes a plugin-signed blob and verifies it signs the
// EXACT canonical transaction APlane planned — never a substitute. Returns the
// signed transaction as hex for passthrough.
func validatePluginSignedSlot(canonical types.Transaction, encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to decode signed bytes: %w", err)
	}
	var stxn types.SignedTxn
	if err := msgpack.Decode(raw, &stxn); err != nil {
		return "", fmt.Errorf("failed to decode signed transaction: %w", err)
	}
	if !bytes.Equal(msgpack.Encode(stxn.Txn), msgpack.Encode(canonical)) {
		return "", fmt.Errorf("signed transaction does not match the canonical bytes")
	}
	return hex.EncodeToString(raw), nil
}
