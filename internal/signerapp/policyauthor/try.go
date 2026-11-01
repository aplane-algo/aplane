// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeval"
)

// Trying a transaction asks what one document decides for it, through the
// evaluator the signer itself uses. It answers for the policy layer only:
// the signer's fee adjustments, key types, the refusals made before policy,
// and which document the node actually applies are not modelled, and the
// result says so.

// Networks is the genesis-hash mapping a try uses, both to compile the
// document and to resolve the transaction's network, so the two agree.
type Networks struct {
	Resolver apconfig.GenesisHashNetworkResolver
	// Source says where the mapping came from, for the result.
	Source string
}

// BuiltinNetworks is the mapping of the built-in Algorand networks.
func BuiltinNetworks() Networks {
	return Networks{Resolver: apconfig.DefaultGenesisHashNetworkResolver(), Source: "built-in networks only"}
}

// genesisHash is the genesis hash a network token maps to.
func (n Networks) genesisHash(network string) (types.Digest, error) {
	var tokens []string
	for hash, token := range n.Resolver.Map() {
		if token != network {
			tokens = append(tokens, token)
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(hash)
		if err != nil || len(raw) != len(types.Digest{}) {
			return types.Digest{}, fmt.Errorf("network %q has an invalid genesis hash", network)
		}
		var d types.Digest
		copy(d[:], raw)
		return d, nil
	}
	sort.Strings(tokens)
	return types.Digest{}, fmt.Errorf("network %q is not known (known: %s)", network, strings.Join(tokens, ", "))
}

// TryTxn is the transaction to try. Amounts are base units: microAlgos for
// ALGO, raw units for an asset. A nonzero Asset makes it an asset transfer.
type TryTxn struct {
	Network  string
	Sender   string
	Receiver string
	Amount   uint64
	Asset    uint64
	Fee      uint64
	// CloseTo closes the sender's ALGO, or with Asset its asset holding, to
	// this address.
	CloseTo string
	// ClawbackFrom makes an asset transfer a clawback from this holder.
	ClawbackFrom string
	RekeyTo      string
	// RekeyTargetHeld answers "does this node hold the rekey target's key?",
	// which decides whether a rekey is foreign. Only a rekey reads it.
	RekeyTargetHeld bool
}

// TryResult is what the document decides, with the deciding rule and every
// rejection, a sentence saying it, and what the answer assumed.
type TryResult struct {
	Role       noderole.Role
	Outcome    policyeval.Outcome
	RuleID     string
	Violations []policy.LintViolation
	Summary    string
	Assumes    []string
}

// Try asks what f's document decides for txn, as the signer's evaluator
// would, using networks to compile the document and resolve the network.
func Try(f *File, txn TryTxn, networks Networks) (TryResult, error) {
	if f.Document == nil {
		return TryResult{}, fmt.Errorf("%s is not a valid policy document; fix its problems first", filepath.Base(f.Path))
	}
	cfg, err := f.Document.Compile(policy.DefaultConfigWithGenesisHashResolver(networks.Resolver))
	if err != nil {
		return TryResult{}, err
	}
	built, err := buildTryTxn(txn, networks)
	if err != nil {
		return TryResult{}, err
	}
	in := policyeval.Input{
		Group:    []types.Transaction{built},
		Slots:    []policyeval.Slot{{Index: 0, Policy: cfg}},
		Networks: networks.Resolver,
	}
	if f.Role == noderole.RoleCosigner {
		in.Role = policyeval.RoleCosigner
	} else {
		// One request with no dummies and no fee adjustment, as a plain
		// single-signature key would be signed.
		in.Plan = &policyeval.PlanFacts{RequestCount: 1, AuthAddressPresent: true}
		if txn.RekeyTo != "" && txn.RekeyTargetHeld {
			in.KnownAddresses = map[string]bool{built.RekeyTo.String(): true}
		}
	}
	verdict, err := policyeval.Evaluate(in)
	if err != nil {
		return TryResult{}, err
	}
	result := TryResult{
		Role:       f.Role,
		Outcome:    verdict.Outcome,
		RuleID:     verdict.RuleID,
		Violations: verdict.Violations,
	}
	result.Summary = trySummary(result)
	result.Assumes = tryAssumptions(f.Role, txn, built, networks)
	return result, nil
}

func buildTryTxn(t TryTxn, networks Networks) (types.Transaction, error) {
	network := t.Network
	if network == "" {
		network = "testnet"
	}
	genesis, err := networks.genesisHash(network)
	if err != nil {
		return types.Transaction{}, err
	}
	addr := func(field, value string, required bool) (types.Address, error) {
		if value == "" {
			if required {
				return types.Address{}, fmt.Errorf("%s is required", field)
			}
			return types.Address{}, nil
		}
		a, err := types.DecodeAddress(value)
		if err != nil {
			return types.Address{}, fmt.Errorf("%s: %q is not an Algorand address", field, value)
		}
		return a, nil
	}
	sender, err := addr("sender", t.Sender, true)
	if err != nil {
		return types.Transaction{}, err
	}
	receiver, err := addr("receiver", t.Receiver, true)
	if err != nil {
		return types.Transaction{}, err
	}
	closeTo, err := addr("close-to", t.CloseTo, false)
	if err != nil {
		return types.Transaction{}, err
	}
	clawbackFrom, err := addr("clawback-from", t.ClawbackFrom, false)
	if err != nil {
		return types.Transaction{}, err
	}
	rekeyTo, err := addr("rekey-to", t.RekeyTo, false)
	if err != nil {
		return types.Transaction{}, err
	}
	txn := types.Transaction{Header: types.Header{
		Sender:      sender,
		Fee:         types.MicroAlgos(t.Fee),
		FirstValid:  1,
		LastValid:   1000,
		GenesisHash: genesis,
		RekeyTo:     rekeyTo,
	}}
	if t.Asset == 0 {
		if !clawbackFrom.IsZero() {
			return types.Transaction{}, errors.New("clawback-from needs an asset")
		}
		txn.Type = types.PaymentTx
		txn.Receiver = receiver
		txn.Amount = types.MicroAlgos(t.Amount)
		txn.CloseRemainderTo = closeTo
		return txn, nil
	}
	txn.Type = types.AssetTransferTx
	txn.XferAsset = types.AssetIndex(t.Asset)
	txn.AssetReceiver = receiver
	txn.AssetAmount = t.Amount
	txn.AssetCloseTo = closeTo
	txn.AssetSender = clawbackFrom
	return txn, nil
}

func trySummary(r TryResult) string {
	if r.Role == noderole.RoleCosigner {
		if r.Outcome == policyeval.Approve {
			return "this cosigner policy document permits the supplied transaction"
		}
		return "this cosigner policy document rejects the supplied transaction"
	}
	switch r.Outcome {
	case policyeval.Reject:
		return "this document rejects the transaction"
	case policyeval.Review:
		if r.RuleID == "" {
			return "this document requires review; with user_auto_approve on, the signer signs it without a prompt"
		}
		return fmt.Sprintf("this document requires review (rule %s); with user_auto_approve on, the signer signs it without a prompt", r.RuleID)
	case policyeval.Approve:
		return fmt.Sprintf("this document approves it without review (rule %s)", r.RuleID)
	default:
		return "no rule in this document decides; the operator default applies"
	}
}

func tryAssumptions(role noderole.Role, t TryTxn, built types.Transaction, networks Networks) []string {
	out := []string{
		networks.Source,
		fmt.Sprintf("fee as entered: %d microAlgos", built.Fee),
	}
	if t.RekeyTo != "" && role != noderole.RoleCosigner {
		held := "no"
		if t.RekeyTargetHeld {
			held = "yes"
		}
		out = append(out, "the node holds the rekey target's key: "+held+" (as entered)")
	}
	if role == noderole.RoleCosigner {
		return append(out,
			"the cosigner holds the witness key",
			"this tests the document, not which document the cosigner applies or whether its deployed copy matches",
		)
	}
	return append(out,
		"no fee or dummies added by the signer for LogicSig or post-quantum keys",
		"the sender's key type (rotating, guarded) is not known",
		"refusals the signer makes before policy are not checked",
	)
}
