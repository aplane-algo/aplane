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
	// ExternalChecks is set when a cosigner document that has external
	// checks would sign: they decide next.
	ExternalChecks *TryExternalChecks
	Summary        string
	Assumes        []string
}

// OutcomeConditionalApprove is the outcome word of a try the policy approves
// and an external check still decides, with no answer given for it: the
// cosigner signs only if its checks pass, and a try asks no source.
const OutcomeConditionalApprove = "conditional_approve"

// OutcomeWord is the result's outcome as a report and a saved case write it:
// the outcome's word, or OutcomeConditionalApprove when the policy approves
// and an external check without an answer then decides. An approval every
// applying check passed, or with no check that applies, is a plain approve;
// a check that refused makes the outcome a reject.
func (r TryResult) OutcomeWord() string {
	if r.Outcome == policyeval.Approve && r.ExternalChecks != nil && !r.ExternalChecks.decided() {
		return OutcomeConditionalApprove
	}
	return r.Outcome.String()
}

// Try asks what f's document decides for txn, as the signer's evaluator
// would, using networks to compile the document and resolve the network. Its
// external checks, if the policy approves, are left undecided.
func Try(f *File, txn TryTxn, networks Networks) (TryResult, error) {
	return TryWithAnswers(f, txn, nil, networks)
}

// TryWithAnswers is Try with the document's external checks judged on
// answers. An answer for a check the document does not have, one for a check
// that does not apply when the policy approves, and one its source could not
// give are errors. When a check refuses, the outcome is a reject and the
// refusal its first violation.
func TryWithAnswers(f *File, txn TryTxn, answers ExternalAnswers, networks Networks) (TryResult, error) {
	if f.Document == nil {
		return TryResult{}, fmt.Errorf("%s is not a valid policy document; fix its problems first", filepath.Base(f.Path))
	}
	if err := validateAnswers(f.Document, answers); err != nil {
		return TryResult{}, err
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
		Group: []types.Transaction{built},
		Slots: []policyeval.Slot{{Index: 0, Policy: cfg}},
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
	if f.Role == noderole.RoleCosigner && verdict.Outcome == policyeval.Approve && len(f.Document.ExternalChecks) > 0 {
		network, _ := networks.Resolver.NetworkForGenesisHashBytes(built.GenesisHash[:])
		x, err := judgeExternalChecks(cfg, built, network, f.Key, answers)
		if err != nil {
			return TryResult{}, err
		}
		result.ExternalChecks = x
		if x.Refusal != nil {
			result.Outcome = policyeval.Reject
			result.Violations = append(result.Violations, refusalViolation(x.Refusal))
		}
	}
	result.Summary = trySummary(result)
	result.Assumes = tryAssumptions(f.Role, f.Key, txn, built, networks, result.ExternalChecks)
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
		return cosignerTrySummary(r)
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

// cosignerTrySummary says what a cosigner document decides: it rejects, or
// it permits and the external checks that apply then pass, refuse, or still
// decide.
func cosignerTrySummary(r TryResult) string {
	permits := "this cosigner policy document permits the supplied transaction"
	x := r.ExternalChecks
	switch {
	case x != nil && x.Refusal != nil:
		return permits + ", but external check " + x.Refusal.CheckID + " refuses it"
	case r.Outcome != policyeval.Approve:
		return "this cosigner policy document rejects the supplied transaction"
	case x == nil:
		return permits
	case len(x.Apply) == 0:
		return permits + "; no external check applies to it"
	}
	var clauses []string
	if passed := x.passedChecks(); len(passed) > 0 {
		clauses = append(clauses, checksClause(passed, "passes", "pass")+" on the answers given")
	}
	if pending := x.pendingChecks(); len(pending) > 0 {
		clauses = append(clauses, "then "+checksClause(pending, "decides", "decide"))
	}
	return permits + "; " + strings.Join(clauses, ", ")
}

// checksClause names checks with a verb in the singular or the plural.
func checksClause(ids []string, one, many string) string {
	if len(ids) == 1 {
		return "external check " + ids[0] + " " + one
	}
	return "external checks " + joinAnd(ids) + " " + many
}

func tryAssumptions(role noderole.Role, key string, t TryTxn, built types.Transaction, networks Networks, x *TryExternalChecks) []string {
	out := []string{
		networks.Source,
		fmt.Sprintf("fee as entered: %d microAlgos", built.Fee),
	}
	if x != nil && len(x.Apply) > 0 {
		out = append(out, "no source is asked: a check is judged only on an answer given for it")
		if key == policy.DefaultKey {
			out = append(out, "the request's witness key is written as default; the cosigner writes the key the request is for")
		} else {
			out = append(out, "the request is for witness key "+key)
		}
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
		"the sender's key type (rotating, cosigned) is not known",
		"refusals the signer makes before policy are not checked",
	)
}
