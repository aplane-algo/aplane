// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
)

// AssetLookup returns an asset's metadata on a network, and whether it is
// known. Explain uses it only to show amounts in display units; the document
// itself holds base units, which are always shown too.
type AssetLookup func(network string, assetID uint64) (asa.Metadata, bool)

const algoDecimals = 6

// Explain describes a valid document in plain language for a reviewer. It
// states only what the document says: offline, nothing tells which policy a
// node runs today. lookup may be nil, in which case ASA amounts are shown in
// base units.
func Explain(doc *policy.PolicyV1, lookup AssetLookup) string {
	e := explainer{doc: doc, lookup: lookup}
	return e.render()
}

type explainer struct {
	doc    *policy.PolicyV1
	lookup AssetLookup
	b      strings.Builder
}

func (e *explainer) line(format string, args ...any) {
	fmt.Fprintf(&e.b, format+"\n", args...)
}

func (e *explainer) render() string {
	d := e.doc
	role := "Signer"
	if d.Role == noderole.RoleCosigner {
		role = "Cosigner"
	}
	if d.IsDefault() {
		e.line("%s default document: governs every key that has no document of its own", role)
	} else {
		e.line("%s key document for %s", role, d.Key)
	}
	if d.Description != "" {
		e.line("Description: %s", d.Description)
	}

	e.line("")
	e.transactionTypes()
	e.guards()

	e.line("")
	e.transfers()

	if d.Role == noderole.RoleCosigner {
		e.line("")
		e.rekeys()
	}
	if len(d.AddressSets) > 0 || len(d.AssetSets) > 0 {
		e.line("")
		e.sets()
	}

	e.line("")
	e.line("Routes match a transaction's sender; this document governs whatever its key signs.")
	return e.b.String()
}

func (e *explainer) transactionTypes() {
	groups := map[policy.TransactionTypeVerdict][]string{}
	for _, name := range policy.TransactionTypeNames {
		v := e.doc.TransactionTypes.Verdict(name)
		groups[v] = append(groups[v], name)
	}
	for _, g := range []struct {
		verdict policy.TransactionTypeVerdict
		label   string
	}{
		{policy.TransactionTypeReject, "Rejected transaction types (always deny)"},
		{policy.TransactionTypeReview, "Reviewed transaction types (always review)"},
		{policy.TransactionTypeAllow, "Allowed transaction types (other rules still apply)"},
	} {
		if names := groups[g.verdict]; len(names) > 0 {
			e.line("%s: %s", g.label, strings.Join(names, ", "))
		}
	}
	if v, ok := e.doc.TransactionTypes[policy.TransactionTypeWildcard]; ok {
		e.line("Any other type: %s", v)
	}
}

func (e *explainer) guards() {
	d := e.doc
	var rejects []string
	if d.RejectCloseRemainder {
		rejects = append(rejects, "ALGO close-outs")
	}
	if d.RejectAssetClose {
		rejects = append(rejects, "ASA close-outs")
	}
	if d.RejectClawback {
		rejects = append(rejects, "clawbacks")
	}
	switch d.Rekeys {
	case policy.RekeysRejectAll:
		// A rotating account's own stage rotation is a protocol rekey, not one
		// this setting judges.
		rejects = append(rejects, "every rekey except a rotating account's own rotation")
	case policy.RekeysRejectForeign:
		rejects = append(rejects, "rekeys to an address this node does not hold and the account does not list")
	}
	if d.RejectRekey {
		// A listed rekey on a cosigned account never asks the cosigner.
		rejects = append(rejects, "every rekey asked of this cosigner")
	}
	if len(rejects) > 0 {
		e.line("Always denied: %s", strings.Join(rejects, "; "))
	}
	if d.MaxFeeMicroAlgos == 0 {
		e.line("Fee cap: none")
	} else {
		e.line("Fee cap: rejects a fee above %s", e.algo(d.MaxFeeMicroAlgos))
	}
	if d.AlwaysReviewWarnings {
		e.line("Warnings found by analysis are sent to review")
	}
	if d.AutoApproveSelfNoOpTransfer {
		e.selfNoOp()
	}
}

// selfNoOp describes auto_approve_self_noop_transfer as what it is: an
// Always Approve rule, reached only when no Always Deny or Always Review rule
// matched, for one narrow transaction shape.
func (e *explainer) selfNoOp() {
	var reachable []string
	for _, txType := range []string{"pay", "axfer"} {
		if e.doc.TransactionTypes.Verdict(txType) == policy.TransactionTypeAllow {
			reachable = append(reachable, txType)
		}
	}
	e.line("Self no-op auto-approval: a lone 0-amount payment or ASA transfer from an account to itself,")
	e.line("  with a fee of at most 0.001 ALGO and no note, lease, rekey, close or clawback, may be")
	e.line("  approved without review, but only when no deny or review rule matched it first")
	if len(reachable) == 0 {
		e.line("  (it never applies here: transaction_types does not allow pay or axfer)")
	} else if len(reachable) == 1 {
		e.line("  (only for %s here: transaction_types does not allow the other)", reachable[0])
	}
}

func (e *explainer) transfers() {
	d := e.doc
	if d.Role == noderole.RoleCosigner {
		e.line("Transfers: allowlist; a transfer no route allows is rejected")
	} else {
		if d.OnNoRoute == policy.TransferOnNoRouteReject && d.CloseOnNoRoute == policy.TransferOnNoRouteReject && d.ClawbackOnNoRoute == policy.TransferOnNoRouteReject {
			e.line("Transfers: allowlist; a transfer, close-out or clawback no route allows is rejected")
		} else {
			e.line("Transfers with no matching route: %s; close-outs: %s; clawbacks: %s",
				missAction(d.OnNoRoute), missAction(d.CloseOnNoRoute), missAction(d.ClawbackOnNoRoute))
		}
	}
	if len(d.BlockedDestinations) > 0 {
		var addrs []string
		for _, a := range d.BlockedDestinations {
			addrs = append(addrs, a.String())
		}
		e.line("Never to (checked before any route): %s", strings.Join(addrs, ", "))
	}
	if len(d.Routes) == 0 {
		e.line("Routes: none")
	} else {
		e.line("Routes:")
	}
	for _, r := range d.Routes {
		networks := "any network"
		if !r.NetworkWildcard {
			networks = strings.Join(r.Networks, ", ")
		}
		e.line("  %s: from %s to %s, assets %s, on %s", r.ID, terms(r.Sources), terms(r.Destinations), terms(r.Assets), networks)
		if r.Description != "" {
			e.line("    %s", r.Description)
		}
		if r.AllowClose {
			e.line("    close-outs to these destinations allowed")
		}
		if r.AllowClawback {
			e.line("    clawbacks allowed, from %s", terms(r.AssetSources))
		}
		e.limits("    ", r.Limits)
	}
	if len(d.Limits) > 0 {
		e.line("Ceilings for every transfer (route limits only add to these):")
		e.limits("  ", d.Limits)
	}
}

func (e *explainer) rekeys() {
	d := e.doc
	switch {
	case d.RejectRekey:
		e.line("Rekeys: every rekey asked of this cosigner is rejected; a listed rekey never asks it")
	case len(d.RekeyPolicy) == 0:
		e.line("Rekeys: every rekey asked of this cosigner is rejected (rekey_policy allows no edges); a listed rekey never asks it")
	default:
		e.line("Rekeys allowed along these edges, each as a zero-amount self-payment:")
		for _, r := range d.RekeyPolicy {
			sender := r.Sender
			if sender == "*" {
				sender = "any sender"
			}
			e.line("  %s to %s", sender, rekeyTargets(r.Targets))
		}
	}
}

func (e *explainer) sets() {
	d := e.doc
	for _, name := range sortedKeys(d.AddressSets) {
		set := d.AddressSets[name]
		if len(set.ByNetwork) == 0 {
			e.line("Address set @%s (every network):", name)
			e.addresses("  ", set.Flat)
			continue
		}
		e.line("Address set @%s:", name)
		for _, network := range sortedKeys(set.ByNetwork) {
			e.line("  %s:", network)
			e.addresses("    ", set.ByNetwork[network])
		}
	}
	for _, name := range sortedKeys(d.AssetSets) {
		e.line("Asset set @%s:", name)
		for _, network := range sortedKeys(d.AssetSets[name]) {
			var refs []string
			for _, ref := range d.AssetSets[name][network] {
				refs = append(refs, e.assetName(network, ref))
			}
			e.line("  %s: %s", network, strings.Join(refs, ", "))
		}
	}
}

// addresses writes one address per line, so a reviewer sees every member.
func (e *explainer) addresses(indent string, list []types.Address) {
	if len(list) == 0 {
		e.line("%s(none)", indent)
	}
	for _, a := range list {
		e.line("%s%s", indent, a.String())
	}
}

// limits writes one line per network and asset, in a fixed order.
func (e *explainer) limits(indent string, limits policy.LimitsV1) {
	for _, network := range sortedKeys(limits) {
		assets := limits[network]
		refs := make([]policy.TransferAssetRef, 0, len(assets))
		for ref := range assets {
			refs = append(refs, ref)
		}
		sort.Slice(refs, func(i, j int) bool {
			if refs[i].Algo != refs[j].Algo {
				return refs[i].Algo
			}
			return refs[i].ASAID < refs[j].ASAID
		})
		for _, ref := range refs {
			t := assets[ref]
			var parts []string
			if t.ReviewAbove != nil {
				parts = append(parts, "review above "+e.amount(network, ref, *t.ReviewAbove))
			}
			if t.RejectAbove != nil {
				parts = append(parts, "reject above "+e.amount(network, ref, *t.RejectAbove))
			}
			e.line("%s%s %s: %s", indent, network, e.assetName(network, ref), strings.Join(parts, ", "))
		}
	}
}

func (e *explainer) algo(raw uint64) string {
	return fmt.Sprintf("%s ALGO (%d microAlgos)", asa.FormatDisplayAmount(raw, asa.Metadata{Decimals: algoDecimals}), raw)
}

// amount shows raw base units of an asset, in display units too when the
// asset's decimals are known, with where they came from.
func (e *explainer) amount(network string, ref policy.TransferAssetRef, raw uint64) string {
	if ref.Algo {
		return e.algo(raw)
	}
	if meta, ok := e.meta(network, ref.ASAID); ok {
		return fmt.Sprintf("%s %s (%d base units; %d decimals, %s)", asa.FormatDisplayAmount(raw, meta), asa.DisplayRef(meta), raw, meta.Decimals, meta.Source)
	}
	return fmt.Sprintf("%d base units (decimals unknown)", raw)
}

func (e *explainer) assetName(network string, ref policy.TransferAssetRef) string {
	if ref.Algo {
		return "ALGO"
	}
	id := strconv.FormatUint(ref.ASAID, 10)
	if meta, ok := e.meta(network, ref.ASAID); ok && meta.UnitName != "" {
		return meta.UnitName + " (asa:" + id + ")"
	}
	return "asa:" + id
}

func (e *explainer) meta(network string, assetID uint64) (asa.Metadata, bool) {
	if e.lookup == nil {
		return asa.Metadata{}, false
	}
	return e.lookup(network, assetID)
}

func missAction(a policy.TransferOnNoRoute) string {
	if a == policy.TransferOnNoRouteOperatorDefault {
		return "left to the operator default"
	}
	return string(a)
}

// terms lists route address or asset terms as written, naming the wildcard.
// rekeyTargets renders a rekey rule's targets: "*" is any address, and "self"
// is the sender's own address, a rekey back to the account's own key.
func rekeyTargets(list []string) string {
	out := make([]string, len(list))
	for i, t := range list {
		switch t {
		case "*":
			out[i] = "any address"
		case "self":
			out[i] = "its own address"
		default:
			out[i] = t
		}
	}
	return strings.Join(out, ", ")
}

func terms(list []string) string {
	out := make([]string, len(list))
	for i, t := range list {
		switch t {
		case "*":
			out[i] = "any"
		default:
			out[i] = t
		}
	}
	return strings.Join(out, ", ")
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
