// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strings"
)

// This file holds what a reviewer is told about a document's external
// sources and checks: the advisories on one document, and the differences
// between two.

const (
	// ConfigAdvisoryExternalFactAlwaysAbsent reports a check that uses a fact
	// some of the units it covers never have, so it refuses every one of them.
	ConfigAdvisoryExternalFactAlwaysAbsent = "external_check:fact_absent_for_covered_units"
	// ConfigAdvisoryExternalNetworkWithoutRoute reports a check for a network
	// no route covers: no transfer there reaches it.
	ConfigAdvisoryExternalNetworkWithoutRoute = "external_check:network_without_route"
	// ConfigAdvisoryExternalPlainHTTP reports a source reached over plain
	// http on loopback.
	ConfigAdvisoryExternalPlainHTTP = "external_check:plain_http_source"
	// ConfigAdvisoryExternalTokenNotSet reports a source that takes a token
	// the document's selector has none of, so every lookup to it refuses.
	// Advisories cannot report it, having no knowledge of tokens:
	// MissingTokenAdvisories does, given the selector's token names, for a
	// live policy apply (the token index), a rescue (the token files) and
	// appolicy check (the names an export's node context recorded).
	ConfigAdvisoryExternalTokenNotSet = "external_check:token_not_set"
)

// MissingTokenAdvisories reports each source of d that takes a token when
// names, the source names d's selector has a token for, lacks it: every
// lookup to that source refuses with token_not_set until one is set.
func (d *PolicyV1) MissingTokenAdvisories(names []string) []ConfigAdvisory {
	var out []ConfigAdvisory
	for _, name := range d.ExternalSourceNames() {
		if d.ExternalSources[name].Token == nil || slices.Contains(names, name) {
			continue
		}
		out = append(out, ConfigAdvisory{
			RuleID:  ConfigAdvisoryExternalTokenNotSet,
			Pointer: "/external_sources/" + escapeJSONPointer(name) + "/token",
			Message: fmt.Sprintf("source %s takes a token and %s has none set, so every lookup to it refuses; set one with apadmin source token set %s %s",
				name, d.Key, d.Key, name),
		})
	}
	return out
}

// externalCloseKinds are the movement kinds whose amount is not known when
// the transaction is signed.
var externalCloseKinds = []TransferMovementKind{TransferMovementPayClose, TransferMovementAssetClose}

// externalCheckAdvisories reports checks and sources that are valid but will
// surprise: a check that always refuses some of what it covers, a check no
// transfer reaches, and a source on plain http.
func (d *PolicyV1) externalCheckAdvisories() []ConfigAdvisory {
	var out []ConfigAdvisory
	add := func(ruleID, pointer, format string, args ...any) {
		out = append(out, ConfigAdvisory{RuleID: ruleID, Pointer: pointer, Message: fmt.Sprintf(format, args...)})
	}
	for _, name := range d.ExternalSourceNames() {
		if u, err := url.Parse(d.ExternalSources[name].BaseURL); err == nil && u.Scheme == "http" {
			add(ConfigAdvisoryExternalPlainHTTP, "/external_sources/"+escapeJSONPointer(name)+"/base_url",
				"source %s is reached over plain http on this machine; its answers and any token are not encrypted", name)
		}
	}
	for i, check := range d.ExternalChecks {
		cp := fmt.Sprintf("/external_checks/%d", i)
		used := check.UsedFacts()
		if slices.Contains(used, "rekey_to") {
			add(ConfigAdvisoryExternalFactAlwaysAbsent, cp,
				"check %s uses rekey_to, which only a rekey has, so it refuses every transaction that does not rekey", check.ID)
		}
		// The two facts below belong to movement checks only, so a check of
		// another scope never uses them.
		if kinds := coveredKinds(check, slices.Contains(used, "amount"), isCloseKind); len(kinds) > 0 {
			add(ConfigAdvisoryExternalFactAlwaysAbsent, cp,
				"check %s uses amount, which a close-out does not have, so it refuses every %s it sees; name the kinds it is for in movement_kinds", check.ID, strings.Join(kinds, " and "))
		}
		if kinds := coveredKinds(check, slices.Contains(used, "asset_source"), isNotClawback); len(kinds) > 0 {
			add(ConfigAdvisoryExternalFactAlwaysAbsent, cp,
				"check %s uses asset_source, which only a clawback has, so it refuses every %s it sees; name clawback alone in movement_kinds", check.ID, strings.Join(kinds, ", "))
		}
		for j, network := range check.Networks {
			if !d.routesCoverNetwork(network) {
				add(ConfigAdvisoryExternalNetworkWithoutRoute, fmt.Sprintf("%s/networks/%d", cp, j),
					"check %s names %s, which no route covers, so no transfer there reaches it", check.ID, network)
			}
		}
	}
	return out
}

// coveredKinds returns the movement kinds check covers that lack a fact it
// uses: those lacks picks out, when usesFact is set.
func coveredKinds(check ExternalCheckV1, usesFact bool, lacks func(TransferMovementKind) bool) []string {
	if !usesFact {
		return nil
	}
	var out []string
	for _, kind := range ExternalMovementKinds {
		if lacks(kind) && check.CoversMovementKind(kind) {
			out = append(out, string(kind))
		}
	}
	return out
}

func isCloseKind(kind TransferMovementKind) bool { return slices.Contains(externalCloseKinds, kind) }

func isNotClawback(kind TransferMovementKind) bool { return kind != TransferMovementClawback }

func (d *PolicyV1) routesCoverNetwork(network string) bool {
	for _, route := range d.Routes {
		if route.NetworkWildcard || slices.Contains(route.Networks, network) {
			return true
		}
	}
	return false
}

// externalChecks reports how next's sources and checks differ from current's.
// A check added makes the document refuse more and one removed less. A change
// inside a check or a source is reported as a change: whether it refuses more
// depends on what the source answers.
func (d *policyDiff) externalChecks(current, next *PolicyV1) {
	for _, name := range unionKeys(current.ExternalSources, next.ExternalSources) {
		path := "/external_sources/" + name
		c, hadC := current.ExternalSources[name]
		n, hasN := next.ExternalSources[name]
		switch {
		case !hadC:
			d.add(path, PolicyChangeNeutral, "source added: %s", n.BaseURL)
		case !hasN:
			d.add(path, PolicyChangeNeutral, "source removed: %s", c.BaseURL)
		default:
			d.text(path+"/base_url", c.BaseURL, n.BaseURL)
			if !reflect.DeepEqual(c.Token, n.Token) {
				d.add(path+"/token", PolicyChangeNeutral, "%s → %s", describeExternalToken(c.Token), describeExternalToken(n.Token))
			}
			if c.TimeoutMS != n.TimeoutMS {
				d.add(path+"/timeout_ms", PolicyChangeNeutral, "%d → %d", c.TimeoutMS, n.TimeoutMS)
			}
			if c.MaxResponseBytes != n.MaxResponseBytes {
				d.add(path+"/max_response_bytes", PolicyChangeNeutral, "%d → %d", c.MaxResponseBytes, n.MaxResponseBytes)
			}
			if !reflect.DeepEqual(c.TLSPins, n.TLSPins) {
				d.add(path+"/tls_spki_sha256", PolicyChangeNeutral, "%s → %s", describeExternalPins(c.TLSPins), describeExternalPins(n.TLSPins))
			}
		}
	}
	byID := func(checks []ExternalCheckV1) map[string]ExternalCheckV1 {
		out := make(map[string]ExternalCheckV1, len(checks))
		for _, check := range checks {
			out[check.ID] = check
		}
		return out
	}
	cur, nxt := byID(current.ExternalChecks), byID(next.ExternalChecks)
	for _, id := range unionKeys(cur, nxt) {
		path := "/external_checks/" + id
		c, hadC := cur[id]
		n, hasN := nxt[id]
		switch {
		case !hadC:
			d.add(path, PolicyChangeTightened, "check added: asks %s", n.Source)
		case !hasN:
			d.add(path, PolicyChangeLoosened, "check removed: no longer asks %s", c.Source)
		default:
			if fields := changedExternalCheckFields(c, n); len(fields) > 0 {
				d.add(path, PolicyChangeNeutral, "check changed: %s", strings.Join(fields, ", "))
			}
		}
	}
}

// changedExternalCheckFields names the document fields in which two checks of
// one ID differ, in canonical order.
func changedExternalCheckFields(c, n ExternalCheckV1) []string {
	var fields []string
	for _, f := range []struct {
		name     string
		cur, nxt any
	}{
		{"description", c.Description, n.Description},
		{"source", c.Source, n.Source},
		{"scope", c.Scope, n.Scope},
		{"networks", routeNetworksOf(c.NetworkWildcard, c.Networks), routeNetworksOf(n.NetworkWildcard, n.Networks)},
		{"movement_kinds", c.MovementKinds, n.MovementKinds},
		{"path", c.Path.Text, n.Path.Text},
		{"query", c.Query, n.Query},
		{"echo_pointer", c.EchoPointer, n.EchoPointer},
		{"require", c.Require, n.Require},
	} {
		if !reflect.DeepEqual(f.cur, f.nxt) {
			fields = append(fields, f.name)
		}
	}
	return fields
}

func routeNetworksOf(wildcard bool, networks []string) []string {
	if wildcard {
		return []string{"*"}
	}
	return networks
}

func describeExternalToken(token *ExternalTokenV1) string {
	if token == nil {
		return "no token"
	}
	return fmt.Sprintf("token in %s", token.Header)
}

func describeExternalPins(pins [][32]byte) string {
	switch len(pins) {
	case 0:
		return "system roots"
	case 1:
		return "1 pinned key"
	default:
		return fmt.Sprintf("%d pinned keys", len(pins))
	}
}
