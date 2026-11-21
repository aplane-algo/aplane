// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/sourcetokens"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// SetSourceToken sets token as source's token for a cosigner policy
// selector: a cosigner key the node holds, or "default" for the node default
// document. It replaces any token source had. The token is copied; the
// caller zeroes its own buffer.
//
// The change is an in-place write of the selected generation's
// source_tokens/<selector>.enc, as key generation and deletion are: no
// generation is minted. It runs under the store mutation lock on an unlocked
// cosigner node, and the token index is published once the write is
// durable. The result lists the selector's tokens without their values.
func (s Service) SetSourceToken(selector, source string, token []byte) ([]sourcetokens.Entry, *Error) {
	setAt := time.Now()
	return s.changeSourceTokens(selector, true, func(current *sourcetokens.File) (*sourcetokens.File, error) {
		return sourcetokens.SetToken(current, selector, source, token, setAt)
	})
}

// RemoveSourceToken removes source's token from a cosigner policy selector.
// Removing the selector's last token deletes its file: nothing is archived,
// so the deleted archive never keeps a removed token. Generations minted
// while the token was set keep their copy until they are pruned.
func (s Service) RemoveSourceToken(selector, source string) ([]sourcetokens.Entry, *Error) {
	return s.changeSourceTokens(selector, false, func(current *sourcetokens.File) (*sourcetokens.File, error) {
		return sourcetokens.RemoveToken(current, source)
	})
}

// MaxListedSourceTokenSelectors bounds a listing of every selector. One
// selector's listing holds at most eight tokens and eight sources, a few
// kilobytes, so this many fit one admin frame with room to spare. A listing
// of one selector is always whole.
const MaxListedSourceTokenSelectors = 512

// ListSourceTokens lists a cosigner node's tokens by source name and set
// time, never by value.
//
// With a selector it lists that one, and then "default" when the selector is
// a key that follows the node default, whose tokens serve its checks. Without
// one it lists every selector with a token or with a source that needs one,
// "default" first, at most MaxListedSourceTokenSelectors of them, and
// returns how many it left out.
//
// A selector's tokens serve the policy document keyed by it: a token is in
// use when a source of that document takes a token by its name, and unused
// otherwise; a source that takes a token the selector lacks is listed as
// needed. It reads the token files of the selected generation under the store
// mutation lock, beside the policy the runtime published from that
// generation, and zeroes every token it decrypts.
func (s Service) ListSourceTokens(selector string) ([]adminproto.SourceTokenSelector, int, *Error) {
	ir := s.Runtime
	if ir == nil {
		return nil, 0, &Error{Kind: ErrorInternal, Message: "product runtime is nil"}
	}
	if ir.NodeRole() != noderole.RoleCosigner {
		return nil, 0, &Error{Kind: ErrorInvalidInput, Message: "source tokens are kept only on a cosigner node"}
	}
	if selector != "" {
		if err := sourcetokens.ValidateSelector(selector); err != nil {
			return nil, 0, &Error{Kind: ErrorInvalidInput, Message: err.Error()}
		}
	}
	unlockMutation, lockErr := s.lockUnlockedMutation()
	if lockErr != nil {
		return nil, 0, lockErr
	}
	defer unlockMutation()
	np := ir.NodePolicy()
	if np == nil {
		return nil, 0, &Error{Kind: ErrorLocked, Message: "policy is not loaded; unlock the signer"}
	}
	var wanted []string
	if selector != "" {
		wanted = []string{selector}
		if selector != sourcetokens.DefaultSelector && !np.HasOwn(selector) {
			if _, err := ir.FindKeyFile(selector); err != nil {
				return nil, 0, &Error{Kind: ErrorNotFound, Message: "the node holds no cosigner key " + selector}
			}
			wanted = append(wanted, sourcetokens.DefaultSelector)
		}
	}
	active, err := ir.ActivePaths()
	if err != nil {
		return nil, 0, mapGenerateError(err)
	}
	var listings map[string][]sourcetokens.Entry
	err = ir.WithKeyring(func(kr *crypto.Keyring) error {
		var readErr error
		listings, readErr = sourcetokens.Listings(active, kr, wanted...)
		return readErr
	})
	if err != nil {
		return nil, 0, sourceTokenError(selector, err)
	}
	if wanted == nil {
		wanted = listedSelectors(np, listings)
	}
	out := make([]adminproto.SourceTokenSelector, 0, min(len(wanted), MaxListedSourceTokenSelectors))
	for _, listed := range wanted {
		listing := sourceTokenListing(np, listed, listings[listed])
		if selector == "" && len(listing.Tokens) == 0 {
			continue
		}
		out = append(out, listing)
	}
	omitted := 0
	if len(out) > MaxListedSourceTokenSelectors {
		out, omitted = out[:MaxListedSourceTokenSelectors], len(out)-MaxListedSourceTokenSelectors
	}
	return out, omitted, nil
}

// listedSelectors is every selector a listing of all might report: those
// with a token file and those with a document of their own, "default" first.
func listedSelectors(np *policyruntime.NodePolicy, listings map[string][]sourcetokens.Entry) []string {
	seen := map[string]bool{sourcetokens.DefaultSelector: true}
	for selector := range listings {
		seen[selector] = true
	}
	for selector := range np.Keys {
		seen[selector] = true
	}
	delete(seen, sourcetokens.DefaultSelector)
	return append([]string{sourcetokens.DefaultSelector}, slices.Sorted(maps.Keys(seen))...)
}

// sourceTokenListing reports selector's tokens against the document keyed by
// it: the node default for "default", the key's own document otherwise, and
// none for a key that follows the node default.
func sourceTokenListing(np *policyruntime.NodePolicy, selector string, entries []sourcetokens.Entry) adminproto.SourceTokenSelector {
	var doc *policy.Config
	if selector == sourcetokens.DefaultSelector {
		doc = np.Default
	} else {
		doc = np.Keys[selector]
	}
	listing := adminproto.SourceTokenSelector{Selector: selector, Policy: adminproto.SourceTokenPolicyDefault}
	if doc != nil || selector == sourcetokens.DefaultSelector {
		listing.Policy = adminproto.SourceTokenPolicyOwn
	}
	var sources map[string]policy.ExternalSourceV1
	if doc != nil {
		sources = doc.ExternalSources
	}
	listing.Sources = slices.Sorted(maps.Keys(sources))
	listing.Tokens = sourceTokenRows(sources, entries)
	return listing
}

// sourceTokenRows is each token set, in use when a source takes a token by
// its name and unused otherwise, and each source that takes a token none
// is set for, needed; sorted by source name.
func sourceTokenRows(sources map[string]policy.ExternalSourceV1, entries []sourcetokens.Entry) []adminproto.SourceTokenInfo {
	rows := make([]adminproto.SourceTokenInfo, 0, len(entries)+len(sources))
	set := make(map[string]bool, len(entries))
	for _, entry := range entries {
		set[entry.Source] = true
		state := adminproto.SourceTokenUnused
		if source, ok := sources[entry.Source]; ok && source.Token != nil {
			state = adminproto.SourceTokenInUse
		}
		rows = append(rows, adminproto.SourceTokenInfo{Source: entry.Source, SetAt: entry.SetAt, State: state})
	}
	for name, source := range sources {
		if source.Token != nil && !set[name] {
			rows = append(rows, adminproto.SourceTokenInfo{Source: name, State: adminproto.SourceTokenNeeded})
		}
	}
	slices.SortFunc(rows, func(a, b adminproto.SourceTokenInfo) int { return strings.Compare(a.Source, b.Source) })
	return rows
}

// sourceTokenChange is a pure change of one selector's token file: nil in,
// for a selector without one, and nil out, to delete it.
type sourceTokenChange func(current *sourcetokens.File) (*sourcetokens.File, error)

// sourceTokenRefusal is the change itself refused (a token or name outside
// the rules, a token past the cap, a source with no token to remove), as
// opposed to a failure to read or write the store.
type sourceTokenRefusal struct{ err error }

func (r sourceTokenRefusal) Error() string { return r.err.Error() }
func (r sourceTokenRefusal) Unwrap() error { return r.err }

func (s Service) changeSourceTokens(selector string, requireHeld bool, change sourceTokenChange) ([]sourcetokens.Entry, *Error) {
	ir := s.Runtime
	if ir == nil {
		return nil, &Error{Kind: ErrorInternal, Message: "product runtime is nil"}
	}
	if ir.NodeRole() != noderole.RoleCosigner {
		return nil, &Error{Kind: ErrorInvalidInput, Message: "source tokens are kept only on a cosigner node"}
	}
	if err := sourcetokens.ValidateSelector(selector); err != nil {
		return nil, &Error{Kind: ErrorInvalidInput, Message: err.Error()}
	}
	unlockMutation, lockErr := s.lockUnlockedMutation()
	if lockErr != nil {
		return nil, lockErr
	}
	defer unlockMutation()
	// The session the write begins in: the index is published only in it.
	generation, unlocked := ir.UnlockedGeneration()
	if !unlocked {
		return nil, &Error{Kind: ErrorLocked, Message: "signer is not unlocked"}
	}
	if requireHeld && selector != sourcetokens.DefaultSelector {
		if _, err := ir.FindKeyFile(selector); err != nil {
			return nil, &Error{Kind: ErrorNotFound, Message: "the node holds no cosigner key " + selector}
		}
	}
	active, err := ir.ActivePaths()
	if err != nil {
		return nil, mapGenerateError(err)
	}

	var next *sourcetokens.File
	defer func() { next.Zero() }()
	var writeErr error
	err = ir.WithKeyring(func(kr *crypto.Keyring) error {
		current, _, err := sourcetokens.ReadFile(active, selector, kr)
		if err != nil {
			return err
		}
		defer current.Zero()
		if next, err = change(current); err != nil {
			return sourceTokenRefusal{err}
		}
		if next == nil {
			writeErr = sourcetokens.RemoveFile(active, selector)
		} else {
			writeErr = sourcetokens.WriteFile(active, next, kr)
		}
		if writeErr != nil {
			// The file may or may not have changed (a directory sync that
			// failed after the rename leaves the new file in place). Publish
			// what it now holds, as a key watcher reload would for a key
			// write, so the runtime never serves a token the file does not.
			republishSourceTokensFromDisk(ir, generation, active, selector, kr)
		}
		return nil
	})
	if err != nil {
		return nil, sourceTokenError(selector, err)
	}
	if writeErr != nil {
		return nil, sourceTokenError(selector, writeErr)
	}
	ir.ReplaceSourceTokens(generation, selector, next)
	return next.Listing(), nil
}

// republishSourceTokensFromDisk publishes selector's tokens as its file holds
// them after a failed write, or none when the file cannot be read: a lookup
// then refuses rather than send a token the store may not keep.
func republishSourceTokensFromDisk(ir *productruntime.Runtime, generation uint64, active storepaths.GenPaths, selector string, kr *crypto.Keyring) {
	onDisk, _, err := sourcetokens.ReadFile(active, selector, kr)
	if err != nil {
		onDisk = nil
	}
	defer onDisk.Zero()
	ir.ReplaceSourceTokens(generation, selector, onDisk)
}

// sourceTokenError classifies a failed token change. No error here carries a
// token value: the sourcetokens package never puts one in an error.
func sourceTokenError(selector string, err error) *Error {
	var refusal sourceTokenRefusal
	switch {
	case isLockedStateError(err):
		return &Error{Kind: ErrorLocked, Message: "signer is locked"}
	case errors.As(err, &refusal) && errors.Is(err, sourcetokens.ErrTokenNotSet):
		return &Error{Kind: ErrorNotFound, Message: err.Error()}
	case errors.As(err, &refusal), errors.Is(err, sourcetokens.ErrFileTooLarge):
		return &Error{Kind: ErrorInvalidInput, Message: err.Error()}
	default:
		return &Error{Kind: ErrorInternal, Message: fmt.Sprintf("changing the source tokens of %s failed: %v", selector, err)}
	}
}

// SetSourceToken sets a source token for an admin session. The request's
// token is copied; the adapter zeroes its own buffer.
func (s IPCService) SetSourceToken(req adminproto.SetSourceTokenRequest) adminproto.SourceTokenChangeResult {
	entries, err := s.Service.SetSourceToken(req.Selector, req.Source, req.Token)
	return s.Service.sourceTokenChangeResult(req.Selector, req.Source, entries, err)
}

// RemoveSourceToken removes a source token for an admin session.
func (s IPCService) RemoveSourceToken(req adminproto.RemoveSourceTokenRequest) adminproto.SourceTokenChangeResult {
	entries, err := s.Service.RemoveSourceToken(req.Selector, req.Source)
	return s.Service.sourceTokenChangeResult(req.Selector, req.Source, entries, err)
}

// ListSourceTokens lists source tokens by name for an admin session.
func (s IPCService) ListSourceTokens(req adminproto.ListSourceTokensRequest) adminproto.ListSourceTokensResult {
	selectors, omitted, err := s.Service.ListSourceTokens(req.Selector)
	if err != nil {
		return adminproto.ListSourceTokensResult{Code: ipcCodeForErrorKind(err), Error: err.Message}
	}
	return adminproto.ListSourceTokensResult{Success: true, Selectors: selectors, Omitted: omitted}
}

// sourceTokenChangeResult reports a change with the selector's tokens after
// it, each with its state against the policy the runtime now holds.
func (s Service) sourceTokenChangeResult(selector, source string, entries []sourcetokens.Entry, err *Error) adminproto.SourceTokenChangeResult {
	if err != nil {
		return adminproto.SourceTokenChangeResult{Selector: selector, Source: source, Code: ipcCodeForErrorKind(err), Error: err.Message}
	}
	np := s.Runtime.NodePolicy()
	if np == nil {
		np = &policyruntime.NodePolicy{}
	}
	return adminproto.SourceTokenChangeResult{
		Success: true, Selector: selector, Source: source,
		Tokens: sourceTokenListing(np, selector, entries).Tokens,
	}
}
