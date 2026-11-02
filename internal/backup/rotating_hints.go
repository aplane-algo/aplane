// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"encoding/hex"
	"math"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/stagetable"
)

// RotatingStageHint is an optional, sealed discovery candidate. Authentication
// of an archive does not establish that the stage is currently live.
type RotatingStageHint struct {
	Stage         uint64  `json:"stage"`
	ObservedRound *uint64 `json:"observed_round,omitempty"`
	Authorizer    string  `json:"authorizer,omitempty"`
	GenesisHash   string  `json:"genesis_hash"`
	KeyType       string  `json:"key_type"`
}

func SnapshotRotatingHints(tables *stagetable.Store) map[string]RotatingStageHint {
	out := make(map[string]RotatingStageHint)
	if tables == nil {
		return out
	}
	for _, o := range tables.Observations() {
		out[o.Account.String()] = RotatingStageHint{Stage: o.Hint.Stage, ObservedRound: o.Hint.Round, Authorizer: o.Hint.Authorizer.String(), GenesisHash: hex.EncodeToString(o.Genesis[:]), KeyType: o.KeyType}
	}
	return out
}

// validatedRotatingHint ignores unusable auxiliary metadata. A bad hint must
// never prevent restoring otherwise valid credentials or create authority.
func validatedRotatingHint(entry CredentialEntry, hints map[string]RotatingStageHint) *RotatingStageHint {
	h, ok := hints[entry.Selector]
	if !ok || entry.Category != keys.CategoryRotatingLsig || h.KeyType != entry.KeyType || h.Stage >= math.MaxUint64-1 {
		return nil
	}
	if h.Authorizer != "" {
		if _, err := types.DecodeAddress(h.Authorizer); err != nil {
			return nil
		}
	}
	payload, err := keys.ParsePayload(entry.KeyJSON)
	if err != nil {
		return nil
	}
	defer payload.ZeroSecrets()
	if h.GenesisHash != hex.EncodeToString(payload.GenesisHash) {
		return nil
	}
	return &h
}

// PublishRotatingHints runs only after the selected credentials have committed,
// under their lifecycle owner's mutation lock. It publishes no address records.
// Cache-only failures are warnings and cannot change the restore outcome.
func PublishRotatingHints(tables *stagetable.Store, hints map[string]RotatingStageHint, logf func(string, ...any)) {
	for account, h := range hints {
		addr, err := types.DecodeAddress(account)
		if err != nil {
			continue
		}
		genesis, err := hex.DecodeString(h.GenesisHash)
		if err != nil {
			continue
		}
		table, err := tables.Table(addr, genesis, nil, h.KeyType)
		if table != nil {
			var auth types.Address
			if h.Authorizer != "" {
				auth, _ = types.DecodeAddress(h.Authorizer)
			}
			err = table.SetHint(stagetable.Hint{Stage: h.Stage, Round: h.ObservedRound, Authorizer: auth, Source: "backup"})
		}
		if err != nil && logf != nil {
			logf("restored %s, but its optional rotating recovery hint was not saved: %v", account, err)
		}
	}
}

// LoadRebuildHints validates hints against the actual selected archive keys.
// Call only after a successful fresh-store commit, while still offline.
func LoadRebuildHints(source string, selectors []string, passphrase []byte) (map[string]RotatingStageHint, error) {
	manifest, err := OpenSealedManifest(source, passphrase)
	if err != nil {
		return nil, err
	}
	keysDir := ResolveBackupKeysDir(source)
	selected, err := normalizeCredentialSelectors(keysDir, selectors)
	if err != nil {
		return nil, err
	}
	out := make(map[string]RotatingStageHint)
	for _, selector := range selected {
		if _, ok := manifest.RotatingStageHints[selector]; !ok {
			continue
		}
		entry, err := inspectCredentialBackupEntry(keysDir, selector, passphrase, "signer")
		if err != nil {
			return nil, err
		}
		h := validatedRotatingHint(entry, manifest.RotatingStageHints)
		entry.ZeroSecrets()
		if h != nil {
			out[selector] = *h
		}
	}
	return out, nil
}
