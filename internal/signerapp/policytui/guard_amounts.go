// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policytui

import (
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/policyview"
	"github.com/aplane-algo/aplane/internal/signerapp/asametadata"
)

var algoGuardMetadata = asa.Metadata{
	UnitName: "ALGO",
	Name:     "Algo",
	Decimals: 6,
	Source:   asa.SourceBuiltin,
}

func isAlgoGuardAsset(asset string) bool {
	return policyview.IsAlgoGuardAsset(asset)
}

func concreteASAIDFromGuardAsset(asset string) (uint64, bool) {
	return policyview.ConcreteASAIDFromGuardAsset(asset)
}

func assetSetNameFromGuardAsset(asset string) (string, bool) {
	return policyview.AssetSetNameFromGuardAsset(asset)
}

func concreteGuardNetworks(networks []string) []string {
	return policyview.ConcreteGuardNetworks(networks)
}

func (m Model) normalizeGuardAsset(raw string, networks []string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if isAlgoGuardAsset(raw) {
		return "algo", nil
	}
	if raw == "*" || strings.HasPrefix(raw, "@") {
		return raw, nil
	}
	if setName, ok := m.matchingAssetSetName(raw); ok {
		return "@" + setName, nil
	}
	if id, ok := concreteASAIDFromGuardAsset(raw); ok {
		return strconv.FormatUint(id, 10), nil
	}

	concreteNetworks := concreteGuardNetworks(networks)
	if len(concreteNetworks) != 1 {
		return "", fmt.Errorf("asset %q is not a numeric ASA ID; cached symbols require one concrete network", raw)
	}
	matches, err := asametadata.NewStore(m.dataDir).SearchLocal(concreteNetworks[0], raw)
	if err != nil {
		return "", err
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("asset %q not found in signer ASA metadata for %s; use a numeric ASA ID or cache the asset first", raw, concreteNetworks[0])
	case 1:
		return strconv.FormatUint(matches[0].AssetID, 10), nil
	default:
		return "", fmt.Errorf("asset symbol %q matches multiple ASAs on %s; use a numeric ASA ID", raw, concreteNetworks[0])
	}
}

func (m Model) formatOptionalGuardAmount(v *uint64, asset string, networks []string) string {
	if v == nil {
		return ""
	}
	meta, ok, err := m.guardAmountMetadata(asset, networks, false)
	if err != nil || !ok {
		return strconv.FormatUint(*v, 10)
	}
	return asa.FormatDisplayAmount(*v, meta)
}

func (m Model) parseOptionalGuardAmount(raw, asset string, networks []string) (*uint64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "-" {
		return nil, nil
	}
	meta, ok, err := m.guardAmountMetadata(asset, networks, true)
	if err != nil {
		return nil, err
	}
	if ok {
		v, err := asa.ParseDisplayAmount(raw, meta)
		if err != nil {
			return nil, err
		}
		return &v, nil
	}
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (m Model) guardAmountHint(asset string, networks []string) string {
	meta, ok, err := m.guardAmountMetadata(asset, networks, false)
	if err == nil && ok {
		return fmt.Sprintf("Use %s display units. Stored policy YAML remains raw base units.", asa.DisplayRef(meta))
	}
	if _, ok := concreteASAIDFromGuardAsset(asset); ok {
		return "Use ASA display units. appolicy resolves decimals from signer metadata when applying."
	}
	return "Use raw base units for wildcard or asset-set guards. Leave blank for no threshold."
}

func (m Model) guardAmountMetadata(asset string, networks []string, allowLive bool) (asa.Metadata, bool, error) {
	asset = strings.TrimSpace(asset)
	if isAlgoGuardAsset(asset) {
		return algoGuardMetadata, true, nil
	}
	if setName, ok := assetSetNameFromGuardAsset(asset); ok {
		return m.assetSetGuardAmountMetadata(setName, networks, allowLive)
	}
	assetID, ok := concreteASAIDFromGuardAsset(asset)
	if !ok {
		return asa.Metadata{}, false, nil
	}
	concreteNetworks := concreteGuardNetworks(networks)
	if len(concreteNetworks) != 1 {
		return asa.Metadata{}, false, fmt.Errorf("ASA display amount thresholds require one concrete network")
	}
	var cfg *serverconfig.ServerConfig
	if allowLive {
		cfg = m.serverConfigPtr()
	}
	meta, err := asametadata.NewStore(m.dataDir).MetadataByID(concreteNetworks[0], assetID, cfg, allowLive)
	if err != nil {
		return asa.Metadata{}, false, err
	}
	return meta, true, nil
}

func (m Model) assetSetGuardAmountMetadata(setName string, networks []string, allowLive bool) (asa.Metadata, bool, error) {
	if m.policy == nil || m.policy.TransferPolicy == nil {
		return asa.Metadata{}, false, nil
	}
	set, ok := m.policy.TransferPolicy.AssetSets[setName]
	if !ok {
		return asa.Metadata{}, false, fmt.Errorf("asset set @%s is not defined", setName)
	}
	concreteNetworks := concreteGuardNetworks(networks)
	if len(concreteNetworks) == 0 {
		return asa.Metadata{}, false, fmt.Errorf("asset-set display amounts require concrete networks")
	}
	var first *asa.Metadata
	var cfg *serverconfig.ServerConfig
	if allowLive {
		cfg = m.serverConfigPtr()
	}
	store := asametadata.NewStore(m.dataDir)
	for _, network := range concreteNetworks {
		ids := set[network]
		if len(ids) != 1 {
			return asa.Metadata{}, false, fmt.Errorf("asset set @%s must resolve to one ASA on %s for display amount editing", setName, network)
		}
		meta, err := store.MetadataByID(network, ids[0], cfg, allowLive)
		if err != nil {
			return asa.Metadata{}, false, err
		}
		if first == nil {
			first = &meta
			continue
		}
		if first.Decimals != meta.Decimals {
			return asa.Metadata{}, false, fmt.Errorf("asset set @%s uses different decimals across selected networks", setName)
		}
	}
	if first == nil {
		return asa.Metadata{}, false, nil
	}
	return *first, true, nil
}

func (m Model) serverConfigPtr() *serverconfig.ServerConfig {
	cfg, err := serverconfig.LoadServerConfig(m.dataDir)
	if err != nil {
		return nil
	}
	return &cfg
}
