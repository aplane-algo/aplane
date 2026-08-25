// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	apconfig "github.com/aplane-algo/aplane/internal/config"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"gopkg.in/yaml.v3"
)

const transferPolicySchemaVersion = 1

const (
	TransferOnNoRouteReject          TransferOnNoRoute = "reject"
	TransferOnNoRouteReview          TransferOnNoRoute = "review"
	TransferOnNoRouteOperatorDefault TransferOnNoRoute = "operator_default"
)

// TransferOnNoRoute controls routing's verdict for an in-scope movement that
// matches no route.
type TransferOnNoRoute string

// StoredTransferPolicy is the YAML representation of transfer routing policy.
// It is intentionally stricter than the legacy top-level policy loader: unknown
// fields under transfer_policy and under routes fail closed.
type StoredTransferPolicy struct {
	SchemaVersion       int                         `yaml:"schema_version,omitempty"`
	Enabled             *bool                       `yaml:"enabled,omitempty"`
	OnNoRoute           *string                     `yaml:"on_no_route,omitempty"`
	CloseOnNoRoute      *string                     `yaml:"close_on_no_route,omitempty"`
	ClawbackOnNoRoute   *string                     `yaml:"clawback_on_no_route,omitempty"`
	BlockedDestinations []string                    `yaml:"blocked_destinations,omitempty"`
	AddressSets         map[string]StoredAddressSet `yaml:"address_sets,omitempty"`
	AssetSets           map[string]StoredAssetSet   `yaml:"asset_sets,omitempty"`
	Routes              []StoredTransferRoute       `yaml:"routes,omitempty"`
	RoutesSet           bool                        `yaml:"-"`
}

// Clone returns a deep copy of the stored transfer routing policy.
func (p *StoredTransferPolicy) Clone() *StoredTransferPolicy {
	if p == nil {
		return nil
	}
	cp := *p
	cp.Enabled = cloneBoolPtr(p.Enabled)
	cp.OnNoRoute = cloneStringPtr(p.OnNoRoute)
	cp.CloseOnNoRoute = cloneStringPtr(p.CloseOnNoRoute)
	cp.ClawbackOnNoRoute = cloneStringPtr(p.ClawbackOnNoRoute)
	cp.BlockedDestinations = append([]string(nil), p.BlockedDestinations...)
	if p.AddressSets != nil {
		cp.AddressSets = make(map[string]StoredAddressSet, len(p.AddressSets))
		for name, set := range p.AddressSets {
			cp.AddressSets[name] = set.Clone()
		}
	}
	if p.AssetSets != nil {
		cp.AssetSets = make(map[string]StoredAssetSet, len(p.AssetSets))
		for name, set := range p.AssetSets {
			cp.AssetSets[name] = set.Clone()
		}
	}
	cp.Routes = cloneStoredTransferRoutes(p.Routes)
	return &cp
}

// StoredAddressSet accepts either a flat list of addresses or a map from
// network context token to addresses.
type StoredAddressSet struct {
	Flat      []string
	ByNetwork map[string][]string
}

// Clone returns a deep copy of the stored address set.
func (s StoredAddressSet) Clone() StoredAddressSet {
	return StoredAddressSet{
		Flat:      append([]string(nil), s.Flat...),
		ByNetwork: cloneStringSliceMap(s.ByNetwork),
	}
}

type StoredAssetSet map[string][]uint64

// Clone returns a deep copy of the stored asset set.
func (s StoredAssetSet) Clone() StoredAssetSet {
	if s == nil {
		return nil
	}
	out := make(StoredAssetSet, len(s))
	for network, ids := range s {
		out[network] = append([]uint64(nil), ids...)
	}
	return out
}

type StoredTransferRoute struct {
	ID              string                        `yaml:"id"`
	Description     string                        `yaml:"description,omitempty"`
	Enabled         *bool                         `yaml:"enabled,omitempty"`
	Networks        []string                      `yaml:"networks"`
	Sources         []string                      `yaml:"sources"`
	AssetSources    []string                      `yaml:"asset_sources,omitempty"`
	Assets          []StoredAssetTerm             `yaml:"assets"`
	Destinations    []string                      `yaml:"destinations"`
	Limits          *StoredAmountLimits           `yaml:"limits,omitempty"`
	LimitsByNetwork map[string]StoredAmountLimits `yaml:"limits_by_network,omitempty"`
	Close           StoredRoutePermission         `yaml:"close,omitempty"`
	Clawback        StoredRoutePermission         `yaml:"clawback,omitempty"`
}

// Clone returns a deep copy of the stored transfer route.
func (r StoredTransferRoute) Clone() StoredTransferRoute {
	cp := r
	cp.Networks = append([]string(nil), r.Networks...)
	cp.Sources = append([]string(nil), r.Sources...)
	cp.AssetSources = append([]string(nil), r.AssetSources...)
	cp.Assets = append([]StoredAssetTerm(nil), r.Assets...)
	cp.Destinations = append([]string(nil), r.Destinations...)
	cp.Enabled = cloneBoolPtr(r.Enabled)
	cp.Limits = r.Limits.Clone()
	cp.LimitsByNetwork = cloneStoredAmountLimitsMap(r.LimitsByNetwork)
	cp.Close = r.Close.Clone()
	cp.Clawback = r.Clawback.Clone()
	return cp
}

type StoredAssetTerm struct {
	Raw string
}

type StoredAmountLimits struct {
	ReviewAbove *uint64 `yaml:"review_above,omitempty"`
	RejectAbove *uint64 `yaml:"reject_above,omitempty"`
}

// Clone returns a deep copy of the stored amount limits.
func (l *StoredAmountLimits) Clone() *StoredAmountLimits {
	if l == nil {
		return nil
	}
	return &StoredAmountLimits{
		ReviewAbove: cloneUint64Ptr(l.ReviewAbove),
		RejectAbove: cloneUint64Ptr(l.RejectAbove),
	}
}

type StoredRoutePermission struct {
	Allow *bool `yaml:"allow,omitempty"`
}

// Clone returns a deep copy of the stored route permission.
func (p StoredRoutePermission) Clone() StoredRoutePermission {
	return StoredRoutePermission{Allow: cloneBoolPtr(p.Allow)}
}

// TransferPolicy is the compiled effective routing policy attached to a policy
// Config. The unexported set maps are retained so key_overrides can layer
// sparse transfer_policy blocks over product-wide policy.
type TransferPolicy struct {
	Enabled             bool
	OnNoRoute           TransferOnNoRoute
	CloseOnNoRoute      TransferOnNoRoute
	ClawbackOnNoRoute   TransferOnNoRoute
	BlockedDestinations map[types.Address]struct{}
	AddressSets         map[string]compiledAddressSet
	AssetSets           map[string]compiledAssetSet
	Routes              []CompiledTransferRoute
	routeIDIndex        map[string]struct{}
}

type CompiledTransferRoute struct {
	ID              string
	Description     string
	Enabled         bool
	NetworkWildcard bool
	Networks        map[string]struct{}
	Sources         compiledAddressTerms
	AssetSources    compiledAddressTerms
	Assets          compiledAssetTerms
	Destinations    compiledAddressTerms
	Limits          *AmountLimits
	LimitsByNetwork map[string]AmountLimits
	AllowClose      bool
	AllowClawback   bool
}

type AmountLimits struct {
	ReviewAbove *uint64
	RejectAbove *uint64
}

type compiledAddressSet struct {
	Flat      []types.Address
	ByNetwork map[string][]types.Address
}

type compiledAssetSet struct {
	ByNetwork map[string][]uint64
}

type compiledAddressTerms struct {
	Wildcard bool
	Self     bool
	Direct   []types.Address
	Sets     []string
}

type compiledAssetTerms struct {
	Wildcard bool
	Algo     bool
	ASAIDs   []uint64
	Sets     []string
}

func (p *StoredTransferPolicy) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("transfer_policy must be a mapping")
	}
	allowed := map[string]struct{}{
		"schema_version":       {},
		"enabled":              {},
		"on_no_route":          {},
		"close_on_no_route":    {},
		"clawback_on_no_route": {},
		"blocked_destinations": {},
		"address_sets":         {},
		"asset_sets":           {},
		"routes":               {},
	}
	type rawPolicy struct {
		SchemaVersion       int                         `yaml:"schema_version"`
		Enabled             *bool                       `yaml:"enabled,omitempty"`
		OnNoRoute           *string                     `yaml:"on_no_route,omitempty"`
		CloseOnNoRoute      *string                     `yaml:"close_on_no_route,omitempty"`
		ClawbackOnNoRoute   *string                     `yaml:"clawback_on_no_route,omitempty"`
		BlockedDestinations []string                    `yaml:"blocked_destinations,omitempty"`
		AddressSets         map[string]StoredAddressSet `yaml:"address_sets,omitempty"`
		AssetSets           map[string]StoredAssetSet   `yaml:"asset_sets,omitempty"`
		Routes              []StoredTransferRoute       `yaml:"routes,omitempty"`
	}
	var raw rawPolicy
	for i := 0; i < len(value.Content); i += 2 {
		key := value.Content[i].Value
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("unknown field %q", key)
		}
		if key == "routes" {
			p.RoutesSet = true
		}
	}
	if err := value.Decode(&raw); err != nil {
		return err
	}
	p.SchemaVersion = raw.SchemaVersion
	p.Enabled = raw.Enabled
	p.OnNoRoute = raw.OnNoRoute
	p.CloseOnNoRoute = raw.CloseOnNoRoute
	p.ClawbackOnNoRoute = raw.ClawbackOnNoRoute
	p.BlockedDestinations = raw.BlockedDestinations
	p.AddressSets = raw.AddressSets
	p.AssetSets = raw.AssetSets
	p.Routes = raw.Routes
	return nil
}

func (p StoredTransferPolicy) MarshalYAML() (any, error) {
	type rawPolicyNoRoutes struct {
		SchemaVersion       int                         `yaml:"schema_version,omitempty"`
		Enabled             *bool                       `yaml:"enabled,omitempty"`
		OnNoRoute           *string                     `yaml:"on_no_route,omitempty"`
		CloseOnNoRoute      *string                     `yaml:"close_on_no_route,omitempty"`
		ClawbackOnNoRoute   *string                     `yaml:"clawback_on_no_route,omitempty"`
		BlockedDestinations []string                    `yaml:"blocked_destinations,omitempty"`
		AddressSets         map[string]StoredAddressSet `yaml:"address_sets,omitempty"`
		AssetSets           map[string]StoredAssetSet   `yaml:"asset_sets,omitempty"`
	}
	type rawPolicyWithRoutes struct {
		SchemaVersion       int                         `yaml:"schema_version,omitempty"`
		Enabled             *bool                       `yaml:"enabled,omitempty"`
		OnNoRoute           *string                     `yaml:"on_no_route,omitempty"`
		CloseOnNoRoute      *string                     `yaml:"close_on_no_route,omitempty"`
		ClawbackOnNoRoute   *string                     `yaml:"clawback_on_no_route,omitempty"`
		BlockedDestinations []string                    `yaml:"blocked_destinations,omitempty"`
		AddressSets         map[string]StoredAddressSet `yaml:"address_sets,omitempty"`
		AssetSets           map[string]StoredAssetSet   `yaml:"asset_sets,omitempty"`
		Routes              []StoredTransferRoute       `yaml:"routes"`
	}
	if p.RoutesSet || len(p.Routes) > 0 {
		routes := p.Routes
		if routes == nil {
			routes = []StoredTransferRoute{}
		}
		return rawPolicyWithRoutes{
			SchemaVersion:       p.SchemaVersion,
			Enabled:             p.Enabled,
			OnNoRoute:           p.OnNoRoute,
			CloseOnNoRoute:      p.CloseOnNoRoute,
			ClawbackOnNoRoute:   p.ClawbackOnNoRoute,
			BlockedDestinations: p.BlockedDestinations,
			AddressSets:         p.AddressSets,
			AssetSets:           p.AssetSets,
			Routes:              routes,
		}, nil
	}
	return rawPolicyNoRoutes{
		SchemaVersion:       p.SchemaVersion,
		Enabled:             p.Enabled,
		OnNoRoute:           p.OnNoRoute,
		CloseOnNoRoute:      p.CloseOnNoRoute,
		ClawbackOnNoRoute:   p.ClawbackOnNoRoute,
		BlockedDestinations: p.BlockedDestinations,
		AddressSets:         p.AddressSets,
		AssetSets:           p.AssetSets,
	}, nil
}

func (s *StoredAddressSet) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.SequenceNode:
		var flat []string
		if err := value.Decode(&flat); err != nil {
			return err
		}
		s.Flat = flat
		return nil
	case yaml.MappingNode:
		byNetwork := make(map[string][]string)
		for i := 0; i < len(value.Content); i += 2 {
			key := value.Content[i].Value
			var addresses []string
			if err := value.Content[i+1].Decode(&addresses); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
			byNetwork[key] = addresses
		}
		s.ByNetwork = byNetwork
		return nil
	default:
		return fmt.Errorf("address set must be a list of addresses or a network map")
	}
}

func (s StoredAddressSet) MarshalYAML() (any, error) {
	if s.ByNetwork != nil {
		return s.ByNetwork, nil
	}
	return s.Flat, nil
}

func (r *StoredTransferRoute) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("route must be a mapping")
	}
	allowed := map[string]struct{}{
		"id":                {},
		"description":       {},
		"enabled":           {},
		"networks":          {},
		"sources":           {},
		"asset_sources":     {},
		"assets":            {},
		"destinations":      {},
		"limits":            {},
		"limits_by_network": {},
		"close":             {},
		"clawback":          {},
	}
	for i := 0; i < len(value.Content); i += 2 {
		key := value.Content[i].Value
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("route: unknown field %q", key)
		}
	}
	type rawRoute StoredTransferRoute
	var raw rawRoute
	if err := value.Decode(&raw); err != nil {
		return err
	}
	*r = StoredTransferRoute(raw)
	return nil
}

func (t *StoredAssetTerm) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("asset term must be a scalar")
	}
	t.Raw = value.Value
	return nil
}

func (t StoredAssetTerm) MarshalYAML() (any, error) {
	return t.Raw, nil
}

func (p *StoredRoutePermission) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("permission block must be a mapping")
	}
	for i := 0; i < len(value.Content); i += 2 {
		if key := value.Content[i].Value; key != "allow" {
			return fmt.Errorf("permission block: unknown field %q", key)
		}
	}
	var raw struct {
		Allow *bool `yaml:"allow,omitempty"`
	}
	if err := value.Decode(&raw); err != nil {
		return err
	}
	p.Allow = raw.Allow
	return nil
}

func (p StoredRoutePermission) IsZero() bool {
	return p.Allow == nil
}

func (tp *TransferPolicy) Clone() *TransferPolicy {
	if tp == nil {
		return nil
	}
	cp := *tp
	cp.BlockedDestinations = cloneAddressSetMap(tp.BlockedDestinations)
	cp.AddressSets = cloneCompiledAddressSets(tp.AddressSets)
	cp.AssetSets = cloneCompiledAssetSets(tp.AssetSets)
	cp.Routes = cloneCompiledRoutes(tp.Routes)
	cp.routeIDIndex = cloneStringSet(tp.routeIDIndex)
	return &cp
}

// Apply layers a stored transfer_policy block over an inherited compiled
// transfer policy and returns a compiled effective policy.
func (p *StoredTransferPolicy) Apply(base *TransferPolicy) (*TransferPolicy, error) {
	if p == nil {
		if base == nil {
			return nil, nil
		}
		return base.Clone(), nil
	}
	if p.SchemaVersion != transferPolicySchemaVersion {
		if p.SchemaVersion == 0 {
			return nil, fmt.Errorf("schema_version is required")
		}
		return nil, fmt.Errorf("unsupported schema_version %d", p.SchemaVersion)
	}
	if p.Enabled == nil {
		return nil, fmt.Errorf("enabled is required")
	}

	effective := &TransferPolicy{
		CloseOnNoRoute:    TransferOnNoRouteReject,
		ClawbackOnNoRoute: TransferOnNoRouteReject,
		AddressSets:       make(map[string]compiledAddressSet),
		AssetSets:         make(map[string]compiledAssetSet),
	}
	if base != nil {
		effective = base.Clone()
	}
	if effective.AddressSets == nil {
		effective.AddressSets = make(map[string]compiledAddressSet)
	}
	if effective.AssetSets == nil {
		effective.AssetSets = make(map[string]compiledAssetSet)
	}

	effective.Enabled = *p.Enabled
	if p.OnNoRoute != nil {
		onNoRoute, err := parseTransferOnNoRoute("on_no_route", *p.OnNoRoute)
		if err != nil {
			return nil, err
		}
		effective.OnNoRoute = onNoRoute
	}
	if p.CloseOnNoRoute != nil {
		closeOnNoRoute, err := parseTransferOnNoRoute("close_on_no_route", *p.CloseOnNoRoute)
		if err != nil {
			return nil, err
		}
		effective.CloseOnNoRoute = closeOnNoRoute
	}
	if p.ClawbackOnNoRoute != nil {
		clawbackOnNoRoute, err := parseTransferOnNoRoute("clawback_on_no_route", *p.ClawbackOnNoRoute)
		if err != nil {
			return nil, err
		}
		effective.ClawbackOnNoRoute = clawbackOnNoRoute
	}
	if effective.CloseOnNoRoute == "" {
		effective.CloseOnNoRoute = TransferOnNoRouteReject
	}
	if effective.ClawbackOnNoRoute == "" {
		effective.ClawbackOnNoRoute = TransferOnNoRouteReject
	}
	if effective.Enabled && effective.OnNoRoute == "" {
		return nil, fmt.Errorf("on_no_route is required when enabled is true")
	}

	blockedDestinations, err := compileBlockedDestinations(p.BlockedDestinations)
	if err != nil {
		return nil, err
	}
	if len(blockedDestinations) > 0 {
		if effective.BlockedDestinations == nil {
			effective.BlockedDestinations = make(map[types.Address]struct{}, len(blockedDestinations))
		}
		for addr := range blockedDestinations {
			effective.BlockedDestinations[addr] = struct{}{}
		}
	}

	for name, set := range p.AddressSets {
		compiled, err := compileAddressSet(name, set)
		if err != nil {
			return nil, err
		}
		effective.AddressSets[name] = compiled
	}
	for name, set := range p.AssetSets {
		compiled, err := compileAssetSet(name, set)
		if err != nil {
			return nil, err
		}
		effective.AssetSets[name] = compiled
	}

	if p.RoutesSet {
		routes, err := compileTransferRoutes(p.Routes, effective.AddressSets, effective.AssetSets)
		if err != nil {
			return nil, err
		}
		effective.Routes = routes
	}
	effective.routeIDIndex = make(map[string]struct{}, len(effective.Routes))
	for _, route := range effective.Routes {
		effective.routeIDIndex[route.ID] = struct{}{}
	}

	return effective, nil
}

func parseTransferOnNoRoute(field, raw string) (TransferOnNoRoute, error) {
	switch TransferOnNoRoute(raw) {
	case TransferOnNoRouteReject, TransferOnNoRouteReview, TransferOnNoRouteOperatorDefault:
		return TransferOnNoRoute(raw), nil
	default:
		return "", fmt.Errorf("invalid %s %q", field, raw)
	}
}

func compileBlockedDestinations(raw []string) (map[types.Address]struct{}, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make(map[types.Address]struct{}, len(raw))
	for _, term := range raw {
		switch {
		case term == "self":
			return nil, fmt.Errorf("blocked_destinations: self is not valid")
		case term == "*":
			return nil, fmt.Errorf("blocked_destinations: * is not valid")
		case strings.HasPrefix(term, "@"):
			return nil, fmt.Errorf("blocked_destinations: address sets are not valid")
		}
		addr, err := types.DecodeAddress(term)
		if err != nil {
			return nil, fmt.Errorf("blocked_destinations: invalid address %q: %w", term, err)
		}
		out[addr] = struct{}{}
	}
	return out, nil
}

func compileAddressSet(name string, set StoredAddressSet) (compiledAddressSet, error) {
	if err := validateSetName(name); err != nil {
		return compiledAddressSet{}, fmt.Errorf("address_sets[%s]: %w", name, err)
	}
	if len(set.Flat) == 0 && len(set.ByNetwork) == 0 {
		return compiledAddressSet{}, fmt.Errorf("address_sets[%s] must not be empty", name)
	}
	if len(set.Flat) > 0 && len(set.ByNetwork) > 0 {
		return compiledAddressSet{}, fmt.Errorf("address_sets[%s] cannot mix flat and network-specific shapes", name)
	}
	out := compiledAddressSet{}
	if len(set.Flat) > 0 {
		addrs, err := parseAddresses(set.Flat)
		if err != nil {
			return compiledAddressSet{}, fmt.Errorf("address_sets[%s]: %w", name, err)
		}
		if len(addrs) == 0 {
			return compiledAddressSet{}, fmt.Errorf("address_sets[%s] must not be empty", name)
		}
		out.Flat = addrs
		return out, nil
	}
	out.ByNetwork = make(map[string][]types.Address, len(set.ByNetwork))
	for network, rawAddrs := range set.ByNetwork {
		if network == "*" {
			return compiledAddressSet{}, fmt.Errorf("address_sets[%s]: * is not a valid network key", name)
		}
		if err := apconfig.ValidateNetworkID(network); err != nil {
			return compiledAddressSet{}, fmt.Errorf("address_sets[%s]: %w", name, err)
		}
		addrs, err := parseAddresses(rawAddrs)
		if err != nil {
			return compiledAddressSet{}, fmt.Errorf("address_sets[%s][%s]: %w", name, network, err)
		}
		if len(addrs) == 0 {
			return compiledAddressSet{}, fmt.Errorf("address_sets[%s][%s] must not be empty", name, network)
		}
		out.ByNetwork[network] = addrs
	}
	return out, nil
}

func compileAssetSet(name string, set StoredAssetSet) (compiledAssetSet, error) {
	if err := validateSetName(name); err != nil {
		return compiledAssetSet{}, fmt.Errorf("asset_sets[%s]: %w", name, err)
	}
	if len(set) == 0 {
		return compiledAssetSet{}, fmt.Errorf("asset_sets[%s] must not be empty", name)
	}
	out := compiledAssetSet{ByNetwork: make(map[string][]uint64, len(set))}
	for network, ids := range set {
		if network == "*" {
			return compiledAssetSet{}, fmt.Errorf("asset_sets[%s]: * is not a valid network key", name)
		}
		if err := apconfig.ValidateNetworkID(network); err != nil {
			return compiledAssetSet{}, fmt.Errorf("asset_sets[%s]: %w", name, err)
		}
		if len(ids) == 0 {
			return compiledAssetSet{}, fmt.Errorf("asset_sets[%s][%s] must not be empty", name, network)
		}
		seen := make(map[uint64]struct{}, len(ids))
		for _, id := range ids {
			if id == 0 {
				return compiledAssetSet{}, fmt.Errorf("asset_sets[%s][%s]: 0 is not a valid ASA ID", name, network)
			}
			seen[id] = struct{}{}
		}
		out.ByNetwork[network] = sortedUintSet(seen)
	}
	return out, nil
}

func compileTransferRoutes(routes []StoredTransferRoute, addressSets map[string]compiledAddressSet, assetSets map[string]compiledAssetSet) ([]CompiledTransferRoute, error) {
	out := make([]CompiledTransferRoute, 0, len(routes))
	seen := make(map[string]struct{}, len(routes))
	for i, route := range routes {
		compiled, err := compileTransferRoute(route, addressSets, assetSets)
		if err != nil {
			return nil, fmt.Errorf("routes[%d]: %w", i, err)
		}
		if _, ok := seen[compiled.ID]; ok {
			return nil, fmt.Errorf("duplicate route id %q", compiled.ID)
		}
		seen[compiled.ID] = struct{}{}
		out = append(out, compiled)
	}
	return out, nil
}

func compileTransferRoute(route StoredTransferRoute, addressSets map[string]compiledAddressSet, assetSets map[string]compiledAssetSet) (CompiledTransferRoute, error) {
	if err := validateRouteID(route.ID); err != nil {
		return CompiledTransferRoute{}, err
	}
	networkWildcard, networks, err := compileNetworks(route.Networks)
	if err != nil {
		return CompiledTransferRoute{}, err
	}
	sources, err := compileAddressTerms("sources", route.Sources, addressSets, false)
	if err != nil {
		return CompiledTransferRoute{}, err
	}
	assetSources, err := compileAddressTerms("asset_sources", route.AssetSources, addressSets, false)
	if err != nil {
		return CompiledTransferRoute{}, err
	}
	assets, err := compileAssetTerms(route.Assets, assetSets)
	if err != nil {
		return CompiledTransferRoute{}, err
	}
	destinations, err := compileAddressTerms("destinations", route.Destinations, addressSets, true)
	if err != nil {
		return CompiledTransferRoute{}, err
	}
	enabled := true
	if route.Enabled != nil {
		enabled = *route.Enabled
	}
	allowClose := route.Close.Allow != nil && *route.Close.Allow
	allowClawback := route.Clawback.Allow != nil && *route.Clawback.Allow
	if len(route.AssetSources) > 0 && !allowClawback {
		return CompiledTransferRoute{}, fmt.Errorf("asset_sources requires clawback.allow:true")
	}
	if allowClawback && len(route.AssetSources) == 0 {
		return CompiledTransferRoute{}, fmt.Errorf("clawback.allow:true requires asset_sources")
	}
	if len(route.AssetSources) > 0 && destinations.Self {
		return CompiledTransferRoute{}, fmt.Errorf("self is not allowed in clawback route destinations")
	}
	if assetSources.Self {
		return CompiledTransferRoute{}, fmt.Errorf("self is not allowed in asset_sources")
	}
	if allowClose && destinations.Wildcard {
		return CompiledTransferRoute{}, fmt.Errorf("close.allow:true with wildcard destinations is not supported")
	}
	compiled := CompiledTransferRoute{
		ID:              route.ID,
		Description:     route.Description,
		Enabled:         enabled,
		NetworkWildcard: networkWildcard,
		Networks:        networks,
		Sources:         sources,
		AssetSources:    assetSources,
		Assets:          assets,
		Destinations:    destinations,
		Limits:          compileAmountLimits(route.Limits),
		LimitsByNetwork: compileLimitsByNetwork(route.LimitsByNetwork),
		AllowClose:      allowClose,
		AllowClawback:   allowClawback,
	}
	if err := validateRouteLimits(compiled, assetSets); err != nil {
		return CompiledTransferRoute{}, err
	}
	return compiled, nil
}

func compileNetworks(raw []string) (bool, map[string]struct{}, error) {
	if len(raw) == 0 {
		return false, nil, fmt.Errorf("networks is required")
	}
	if len(raw) == 1 && raw[0] == "*" {
		return true, nil, nil
	}
	networks := make(map[string]struct{}, len(raw))
	for _, network := range raw {
		if network == "*" {
			return false, nil, fmt.Errorf("networks must be [\"*\"] or concrete tokens, not mixed")
		}
		if err := apconfig.ValidateNetworkID(network); err != nil {
			return false, nil, err
		}
		networks[network] = struct{}{}
	}
	return false, networks, nil
}

func compileAddressTerms(label string, raw []string, sets map[string]compiledAddressSet, allowSelf bool) (compiledAddressTerms, error) {
	if len(raw) == 0 && label != "asset_sources" {
		return compiledAddressTerms{}, fmt.Errorf("%s is required", label)
	}
	var out compiledAddressTerms
	for _, term := range raw {
		switch {
		case term == "*":
			out.Wildcard = true
		case term == "self":
			if !allowSelf {
				return compiledAddressTerms{}, fmt.Errorf("self is not allowed in %s", label)
			}
			out.Self = true
		case strings.HasPrefix(term, "@"):
			name := strings.TrimPrefix(term, "@")
			if _, ok := sets[name]; !ok {
				return compiledAddressTerms{}, fmt.Errorf("unresolved address set %q in %s", name, label)
			}
			out.Sets = append(out.Sets, name)
		default:
			addr, err := types.DecodeAddress(term)
			if err != nil {
				return compiledAddressTerms{}, fmt.Errorf("invalid address %q in %s: %w", term, label, err)
			}
			out.Direct = append(out.Direct, addr)
		}
	}
	return out, nil
}

func compileAssetTerms(raw []StoredAssetTerm, sets map[string]compiledAssetSet) (compiledAssetTerms, error) {
	if len(raw) == 0 {
		return compiledAssetTerms{}, fmt.Errorf("assets is required")
	}
	var out compiledAssetTerms
	for _, term := range raw {
		rawTerm := strings.TrimSpace(term.Raw)
		switch {
		case rawTerm == "algo":
			out.Algo = true
		case rawTerm == "*":
			out.Wildcard = true
		case strings.HasPrefix(rawTerm, "@"):
			name := strings.TrimPrefix(rawTerm, "@")
			if _, ok := sets[name]; !ok {
				return compiledAssetTerms{}, fmt.Errorf("unresolved asset set %q", name)
			}
			out.Sets = append(out.Sets, name)
		case strings.HasPrefix(rawTerm, "asa:"):
			id, err := parseASAID(strings.TrimPrefix(rawTerm, "asa:"))
			if err != nil {
				return compiledAssetTerms{}, err
			}
			out.ASAIDs = append(out.ASAIDs, id)
		default:
			id, err := parseASAID(rawTerm)
			if err != nil {
				return compiledAssetTerms{}, fmt.Errorf("invalid asset term %q", rawTerm)
			}
			out.ASAIDs = append(out.ASAIDs, id)
		}
	}
	return out, nil
}

func compileAmountLimits(limits *StoredAmountLimits) *AmountLimits {
	if limits == nil {
		return nil
	}
	return &AmountLimits{
		ReviewAbove: cloneUint64Ptr(limits.ReviewAbove),
		RejectAbove: cloneUint64Ptr(limits.RejectAbove),
	}
}

func compileLimitsByNetwork(in map[string]StoredAmountLimits) map[string]AmountLimits {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]AmountLimits, len(in))
	for network, limits := range in {
		out[network] = AmountLimits{
			ReviewAbove: cloneUint64Ptr(limits.ReviewAbove),
			RejectAbove: cloneUint64Ptr(limits.RejectAbove),
		}
	}
	return out
}

func validateRouteLimits(route CompiledTransferRoute, assetSets map[string]compiledAssetSet) error {
	if !hasAnyLimits(route.Limits, route.LimitsByNetwork) {
		return nil
	}
	if route.Assets.Wildcard {
		return fmt.Errorf("active amount limits are not allowed with wildcard assets")
	}
	routeNetworks := routeLimitNetworks(route, assetSets)
	if len(routeNetworks) == 0 && !route.NetworkWildcard {
		routeNetworks = sortedStringSet(route.Networks)
	}
	if len(route.LimitsByNetwork) > 0 {
		for network, limits := range route.LimitsByNetwork {
			if err := apconfig.ValidateNetworkID(network); err != nil {
				return err
			}
			if !route.NetworkWildcard {
				if _, ok := route.Networks[network]; !ok {
					return fmt.Errorf("limits_by_network[%s] is not included in route networks", network)
				}
			}
			if err := validateThresholdOrder(limits); err != nil {
				return fmt.Errorf("limits_by_network[%s]: %w", network, err)
			}
		}
	}
	if route.Limits != nil {
		if err := validateThresholdOrder(*route.Limits); err != nil {
			return fmt.Errorf("limits: %w", err)
		}
	}
	for _, network := range routeNetworks {
		assets := routeAssetsForNetwork(route.Assets, assetSets, network)
		if len(assets) > 1 {
			return fmt.Errorf("active amount limits require one asset unit per network")
		}
	}
	if len(routeNetworks) == 0 {
		assets := routeAssetsForNetwork(route.Assets, assetSets, "")
		if len(assets) > 1 {
			return fmt.Errorf("active amount limits require one asset unit per network")
		}
	}
	if route.Limits != nil && len(route.Assets.Sets) > 0 {
		var first *assetUnit
		for _, network := range routeNetworks {
			assets := routeAssetsForNetwork(route.Assets, assetSets, network)
			if len(assets) == 0 {
				continue
			}
			unit := assets[0]
			if first == nil {
				first = &unit
				continue
			}
			if *first != unit {
				return fmt.Errorf("global limits cannot span asset sets that resolve to different ASA IDs across networks")
			}
		}
	}
	return nil
}

func validateThresholdOrder(limits AmountLimits) error {
	if limits.ReviewAbove != nil && limits.RejectAbove != nil && *limits.RejectAbove < *limits.ReviewAbove {
		return fmt.Errorf("reject_above must be greater than or equal to review_above")
	}
	return nil
}

func hasAnyLimits(limits *AmountLimits, byNetwork map[string]AmountLimits) bool {
	if limits != nil && (limits.ReviewAbove != nil || limits.RejectAbove != nil) {
		return true
	}
	for _, limits := range byNetwork {
		if limits.ReviewAbove != nil || limits.RejectAbove != nil {
			return true
		}
	}
	return false
}

type assetUnit struct {
	Algo bool
	ASA  uint64
}

func routeLimitNetworks(route CompiledTransferRoute, assetSets map[string]compiledAssetSet) []string {
	if !route.NetworkWildcard {
		return sortedStringSet(route.Networks)
	}
	seen := make(map[string]struct{})
	for _, setName := range route.Assets.Sets {
		for network := range assetSets[setName].ByNetwork {
			seen[network] = struct{}{}
		}
	}
	for network := range route.LimitsByNetwork {
		seen[network] = struct{}{}
	}
	return sortedStringSet(seen)
}

func routeAssetsForNetwork(terms compiledAssetTerms, assetSets map[string]compiledAssetSet, network string) []assetUnit {
	seen := make(map[assetUnit]struct{})
	if terms.Algo {
		seen[assetUnit{Algo: true}] = struct{}{}
	}
	for _, id := range terms.ASAIDs {
		seen[assetUnit{ASA: id}] = struct{}{}
	}
	for _, setName := range terms.Sets {
		for _, id := range assetSets[setName].ByNetwork[network] {
			seen[assetUnit{ASA: id}] = struct{}{}
		}
	}
	out := make([]assetUnit, 0, len(seen))
	for unit := range seen {
		out = append(out, unit)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Algo != out[j].Algo {
			return out[i].Algo
		}
		return out[i].ASA < out[j].ASA
	})
	return out
}

func parseAddresses(raw []string) ([]types.Address, error) {
	out := make([]types.Address, 0, len(raw))
	for _, encoded := range raw {
		addr, err := types.DecodeAddress(encoded)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q: %w", encoded, err)
		}
		out = append(out, addr)
	}
	return out, nil
}

func parseASAID(raw string) (uint64, error) {
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, err
	}
	if id == 0 {
		return 0, fmt.Errorf("0 is not a valid ASA ID")
	}
	return id, nil
}

func validateSetName(name string) error {
	if name == "" {
		return fmt.Errorf("set name is required")
	}
	for i, r := range name {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			continue
		}
		return fmt.Errorf("invalid set name %q at character %d", name, i)
	}
	return nil
}

func validateRouteID(id string) error {
	if id == "" {
		return fmt.Errorf("route id is required")
	}
	for i, r := range id {
		ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-'
		if !ok {
			return fmt.Errorf("invalid route id %q", id)
		}
		if i == 0 && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return fmt.Errorf("invalid route id %q", id)
		}
	}
	return nil
}

func sortedStringSet(in map[string]struct{}) []string {
	out := make([]string, 0, len(in))
	for v := range in {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func sortedUintSet(in map[uint64]struct{}) []uint64 {
	out := make([]uint64, 0, len(in))
	for v := range in {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func cloneUint64Ptr(v *uint64) *uint64 {
	if v == nil {
		return nil
	}
	cp := *v
	return &cp
}

func cloneStringPtr(in *string) *string {
	if in == nil {
		return nil
	}
	v := *in
	return &v
}

func cloneStringSliceMap(in map[string][]string) map[string][]string {
	if in == nil {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func cloneStoredTransferRoutes(in []StoredTransferRoute) []StoredTransferRoute {
	if in == nil {
		return nil
	}
	out := make([]StoredTransferRoute, len(in))
	for i, route := range in {
		out[i] = route.Clone()
	}
	return out
}

func cloneStoredAmountLimitsMap(in map[string]StoredAmountLimits) map[string]StoredAmountLimits {
	if in == nil {
		return nil
	}
	out := make(map[string]StoredAmountLimits, len(in))
	for network, limits := range in {
		out[network] = StoredAmountLimits{
			ReviewAbove: cloneUint64Ptr(limits.ReviewAbove),
			RejectAbove: cloneUint64Ptr(limits.RejectAbove),
		}
	}
	return out
}

func cloneAddressSetMap(in map[types.Address]struct{}) map[types.Address]struct{} {
	if in == nil {
		return nil
	}
	out := make(map[types.Address]struct{}, len(in))
	for addr := range in {
		out[addr] = struct{}{}
	}
	return out
}

func cloneCompiledAddressSets(in map[string]compiledAddressSet) map[string]compiledAddressSet {
	if in == nil {
		return nil
	}
	out := make(map[string]compiledAddressSet, len(in))
	for name, set := range in {
		out[name] = compiledAddressSet{
			Flat:      append([]types.Address(nil), set.Flat...),
			ByNetwork: cloneAddressNetworkMap(set.ByNetwork),
		}
	}
	return out
}

func cloneCompiledAssetSets(in map[string]compiledAssetSet) map[string]compiledAssetSet {
	if in == nil {
		return nil
	}
	out := make(map[string]compiledAssetSet, len(in))
	for name, set := range in {
		out[name] = compiledAssetSet{ByNetwork: cloneUintNetworkMap(set.ByNetwork)}
	}
	return out
}

func cloneCompiledRoutes(in []CompiledTransferRoute) []CompiledTransferRoute {
	if in == nil {
		return nil
	}
	out := make([]CompiledTransferRoute, len(in))
	for i, route := range in {
		out[i] = route
		out[i].Networks = cloneStringSet(route.Networks)
		out[i].Sources = cloneAddressTerms(route.Sources)
		out[i].AssetSources = cloneAddressTerms(route.AssetSources)
		out[i].Assets = cloneAssetTerms(route.Assets)
		out[i].Destinations = cloneAddressTerms(route.Destinations)
		out[i].Limits = cloneAmountLimits(route.Limits)
		out[i].LimitsByNetwork = cloneLimitsByNetwork(route.LimitsByNetwork)
	}
	return out
}

func cloneAddressTerms(in compiledAddressTerms) compiledAddressTerms {
	return compiledAddressTerms{
		Wildcard: in.Wildcard,
		Self:     in.Self,
		Direct:   append([]types.Address(nil), in.Direct...),
		Sets:     append([]string(nil), in.Sets...),
	}
}

func cloneAssetTerms(in compiledAssetTerms) compiledAssetTerms {
	return compiledAssetTerms{
		Wildcard: in.Wildcard,
		Algo:     in.Algo,
		ASAIDs:   append([]uint64(nil), in.ASAIDs...),
		Sets:     append([]string(nil), in.Sets...),
	}
}

func cloneAmountLimits(in *AmountLimits) *AmountLimits {
	if in == nil {
		return nil
	}
	return &AmountLimits{
		ReviewAbove: cloneUint64Ptr(in.ReviewAbove),
		RejectAbove: cloneUint64Ptr(in.RejectAbove),
	}
}

func cloneLimitsByNetwork(in map[string]AmountLimits) map[string]AmountLimits {
	if in == nil {
		return nil
	}
	out := make(map[string]AmountLimits, len(in))
	for network, limits := range in {
		out[network] = AmountLimits{
			ReviewAbove: cloneUint64Ptr(limits.ReviewAbove),
			RejectAbove: cloneUint64Ptr(limits.RejectAbove),
		}
	}
	return out
}

func cloneAddressNetworkMap(in map[string][]types.Address) map[string][]types.Address {
	if in == nil {
		return nil
	}
	out := make(map[string][]types.Address, len(in))
	for network, addresses := range in {
		out[network] = append([]types.Address(nil), addresses...)
	}
	return out
}

func cloneUintNetworkMap(in map[string][]uint64) map[string][]uint64 {
	if in == nil {
		return nil
	}
	out := make(map[string][]uint64, len(in))
	for network, values := range in {
		out[network] = append([]uint64(nil), values...)
	}
	return out
}

func cloneStringSet(in map[string]struct{}) map[string]struct{} {
	if in == nil {
		return nil
	}
	out := make(map[string]struct{}, len(in))
	for v := range in {
		out[v] = struct{}{}
	}
	return out
}
