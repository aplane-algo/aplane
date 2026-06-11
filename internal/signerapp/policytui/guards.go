// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policytui

// Guards (routes) screen: guard-group list, ordering, YAML view,
// and route-slice operations.

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/policy"
)

func (m Model) handleRouteKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m.requestQuit()
	case "esc", "backspace":
		m.screen = screenHome
		m.status = fmt.Sprintf("%s fields", strings.ToLower(m.target.Label()))
		m.err = ""
		return m, nil
	}
	if m.busy {
		return m, nil
	}
	routes := m.routes()
	groups := transferGuardGroups(routes)
	switch msg.String() {
	case "up", "k":
		if m.routeCursor > 0 {
			m.routeCursor--
		}
	case "down", "j":
		if m.routeCursor < len(groups)-1 {
			m.routeCursor++
		}
	case "enter", "e":
		if len(groups) == 0 {
			m.status = "no guards to edit"
			return m, nil
		}
		return m.openGuardGroupEditor(groups[m.routeCursor]), nil
	case " ":
		if len(groups) == 0 {
			m.status = "no guards to edit"
			return m, nil
		}
		group := groups[m.routeCursor]
		m.cycleSelectedGuardGroupEnabled(group)
		m.status = fmt.Sprintf("changed guard %s enabled to %s", group.ID, boolValueWithDefault(m.selectedGuardGroupEnabled(group), true))
		m.err = ""
	case "n":
		m.enableTransferPolicyForGuards()
		route := m.newRoute()
		m.policy.TransferPolicy.Routes = append(m.policy.TransferPolicy.Routes, route)
		m.policy.TransferPolicy.RoutesSet = true
		m.routeCursor = len(transferGuardGroups(m.policy.TransferPolicy.Routes)) - 1
		m.status = fmt.Sprintf("added guard %s", guardNameFromRoute(route.ID, route.Assets[0].Raw))
		m.err = ""
	case "c":
		if len(groups) == 0 {
			m.status = "no guard to clone"
			return m, nil
		}
		group := groups[m.routeCursor]
		clones := m.cloneGuardGroup(group)
		_, end := guardGroupRouteRange(group)
		m.policy.TransferPolicy.Routes = insertRoutes(m.policy.TransferPolicy.Routes, end, clones)
		m.policy.TransferPolicy.RoutesSet = true
		m.routeCursor++
		m.status = fmt.Sprintf("cloned guard %s", group.ID)
		m.err = ""
	case "d":
		if len(groups) == 0 {
			m.status = "no guard to delete"
			return m, nil
		}
		m.screen = screenDeleteRouteConfirm
		m.deleteRouteIndex = m.routeCursor
		m.status = fmt.Sprintf("confirm delete guard %s", groups[m.routeCursor].ID)
		m.err = ""
	case "b":
		return m.openBlockedDestinationsEditor(), nil
	case "u":
		if m.routeCursor <= 0 || len(groups) == 0 {
			return m, nil
		}
		m.policy.TransferPolicy.Routes = moveGuardGroupUp(routes, groups, m.routeCursor)
		m.policy.TransferPolicy.RoutesSet = true
		m.routeCursor--
		m.status = "moved guard up"
		m.err = ""
	case "U":
		if m.routeCursor >= len(groups)-1 || len(groups) == 0 {
			return m, nil
		}
		m.policy.TransferPolicy.Routes = moveGuardGroupDown(routes, groups, m.routeCursor)
		m.policy.TransferPolicy.RoutesSet = true
		m.routeCursor++
		m.status = "moved guard down"
		m.err = ""
	case "p":
		m.ensureTransferPolicy()
		return m.openTransferSettings(), nil
	case "t", "T":
		return m.openAssetSets(), nil
	case "y", "Y":
		m.screen = screenRouteYAML
		m.routeYAMLOffset = 0
		m.status = "transfer policy yaml"
		m.err = ""
	case "a":
		return m.applyProduction()
	case "w":
		return m.openWriteFile()
	case "v":
		return m.validate()
	}
	return m, nil
}

func (m Model) handleRouteYAMLKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m.requestQuit()
	case "esc", "b", "backspace":
		m.screen = screenRoutes
		m.routeYAMLOffset = 0
		m.status = "guard list"
		m.err = ""
		return m, nil
	case "up", "k":
		if m.routeYAMLOffset > 0 {
			m.routeYAMLOffset--
		}
		return m, nil
	case "down", "j":
		maxOffset := m.routeYAMLMaxOffset()
		if m.routeYAMLOffset < maxOffset {
			m.routeYAMLOffset++
		}
		return m, nil
	case "pgup":
		m.routeYAMLOffset -= m.routeYAMLVisibleLines()
		if m.routeYAMLOffset < 0 {
			m.routeYAMLOffset = 0
		}
		return m, nil
	case "pgdown":
		maxOffset := m.routeYAMLMaxOffset()
		m.routeYAMLOffset += m.routeYAMLVisibleLines()
		if m.routeYAMLOffset > maxOffset {
			m.routeYAMLOffset = maxOffset
		}
		return m, nil
	case "a":
		return m.applyProduction()
	case "w":
		return m.openWriteFile()
	}
	return m, nil
}

func (m Model) handleDeleteRouteConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m.requestQuit()
	case "y", "d":
		return m.deleteSelectedRouteConfirmed(), nil
	case "n", "esc", "b", "backspace":
		m.screen = screenRoutes
		m.status = "delete canceled"
		m.err = ""
		return m, nil
	}
	return m, nil
}

func (m Model) deleteSelectedRouteConfirmed() Model {
	groups := transferGuardGroups(m.routes())
	if m.deleteRouteIndex < 0 || m.deleteRouteIndex >= len(groups) {
		m.screen = screenRoutes
		m.status = "guard no longer exists"
		return m
	}
	group := groups[m.deleteRouteIndex]
	deleted := group.ID
	start, end := guardGroupRouteRange(group)
	m.policy.TransferPolicy.Routes = removeRouteBlock(m.policy.TransferPolicy.Routes, start, end)
	m.policy.TransferPolicy.RoutesSet = true
	if m.routeCursor >= len(transferGuardGroups(m.policy.TransferPolicy.Routes)) && m.routeCursor > 0 {
		m.routeCursor--
	}
	m.screen = screenRoutes
	m.status = fmt.Sprintf("deleted guard %s", deleted)
	m.err = ""
	return m
}

func (m Model) routeView() string {
	var b strings.Builder
	routes := m.routes()
	groups := transferGuardGroups(routes)
	b.WriteString(sectionStyle.Render("Transfer Guards"))
	b.WriteString("\n\n")
	b.WriteString(metadataStyle.Render("Blocked Destinations"))
	b.WriteString("\n")
	b.WriteString("  ")
	b.WriteString(ellipsize(blockedDestinationsSummary(m.policy), m.panelWidth()-6))
	b.WriteString("\n\n")
	if m.policy == nil || m.policy.TransferPolicy == nil {
		b.WriteString(readonlyStyle.Render("transfer routing is off; no stored guards are present"))
		b.WriteString("\n")
	} else if len(groups) == 0 {
		b.WriteString(readonlyStyle.Render("no stored guards"))
		b.WriteString("\n")
	} else {
		if m.routeCursor >= len(groups) {
			m.routeCursor = len(groups) - 1
		}
		advanced := false
		for i, group := range groups {
			if group.Advanced {
				advanced = true
			}
			b.WriteString(m.renderGuardGroup(i, group))
			b.WriteString("\n")
		}
		if advanced {
			b.WriteString("\n")
			b.WriteString(descriptionStyle.Render("Advanced rows are YAML-only; press y to inspect or edit the full policy."))
			b.WriteString("\n")
		}
	}
	b.WriteString("\nkeys: up/down move  enter/e edit guard  n new  c clone  d delete  b blocked destinations  u/U reorder  p settings  t asset sets  y yaml  space cycle enabled  v validate  w write draft  a apply production  esc/backspace back  q quit\n")
	if m.modified() {
		b.WriteString(modifiedProductionWarning + "\n")
	}
	return m.renderHelp(b.String())
}

func (m Model) routeYAMLView() string {
	var b strings.Builder
	b.WriteString(sectionStyle.Render("Transfer Policy YAML"))
	b.WriteString("\n\n")
	lines := strings.Split(strings.TrimRight(m.transferPolicyYAML(), "\n"), "\n")
	visibleLines := m.routeYAMLVisibleLines()
	offset := m.routeYAMLOffset
	if offset < 0 || offset >= len(lines) {
		offset = 0
	}
	end := offset + visibleLines
	if end > len(lines) {
		end = len(lines)
	}

	if offset > 0 {
		b.WriteString(scrollMoreAboveLine(offset))
		b.WriteString("\n")
	}
	for _, line := range lines[offset:end] {
		b.WriteString(ellipsize(line, m.routeYAMLLineWidth()))
		b.WriteString("\n")
	}
	if end < len(lines) {
		b.WriteString(scrollMoreBelowLine(len(lines) - end))
		b.WriteString("\n")
	}
	b.WriteString("\nkeys: up/down/pgup/pgdown scroll  w write draft  a apply production  esc/b back  q quit\n")
	if m.modified() {
		b.WriteString(modifiedProductionWarning + "\n")
	}
	return m.renderHelp(b.String())
}

func (m Model) routeYAMLVisibleLines() int {
	if m.height <= 0 {
		return 20
	}
	visible := m.height - m.appChromeLines() - m.routeYAMLChromeLines()
	if visible < 3 {
		return 3
	}
	return visible
}

func (m Model) routeYAMLChromeLines() int {
	// YAML screen title, spacer, both possible scroll markers, spacer, key help.
	lines := 6
	if m.modified() {
		lines++
	}
	return lines
}

func (m Model) routeYAMLLineWidth() int {
	width := m.panelWidth() - 4
	if width < 20 {
		return 20
	}
	return width
}

func (m Model) deleteRouteConfirmView() string {
	routeID := "(missing)"
	if routes := m.routes(); m.deleteRouteIndex >= 0 && m.deleteRouteIndex < len(routes) {
		routeID = routes[m.deleteRouteIndex].ID
	}
	return m.renderHelp(renderLines(
		sectionStyle.Render("Delete Transfer Guard"),
		"",
		statusWarnStyle.Render("Delete guard "+routeID+"?"),
		"",
		"This removes the underlying route from the in-memory policy draft.",
		"Use a from the guard list to apply the draft to production.",
		"",
		"keys: y delete  n cancel  esc cancel",
	))
}

func (m Model) renderGuardGroup(i int, group transferGuardGroup) string {
	name := group.ID
	if description := strings.TrimSpace(group.Description); description != "" {
		name += " - " + description
	}
	var line string
	if group.Advanced {
		line = fmt.Sprintf("%s  advanced: %s", name, group.AdvancedReason)
	} else {
		line = fmt.Sprintf("%s  net=%s src=%s dst=%s %s=%s",
			name,
			guardTermSummary(group.Networks),
			guardTermSummary(group.Sources),
			guardTermSummary(group.Destinations),
			guardGroupAssetLabel(group),
			guardGroupAssetSummary(group),
		)
	}
	line = ellipsize(line, m.panelWidth()-6)
	if i == m.routeCursor {
		return selectedStyle.Render("  " + line + "  ")
	}
	return "  " + line
}

func guardGroupAssetLabel(group transferGuardGroup) string {
	if len(group.AssetRows) == 1 {
		return "asset"
	}
	return "assets"
}

func guardGroupAssetSummary(group transferGuardGroup) string {
	if group.Advanced {
		return "-"
	}
	switch len(group.AssetRows) {
	case 0:
		return "-"
	case 1:
		return emptyGuardDisplay(group.AssetRows[0].Asset)
	default:
		return fmt.Sprintf("%d", len(group.AssetRows))
	}
}

func guardTermSummary(terms []string) string {
	switch len(terms) {
	case 0:
		return "-"
	case 1:
		return terms[0]
	default:
		return fmt.Sprintf("%d", len(terms))
	}
}

func emptyGuardDisplay(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

func (m Model) transferPolicyYAML() string {
	if m.policy == nil || m.policy.TransferPolicy == nil {
		return "transfer_policy: null\n"
	}
	data, err := m.target.Marshal(&policy.StoredConfig{
		TransferPolicy: cloneTransferPolicy(m.policy.TransferPolicy),
	})
	if err != nil {
		return fmt.Sprintf("# failed to render transfer_policy: %v\n", err)
	}
	return string(data)
}

func (m Model) routeYAMLMaxOffset() int {
	lines := strings.Split(strings.TrimRight(m.transferPolicyYAML(), "\n"), "\n")
	maxOffset := len(lines) - m.routeYAMLVisibleLines()
	if maxOffset < 0 {
		return 0
	}
	return maxOffset
}

func (m *Model) ensureTransferPolicy() {
	if m.policy == nil {
		m.policy = &policy.StoredConfig{}
	}
	if m.policy.TransferPolicy != nil {
		return
	}
	enabled := false
	onNoRoute := string(policy.TransferOnNoRouteReject)
	closeOnNoRoute := string(policy.TransferOnNoRouteReject)
	clawbackOnNoRoute := string(policy.TransferOnNoRouteReject)
	m.policy.TransferPolicy = &policy.StoredTransferPolicy{
		SchemaVersion:     1,
		Enabled:           &enabled,
		OnNoRoute:         &onNoRoute,
		CloseOnNoRoute:    &closeOnNoRoute,
		ClawbackOnNoRoute: &clawbackOnNoRoute,
		AssetSets:         defaultAssetSets(),
		RoutesSet:         true,
	}
}

func (m *Model) enableTransferPolicyForGuards() {
	m.ensureTransferPolicy()
	enabled := true
	m.policy.TransferPolicy.Enabled = &enabled
	if m.policy.TransferPolicy.OnNoRoute == nil {
		onNoRoute := string(policy.TransferOnNoRouteReject)
		m.policy.TransferPolicy.OnNoRoute = &onNoRoute
	}
	if m.policy.TransferPolicy.CloseOnNoRoute == nil {
		closeOnNoRoute := string(policy.TransferOnNoRouteReject)
		m.policy.TransferPolicy.CloseOnNoRoute = &closeOnNoRoute
	}
	if m.policy.TransferPolicy.ClawbackOnNoRoute == nil {
		clawbackOnNoRoute := string(policy.TransferOnNoRouteReject)
		m.policy.TransferPolicy.ClawbackOnNoRoute = &clawbackOnNoRoute
	}
}

func (m Model) newRoute() policy.StoredTransferRoute {
	asset := "algo"
	name := m.uniqueGuardName("new_guard", []string{asset})
	return policy.StoredTransferRoute{
		ID:           guardRouteID(name, asset),
		Networks:     []string{"*"},
		Sources:      []string{"*"},
		Assets:       []policy.StoredAssetTerm{{Raw: asset}},
		Destinations: []string{"self"},
	}
}

func (m Model) cloneGuardGroup(group transferGuardGroup) []policy.StoredTransferRoute {
	clone := group
	clone.ID = m.uniqueGuardName(group.ID+"_copy", guardGroupAssets(group))
	clone.Description = ""
	clone.RouteIndexes = nil
	for i := range clone.AssetRows {
		clone.AssetRows[i].RouteIndex = -1
		clone.AssetRows[i].RouteID = ""
	}
	routes, err := guardGroupToRoutes(clone, m.routes())
	if err != nil {
		return nil
	}
	return routes
}

func (m Model) uniqueGuardName(base string, assets []string) string {
	return uniqueGuardNameWithSeen(base, assets, routeIDSet(m.routes()))
}

func uniqueGuardNameWithSeen(base string, assets []string, seen map[string]struct{}) string {
	base = strings.TrimSpace(base)
	if base == "" {
		base = "guard"
	}
	if len(assets) == 0 {
		assets = []string{"asset"}
	}
	if guardRouteIDsAvailable(base, assets, seen) {
		return base
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s_%d", base, i)
		if guardRouteIDsAvailable(candidate, assets, seen) {
			return candidate
		}
	}
}

func guardRouteIDsAvailable(guardName string, assets []string, seen map[string]struct{}) bool {
	for _, asset := range assets {
		if _, ok := seen[guardRouteID(guardName, asset)]; ok {
			return false
		}
	}
	return true
}

func guardGroupAssets(group transferGuardGroup) []string {
	assets := make([]string, 0, len(group.AssetRows))
	for _, row := range group.AssetRows {
		assets = append(assets, row.Asset)
	}
	return assets
}

func routeIDSet(routes []policy.StoredTransferRoute) map[string]struct{} {
	seen := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		seen[route.ID] = struct{}{}
	}
	return seen
}

func cloneRoute(route policy.StoredTransferRoute) policy.StoredTransferRoute {
	out := route
	out.Networks = append([]string(nil), route.Networks...)
	out.Sources = append([]string(nil), route.Sources...)
	out.AssetSources = append([]string(nil), route.AssetSources...)
	out.Assets = append([]policy.StoredAssetTerm(nil), route.Assets...)
	out.Destinations = append([]string(nil), route.Destinations...)
	if route.Limits != nil {
		limits := *route.Limits
		if route.Limits.ReviewAbove != nil {
			v := *route.Limits.ReviewAbove
			limits.ReviewAbove = &v
		}
		if route.Limits.RejectAbove != nil {
			v := *route.Limits.RejectAbove
			limits.RejectAbove = &v
		}
		out.Limits = &limits
	}
	if route.LimitsByNetwork != nil {
		out.LimitsByNetwork = make(map[string]policy.StoredAmountLimits, len(route.LimitsByNetwork))
		for network, limits := range route.LimitsByNetwork {
			cp := limits
			if limits.ReviewAbove != nil {
				v := *limits.ReviewAbove
				cp.ReviewAbove = &v
			}
			if limits.RejectAbove != nil {
				v := *limits.RejectAbove
				cp.RejectAbove = &v
			}
			out.LimitsByNetwork[network] = cp
		}
	}
	if route.Enabled != nil {
		v := *route.Enabled
		out.Enabled = &v
	}
	if route.Close.Allow != nil {
		v := *route.Close.Allow
		out.Close.Allow = &v
	}
	if route.Clawback.Allow != nil {
		v := *route.Clawback.Allow
		out.Clawback.Allow = &v
	}
	return out
}

func insertRoutes(routes []policy.StoredTransferRoute, index int, inserted []policy.StoredTransferRoute) []policy.StoredTransferRoute {
	if index < 0 {
		index = 0
	}
	if index > len(routes) {
		index = len(routes)
	}
	if len(inserted) == 0 {
		return routes
	}
	routes = append(routes, inserted...)
	copy(routes[index+len(inserted):], routes[index:])
	copy(routes[index:], inserted)
	return routes
}

func removeRouteBlock(routes []policy.StoredTransferRoute, start, end int) []policy.StoredTransferRoute {
	if start < 0 {
		start = 0
	}
	if end > len(routes) {
		end = len(routes)
	}
	if start >= end {
		return routes
	}
	copy(routes[start:], routes[end:])
	return routes[:len(routes)-(end-start)]
}

func guardGroupRouteRange(group transferGuardGroup) (int, int) {
	if len(group.RouteIndexes) == 0 {
		return 0, 0
	}
	start := group.RouteIndexes[0]
	end := group.RouteIndexes[len(group.RouteIndexes)-1] + 1
	return start, end
}

func moveGuardGroupUp(routes []policy.StoredTransferRoute, groups []transferGuardGroup, index int) []policy.StoredTransferRoute {
	if index <= 0 || index >= len(groups) {
		return routes
	}
	prevStart, _ := guardGroupRouteRange(groups[index-1])
	start, end := guardGroupRouteRange(groups[index])
	if prevStart < 0 || start < prevStart || end > len(routes) {
		return routes
	}
	out := make([]policy.StoredTransferRoute, 0, len(routes))
	out = append(out, routes[:prevStart]...)
	out = append(out, routes[start:end]...)
	out = append(out, routes[prevStart:start]...)
	out = append(out, routes[end:]...)
	return out
}

func moveGuardGroupDown(routes []policy.StoredTransferRoute, groups []transferGuardGroup, index int) []policy.StoredTransferRoute {
	if index < 0 || index >= len(groups)-1 {
		return routes
	}
	start, end := guardGroupRouteRange(groups[index])
	_, nextEnd := guardGroupRouteRange(groups[index+1])
	if start < 0 || end < start || nextEnd > len(routes) {
		return routes
	}
	out := make([]policy.StoredTransferRoute, 0, len(routes))
	out = append(out, routes[:start]...)
	out = append(out, routes[end:nextEnd]...)
	out = append(out, routes[start:end]...)
	out = append(out, routes[nextEnd:]...)
	return out
}

func (m Model) routes() []policy.StoredTransferRoute {
	if m.policy == nil || m.policy.TransferPolicy == nil {
		return nil
	}
	return m.policy.TransferPolicy.Routes
}

func (m *Model) cycleSelectedGuardGroupEnabled(group transferGuardGroup) {
	if m.policy == nil || m.policy.TransferPolicy == nil {
		return
	}
	next := nextBoolOverride(group.Enabled, true)
	for _, index := range group.RouteIndexes {
		if index < 0 || index >= len(m.policy.TransferPolicy.Routes) {
			continue
		}
		m.policy.TransferPolicy.Routes[index].Enabled = cloneBoolPtr(next)
	}
	m.policy.TransferPolicy.RoutesSet = true
}

func (m Model) selectedGuardGroupEnabled(group transferGuardGroup) *bool {
	if m.policy == nil || m.policy.TransferPolicy == nil || len(group.RouteIndexes) == 0 {
		return nil
	}
	index := group.RouteIndexes[0]
	if index < 0 || index >= len(m.policy.TransferPolicy.Routes) {
		return nil
	}
	return m.policy.TransferPolicy.Routes[index].Enabled
}

func nextBoolOverride(current *bool, defaultValue bool) *bool {
	currentValue := defaultValue
	if current != nil {
		currentValue = *current
	}
	next := !currentValue
	if next == defaultValue {
		return nil
	}
	v := next
	return &v
}
