// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/clientdata"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"github.com/aplane-algo/aplane/internal/tokenfile"
	"github.com/aplane-algo/aplane/internal/witness"
)

// ErrCosignerEndpointURLRequired marks setup input that needs a client-local
// route supplied by the caller.
var ErrCosignerEndpointURLRequired = errors.New("cosigner endpoint URL is required")

// ErrCosignerEndpointAlreadyConfigured marks a request to name a cosigner
// connection whose destination already has a different connection name.
var ErrCosignerEndpointAlreadyConfigured = errors.New("cosigner endpoint is already configured")

// Setup failures that belong to the connection being added. Only these, and
// failures to reach or authenticate to that connection, fail guided setup; the
// state of other connections and of accounts that need other cosigners is
// reported without failing it.
var (
	// ErrCosignerSetupNotCosigner marks an endpoint whose node reports a role
	// other than cosigner.
	ErrCosignerSetupNotCosigner = errors.New("endpoint is not a cosigner")
	// ErrCosignerSetupRoleUnverified marks an endpoint whose node role could
	// not be read, or was absent or unrecognized.
	ErrCosignerSetupRoleUnverified = errors.New("could not verify that this endpoint is a cosigner")
	// ErrCosignerSetupDuplicateRoute marks a key advertised by both the new
	// connection and another one, which blocks signing for that key.
	ErrCosignerSetupDuplicateRoute = errors.New("duplicate cosigner route")
)

// CosignerSetupRequest describes the client-local route choices used to
// prepare a guided cosigner setup. The client is told the cosigner's address;
// it never handles the cosigner's key, which the signer imports from the
// cosigner's exported key file.
type CosignerSetupRequest struct {
	Alias  string
	URL    string
	DryRun bool
}

// CosignerSetupTarget is what guided setup can decide before asking the user
// anything: the destination, and the connection name to use for it.
type CosignerSetupTarget struct {
	URL string
	// ExistingAlias names the cosigner connection already configured for URL.
	ExistingAlias string
	// SuggestedAlias is a free connection name derived from the endpoint host.
	// It is empty when ExistingAlias is set.
	SuggestedAlias string
}

// CosignerSetupPlan is an immutable reviewed setup proposal. ExistingEndpoint is
// compared again under the client lock before the route is changed.
type CosignerSetupPlan struct {
	Alias               string
	Endpoint            config.ClientEndpointConfig
	ExistingEndpoint    *config.ClientEndpointConfig
	Created             bool
	Updated             bool
	ReplacementRequired bool
	DestinationChanged  bool
	// RetiresToken reports that applying the plan removes a stored token: one
	// issued by the previous destination, or one left over under the name of a
	// connection this plan creates.
	RetiresToken bool
	DryRun       bool
}

// Unchanged reports that the plan reuses an existing connection as it is.
func (p CosignerSetupPlan) Unchanged() bool {
	return !p.Created && !p.Updated
}

// CosignerSetupResult reports completed client-owned effects without exposing
// credential values or paths. Connection and route outcomes are separate and
// are never folded into one readiness flag.
type CosignerSetupResult struct {
	Alias        string
	URL          string
	Created      bool
	Updated      bool
	TokenIssued  bool
	TokenRetired bool
	// Connected reports that the endpoint was reached, authenticated, and
	// reported the cosigner role.
	Connected      bool
	NodeRole       string
	AdvertisedKeys int
	Routes         *CosignerSetupRoutes
	DryRun         bool

	RenderLines []string
}

// CosignerSetupRoutes is the route sweep observed at the end of guided setup,
// reported as the resolver classified it.
type CosignerSetupRoutes struct {
	// AccountInventory is "available" when the primary signer's inventory was
	// read; InventoryError explains why it was not.
	AccountInventory string
	InventoryError   string
	AccountsRequired int
	AccountsRouted   int
	// Unrouted lists accounts that need a cosigner and have no single route.
	Unrouted []engine.CosignerAccountRouteObservation

	// Stopped is the sweep error when discovery ended before every connection
	// was contacted. No route conclusion is drawn in that case.
	Stopped string
	// HostKeyMismatch lists connections that answered with a key other than
	// the pinned one. They were contacted; they are not "not checked".
	HostKeyMismatch []string
	// NotContacted lists connections the sweep never reached.
	NotContacted []string
	// Unread lists other connections that were tried and failed. Routes through
	// answering connections still stand; duplicates there cannot be ruled out.
	Unread []CosignerSetupUnreadConnection

	// Duplicates maps a Witness Key ID advertised by this connection and
	// another to the aliases advertising it.
	Duplicates map[string][]string
	// OtherDuplicates are duplicate routes that do not involve this connection.
	OtherDuplicates map[string][]string
}

// CosignerSetupUnreadConnection is another connection the sweep tried and
// could not read.
type CosignerSetupUnreadConnection struct {
	Alias string
	State string
}

// ResolveCosignerSetupTarget decides the destination and connection name
// before any prompt. A cosigner connection already configured for the
// destination is reused; otherwise a free name is suggested.
func (a *App) ResolveCosignerSetupTarget(req CosignerSetupRequest) (CosignerSetupTarget, error) {
	target := CosignerSetupTarget{URL: strings.TrimRight(strings.TrimSpace(req.URL), "/")}
	if target.URL == "" {
		return CosignerSetupTarget{}, fmt.Errorf("%w; pass the cosigner URL", ErrCosignerEndpointURLRequired)
	}
	registry, _, err := config.LoadStoredClientEndpointRegistry(a.DataDir)
	if err != nil {
		return CosignerSetupTarget{}, err
	}
	if alias, ok := existingCosignerAliasForURL(registry, target.URL); ok {
		target.ExistingAlias = alias
		return target, nil
	}
	target.SuggestedAlias = suggestCosignerAlias(registry, target.URL)
	return target, nil
}

func existingCosignerAliasForURL(registry config.ClientEndpointRegistry, rawURL string) (string, bool) {
	aliases := make([]string, 0, len(registry.Endpoints))
	for alias, endpoint := range registry.Endpoints {
		if endpoint.Role == config.ClientEndpointRoleCosigner && endpoint.URL == rawURL {
			aliases = append(aliases, alias)
		}
	}
	if len(aliases) == 0 {
		return "", false
	}
	sort.Strings(aliases)
	return aliases[0], true
}

// suggestCosignerAlias derives a valid, unused connection name from the
// endpoint host, such as cosigner-example for ssh://cosigner.example:1127.
func suggestCosignerAlias(registry config.ClientEndpointRegistry, rawURL string) string {
	base := "cosigner"
	if parsed, err := url.Parse(rawURL); err == nil {
		host := strings.ToLower(strings.Trim(parsed.Hostname(), "[]"))
		ip := net.ParseIP(host)
		switch {
		case host == "":
		case host == "localhost" || (ip != nil && ip.IsLoopback()):
			base = "cosigner-local"
		default:
			var name strings.Builder
			for _, r := range host {
				switch {
				case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
					name.WriteRune(r)
				default:
					name.WriteByte('-')
				}
			}
			sanitized := strings.Trim(name.String(), "-")
			switch {
			case sanitized == "":
			case strings.HasPrefix(sanitized, "cosigner"):
				base = sanitized
			default:
				base = "cosigner-" + sanitized
			}
		}
	}
	candidate := base
	for suffix := 2; ; suffix++ {
		if _, taken := registry.Endpoints[candidate]; !taken {
			return candidate
		}
		candidate = fmt.Sprintf("%s-%d", base, suffix)
	}
}

// PrepareCosignerSetup validates the request and calculates the exact client
// endpoint change. It performs no writes or network operations.
func (a *App) PrepareCosignerSetup(req CosignerSetupRequest) (CosignerSetupPlan, error) {
	alias := strings.TrimSpace(req.Alias)
	if err := config.ValidateClientEndpointAlias(alias); err != nil {
		return CosignerSetupPlan{}, fmt.Errorf("cosigner endpoint alias: %w", err)
	}
	registry, _, err := config.LoadStoredClientEndpointRegistry(a.DataDir)
	if err != nil {
		return CosignerSetupPlan{}, err
	}
	existing, exists := registry.Endpoint(alias)
	if exists && existing.Role != config.ClientEndpointRoleCosigner {
		return CosignerSetupPlan{}, fmt.Errorf("endpoint alias %q has role %q; choose a cosigner alias", alias, existing.Role)
	}
	candidate := existing
	candidate.Role = config.ClientEndpointRoleCosigner

	if resolved := strings.TrimSpace(req.URL); resolved != "" {
		candidate.URL = resolved
	}
	if candidate.URL == "" {
		return CosignerSetupPlan{}, fmt.Errorf("%w; pass the cosigner URL", ErrCosignerEndpointURLRequired)
	}

	normalizedURL := strings.TrimRight(strings.TrimSpace(candidate.URL), "/")
	if other, ok := existingCosignerAliasForURL(registry, normalizedURL); ok && other != alias {
		return CosignerSetupPlan{}, fmt.Errorf(
			"%w: %s is already the connection %q; rerun without --alias, or with --alias %s",
			ErrCosignerEndpointAlreadyConfigured, normalizedURL, other, other,
		)
	}

	preview, err := config.PlanStoredClientEndpointUpsert(a.DataDir, alias, candidate, true)
	if err != nil {
		return CosignerSetupPlan{}, err
	}
	plan := CosignerSetupPlan{
		Alias: alias, Endpoint: preview.Endpoint,
		Created: preview.Created, Updated: preview.Updated,
		ReplacementRequired: exists && preview.Updated, DryRun: req.DryRun,
		DestinationChanged: preview.DestinationChanged, RetiresToken: preview.RetiresExistingToken,
	}
	if exists {
		copy := existing
		plan.ExistingEndpoint = &copy
	}
	return plan, nil
}

// ApplyCosignerSetupEndpoint revalidates and applies a reviewed route under the
// shared client lock. Network and token operations must run after it returns.
// Creating the alias or changing its destination retires any stored token in
// the same locked step, before the new route is written.
func (a *App) ApplyCosignerSetupEndpoint(plan CosignerSetupPlan, replace bool) (config.ClientEndpointConfig, error) {
	if plan.DryRun {
		return plan.Endpoint, nil
	}
	if plan.ReplacementRequired && !replace {
		return config.ClientEndpointConfig{}, fmt.Errorf("endpoint alias %q has different settings; confirm replacement", plan.Alias)
	}
	var resolved config.ClientEndpointConfig
	err := clientdata.WithExclusiveLock(a.DataDir, func() error {
		registry, _, err := config.LoadStoredClientEndpointRegistry(a.DataDir)
		if err != nil {
			return err
		}
		current, exists := registry.Endpoint(plan.Alias)
		if plan.ExistingEndpoint == nil {
			if exists {
				return fmt.Errorf("endpoint alias %q changed after review; review setup again", plan.Alias)
			}
		} else if !exists || current != *plan.ExistingEndpoint {
			return fmt.Errorf("endpoint alias %q changed after review; review setup again", plan.Alias)
		}
		upsert, err := config.PlanStoredClientEndpointUpsert(a.DataDir, plan.Alias, plan.Endpoint, replace)
		if err != nil {
			return err
		}
		if !upsert.Created && !upsert.Updated {
			return nil
		}
		return config.ApplyStoredClientEndpointUpsert(a.DataDir, upsert)
	})
	if err != nil {
		return config.ClientEndpointConfig{}, err
	}
	cfg, err := config.LoadConfig(a.DataDir)
	if err != nil {
		return config.ClientEndpointConfig{}, err
	}
	endpoint, ok := cfg.Endpoints.Endpoint(plan.Alias)
	if !ok {
		return config.ClientEndpointConfig{}, fmt.Errorf("configured endpoint %q is missing", plan.Alias)
	}
	a.adoptConfig(cfg)
	resolved = endpoint
	return resolved, nil
}

// CompleteCosignerSetup establishes endpoint access when needed, confirms the
// node is a cosigner, and reports the route sweep. It never changes the
// primary tunnel.
//
// The returned error covers only this connection: access, node role, and
// duplicate routes that involve it. The result is returned alongside an error
// so callers can report completed effects.
func (a *App) CompleteCosignerSetup(ctx context.Context, plan CosignerSetupPlan, endpoint config.ClientEndpointConfig, approve sshtunnel.HostKeyApprovalHandler, onProvisioningStarted func(string)) (*CosignerSetupResult, error) {
	result := &CosignerSetupResult{
		Alias: plan.Alias, URL: endpoint.URL, Created: plan.Created, Updated: plan.Updated,
		DryRun: plan.DryRun,
	}
	if plan.DryRun {
		result.RenderLines = cosignerSetupRenderLines(result, nil)
		return result, nil
	}
	result.TokenRetired = plan.RetiresToken

	token, err := tokenfile.ReadToken(endpoint.TokenFile)
	if err != nil {
		return result, fmt.Errorf("read cosigner endpoint token: %w", err)
	}
	// Applying the plan already retired any token that predates this route, so
	// a token found here was issued for it.
	if token == "" || plan.DestinationChanged {
		if !strings.HasPrefix(endpoint.URL, "ssh://") {
			switch {
			case plan.DestinationChanged:
				return result, fmt.Errorf("endpoint %q changed destinations; the previous destination's token was retired; install a token for the new endpoint and rerun", plan.Alias)
			case plan.Created && plan.RetiresToken:
				return result, fmt.Errorf("endpoint %q has no token; a token file left over under this name was removed; automatic enrollment requires ssh://; install this endpoint's token and rerun", plan.Alias)
			}
			return result, fmt.Errorf("endpoint %q has no token; automatic enrollment requires ssh://; install its token and rerun", plan.Alias)
		}
		if err := a.requestCosignerTokenIsolated(ctx, plan.Alias, endpoint, approve, onProvisioningStarted); err != nil {
			return result, err
		}
		result.TokenIssued = true
	}

	inspection, err := a.eng.InspectCosignerEndpointWithHostKeyApproval(ctx, endpoint, approve)
	result.NodeRole = inspection.NodeRole
	if err != nil {
		switch {
		case errors.Is(err, engine.ErrCosignerDiscoveryLocked):
			return result, fmt.Errorf("connected and authenticated; cosigner is locked; unlock it in apadmin and rerun: %w", err)
		case errors.Is(err, engine.ErrCosignerDiscoveryAuth) && !result.TokenIssued:
			return result, fmt.Errorf("stored token for endpoint %q was rejected; run request-token --endpoint %s to re-enroll: %w", plan.Alias, plan.Alias, err)
		case inspection.NodeRole == "":
			return result, fmt.Errorf("%w: %w", ErrCosignerSetupRoleUnverified, err)
		default:
			return result, err
		}
	}
	switch inspection.NodeRole {
	case engine.NodeRoleCosigner:
	case config.ClientEndpointRoleSigner:
		return result, fmt.Errorf(
			"%w: %s reports the signer role; set up a signer connection with 'endpoints import --alias <alias> --role signer <endpoint-json>', then 'request-token' and 'connect'",
			ErrCosignerSetupNotCosigner, endpoint.URL,
		)
	case "":
		return result, fmt.Errorf("%w: %s did not report a node role", ErrCosignerSetupRoleUnverified, endpoint.URL)
	default:
		return result, fmt.Errorf("%w: %s reports the unrecognized role %q", ErrCosignerSetupRoleUnverified, endpoint.URL, inspection.NodeRole)
	}
	result.Connected = true
	result.AdvertisedKeys = len(inspection.Keys)

	registry := a.Config.ClientEndpointsOrDefault()
	if cfg, loadErr := config.LoadConfig(a.DataDir); loadErr == nil {
		registry = cfg.Endpoints
	}
	status := a.eng.CosignerStatus(ctx, registry)
	result.Routes = cosignerSetupRoutes(plan.Alias, status)
	result.RenderLines = cosignerSetupRenderLines(result, a.accountLabel)
	if len(result.Routes.Duplicates) > 0 {
		ids := sortedKeys(result.Routes.Duplicates)
		return result, fmt.Errorf(
			"%w: Witness Key ID %s is advertised by connections %s; signing needs a unique route",
			ErrCosignerSetupDuplicateRoute, witness.GroupedID(ids[0]), strings.Join(result.Routes.Duplicates[ids[0]], " and "),
		)
	}
	return result, nil
}

// RemoveCreatedCosignerConnection removes a connection that this setup run
// created and that turned out not to be usable. It revalidates under the client
// lock that the route is still the one this run wrote. Its token is retired
// with it, as for any deleted endpoint. Host trust is left for separate
// cleanup.
func (a *App) RemoveCreatedCosignerConnection(plan CosignerSetupPlan) error {
	if !plan.Created || plan.DryRun {
		return fmt.Errorf("connection %q was not created by this setup run", plan.Alias)
	}
	err := clientdata.WithExclusiveLock(a.DataDir, func() error {
		registry, _, err := config.LoadStoredClientEndpointRegistry(a.DataDir)
		if err != nil {
			return err
		}
		current, exists := registry.Endpoint(plan.Alias)
		if !exists {
			return nil
		}
		if current != plan.Endpoint {
			return fmt.Errorf("connection %q changed since setup; it was not removed", plan.Alias)
		}
		_, err = config.RemoveStoredClientEndpoint(a.DataDir, plan.Alias)
		return err
	})
	if err != nil {
		return err
	}
	return a.reloadConfigAfterEndpointChange()
}

func (a *App) requestCosignerTokenIsolated(ctx context.Context, alias string, endpoint config.ClientEndpointConfig, approve sshtunnel.HostKeyApprovalHandler, onProvisioningStarted func(string)) error {
	endpointSSH, err := config.ResolveClientEndpointSSH(endpoint)
	if err != nil {
		return err
	}
	token, err := a.eng.Connection.RequestTokenWithContext(ctx, endpointSSH.Host, endpointSSH.Port, endpointSSH.IdentityFile, endpointSSH.KnownHostsPath, approve, onProvisioningStarted)
	if err != nil {
		return fmt.Errorf("request token from endpoint %q: %w", alias, err)
	}
	if _, err := a.saveEndpointTokenIfCurrent(alias, endpoint, token); err != nil {
		return fmt.Errorf("save token for endpoint %q: %w", alias, err)
	}
	return nil
}

// saveEndpointTokenIfCurrent stores a freshly issued token only while alias
// still names the destination and token file that enrollment started with.
// Enrollment waits for operator approval with the client lock released, so the
// alias can be replaced in the meantime; a token issued by the old destination
// must not land under the new route.
func (a *App) saveEndpointTokenIfCurrent(alias string, requested config.ClientEndpointConfig, token string) (string, error) {
	if a.DataDir == "" {
		// Without a data directory there is no stored registry to revalidate.
		return a.eng.SaveApshellTokenToPath(requested.TokenFile, token)
	}
	var tokenPath string
	err := clientdata.WithExclusiveLock(a.DataDir, func() error {
		registry, err := config.LoadClientEndpointRegistry(a.DataDir)
		if err != nil {
			return err
		}
		current, ok := registry.Endpoint(alias)
		if !ok {
			return fmt.Errorf("endpoint %q was removed while its access request was pending; the issued token was discarded", alias)
		}
		sameTokenFile := requested.TokenFile == "" || config.SameClientEndpointTokenFile(a.DataDir, requested, current)
		if config.ClientEndpointDestinationChanged(requested, current) || !sameTokenFile {
			return fmt.Errorf("endpoint %q changed while its access request was pending; the issued token was discarded; rerun to request access for the current destination", alias)
		}
		tokenPath = current.TokenFile
		if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
			return err
		}
		return tokenfile.WriteToken(tokenPath, token)
	})
	if err != nil {
		return "", err
	}
	return tokenPath, nil
}

func (a *App) accountLabel(address string) string {
	if a.eng != nil {
		if alias := a.eng.AliasCache.GetAliasForAddress(address); alias != "" {
			return alias + " (" + address + ")"
		}
	}
	return address
}

// cosignerSetupRoutes projects the resolver's sweep onto the connection being
// added, keeping its classifications: answered connections count toward routes
// and duplicates, failed ones are ignored by routing but qualify the result,
// and a sweep that stopped early supports no positive route conclusion.
func cosignerSetupRoutes(alias string, status engine.CosignerStatusResult) *CosignerSetupRoutes {
	routes := &CosignerSetupRoutes{
		AccountInventory: status.AccountInventory,
		InventoryError:   status.InventoryError,
		Stopped:          status.DiscoveryError,
	}
	for _, connection := range status.Connections {
		switch {
		case connection.State == engine.CosignerConnectionHostKeyMismatch:
			routes.HostKeyMismatch = append(routes.HostKeyMismatch, connection.Alias)
		case connection.State == engine.CosignerConnectionNotChecked:
			routes.NotContacted = append(routes.NotContacted, connection.Alias)
		case connection.State != engine.CosignerConnectionReachable:
			routes.Unread = append(routes.Unread, CosignerSetupUnreadConnection{Alias: connection.Alias, State: connection.State})
		}
	}
	for id, aliases := range status.DuplicateRoutes {
		target := &routes.OtherDuplicates
		for _, candidate := range aliases {
			if candidate == alias {
				target = &routes.Duplicates
			}
		}
		if *target == nil {
			*target = map[string][]string{}
		}
		(*target)[id] = aliases
	}
	for _, account := range status.Accounts {
		routes.AccountsRequired++
		if account.State == engine.CosignerAccountRouteAvailable {
			routes.AccountsRouted++
			continue
		}
		routes.Unrouted = append(routes.Unrouted, account)
	}
	return routes
}

func cosignerSetupRenderLines(result *CosignerSetupResult, accountLabel func(string) string) []string {
	if result.DryRun {
		return []string{
			"Cosigner connection dry run:",
			fmt.Sprintf("  connection: %s (%s)", result.Alias, result.URL),
			"  no files changed; host trust, access, node role, and routes were not checked",
		}
	}
	if !result.Connected {
		return nil
	}
	connection := fmt.Sprintf("Connection %s ready", result.Alias)
	if result.TokenIssued {
		connection += "; access token saved"
	}
	lines := []string{connection + ".", fmt.Sprintf("%d cosigner key(s) advertised.", result.AdvertisedKeys)}
	routes := result.Routes
	if routes == nil {
		return lines
	}
	for _, id := range sortedKeys(routes.Duplicates) {
		lines = append(lines, fmt.Sprintf(
			"Duplicate route: Witness Key ID %s is advertised by %s. Signing needs a unique route.",
			witness.GroupedID(id), strings.Join(routes.Duplicates[id], " and "),
		))
	}
	for _, id := range sortedKeys(routes.OtherDuplicates) {
		lines = append(lines, fmt.Sprintf(
			"Duplicate route on other connections: Witness Key ID %s via %s.",
			witness.GroupedID(id), strings.Join(routes.OtherDuplicates[id], ", "),
		))
	}
	if routes.Stopped != "" {
		if len(routes.HostKeyMismatch) > 0 {
			lines = append(lines, fmt.Sprintf(
				"Route check stopped: the host key for %s does not match its pinned key.",
				strings.Join(routes.HostKeyMismatch, ", "),
			))
		} else {
			lines = append(lines, "Route check stopped: "+routes.Stopped+".")
		}
		if len(routes.NotContacted) > 0 {
			lines = append(lines, "Not contacted: "+strings.Join(routes.NotContacted, ", ")+".")
		}
		return append(lines, "Resolve it, then run cosigner status.")
	}
	switch {
	case routes.AccountInventory != "available":
		lines = append(lines, "Account routes not checked: "+routes.InventoryError+".", "Then run cosigner status.")
	case routes.AccountsRequired == 0:
		lines = append(lines, "No accounts requiring a cosigner on the connected signer.",
			"Next: create an account in signer-side apadmin and choose this cosigner's key file.")
	case len(routes.Unread) > 0:
		lines = append(lines, fmt.Sprintf("Matching route observed for %d of %d accounts on the connected signer.", routes.AccountsRouted, routes.AccountsRequired))
	default:
		lines = append(lines, fmt.Sprintf("Cosigner routes available for %d of %d accounts on the connected signer.", routes.AccountsRouted, routes.AccountsRequired))
	}
	if routes.AccountInventory == "available" {
		for _, account := range routes.Unrouted {
			label := account.Address
			if accountLabel != nil {
				label = accountLabel(account.Address)
			}
			line := fmt.Sprintf("  %s: %s", label, account.State)
			if account.WitnessKeyID != "" {
				line += " (needs " + witness.GroupedID(account.WitnessKeyID) + ")"
			}
			lines = append(lines, line)
		}
	}
	if len(routes.Unread) > 0 {
		unread := make([]string, 0, len(routes.Unread))
		for _, connection := range routes.Unread {
			unread = append(unread, fmt.Sprintf("%s (%s)", connection.Alias, connection.State))
		}
		lines = append(lines, "Could not read: "+strings.Join(unread, ", ")+". Duplicates there cannot be ruled out.")
	}
	return lines
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
