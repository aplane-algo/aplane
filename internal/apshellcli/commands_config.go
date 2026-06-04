// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Configuration and connection commands

import (
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/config"
)

func (r *REPLState) cmdNetwork(args []string, _ interface{}) error {
	return setNetwork(r, args)
}

func (r *REPLState) cmdWrite(args []string, _ interface{}) error {
	return toggleWriteMode(r, args)
}

func (r *REPLState) cmdVerbose(args []string, _ interface{}) error {
	result, err := execVerbose(r, args)
	if err != nil {
		return err
	}
	result.RenderText(r.Out, r)
	return nil
}

func (r *REPLState) cmdSimulate(args []string, _ interface{}) error {
	return toggleSimulate(r, args)
}

func (r *REPLState) cmdConnect(args []string, _ interface{}) error {
	if len(args) == 0 {
		return connectConfigured(r)
	}
	if len(args) == 1 {
		return connectEndpointAlias(r, args[0])
	}
	return fmt.Errorf("usage: connect [endpoint-alias]")
}

func (r *REPLState) cmdRequestToken(args []string, _ interface{}) error {
	// Parse connection info
	if len(args) == 0 {
		return requestTokenConfigured(r)
	}
	if len(args) == 2 && (args[0] == "--endpoint" || args[0] == "-e") {
		return requestTokenEndpointAlias(r, args[1])
	}

	// Parse connection string
	connStr := strings.Join(args, " ")
	parsed, err := config.ParseConnectionString(connStr)
	if err != nil {
		return fmt.Errorf("invalid connection: %w", err)
	}

	return requestToken(r, parsed.Host, parsed.SSHPort)
}

func (r *REPLState) cmdEndpoints(args []string, _ interface{}) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: endpoints list | endpoints show <alias> | endpoints import --alias <alias> [--dry-run] <endpoint-json> | endpoints discover-attestors [--dry-run] | endpoints default <alias> | endpoints delete <alias>")
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("usage: endpoints list")
		}
		result, err := r.app().EndpointsList(r.commandContext())
		if err != nil {
			return err
		}
		r.renderEndpointsList(result)
		return nil
	case "show":
		if len(args) != 2 {
			return fmt.Errorf("usage: endpoints show <alias>")
		}
		result, err := r.app().EndpointShow(r.commandContext(), args[1])
		if err != nil {
			return err
		}
		r.renderEndpointShow(result)
		return nil
	case "import":
		req, err := parseEndpointImportArgs(args[1:])
		if err != nil {
			return err
		}
		result, err := r.app().EndpointImport(r.commandContext(), req)
		if err != nil {
			return err
		}
		if !result.DryRun {
			if cfg, err := config.LoadConfig(r.DataDir); err == nil {
				r.Config = cfg
				r.app().Config = cfg
			}
		}
		for _, line := range result.RenderLines {
			r.println(line)
		}
		if !result.DryRun {
			r.printf("Run 'request-token --endpoint %s' before using this endpoint.\n", result.Alias)
		}
		return nil
	case "discover-attestors":
		req, err := parseEndpointDiscoverAttestorsArgs(args[1:])
		if err != nil {
			return err
		}
		result, err := r.app().EndpointDiscoverAttestors(r.commandContext(), req)
		if err != nil {
			return err
		}
		if !result.DryRun {
			if cfg, err := config.LoadConfig(r.DataDir); err == nil {
				r.Config = cfg
				r.app().Config = cfg
			}
		}
		for _, line := range result.RenderLines {
			r.println(line)
		}
		return nil
	case "default":
		if len(args) != 2 {
			return fmt.Errorf("usage: endpoints default <alias>")
		}
		result, err := r.app().EndpointDefault(r.commandContext(), args[1])
		if err != nil {
			return err
		}
		if cfg, err := config.LoadConfig(r.DataDir); err == nil {
			r.Config = cfg
			r.app().Config = cfg
		}
		for _, line := range result.RenderLines {
			r.println(line)
		}
		return nil
	case "delete":
		if len(args) != 2 {
			return fmt.Errorf("usage: endpoints delete <alias>")
		}
		result, err := r.app().EndpointDelete(r.commandContext(), args[1])
		if err != nil {
			return err
		}
		if cfg, err := config.LoadConfig(r.DataDir); err == nil {
			r.Config = cfg
			r.app().Config = cfg
		}
		for _, line := range result.RenderLines {
			r.println(line)
		}
		return nil
	default:
		return fmt.Errorf("unknown endpoints subcommand %q", args[0])
	}
}

func (r *REPLState) cmdScript(args []string, _ interface{}) error {
	return r.runScript(args)
}

func (r *REPLState) cmdConfig(_ []string, _ interface{}) error {
	// Display current config
	config.DisplayConfig(r.DataDir)
	r.println("Note: Config is read-only. Edit config.yaml in the data directory manually.")
	return nil
}

func parseEndpointImportArgs(args []string) (apshellapp.EndpointImportRequest, error) {
	var req apshellapp.EndpointImportRequest
	const usage = "usage: endpoints import --alias <alias> [--dry-run] <endpoint-json>"
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--dry-run":
			req.DryRun = true
		case "--alias", "-a":
			if req.Alias != "" {
				return req, errors.New(usage)
			}
			i++
			if i >= len(args) || args[i] == "" || strings.HasPrefix(args[i], "-") {
				return req, errors.New(usage)
			}
			req.Alias = args[i]
		default:
			if strings.HasPrefix(arg, "-") {
				return req, fmt.Errorf("unknown endpoints import flag %q", arg)
			}
			if req.Path != "" {
				return req, errors.New(usage)
			}
			req.Path = arg
		}
	}
	if req.Alias == "" || req.Path == "" {
		return req, errors.New(usage)
	}
	return req, nil
}

func parseEndpointDiscoverAttestorsArgs(args []string) (apshellapp.EndpointDiscoverAttestorsRequest, error) {
	var req apshellapp.EndpointDiscoverAttestorsRequest
	const usage = "usage: endpoints discover-attestors [--dry-run]"
	for _, arg := range args {
		switch arg {
		case "--dry-run":
			if req.DryRun {
				return req, errors.New(usage)
			}
			req.DryRun = true
		default:
			return req, errors.New(usage)
		}
	}
	return req, nil
}

func (r *REPLState) renderEndpointsList(result *apshellapp.EndpointsListResult) {
	if len(result.Endpoints) == 0 {
		r.println("No endpoints configured")
		return
	}
	w := tabwriter.NewWriter(r.Out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ALIAS\tDEFAULT\tURL\tTOKEN\tATTESTORS")
	for _, endpoint := range result.Endpoints {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n",
			endpoint.Alias,
			yesNo(endpoint.IsDefault),
			endpoint.URL,
			tokenStatusLabel(endpoint),
			len(endpoint.PublishedAttestorPublicKeys),
		)
	}
	_ = w.Flush()
}

func (r *REPLState) renderEndpointShow(result *apshellapp.EndpointShowResult) {
	endpoint := result.Endpoint
	r.printf("Alias: %s\n", endpoint.Alias)
	r.printf("Default: %s\n", yesNo(endpoint.IsDefault))
	r.printf("URL: %s\n", endpoint.URL)
	r.printf("Signer port: %d\n", endpoint.SignerPort)
	r.printf("Local port: %d\n", endpoint.LocalPort)
	r.printf("Identity file: %s\n", endpoint.IdentityFile)
	r.printf("Known hosts: %s\n", endpoint.KnownHostsPath)
	r.printf("Token file: %s\n", endpoint.TokenFile)
	r.printf("Token present: %s\n", tokenStatusLabel(endpoint))
	if len(endpoint.PublishedAttestorPublicKeys) == 0 {
		r.println("Published attestors: none")
		return
	}
	r.println("Published attestors:")
	for _, publicKey := range endpoint.PublishedAttestorPublicKeys {
		r.printf("  %s\n", publicKey)
	}
}

func tokenStatusLabel(endpoint apshellapp.EndpointEntry) string {
	if endpoint.TokenError != "" {
		return "error"
	}
	return yesNo(endpoint.TokenPresent)
}

func yesNo(ok bool) string {
	if ok {
		return "yes"
	}
	return "no"
}

func (r *REPLState) cmdPlugins(args []string, _ interface{}) error {
	result, err := r.app().PluginsInfo(r.commandContext(), args)
	if err != nil {
		return err
	}

	if result.Mode == "list" && len(result.Plugins) == 0 {
		r.println("No external plugins found")
		return nil
	}

	if result.Mode == "show" && result.Plugin != nil {
		plugin := result.Plugin
		r.printf("%s v%s\n", plugin.Name, plugin.Version)
		if plugin.Description != "" {
			r.printf("  %s\n", plugin.Description)
		}
		if plugin.Author != "" {
			r.printf("  Author: %s\n", plugin.Author)
		}
		if len(plugin.Networks) > 0 {
			r.printf("  Networks: %s\n", strings.Join(plugin.Networks, ", "))
		}
		r.println("  Commands:")
		for _, cmd := range plugin.Commands {
			r.printf("    %s - %s\n", cmd.Name, cmd.Description)
			if cmd.Usage != "" {
				r.printf("      Usage: %s\n", cmd.Usage)
			}
		}
		return nil
	}

	r.printf("%s:\n", result.Summary.Message)
	for _, plugin := range result.Plugins {
		// Collect command names
		var cmdNames []string
		for _, cmd := range plugin.Commands {
			cmdNames = append(cmdNames, cmd.Name)
		}

		r.printf("  %s v%s", plugin.Name, plugin.Version)
		if plugin.Description != "" {
			r.printf(" - %s", plugin.Description)
		}
		r.println()
		r.printf("    Commands: %s\n", strings.Join(cmdNames, ", "))
		if len(plugin.Networks) > 0 {
			r.printf("    Networks: %s\n", strings.Join(plugin.Networks, ", "))
		}
	}
	return nil
}
