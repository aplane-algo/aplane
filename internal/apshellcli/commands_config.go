// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Configuration and connection commands

import (
	"errors"
	"fmt"
	"strconv"
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
	if len(args) == 0 {
		return requestTokenConfigured(r)
	}
	if len(args) == 2 && (args[0] == "--endpoint" || args[0] == "-e") {
		return requestTokenEndpointAlias(r, args[1])
	}
	return fmt.Errorf("usage: request-token [--endpoint <alias>]")
}

func (r *REPLState) cmdEndpoints(args []string, _ interface{}) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: endpoints list | endpoints show <alias> | endpoints sentries | endpoints create --alias <alias> --endpoint <url> --sentryport <port> [--dry-run] | endpoints import --alias <alias> --role signer|sentry [--dry-run] <endpoint-json> | endpoints sync-sentries [--dry-run] [--yes] | endpoints default <alias> | endpoints delete <alias>")
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
	case "sentries":
		if len(args) != 1 {
			return fmt.Errorf("usage: endpoints sentries")
		}
		result, err := r.app().EndpointSentries(r.commandContext())
		if err != nil {
			return err
		}
		r.renderEndpointSentries(result)
		return nil
	case "create", "create-sentry":
		req, err := parseEndpointCreateSentryArgs(args[1:])
		if err != nil {
			return err
		}
		result, err := r.app().EndpointCreateSentry(r.commandContext(), req)
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
	case "discover-sentries":
		req, err := parseEndpointDiscoverSentriesArgs(args[1:])
		if err != nil {
			return err
		}
		result, err := r.app().EndpointDiscoverSentries(r.commandContext(), req)
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
	case "sync-sentries":
		req, err := parseEndpointSyncSentriesArgs(args[1:])
		if err != nil {
			return err
		}
		result, err := r.app().EndpointSyncSentries(r.commandContext(), req)
		if err != nil {
			return err
		}
		if result.NeedsConfirmation {
			for _, line := range result.RenderLines {
				r.progressPrintln(line)
			}
		} else {
			for _, line := range result.RenderLines {
				r.println(line)
			}
		}
		if result.NeedsConfirmation {
			if !r.app().IsConnected() {
				return fmt.Errorf("not connected to Signer; run connect before syncing sentries to the signer library")
			}
			if r.AutoConfirm {
				return fmt.Errorf("endpoints sync-sentries requires --yes to update the signer library in non-interactive mode")
			}
			response, err := r.readPromptResponse("Sync these sentries to the signer library? [y/N]: ")
			if err != nil {
				return err
			}
			if response != "y" && response != "yes" {
				r.println("Sync cancelled")
				return nil
			}
			confirmed, err := r.app().EndpointConfirmSyncSentries(r.commandContext())
			if err != nil {
				return err
			}
			for _, line := range confirmed.RenderLines {
				r.println(line)
			}
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
	const usage = "usage: endpoints import --alias <alias> --role signer|sentry [--dry-run] <endpoint-json>"
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
		case "--role", "-r":
			if req.Role != "" {
				return req, errors.New(usage)
			}
			i++
			if i >= len(args) || args[i] == "" || strings.HasPrefix(args[i], "-") {
				return req, errors.New(usage)
			}
			req.Role = args[i]
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
	if req.Alias == "" || req.Role == "" || req.Path == "" {
		return req, errors.New(usage)
	}
	return req, nil
}

func parseEndpointCreateSentryArgs(args []string) (apshellapp.EndpointCreateSentryRequest, error) {
	var req apshellapp.EndpointCreateSentryRequest
	const usage = "usage: endpoints create --alias <alias> --endpoint <url> --sentryport <port> [--dry-run]"
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--dry-run":
			if req.DryRun {
				return req, errors.New(usage)
			}
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
		case "--endpoint", "--url":
			if req.URL != "" {
				return req, errors.New(usage)
			}
			i++
			if i >= len(args) || args[i] == "" || strings.HasPrefix(args[i], "-") {
				return req, errors.New(usage)
			}
			req.URL = args[i]
		case "--sentryport", "--sentry-port":
			if req.SentryPort != 0 {
				return req, errors.New(usage)
			}
			i++
			if i >= len(args) || args[i] == "" || strings.HasPrefix(args[i], "-") {
				return req, errors.New(usage)
			}
			port, err := strconv.Atoi(args[i])
			if err != nil || port <= 0 || port > 65535 {
				return req, errors.New(usage)
			}
			req.SentryPort = port
		default:
			return req, errors.New(usage)
		}
	}
	if req.Alias == "" || req.URL == "" || req.SentryPort == 0 {
		return req, errors.New(usage)
	}
	return req, nil
}

func parseEndpointDiscoverSentriesArgs(args []string) (apshellapp.EndpointDiscoverSentriesRequest, error) {
	var req apshellapp.EndpointDiscoverSentriesRequest
	const usage = "usage: endpoints discover-sentries [--dry-run]"
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

func parseEndpointSyncSentriesArgs(args []string) (apshellapp.EndpointSyncSentriesRequest, error) {
	var req apshellapp.EndpointSyncSentriesRequest
	const usage = "usage: endpoints sync-sentries [--dry-run] [--yes]"
	for _, arg := range args {
		switch arg {
		case "--dry-run":
			if req.DryRun {
				return req, errors.New(usage)
			}
			req.DryRun = true
		case "--yes", "-y":
			if req.ApproveSignerSync {
				return req, errors.New(usage)
			}
			req.ApproveSignerSync = true
		default:
			return req, errors.New(usage)
		}
	}
	if req.DryRun && req.ApproveSignerSync {
		return req, errors.New(usage)
	}
	return req, nil
}

func (r *REPLState) renderEndpointsList(result *apshellapp.EndpointsListResult) {
	if len(result.Endpoints) == 0 {
		r.println("No endpoints configured")
		return
	}
	w := tabwriter.NewWriter(r.Out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ALIAS\tROLE\tDEFAULT\tURL\tTOKEN\tSENTRY KEYS")
	for _, endpoint := range result.Endpoints {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\n",
			endpoint.Alias,
			endpoint.Role,
			yesNo(endpoint.IsDefault),
			endpoint.URL,
			tokenStatusLabel(endpoint),
			len(endpoint.PublishedSentryComponents),
		)
	}
	_ = w.Flush()
}

func (r *REPLState) renderEndpointShow(result *apshellapp.EndpointShowResult) {
	endpoint := result.Endpoint
	r.printf("Alias: %s\n", endpoint.Alias)
	r.printf("Role: %s\n", endpoint.Role)
	r.printf("Default: %s\n", yesNo(endpoint.IsDefault))
	r.printf("URL: %s\n", endpoint.URL)
	r.printf("Signer port: %d\n", endpoint.SignerPort)
	r.printf("Local port: %d\n", endpoint.LocalPort)
	r.printf("Identity file: %s\n", endpoint.IdentityFile)
	r.printf("Known hosts: %s\n", endpoint.KnownHostsPath)
	r.printf("Token file: %s\n", endpoint.TokenFile)
	r.printf("Token present: %s\n", tokenStatusLabel(endpoint))
	if len(endpoint.PublishedSentryComponents) == 0 {
		r.println("Published sentries: none")
		return
	}
	r.println("Published sentries:")
	w := tabwriter.NewWriter(r.Out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "  SENTRY KEY\tKEY TYPE\tLAST SEEN")
	for _, sentry := range endpoint.PublishedSentries {
		_, _ = fmt.Fprintf(w, "  %s\t%s\t%s\n",
			sentry.ComponentKey,
			sentry.KeyType,
			sentry.LastSeenAt,
		)
	}
	_ = w.Flush()
}

func (r *REPLState) renderEndpointSentries(result *apshellapp.EndpointSentriesResult) {
	if len(result.Sentries) == 0 {
		r.println("No endpoint-discovered sentries")
		return
	}
	w := tabwriter.NewWriter(r.Out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ENDPOINT\tSENTRY KEY\tKEY TYPE")
	for _, sentry := range result.Sentries {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n",
			sentry.EndpointAlias,
			sentry.ComponentKey,
			sentry.KeyType,
		)
	}
	_ = w.Flush()
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
