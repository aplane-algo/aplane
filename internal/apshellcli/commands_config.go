// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Configuration and connection commands

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/config"
)

const endpointsUsage = "endpoints list | " +
	"endpoints show <alias> | " +
	"endpoints create --alias <alias> --endpoint <url> --sentryport <port> [--dry-run] | " +
	"endpoints import --alias <alias> --role signer|sentry [--dry-run] <endpoint-json> | " +
	"endpoints discover-sentries | " +
	"endpoints default <alias> | " +
	"endpoints delete <alias>"

func (r *REPLState) cmdNetwork(args []string, _ interface{}) (command.Result, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("usage: network <network>")
	}
	result, err := r.app().SwitchNetwork(r.commandContext(), apshellapp.SwitchNetworkRequest{Network: args[0]})
	if err != nil {
		return nil, err
	}
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutputResult(w, func() error { return r.renderSwitchNetworkResult(result) })
	}, networkProjection{OldNetwork: result.OldNetwork, Network: result.NewNetwork})
}

func (r *REPLState) cmdWrite(args []string, _ interface{}) (command.Result, error) {
	result, err := execWrite(r, args)
	if err != nil {
		return nil, err
	}
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() { renderToggle(r, result) })
	}, toggleProjection(result))
}

func (r *REPLState) cmdVerbose(args []string, _ interface{}) (command.Result, error) {
	result, err := execVerbose(r, args)
	if err != nil {
		return nil, err
	}
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() { renderToggle(r, result) })
	}, toggleProjection(result))
}

func (r *REPLState) cmdSimulate(args []string, _ interface{}) (command.Result, error) {
	return executeSimulate(r, args)
}

func (r *REPLState) cmdConnect(args []string, _ interface{}) (command.Result, error) {
	var result *apshellapp.ConnectResult
	var err error
	alias := ""
	if len(args) == 0 {
		result, err = executeConnectConfigured(r)
	} else if len(args) == 1 {
		alias = args[0]
		result, err = executeConnectEndpointAlias(r, alias)
	} else {
		return nil, fmt.Errorf("usage: connect [endpoint-alias]")
	}
	if err != nil {
		return nil, err
	}
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutputResult(w, func() error {
			if alias != "" {
				r.printf("Connecting to endpoint %s...\n", alias)
			}
			r.println("Using SSH public key authentication...")
			return r.renderConnectResult(result)
		})
	}, connectionProjection{
		Connected: true, Target: result.Target, Port: result.Port, KeyCount: result.KeyCount,
		Locked: result.Locked, AlreadyConnected: result.AlreadyConnected,
	})
}

func (r *REPLState) cmdRequestToken(args []string, ctx interface{}) (command.Result, error) {
	return newTerminalCommandResult(nil), r.runRequestToken(args, ctx)
}

func (r *REPLState) runRequestToken(args []string, _ interface{}) error {
	if len(args) == 0 {
		return requestTokenConfigured(r)
	}
	if len(args) == 2 && (args[0] == "--endpoint" || args[0] == "-e") {
		return requestTokenEndpointAlias(r, args[1])
	}
	return fmt.Errorf("usage: request-token [--endpoint <alias>]")
}

func (r *REPLState) cmdEndpoints(args []string, _ interface{}) (command.Result, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("usage: %s", endpointsUsage)
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return nil, fmt.Errorf("usage: endpoints list")
		}
		result, err := r.app().EndpointsList(r.commandContext())
		if err != nil {
			return nil, err
		}
		projection := make([]endpointProjection, len(result.Endpoints))
		for i, endpoint := range result.Endpoints {
			projection[i] = projectEndpointEntry(endpoint)
		}
		return newShellCommandResult(func(w io.Writer) error {
			return r.withOutput(w, func() { r.renderEndpointsList(result) })
		}, projection)
	case "show":
		if len(args) != 2 {
			return nil, fmt.Errorf("usage: endpoints show <alias>")
		}
		result, err := r.app().EndpointShow(r.commandContext(), args[1])
		if err != nil {
			return nil, err
		}
		return newShellCommandResult(func(w io.Writer) error {
			return r.withOutput(w, func() { r.renderEndpointShow(result) })
		}, projectEndpointEntry(result.Endpoint))
	case "create", "create-sentry":
		req, err := parseEndpointCreateSentryArgs(args[1:])
		if err != nil {
			return nil, err
		}
		result, err := r.app().EndpointCreateSentry(r.commandContext(), req)
		if err != nil {
			return nil, err
		}
		if !result.DryRun {
			if cfg, err := config.LoadConfig(r.DataDir); err == nil {
				r.Config = cfg
				r.app().Config = cfg
			}
		}
		return newShellCommandResult(func(w io.Writer) error {
			return r.withOutput(w, func() {
				for _, line := range result.RenderLines {
					r.println(line)
				}
				if !result.DryRun {
					r.printf("Run 'request-token --endpoint %s' before using this endpoint.\n", result.Alias)
				}
			})
		}, endpointMutationProjection{
			Mode: "create", Alias: result.Alias, Role: result.Role, URL: result.URL,
			Port: result.SentryPort, DryRun: result.DryRun, Created: result.Created, Updated: result.Updated,
		})
	case "import":
		req, err := parseEndpointImportArgs(args[1:])
		if err != nil {
			return nil, err
		}
		result, err := r.app().EndpointImport(r.commandContext(), req)
		if err != nil {
			return nil, err
		}
		if !result.DryRun {
			if cfg, err := config.LoadConfig(r.DataDir); err == nil {
				r.Config = cfg
				r.app().Config = cfg
			}
		}
		return newShellCommandResult(func(w io.Writer) error {
			return r.withOutput(w, func() {
				for _, line := range result.RenderLines {
					r.println(line)
				}
				if !result.DryRun {
					r.printf("Run 'request-token --endpoint %s' before using this endpoint.\n", result.Alias)
				}
			})
		}, endpointMutationProjection{
			Mode: "import", Alias: result.Alias, Role: result.Role, URL: result.URL,
			Port: result.SignerPort, DryRun: result.DryRun, Created: result.Created,
			Updated: result.Updated, DefaultChanged: result.DefaultChanged,
		})
	case "discover-sentries":
		req, err := parseEndpointDiscoverSentriesArgs(args[1:])
		if err != nil {
			return nil, err
		}
		result, err := r.app().EndpointDiscoverSentries(r.commandContext(), req)
		if err != nil {
			return nil, err
		}
		projection := endpointDiscoveryProjection{PublicKeyCount: result.PublicKeyCount}
		projection.Endpoints = make([]endpointDiscoveryEntry, len(result.Endpoints))
		for i, endpoint := range result.Endpoints {
			entry := endpointDiscoveryEntry{Alias: endpoint.Alias, Skipped: endpoint.Skipped, Error: endpoint.Error}
			entry.Keys = make([]endpointDiscoveryKey, len(endpoint.Keys))
			for j, key := range endpoint.Keys {
				entry.Keys[j] = endpointDiscoveryKey{
					PublicKey: key.PublicKey, ComponentKey: key.ComponentKey, KeyType: key.KeyType,
				}
			}
			projection.Endpoints[i] = entry
		}
		return newShellCommandResult(func(w io.Writer) error {
			return r.withOutput(w, func() {
				for _, line := range result.RenderLines {
					r.println(line)
				}
			})
		}, projection)
	case "default":
		if len(args) != 2 {
			return nil, fmt.Errorf("usage: endpoints default <alias>")
		}
		result, err := r.app().EndpointDefault(r.commandContext(), args[1])
		if err != nil {
			return nil, err
		}
		if cfg, err := config.LoadConfig(r.DataDir); err == nil {
			r.Config = cfg
			r.app().Config = cfg
		}
		return endpointRenderLinesResult(r, result.RenderLines, endpointMutationProjection{
			Mode: "default", Alias: result.Alias, PreviousDefault: result.PreviousAlias, DefaultChanged: true,
		})
	case "delete":
		if len(args) != 2 {
			return nil, fmt.Errorf("usage: endpoints delete <alias>")
		}
		result, err := r.app().EndpointDelete(r.commandContext(), args[1])
		if err != nil {
			return nil, err
		}
		if cfg, err := config.LoadConfig(r.DataDir); err == nil {
			r.Config = cfg
			r.app().Config = cfg
		}
		return endpointRenderLinesResult(r, result.RenderLines, endpointMutationProjection{
			Mode: "delete", Alias: result.Alias, Deleted: true,
		})
	default:
		return nil, fmt.Errorf("unknown endpoints subcommand %q", args[0])
	}
}

func endpointRenderLinesResult(r *REPLState, lines []string, projection interface{}) (command.Result, error) {
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() {
			for _, line := range lines {
				r.println(line)
			}
		})
	}, projection)
}

func (r *REPLState) cmdScript(args []string, _ interface{}) (command.Result, error) {
	return newTerminalCommandResult(nil), r.runScript(args)
}

func (r *REPLState) cmdConfig(_ []string, _ interface{}) (command.Result, error) {
	// Display current config
	config.DisplayConfig(r.DataDir)
	r.println("Note: Config is read-only. Edit config.yaml in the data directory manually.")
	return newTerminalCommandResult(nil), nil
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
	if len(args) != 0 {
		return req, errors.New("usage: endpoints discover-sentries")
	}
	return req, nil
}

func (r *REPLState) renderEndpointsList(result *apshellapp.EndpointsListResult) {
	if len(result.Endpoints) == 0 {
		r.println("No endpoints configured")
		return
	}
	w := tabwriter.NewWriter(r.Out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ALIAS\tROLE\tDEFAULT\tURL\tTOKEN")
	for _, endpoint := range result.Endpoints {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			endpoint.Alias,
			endpoint.Role,
			yesNo(endpoint.IsDefault),
			endpoint.URL,
			tokenStatusLabel(endpoint),
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

func (r *REPLState) cmdPlugins(args []string, _ interface{}) (command.Result, error) {
	result, err := r.app().PluginsInfo(r.commandContext(), args)
	if err != nil {
		return nil, err
	}
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() {
			if result.Mode == "list" && len(result.Plugins) == 0 {
				r.println("No external plugins found")
				return
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
				return
			}
			r.printf("%s:\n", result.Summary.Message)
			for _, plugin := range result.Plugins {
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
		})
	}, projectPluginsResult(result))
}
