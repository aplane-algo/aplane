// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

// Command registry initialization

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/util"
)

// mustRegister registers a command and panics if there's an error.
// Used during initialization where registration errors are programming bugs.
func mustRegister(registry *command.Registry, cmd *command.Command) {
	if err := registry.Register(cmd); err != nil {
		panic(fmt.Sprintf("failed to register command %q: %v", cmd.Name, err))
	}
}

// initCommandRegistry initializes the command registry with all REPL commands
func (r *REPLState) initCommandRegistry() *command.Registry {
	registry := command.NewRegistry()

	// Transaction Commands
	mustRegister(registry, &command.Command{
		Name:        "send",
		Usage:       "send <amount> <asset> from <sender> to <receiver> [note=<text>] [nowait] [atomic]",
		Description: "Send ALGO or ASA tokens. Use 'atomic' with @setname to send as atomic group",
		Category:    command.CategoryTransaction,
		Handler:     command.NewInternalHandler(r.cmdSend),
	})

	mustRegister(registry, &command.Command{
		Name:        "sweep",
		Usage:       "sweep <asset> [from [account1 account2 ...]] to <dest> [leaving <amount>] [nowait]",
		Description: "Sweep asset from accounts to destination (defaults to all signable accounts)",
		Category:    command.CategoryTransaction,
		Handler:     command.NewInternalHandler(r.cmdSweep),
	})

	mustRegister(registry, &command.Command{
		Name:        "sign",
		Usage:       "sign <file> [nowait]",
		Description: "Sign and submit transaction(s) from external file",
		Category:    command.CategoryTransaction,
		Handler:     command.NewInternalHandler(r.cmdSign),
	})

	mustRegister(registry, &command.Command{
		Name:        "optin",
		Usage:       "optin <asset> for <account> [nowait]",
		Description: "Opt into an ASA",
		Category:    command.CategoryTransaction,
		Handler:     command.NewInternalHandler(r.cmdOptin),
	})

	mustRegister(registry, &command.Command{
		Name:        "optout",
		Usage:       "optout <asset> from <account> [to <dest>] [nowait]",
		Description: "Opt out of an ASA. Requires 'to <dest>' if account holds balance",
		Category:    command.CategoryTransaction,
		Handler:     command.NewInternalHandler(r.cmdOptout),
	})

	mustRegister(registry, &command.Command{
		Name:        "keyreg",
		Usage:       "keyreg <account> online|offline [votekey=<key>] [eligible=true] [nowait]",
		Description: "Mark account status for consensus participation",
		Category:    command.CategoryTransaction,
		Handler:     command.NewInternalHandler(r.cmdKeyreg),
	})

	mustRegister(registry, &command.Command{
		Name:        "close",
		Usage:       "close <account> to <destination> [nowait]",
		Description: "Close account and send all ALGO to destination. Fails if account is online or has ASAs",
		Category:    command.CategoryTransaction,
		Handler:     command.NewInternalHandler(r.cmdClose),
	})

	mustRegister(registry, &command.Command{
		Name:        "balance",
		Aliases:     []string{"bal"},
		Usage:       "balance <account|@all|@signers|@set> [asa|algo]",
		Description: "Show balances for account(s) or sets",
		Category:    command.CategoryInfo,
		Handler:     command.NewInternalHandler(r.cmdBalance),
		ArgSpecs: []cmdspec.ArgSpec{
			{Type: cmdspec.ArgTypeAddress},
			{Type: cmdspec.ArgTypeAsset},
		},
	})

	mustRegister(registry, &command.Command{
		Name:        "holders",
		Usage:       "holders [asa|algo]",
		Description: "Show accounts with non-zero balance",
		Category:    command.CategoryInfo,
		Handler:     command.NewInternalHandler(r.cmdHolders),
		ArgSpecs: []cmdspec.ArgSpec{
			{Type: cmdspec.ArgTypeAsset},
		},
	})

	mustRegister(registry, &command.Command{
		Name:        "participation",
		Usage:       "participation <address>",
		Description: "Show detailed account participation status",
		Category:    command.CategoryInfo,
		Handler:     command.NewInternalHandler(r.cmdParticipation),
	})

	// Alias Management
	mustRegister(registry, &command.Command{
		Name:        "alias",
		Usage:       "alias [<address> <name>] | alias remove <name>",
		Description: "Manage address aliases",
		Category:    command.CategoryAlias,
		Handler:     command.NewInternalHandler(r.cmdAlias),
	})

	// Account Validation
	mustRegister(registry, &command.Command{
		Name:        "validate",
		Usage:       "validate <account>",
		Description: "Validate account signing by sending 0 ALGO to itself (works with sets: validate @setname)",
		Category:    command.CategoryTransaction,
		Handler:     command.NewInternalHandler(r.cmdValidate),
	})

	mustRegister(registry, &command.Command{
		Name:        "sets",
		Usage:       "sets [<name> [<addr>...]] | sets add <addr>... to <name> | sets remove <addr>... from <name> | sets delete <name>",
		Description: "Manage address sets (collections). Reference with @setname",
		Category:    command.CategoryAlias,
		Handler:     command.NewInternalHandler(r.cmdSets),
	})

	// Rekey Management
	mustRegister(registry, &command.Command{
		Name:        "rekey",
		Usage:       "rekey [<account> to <signer>] [nowait] | rekey refresh",
		Description: "Query and manage account rekeying. Use 'rekey refresh' to rebuild auth cache",
		Category:    command.CategoryRekey,
		Handler:     command.NewInternalHandler(r.cmdRekey),
	})

	mustRegister(registry, &command.Command{
		Name:        "unrekey",
		Usage:       "unrekey <address|alias> [nowait]",
		Description: "Rekey account back to itself",
		Category:    command.CategoryRekey,
		Handler:     command.NewInternalHandler(r.cmdUnrekey),
	})

	// Information
	mustRegister(registry, &command.Command{
		Name:        "help",
		Aliases:     []string{"h"},
		Usage:       "help [command]",
		Description: "Show help for commands",
		Category:    command.CategoryInfo,
		Handler:     command.NewInternalHandler(r.cmdHelp),
	})

	mustRegister(registry, &command.Command{
		Name:        "status",
		Usage:       "status",
		Description: "Show current configuration",
		Category:    command.CategoryInfo,
		Handler:     command.NewInternalHandler(r.cmdStatus),
	})

	mustRegister(registry, &command.Command{
		Name:        "accounts",
		Usage:       "accounts",
		Description: "List all accounts (aliases + signer accounts)",
		Category:    command.CategoryInfo,
		Handler:     command.NewInternalHandler(r.cmdAccounts),
	})

	mustRegister(registry, &command.Command{
		Name:        "keys",
		Usage:       "keys",
		Description: "List accounts available for signing from Signer",
		Category:    command.CategoryKeyMgmt,
		Handler:     command.NewInternalHandler(r.cmdSigners),
	})

	mustRegister(registry, &command.Command{
		Name:        "keytypes",
		Usage:       "keytypes",
		Description: "List available key types from Signer",
		Category:    command.CategoryKeyMgmt,
		Handler:     command.NewInternalHandler(r.cmdKeytypes),
	})

	mustRegister(registry, &command.Command{
		Name:        "generate",
		Usage:       "generate <key_type> [param=value ...]",
		Description: "Generate a new key on Signer",
		Category:    command.CategoryKeyMgmt,
		Handler:     command.NewInternalHandler(r.cmdGenerate),
	})

	mustRegister(registry, &command.Command{
		Name:        "delete",
		Usage:       "delete <address>",
		Description: "Delete a key from Signer",
		Category:    command.CategoryKeyMgmt,
		Handler:     command.NewInternalHandler(r.cmdDelete),
	})

	mustRegister(registry, &command.Command{
		Name:        "info",
		Usage:       "info <asa>",
		Description: "Show ASA information",
		Category:    command.CategoryASA,
		Handler:     command.NewInternalHandler(r.cmdInfo),
	})

	mustRegister(registry, &command.Command{
		Name:        "plugins",
		Usage:       "plugins [name]",
		Description: "List external plugins or show details for a specific plugin",
		Category:    command.CategoryInfo,
		Handler:     command.NewInternalHandler(r.cmdPlugins),
	})

	// ASA Management
	mustRegister(registry, &command.Command{
		Name:        "asa",
		Usage:       "asa <list|add|remove|clear> [args...]",
		Description: "manage ASA cache",
		Category:    command.CategoryASA,
		Handler:     command.NewInternalHandler(r.cmdASA),
	})

	// Configuration
	mustRegister(registry, &command.Command{
		Name:        "network",
		Usage:       "network <mainnet|testnet|betanet>",
		Description: "Change network",
		Category:    command.CategoryConfig,
		Handler:     command.NewInternalHandler(r.cmdNetwork),
	})

	mustRegister(registry, &command.Command{
		Name:        "write",
		Usage:       "write [on|off]",
		Description: "Toggle transaction write mode",
		Category:    command.CategoryConfig,
		Handler:     command.NewInternalHandler(r.cmdWrite),
	})

	mustRegister(registry, &command.Command{
		Name:        "verbose",
		Usage:       "verbose [on|off]",
		Description: "Toggle detailed signing output (default: off)",
		Category:    command.CategoryConfig,
		Handler:     command.NewInternalHandler(r.cmdVerbose),
	})

	mustRegister(registry, &command.Command{
		Name:        "simulate",
		Usage:       "simulate [on|off | <command>]",
		Description: "Toggle simulation mode or simulate a single command (dry-run)",
		Category:    command.CategoryConfig,
		Handler:     command.NewInternalHandler(r.cmdSimulate),
	})

	mustRegister(registry, &command.Command{
		Name:        "config",
		Usage:       "config",
		Description: "Display configuration from ./config.yaml",
		Category:    command.CategoryConfig,
		Handler:     command.NewInternalHandler(r.cmdConfig),
	})

	mustRegister(registry, &command.Command{
		Name:        "setenv",
		Usage:       "setenv <name> <value>",
		Description: "Set environment variable (e.g., setenv ANTHROPIC_API_KEY sk-...)",
		Category:    command.CategoryConfig,
		Handler:     command.NewInternalHandler(r.cmdSetenv),
	})

	// Automation
	mustRegister(registry, &command.Command{
		Name:        "script",
		Usage:       "script <file>",
		Description: "Execute REPL commands from a file",
		Category:    command.CategoryAutomation,
		Handler:     command.NewInternalHandler(r.cmdScript),
	})

	mustRegister(registry, &command.Command{
		Name:        "js",
		Usage:       "js [file.js | { code } | code]",
		Description: "Execute JavaScript code (file, inline, or multi-line mode)",
		Category:    command.CategoryAutomation,
		Handler:     command.NewInternalHandler(r.cmdJS),
	})

	mustRegister(registry, &command.Command{
		Name:        "ai",
		Usage:       "ai <prompt>",
		Description: "Generate and execute JavaScript using AI",
		Category:    command.CategoryAutomation,
		Handler:     command.NewInternalHandler(r.cmdAI),
	})

	mustRegister(registry, &command.Command{
		Name:        "jssave",
		Usage:       "jssave <path>",
		Description: "Save last executed JavaScript (from js or ai) to file",
		Category:    command.CategoryAutomation,
		Handler:     command.NewInternalHandler(r.cmdJSSave),
	})

	// Remote Signing
	mustRegister(registry, &command.Command{
		Name:        "connect",
		Usage:       "connect [host:port] [ssh-port]",
		Description: fmt.Sprintf("Connect to Signer via SSH tunnel (default SSH port %d)", util.DefaultSSHPort),
		Category:    command.CategoryRemote,
		Handler:     command.NewInternalHandler(r.cmdConnect),
	})

	mustRegister(registry, &command.Command{
		Name:        "request-token",
		Usage:       "request-token <host> [--ssh-port <port>]",
		Description: "Request API token from Signer (requires operator approval)",
		Category:    command.CategoryRemote,
		Handler:     command.NewInternalHandler(r.cmdRequestToken),
	})

	// Quit
	mustRegister(registry, &command.Command{
		Name:        "quit",
		Aliases:     []string{"exit", "q"},
		Usage:       "quit",
		Description: "Exit apshell",
		Category:    command.CategoryInfo,
		Handler:     command.NewInternalHandler(r.cmdQuit),
	})

	// Register statically compiled plugins
	// Plugins are explicitly imported at the top of this file for security
	// To add a plugin: import it with blank import (_), and it will auto-register via init()
	for _, plugin := range command.GetStaticPlugins() {
		mustRegister(registry, plugin)
	}

	return registry
}
