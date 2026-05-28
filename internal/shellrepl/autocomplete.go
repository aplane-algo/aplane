// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package shellrepl

import (
	"regexp"
	"strings"

	"github.com/chzyer/readline"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
)

// Helper functions to reduce code duplication in autocomplete

// getAllAddresses returns signer addresses + alias addresses (deduplicated, uppercase).
// If ensureSignerCache is non-nil and the signer cache is empty, it calls the callback
// to attempt a refresh (e.g., after signer unlock).
func getAllAddresses(signerCache *cache.SignerCache, aliasCache *cache.AliasCache, ensureSignerCache func() error) []string {
	if ensureSignerCache != nil && signerCache != nil && signerCache.Count() == 0 {
		_ = ensureSignerCache()
	}
	seen := make(map[string]bool)
	var addrs []string

	// Add signer addresses
	if signerCache != nil && signerCache.Keys != nil {
		for addr := range signerCache.Keys {
			upper := strings.ToUpper(addr)
			if !seen[upper] {
				seen[upper] = true
				addrs = append(addrs, upper)
			}
		}
	}

	// Add alias addresses (the addresses aliases point to, not the names)
	if aliasCache != nil && aliasCache.Aliases != nil {
		for _, addr := range aliasCache.Aliases {
			upper := strings.ToUpper(addr)
			if !seen[upper] {
				seen[upper] = true
				addrs = append(addrs, upper)
			}
		}
	}

	return addrs
}

func getAliasNames(aliasCache *cache.AliasCache) []string {
	if aliasCache == nil || aliasCache.Aliases == nil {
		return nil
	}
	names := make([]string, 0, len(aliasCache.Aliases))
	for name := range aliasCache.Aliases {
		names = append(names, name)
	}
	return names
}

// insideBracketGroup returns true if the cursor is inside an unclosed [ ] group.
// Checks whether the last '[' appears after the last ']' (or there's no ']' at all).
func insideBracketGroup(line string) bool {
	lastOpen := strings.LastIndex(line, "[")
	if lastOpen == -1 {
		return false
	}
	lastClose := strings.LastIndex(line, "]")
	return lastOpen > lastClose
}

// stringsToRuneSuggestions converts string slice to readline suggestions (with trailing space)
func stringsToRuneSuggestions(strs []string) [][]rune {
	suggestions := make([][]rune, 0, len(strs))
	for _, s := range strs {
		suggestions = append(suggestions, []rune(s+" "))
	}
	return suggestions
}

// stringsToRuneSuggestionsPartial converts strings to suggestions showing only the remaining part
func stringsToRuneSuggestionsPartial(strs []string, partialLen int) [][]rune {
	suggestions := make([][]rune, 0, len(strs))
	for _, s := range strs {
		if partialLen < len(s) {
			suggestions = append(suggestions, []rune(s[partialLen:]+" "))
		}
	}
	return suggestions
}

// filterByPrefix returns strings that match the prefix (case-insensitive)
func filterByPrefix(strs []string, prefix string) []string {
	prefixLower := strings.ToLower(prefix)
	var result []string
	for _, s := range strs {
		if strings.HasPrefix(strings.ToLower(s), prefixLower) {
			result = append(result, s)
		}
	}
	return result
}

func completionForCandidates(candidates []string, partial string, trailingSpace bool) ([][]rune, int, bool) {
	if len(candidates) == 0 {
		return nil, 0, false
	}
	if trailingSpace {
		return stringsToRuneSuggestions(candidates), 0, true
	}
	matches := filterByPrefix(candidates, partial)
	if len(matches) == 0 {
		return nil, 0, false
	}
	return stringsToRuneSuggestionsPartial(matches, len(partial)), len(partial), true
}

type completableCommand struct {
	command       string
	args          []string
	currentArg    string
	currentArgIdx int
	trailingSpace bool
	inQuotes      bool
}

func newCompletableCommand(line string) completableCommand {
	parsed := parseCompletableCommandLine(line)
	cmd := completableCommand{
		currentArgIdx: -1,
		trailingSpace: parsed.trailingSpace,
		inQuotes:      parsed.inQuotes,
	}
	if len(parsed.parts) == 0 {
		return cmd
	}
	cmd.command = strings.ToLower(parsed.parts[0])
	if len(parsed.parts) > 1 {
		cmd.args = parsed.parts[1:]
	}
	if parsed.trailingSpace {
		cmd.currentArgIdx = len(cmd.args)
		return cmd
	}
	cmd.currentArgIdx = len(cmd.args) - 1
	if cmd.currentArgIdx >= 0 && cmd.currentArgIdx < len(cmd.args) {
		cmd.currentArg = cmd.args[cmd.currentArgIdx]
	}
	return cmd
}

func (cmd completableCommand) previousArg() string {
	idx := cmd.currentArgIdx - 1
	if idx < 0 || idx >= len(cmd.args) {
		return ""
	}
	return strings.ToLower(cmd.args[idx])
}

func (cmd completableCommand) hasArg(value string) bool {
	for _, arg := range cmd.args {
		if strings.EqualFold(arg, value) {
			return true
		}
	}
	return false
}

func buildPcItemForStrings(name string, values []string) *readline.PrefixCompleter {
	children := make([]readline.PrefixCompleterInterface, 0, len(values))
	for _, value := range values {
		children = append(children, readline.PcItem(value))
	}
	return readline.PcItem(name, children...)
}

// PluginSpec holds a plugin's completion specification
type PluginSpec struct {
	Name     string
	ArgSpecs []cmdspec.ArgSpec
}

// ContextCompleter wraps PrefixCompleter with context-aware completion
type ContextCompleter struct {
	prefix            *readline.PrefixCompleter
	signerCache       *cache.SignerCache
	aliasCache        *cache.AliasCache
	asaCache          *cache.ASACache
	setCache          *cache.SetCache
	plugins           []PluginSpec // Plugins with their ArgSpecs
	ensureSignerCache func() error // Optional callback to refresh signer cache if empty
}

// getSuggestionsForArgSpec returns completions based on an ArgSpec type
func (c *ContextCompleter) getSuggestionsForArgSpec(spec cmdspec.ArgSpec) []string {
	switch spec.Type {
	case cmdspec.ArgTypeAddress:
		return getAllAddresses(c.signerCache, c.aliasCache, c.ensureSignerCache)
	case cmdspec.ArgTypeAsset:
		suggestions := []string{"algo"}
		if c.asaCache != nil {
			for _, info := range c.asaCache.Assets {
				suggestions = append(suggestions, info.UnitName)
			}
		}
		return suggestions
	case cmdspec.ArgTypeSet:
		var suggestions []string
		if c.setCache != nil {
			for name := range c.setCache.Sets {
				suggestions = append(suggestions, "@"+name)
			}
		}
		return suggestions
	case cmdspec.ArgTypeKeyword:
		return spec.Values
	case cmdspec.ArgTypeNumber, cmdspec.ArgTypeFile:
		// No completion for numbers or files (let readline handle files)
		return nil
	case cmdspec.ArgTypeCustom:
		// Custom completions require RPC call to plugin (future)
		// For now, return empty
		return nil
	default:
		return nil
	}
}

// resolveArgSpec resolves the effective ArgSpec at a given position, considering branches.
// args contains the arguments typed so far (excluding the command name).
// argIndex is the position we're completing (0-based).
// Returns the resolved ArgSpec, or nil if no spec applies.
func resolveArgSpec(specs []cmdspec.ArgSpec, args []string, argIndex int) *cmdspec.ArgSpec {
	// Walk through specs, handling branches as we go
	currentSpecs := specs
	currentOffset := 0 // Offset into currentSpecs

	for i := 0; i <= argIndex; i++ {
		specIdx := i - currentOffset
		if specIdx >= len(currentSpecs) {
			return nil // No more specs
		}

		spec := currentSpecs[specIdx]

		// Check if this spec is a branching point
		if len(spec.Branches) > 0 {
			// Find a matching branch based on previous args
			var matchedBranch *cmdspec.ArgBranch
			for _, branch := range spec.Branches {
				if branch.When.Arg < len(args) {
					argValue := args[branch.When.Arg]
					if matched, _ := regexp.MatchString(branch.When.Matches, argValue); matched {
						matchedBranch = &branch
						break
					}
				}
			}

			if matchedBranch != nil {
				// Switch to branch's specs for subsequent positions
				currentSpecs = matchedBranch.Specs
				currentOffset = i // Reset offset to current position
			} else {
				// No branch matched - no completion for this or subsequent positions
				return nil
			}
		}

		// If this is the position we're completing, return the spec
		if i == argIndex {
			specIdx = i - currentOffset
			if specIdx >= len(currentSpecs) {
				return nil
			}
			finalSpec := currentSpecs[specIdx]
			// Don't return branching specs directly - they need to be resolved
			if len(finalSpec.Branches) > 0 {
				return nil // Branch not yet resolvable
			}
			return &finalSpec
		}
	}

	return nil
}

// Do implements readline.AutoCompleter
// This intercepts completion requests to provide case-insensitive address matching
// and ArgSpec-based completion for plugins.
func (c *ContextCompleter) Do(line []rune, pos int) ([][]rune, int) {
	lineStr := string(line[:pos])

	// Check for plugin ArgSpec-based completion
	parsed := parseCompletableCommandLine(lineStr)
	parts := parsed.parts
	if len(parts) >= 1 {
		cmdName := strings.ToLower(parts[0])
		for _, plugin := range c.plugins {
			if strings.ToLower(plugin.Name) == cmdName && len(plugin.ArgSpecs) > 0 {
				// Get args typed so far (excluding command name)
				args := []string{}
				if len(parts) > 1 {
					args = parts[1:]
				}

				// Determine which argument position we're completing
				// argIndex is relative to args (not parts), 0-based
				argIndex := len(args) - 1 // Index of current argument we're completing
				if argIndex < 0 {
					argIndex = 0
				}

				// If line ends with space, we're starting a new argument
				if parsed.trailingSpace {
					argIndex = len(args) // Next argument position
				}

				// Resolve the ArgSpec for this position (handles branches)
				spec := resolveArgSpec(plugin.ArgSpecs, args, argIndex)
				if spec != nil {
					suggestions := c.getSuggestionsForArgSpec(*spec)

					if len(suggestions) > 0 {
						// If we're mid-typing (no trailing space), filter and return remaining part
						if !parsed.trailingSpace && len(parts) > 1 {
							partial := parts[len(parts)-1]
							partialLen := len(partial)
							candidates := filterByPrefix(suggestions, partial)
							if len(candidates) > 0 {
								// readline appends without deleting, so return only the
								// remaining part after what's been typed. Addresses get
								// uppercased later anyway, so mixed case is fine.
								return stringsToRuneSuggestionsPartial(candidates, partialLen), partialLen
							}
						} else {
							return stringsToRuneSuggestions(suggestions), 0
						}
					}
				}
			}
		}
	}

	allAddresses := getAllAddresses(c.signerCache, c.aliasCache, c.ensureSignerCache)

	if suggestions, offset, ok := c.completeAlias(lineStr, allAddresses); ok {
		return suggestions, offset
	}
	if suggestions, offset, ok := c.completeRekey(lineStr, allAddresses); ok {
		return suggestions, offset
	}

	if suggestions, offset, ok := c.completeAddressFromCommand(lineStr, allAddresses); ok {
		return suggestions, offset
	}

	// Fall back to prefix completer
	return c.prefix.Do(line, pos)
}

func (c *ContextCompleter) completeAddressFromCommand(lineStr string, allAddresses []string) ([][]rune, int, bool) {
	if len(allAddresses) == 0 {
		return nil, 0, false
	}

	current := newCompletableCommand(lineStr)
	if current.command == "" || current.inQuotes {
		return nil, 0, false
	}

	// Bracket groups use raw text because the command tokenizer deliberately
	// treats brackets as ordinary argument characters.
	if insideBracketGroup(lineStr) {
		return completionForCandidates(allAddresses, current.currentArg, current.trailingSpace)
	}

	firstAddressArgCommands := map[string]bool{
		"delete":        true,
		"unrekey":       true,
		"keyreg":        true,
		"close":         true,
		"balance":       true,
		"participation": true,
		"validate":      true,
		"info":          true,
	}
	if firstAddressArgCommands[current.command] && current.currentArgIdx == 0 {
		return completionForCandidates(allAddresses, current.currentArg, current.trailingSpace)
	}

	if current.command == "sets" && len(current.args) > 0 {
		subcommand := strings.ToLower(current.args[0])
		if (subcommand == "add" || subcommand == "remove") && current.currentArgIdx == 1 {
			return completionForCandidates(allAddresses, current.currentArg, current.trailingSpace)
		}
	}

	switch current.previousArg() {
	case "from", "to", "for":
		return completionForCandidates(allAddresses, current.currentArg, current.trailingSpace)
	default:
		return nil, 0, false
	}
}

func (c *ContextCompleter) completeAlias(lineStr string, allAddresses []string) ([][]rune, int, bool) {
	parsed := parseCompletableCommandLine(lineStr)
	parts := parsed.parts
	if len(parts) == 0 || strings.ToLower(parts[0]) != "alias" {
		return nil, 0, false
	}
	trailingSpace := parsed.trailingSpace
	aliasNames := getAliasNames(c.aliasCache)

	if len(parts) == 1 {
		if trailingSpace {
			return stringsToRuneSuggestions([]string{"list", "delete", "remove"}), 0, true
		}
		return nil, 0, false
	}

	aliasSubcommand := strings.ToLower(parts[1])
	if aliasSubcommand == "list" {
		return nil, 0, true
	}
	if aliasSubcommand == "delete" || aliasSubcommand == "remove" {
		if len(parts) == 2 && trailingSpace {
			return stringsToRuneSuggestions(aliasNames), 0, true
		}
		if len(parts) == 3 && !trailingSpace {
			partial := parts[2]
			candidates := filterByPrefix(aliasNames, partial)
			if len(candidates) > 0 {
				return stringsToRuneSuggestionsPartial(candidates, len(partial)), len(partial), true
			}
		}
		return nil, 0, true
	}

	if len(parts) == 2 && trailingSpace {
		return stringsToRuneSuggestions(allAddresses), 0, true
	}
	if len(parts) == 3 && !trailingSpace {
		partial := parts[2]
		candidates := filterByPrefix(allAddresses, partial)
		if len(candidates) > 0 {
			return stringsToRuneSuggestionsPartial(candidates, len(partial)), len(partial), true
		}
		return nil, 0, true
	}
	return nil, 0, true
}

func (c *ContextCompleter) completeRekey(lineStr string, allAddresses []string) ([][]rune, int, bool) {
	parsed := parseCompletableCommandLine(lineStr)
	parts := parsed.parts
	if len(parts) == 0 || strings.ToLower(parts[0]) != "rekey" {
		return nil, 0, false
	}
	trailingSpace := parsed.trailingSpace
	firstArgSuggestions := append([]string{"list", "refresh"}, allAddresses...)

	if len(parts) == 1 {
		if trailingSpace {
			return stringsToRuneSuggestions(firstArgSuggestions), 0, true
		}
		return nil, 0, false
	}

	subcommand := strings.ToLower(parts[1])
	switch subcommand {
	case "list":
		return nil, 0, true
	case "refresh":
		if len(parts) == 2 && trailingSpace {
			return stringsToRuneSuggestions(allAddresses), 0, true
		}
		if len(parts) == 3 && !trailingSpace {
			partial := parts[2]
			candidates := filterByPrefix(allAddresses, partial)
			if len(candidates) > 0 {
				return stringsToRuneSuggestionsPartial(candidates, len(partial)), len(partial), true
			}
		}
		return nil, 0, true
	}

	if len(parts) == 2 && !trailingSpace {
		partial := parts[1]
		candidates := filterByPrefix(firstArgSuggestions, partial)
		if len(candidates) > 0 {
			return stringsToRuneSuggestionsPartial(candidates, len(partial)), len(partial), true
		}
		return nil, 0, true
	}
	if len(parts) == 2 && trailingSpace {
		return stringsToRuneSuggestions([]string{"to"}), 0, true
	}
	return nil, 0, false
}

// getSuggestionsForType returns suggestions for a given ArgSpec type (standalone helper)
func getSuggestionsForType(spec *cmdspec.ArgSpec, signerCache *cache.SignerCache, aliasCache *cache.AliasCache, asaCache *cache.ASACache, setCache *cache.SetCache, ensureSignerCache func() error) []string {
	if spec == nil {
		return nil
	}
	switch spec.Type {
	case cmdspec.ArgTypeAddress:
		return getAllAddresses(signerCache, aliasCache, ensureSignerCache)
	case cmdspec.ArgTypeAsset:
		suggestions := []string{"algo"}
		if asaCache != nil {
			for _, info := range asaCache.Assets {
				suggestions = append(suggestions, info.UnitName)
			}
		}
		return suggestions
	case cmdspec.ArgTypeSet:
		var suggestions []string
		if setCache != nil {
			for setName := range setCache.Sets {
				suggestions = append(suggestions, "@"+setName)
			}
		}
		return suggestions
	case cmdspec.ArgTypeKeyword:
		return spec.Values
	}
	return nil
}

// buildPcItemForArgSpecs creates a PcItem with dynamic completion based on ArgSpecs
func buildPcItemForArgSpecs(name string, specs []cmdspec.ArgSpec, signerCache *cache.SignerCache, aliasCache *cache.AliasCache, asaCache *cache.ASACache, setCache *cache.SetCache, ensureSignerCache func() error) *readline.PrefixCompleter {
	if len(specs) == 0 {
		return readline.PcItem(name)
	}

	// For PrefixCompleter, we provide suggestions based on ArgSpecs with branch support
	return readline.PcItem(name,
		readline.PcItemDynamic(func(line string) []string {
			// Determine which argument position based on fields in line
			parsed := parseCompletableCommandLine(line)
			parts := parsed.parts
			argIndex := len(parts) - 1 // Current position (0 = command itself)
			if parsed.trailingSpace {
				argIndex = len(parts)
			}

			// Get args typed so far (excluding command name)
			args := []string{}
			if len(parts) > 1 {
				args = parts[1:]
			}

			// Resolve ArgSpec considering branches
			spec := resolveArgSpec(specs, args, argIndex)
			return getSuggestionsForType(spec, signerCache, aliasCache, asaCache, setCache, ensureSignerCache)
		}),
	)
}

// CreateDynamicCompleter creates a readline autocompleter with dynamic suggestions
// based on the current state of aliases, ASAs, sets, and signer keys.
// ensureSignerCache is called on tab-complete when the signer cache is empty, to auto-refresh after unlock.
// externalPlugins is optional; pass nil if no external plugins are discovered yet.
func CreateDynamicCompleter(aliasCache *cache.AliasCache, asaCache *cache.ASACache, setCache *cache.SetCache, signerCache *cache.SignerCache, ensureSignerCache func() error, networkTokens []string, externalPlugins []*discovery.Plugin) readline.AutoCompleter {
	// Build plugin completion specs from external plugins
	var plugins []PluginSpec
	var pluginItems []*readline.PrefixCompleter
	for _, extPlugin := range externalPlugins {
		if extPlugin.Manifest == nil {
			continue
		}
		for _, cmd := range extPlugin.Manifest.Commands {
			plugins = append(plugins, PluginSpec{
				Name:     cmd.Name,
				ArgSpecs: cmd.ArgSpecs,
			})
			pluginItems = append(pluginItems,
				buildPcItemForArgSpecs(cmd.Name, cmd.ArgSpecs, signerCache, aliasCache, asaCache, setCache, ensureSignerCache))
		}
	}

	prefix := readline.NewPrefixCompleter(
		readline.PcItem("send"),

		readline.PcItem("balance",
			readline.PcItemDynamic(func(line string) []string {
				parts := parseCompletableCommandLine(line).parts

				// If we already have "balance <account>", suggest assets
				if len(parts) >= 2 {
					suggestions := []string{"algo"}
					for _, info := range asaCache.Assets {
						suggestions = append(suggestions, info.UnitName)
					}
					return suggestions
				}

				// First argument: suggest addresses + dynamic sets
				suggestions := []string{"@all", "@signers"}
				suggestions = append(suggestions, getAllAddresses(signerCache, aliasCache, ensureSignerCache)...)
				return suggestions
			}),
		),

		readline.PcItem("holders",
			readline.PcItemDynamic(func(line string) []string {
				// Suggest assets
				suggestions := []string{"algo"}
				for _, info := range asaCache.Assets {
					suggestions = append(suggestions, info.UnitName)
				}
				return suggestions
			}),
		),

		readline.PcItem("optin",
			readline.PcItemDynamic(func(line string) []string {
				suggestions := []string{"for", "nowait"}
				suggestions = append(suggestions, getAllAddresses(signerCache, aliasCache, ensureSignerCache)...)
				for _, info := range asaCache.Assets {
					suggestions = append(suggestions, info.UnitName)
				}
				return suggestions
			}),
		),

		readline.PcItem("rekey",
			readline.PcItem("list"),
			readline.PcItem("refresh"),
			readline.PcItemDynamic(func(line string) []string {
				suggestions := []string{"list", "refresh", "to", "nowait"}
				return append(suggestions, getAllAddresses(signerCache, aliasCache, ensureSignerCache)...)
			}),
		),

		readline.PcItem("unrekey",
			readline.PcItemDynamic(func(line string) []string {
				suggestions := []string{"nowait"}
				return append(suggestions, getAllAddresses(signerCache, aliasCache, ensureSignerCache)...)
			}),
		),

		readline.PcItem("keyreg",
			readline.PcItemDynamic(func(line string) []string {
				suggestions := []string{"online", "offline", "nowait"}
				return append(suggestions, getAllAddresses(signerCache, aliasCache, ensureSignerCache)...)
			}),
		),

		readline.PcItem("close",
			readline.PcItemDynamic(func(line string) []string {
				suggestions := []string{"to", "nowait"}
				return append(suggestions, getAllAddresses(signerCache, aliasCache, ensureSignerCache)...)
			}),
		),

		readline.PcItem("optout",
			readline.PcItemDynamic(func(line string) []string {
				suggestions := []string{"from", "to", "nowait"}
				suggestions = append(suggestions, getAllAddresses(signerCache, aliasCache, ensureSignerCache)...)
				for _, info := range asaCache.Assets {
					suggestions = append(suggestions, info.UnitName)
				}
				return suggestions
			}),
		),

		readline.PcItem("sweep",
			readline.PcItemDynamic(func(line string) []string {
				suggestions := []string{"from", "to", "leaving", "nowait", "algo"}
				suggestions = append(suggestions, getAllAddresses(signerCache, aliasCache, ensureSignerCache)...)
				for _, info := range asaCache.Assets {
					suggestions = append(suggestions, info.UnitName)
				}
				for name := range setCache.Sets {
					suggestions = append(suggestions, "@"+name)
				}
				return suggestions
			}),
		),

		readline.PcItem("participation",
			readline.PcItemDynamic(func(line string) []string {
				return getAllAddresses(signerCache, aliasCache, ensureSignerCache)
			}),
		),

		readline.PcItem("validate",
			readline.PcItemDynamic(func(line string) []string {
				suggestions := getAllAddresses(signerCache, aliasCache, ensureSignerCache)
				for name := range setCache.Sets {
					suggestions = append(suggestions, "@"+name)
				}
				return suggestions
			}),
		),

		readline.PcItem("alias",
			readline.PcItem("list"),
			readline.PcItem("delete"),
			readline.PcItem("remove"),
			readline.PcItemDynamic(func(line string) []string {
				parts := parseCompletableCommandLine(line).parts
				aliasSubcommand := ""
				if len(parts) >= 2 {
					aliasSubcommand = strings.ToLower(parts[1])
				}
				if aliasSubcommand == "delete" || aliasSubcommand == "remove" {
					return getAliasNames(aliasCache)
				}
				if len(parts) >= 2 {
					return getAllAddresses(signerCache, aliasCache, ensureSignerCache)
				}
				return []string{"list", "delete", "remove"}
			}),
		),

		readline.PcItem("asa",
			readline.PcItem("list"),
			readline.PcItem("add"),
			readline.PcItem("remove"),
			readline.PcItem("clear"),
		),

		readline.PcItem("box",
			readline.PcItem("create"),
			readline.PcItem("write"),
			readline.PcItem("read"),
			readline.PcItem("delete"),
		),

		readline.PcItem("sets",
			readline.PcItem("list"),
			readline.PcItem("add",
				readline.PcItemDynamic(func(line string) []string {
					current := newCompletableCommand(line)
					var suggestions []string
					if current.command == "sets" && !current.hasArg("to") {
						suggestions = append(suggestions, "to")
					}
					return append(suggestions, getAllAddresses(signerCache, aliasCache, ensureSignerCache)...)
				}),
			),
			readline.PcItem("remove",
				readline.PcItemDynamic(func(line string) []string {
					current := newCompletableCommand(line)
					var suggestions []string
					if current.command == "sets" && !current.hasArg("from") {
						suggestions = append(suggestions, "from")
					}
					return append(suggestions, getAllAddresses(signerCache, aliasCache, ensureSignerCache)...)
				}),
			),
			readline.PcItem("delete",
				readline.PcItemDynamic(func(line string) []string {
					var suggestions []string
					for name := range setCache.Sets {
						suggestions = append(suggestions, name)
					}
					return suggestions
				}),
			),
		),

		readline.PcItem("info",
			readline.PcItemDynamic(func(line string) []string {
				return getAllAddresses(signerCache, aliasCache, ensureSignerCache)
			}),
		),

		readline.PcItem("app",
			readline.PcItem("read",
				readline.PcItem("global"),
				readline.PcItem("local"),
				readline.PcItem("box"),
				readline.PcItem("boxes"),
			),
			readline.PcItem("call",
				readline.PcItemDynamic(func(_ string) []string {
					return []string{"<app-id>"}
				}),
				readline.PcItem("raw"),
			),
		),

		readline.PcItem("accounts"),
		readline.PcItem("bal"),
		readline.PcItem("js"),
		readline.PcItem("jssave"),
		readline.PcItem("jslist"),
		readline.PcItem("keys"),
		readline.PcItem("plugins"),
		readline.PcItem("sign"),
		readline.PcItem("connect"),
		readline.PcItem("write"),
		readline.PcItem("script"),
		readline.PcItem("verbose"),
		readline.PcItem("simulate",
			readline.PcItem("on"),
			readline.PcItem("off"),
			readline.PcItem("send"),
			readline.PcItem("keyreg"),
			readline.PcItem("sign"),
			readline.PcItem("optin"),
			readline.PcItem("optout"),
			readline.PcItem("sweep"),
			readline.PcItem("validate"),
			readline.PcItem("rekey"),
			readline.PcItem("unrekey"),
			readline.PcItem("close"),
			readline.PcItem("app"),
		),
		readline.PcItem("config"),

		buildPcItemForStrings("network", networkTokens),

		readline.PcItem("status"),
		readline.PcItem("help"),
		readline.PcItem("h"),
		readline.PcItem("quit"),
		readline.PcItem("exit"),
		readline.PcItem("q"),
	)

	// Add plugin items to prefix completer
	for _, item := range pluginItems {
		prefix.Children = append(prefix.Children, item)
	}

	return &ContextCompleter{
		prefix:            prefix,
		signerCache:       signerCache,
		aliasCache:        aliasCache,
		asaCache:          asaCache,
		setCache:          setCache,
		plugins:           plugins,
		ensureSignerCache: ensureSignerCache,
	}
}
