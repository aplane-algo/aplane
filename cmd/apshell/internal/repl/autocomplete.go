// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package repl

import (
	"regexp"
	"strings"

	"github.com/chzyer/readline"

	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/util"
)

// Helper functions to reduce code duplication in autocomplete

// getAllAddresses returns signer addresses + alias addresses (deduplicated, uppercase)
func getAllAddresses(signerCache *util.SignerCache, aliasCache *util.AliasCache) []string {
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

// PluginSpec holds a plugin's completion specification
type PluginSpec struct {
	Name     string
	ArgSpecs []cmdspec.ArgSpec
}

// ContextCompleter wraps PrefixCompleter with context-aware completion
type ContextCompleter struct {
	prefix      *readline.PrefixCompleter
	signerCache *util.SignerCache
	aliasCache  *util.AliasCache
	asaCache    *util.ASACache
	setCache    *util.SetCache
	plugins     []PluginSpec // Plugins with their ArgSpecs
}

// getSuggestionsForArgSpec returns completions based on an ArgSpec type
func (c *ContextCompleter) getSuggestionsForArgSpec(spec cmdspec.ArgSpec) []string {
	switch spec.Type {
	case cmdspec.ArgTypeAddress:
		return getAllAddresses(c.signerCache, c.aliasCache)
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
	lowerLine := strings.ToLower(lineStr)

	// Keywords after which addresses are expected (used in multiple commands)
	addressKeywords := []struct {
		keyword string
		length  int
	}{
		{"from ", 5},
		{"to ", 3},
		{"for ", 4}, // optin ... for <addr>
	}

	// Built-in commands that take an address as first argument
	addressCommands := []struct {
		command string
		length  int
	}{
		{"alias ", 6},
		{"rekey ", 6},
		{"unrekey ", 8},
		{"keyreg ", 7},
		{"close ", 6},
		{"balance ", 8},
		{"participation ", 14},
		{"validate ", 9},
		{"info ", 5},
		{"sets add ", 9},
		{"sets remove ", 12},
	}

	// Check for plugin ArgSpec-based completion
	parts := strings.Fields(lineStr)
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
				if strings.HasSuffix(lineStr, " ") {
					argIndex = len(args) // Next argument position
				}

				// Resolve the ArgSpec for this position (handles branches)
				spec := resolveArgSpec(plugin.ArgSpecs, args, argIndex)
				if spec != nil {
					suggestions := c.getSuggestionsForArgSpec(*spec)

					if len(suggestions) > 0 {
						// If we're mid-typing (no trailing space), filter and return remaining part
						if !strings.HasSuffix(lineStr, " ") && len(parts) > 1 {
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

	allAddresses := getAllAddresses(c.signerCache, c.aliasCache)

	// Check if line ends with a keyword/command that expects an address
	for _, kw := range addressKeywords {
		if strings.HasSuffix(lowerLine, kw.keyword) {
			return stringsToRuneSuggestions(allAddresses), 0
		}
	}
	for _, cmd := range addressCommands {
		if strings.HasSuffix(lowerLine, cmd.command) {
			return stringsToRuneSuggestions(allAddresses), 0
		}
	}

	// Check if we're typing a partial address after a keyword
	keywordEnd := -1
	for _, kw := range addressKeywords {
		idx := strings.LastIndex(lowerLine, kw.keyword)
		if idx != -1 && idx+kw.length > keywordEnd {
			keywordEnd = idx + kw.length
		}
	}

	// Check if we're typing a partial address after a command
	for _, cmd := range addressCommands {
		idx := strings.LastIndex(lowerLine, cmd.command)
		if idx != -1 && idx+cmd.length > keywordEnd {
			keywordEnd = idx + cmd.length
		}
	}

	if keywordEnd > 0 && keywordEnd < len(lineStr) {
		partial := lineStr[keywordEnd:]
		if !strings.Contains(partial, " ") { // Still typing the address
			partialLen := len(partial)
			candidates := filterByPrefix(allAddresses, partial)
			if len(candidates) > 0 {
				// readline appends without deleting, so return only the
				// remaining part. Addresses get uppercased later anyway.
				return stringsToRuneSuggestionsPartial(candidates, partialLen), partialLen
			}
		}
	}

	// Fall back to prefix completer
	return c.prefix.Do(line, pos)
}

// getSuggestionsForType returns suggestions for a given ArgSpec type (standalone helper)
func getSuggestionsForType(spec *cmdspec.ArgSpec, signerCache *util.SignerCache, aliasCache *util.AliasCache, asaCache *util.ASACache, setCache *util.SetCache) []string {
	if spec == nil {
		return nil
	}
	switch spec.Type {
	case cmdspec.ArgTypeAddress:
		return getAllAddresses(signerCache, aliasCache)
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
func buildPcItemForArgSpecs(name string, specs []cmdspec.ArgSpec, signerCache *util.SignerCache, aliasCache *util.AliasCache, asaCache *util.ASACache, setCache *util.SetCache) *readline.PrefixCompleter {
	if len(specs) == 0 {
		return readline.PcItem(name)
	}

	// For PrefixCompleter, we provide suggestions based on ArgSpecs with branch support
	return readline.PcItem(name,
		readline.PcItemDynamic(func(line string) []string {
			// Determine which argument position based on fields in line
			parts := strings.Fields(line)
			argIndex := len(parts) - 1 // Current position (0 = command itself)
			if strings.HasSuffix(line, " ") {
				argIndex = len(parts)
			}

			// Get args typed so far (excluding command name)
			args := []string{}
			if len(parts) > 1 {
				args = parts[1:]
			}

			// Resolve ArgSpec considering branches
			spec := resolveArgSpec(specs, args, argIndex)
			return getSuggestionsForType(spec, signerCache, aliasCache, asaCache, setCache)
		}),
	)
}

// CreateDynamicCompleter creates a readline autocompleter with dynamic suggestions
// based on the current state of aliases, ASAs, sets, and signer keys.
// externalPlugins is optional; pass nil if no external plugins are discovered yet.
func CreateDynamicCompleter(aliasCache *util.AliasCache, asaCache *util.ASACache, setCache *util.SetCache, signerCache *util.SignerCache, externalPlugins []*discovery.Plugin) readline.AutoCompleter {
	// Discover core plugins and build completion specs
	var plugins []PluginSpec
	staticPlugins := command.GetStaticPlugins()

	// Build plugin PcItems and specs
	var pluginItems []*readline.PrefixCompleter
	for _, plugin := range staticPlugins {
		// Store plugin spec for ContextCompleter
		plugins = append(plugins, PluginSpec{
			Name:     plugin.Name,
			ArgSpecs: plugin.ArgSpecs,
		})

		// Build PcItem for PrefixCompleter
		pluginItems = append(pluginItems,
			buildPcItemForArgSpecs(plugin.Name, plugin.ArgSpecs, signerCache, aliasCache, asaCache, setCache))
	}

	// Add external plugins
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
				buildPcItemForArgSpecs(cmd.Name, cmd.ArgSpecs, signerCache, aliasCache, asaCache, setCache))
		}
	}

	prefix := readline.NewPrefixCompleter(
		readline.PcItem("send"),

		readline.PcItem("balance",
			readline.PcItemDynamic(func(line string) []string {
				parts := strings.Fields(line)

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
				suggestions = append(suggestions, getAllAddresses(signerCache, aliasCache)...)
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
				suggestions = append(suggestions, getAllAddresses(signerCache, aliasCache)...)
				for _, info := range asaCache.Assets {
					suggestions = append(suggestions, info.UnitName)
				}
				return suggestions
			}),
		),

		readline.PcItem("rekey",
			readline.PcItemDynamic(func(line string) []string {
				suggestions := []string{"to", "nowait"}
				return append(suggestions, getAllAddresses(signerCache, aliasCache)...)
			}),
		),

		readline.PcItem("unrekey",
			readline.PcItemDynamic(func(line string) []string {
				suggestions := []string{"nowait"}
				return append(suggestions, getAllAddresses(signerCache, aliasCache)...)
			}),
		),

		readline.PcItem("keyreg",
			readline.PcItemDynamic(func(line string) []string {
				suggestions := []string{"online", "offline", "nowait"}
				return append(suggestions, getAllAddresses(signerCache, aliasCache)...)
			}),
		),

		readline.PcItem("close",
			readline.PcItemDynamic(func(line string) []string {
				suggestions := []string{"to", "nowait"}
				return append(suggestions, getAllAddresses(signerCache, aliasCache)...)
			}),
		),

		readline.PcItem("optout",
			readline.PcItemDynamic(func(line string) []string {
				suggestions := []string{"from", "to", "nowait"}
				suggestions = append(suggestions, getAllAddresses(signerCache, aliasCache)...)
				for _, info := range asaCache.Assets {
					suggestions = append(suggestions, info.UnitName)
				}
				return suggestions
			}),
		),

		readline.PcItem("sweep",
			readline.PcItemDynamic(func(line string) []string {
				suggestions := []string{"from", "to", "leaving", "nowait", "algo"}
				suggestions = append(suggestions, getAllAddresses(signerCache, aliasCache)...)
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
				return getAllAddresses(signerCache, aliasCache)
			}),
		),

		readline.PcItem("validate",
			readline.PcItemDynamic(func(line string) []string {
				suggestions := getAllAddresses(signerCache, aliasCache)
				for name := range setCache.Sets {
					suggestions = append(suggestions, "@"+name)
				}
				return suggestions
			}),
		),

		readline.PcItem("alias",
			readline.PcItem("remove"),
			readline.PcItemDynamic(func(line string) []string {
				return getAllAddresses(signerCache, aliasCache)
			}),
		),

		readline.PcItem("asa",
			readline.PcItem("list"),
			readline.PcItem("add"),
			readline.PcItem("remove"),
			readline.PcItem("clear"),
		),

		readline.PcItem("sets",
			readline.PcItem("add",
				readline.PcItemDynamic(func(line string) []string {
					var suggestions []string
					if strings.Contains(line, "sets add") && !strings.Contains(line, " to ") {
						suggestions = append(suggestions, "to")
					}
					return append(suggestions, getAllAddresses(signerCache, aliasCache)...)
				}),
			),
			readline.PcItem("remove",
				readline.PcItemDynamic(func(line string) []string {
					var suggestions []string
					if strings.Contains(line, "sets remove") && !strings.Contains(line, " from ") {
						suggestions = append(suggestions, "from")
					}
					return append(suggestions, getAllAddresses(signerCache, aliasCache)...)
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
				return getAllAddresses(signerCache, aliasCache)
			}),
		),

		readline.PcItem("accounts"),
		readline.PcItem("ai"),
		readline.PcItem("bal"),
		readline.PcItem("js"),
		readline.PcItem("jssave"),
		readline.PcItem("keys"),
		readline.PcItem("plugins"),
		readline.PcItem("setenv"),
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
			readline.PcItem("selfping"),
		),
		readline.PcItem("config"),

		readline.PcItem("network",
			readline.PcItem("mainnet"),
			readline.PcItem("testnet"),
			readline.PcItem("betanet"),
		),

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
		prefix:      prefix,
		signerCache: signerCache,
		aliasCache:  aliasCache,
		asaCache:    asaCache,
		setCache:    setCache,
		plugins:     plugins,
	}
}
