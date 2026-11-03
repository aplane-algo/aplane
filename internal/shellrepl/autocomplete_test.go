// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package shellrepl

import (
	"sort"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/cmdspec"
)

func TestDeleteCommandAddressCompletion(t *testing.T) {
	account := crypto.GenerateAccount()
	address := account.Address.String()

	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(address, "ed25519")

	completer := &ContextCompleter{
		signerCache: &signerCache,
		aliasCache:  &cache.AliasCache{Aliases: map[string]string{}},
	}

	input := "delete " + address[:2]
	suggestions, offset := completer.Do([]rune(input), len(input))
	if offset != 2 {
		t.Fatalf("offset = %d, want 2", offset)
	}
	if len(suggestions) == 0 {
		t.Fatal("expected completion suggestions for delete command")
	}

	want := address[2:] + " "
	if got := string(suggestions[0]); got != want {
		t.Fatalf("first suggestion = %q, want %q", got, want)
	}
}

func TestAliasCommandCompletesAddressAsSecondArgument(t *testing.T) {
	account := crypto.GenerateAccount()
	address := account.Address.String()

	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(address, "ed25519")

	completer := &ContextCompleter{
		signerCache: &signerCache,
		aliasCache:  &cache.AliasCache{Aliases: map[string]string{}},
	}

	input := "alias treasury " + address[:3]
	suggestions, offset := completer.Do([]rune(input), len(input))
	if offset != 3 {
		t.Fatalf("offset = %d, want 3", offset)
	}
	if len(suggestions) == 0 {
		t.Fatal("expected completion suggestions for alias address argument")
	}

	want := address[3:] + " "
	if got := string(suggestions[0]); got != want {
		t.Fatalf("first suggestion = %q, want %q", got, want)
	}
}

func TestAddressCompletionUsesParsedKeywordPosition(t *testing.T) {
	account := crypto.GenerateAccount()
	address := account.Address.String()

	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(address, "ed25519")

	completer := &ContextCompleter{
		signerCache: &signerCache,
		aliasCache:  &cache.AliasCache{Aliases: map[string]string{}},
	}

	input := "optin usdc for " + address[:4]
	suggestions, offset := completer.Do([]rune(input), len(input))
	if offset != 4 {
		t.Fatalf("offset = %d, want 4", offset)
	}
	if len(suggestions) == 0 {
		t.Fatal("expected address suggestions after parsed for keyword")
	}

	want := address[4:] + " "
	if got := string(suggestions[0]); got != want {
		t.Fatalf("first suggestion = %q, want %q", got, want)
	}
}

func TestAddressCompletionDoesNotTriggerInsideQuotes(t *testing.T) {
	account := crypto.GenerateAccount()
	address := account.Address.String()
	completer := &ContextCompleter{}

	input := `send 1 algo from ` + address + ` to receiver note="to ` + address[:4]
	suggestions, offset, ok := completer.completeAddressFromCommand(input, []string{address})
	if ok {
		t.Fatalf("completeAddressFromCommand ok = true, suggestions = %q, offset = %d", suggestions, offset)
	}
	if len(suggestions) != 0 || offset != 0 {
		t.Fatalf("suggestions = %q, offset = %d; want no suggestions and offset 0", suggestions, offset)
	}
}

func TestAddressCompletionDoesNotTreatQuotedBracketAsGroup(t *testing.T) {
	account := crypto.GenerateAccount()
	address := account.Address.String()
	completer := &ContextCompleter{}

	input := `send 1 algo note="[` + address[:4]
	suggestions, offset, ok := completer.completeAddressFromCommand(input, []string{address})
	if ok {
		t.Fatalf("completeAddressFromCommand ok = true, suggestions = %q, offset = %d", suggestions, offset)
	}
	if len(suggestions) != 0 || offset != 0 {
		t.Fatalf("suggestions = %q, offset = %d; want no suggestions and offset 0", suggestions, offset)
	}
}

func TestSetsAddCompletesAddressFromParsedPosition(t *testing.T) {
	account := crypto.GenerateAccount()
	address := account.Address.String()

	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(address, "ed25519")

	completer := &ContextCompleter{
		signerCache: &signerCache,
		aliasCache:  &cache.AliasCache{Aliases: map[string]string{}},
	}

	input := "sets add " + address[:3]
	suggestions, offset := completer.Do([]rune(input), len(input))
	if offset != 3 {
		t.Fatalf("offset = %d, want 3", offset)
	}
	if len(suggestions) == 0 {
		t.Fatal("expected address suggestions for sets add")
	}

	want := address[3:] + " "
	if got := string(suggestions[0]); got != want {
		t.Fatalf("first suggestion = %q, want %q", got, want)
	}
}

func TestAliasCommandCompletesListSubcommand(t *testing.T) {
	completer := &ContextCompleter{}

	input := "alias "
	suggestions, offset := completer.Do([]rune(input), len(input))
	if offset != 0 {
		t.Fatalf("offset = %d, want 0", offset)
	}
	if len(suggestions) == 0 {
		t.Fatal("expected alias subcommand suggestions")
	}
	if got := string(suggestions[0]); got != "list " {
		t.Fatalf("first suggestion = %q, want list", got)
	}
}

func TestAliasDeleteCompletesAliasNames(t *testing.T) {
	completer := &ContextCompleter{
		aliasCache: &cache.AliasCache{Aliases: map[string]string{
			"treasury": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		}},
	}

	input := "alias delete tr"
	suggestions, offset := completer.Do([]rune(input), len(input))
	if offset != 2 {
		t.Fatalf("offset = %d, want 2", offset)
	}
	if len(suggestions) == 0 {
		t.Fatal("expected completion suggestions for alias delete")
	}
	if got := string(suggestions[0]); got != "easury " {
		t.Fatalf("first suggestion = %q, want easury", got)
	}
}

func TestRekeyCommandCompletesListSubcommand(t *testing.T) {
	completer := &ContextCompleter{}

	input := "rekey l"
	suggestions, offset := completer.Do([]rune(input), len(input))
	if offset != 1 {
		t.Fatalf("offset = %d, want 1", offset)
	}
	if len(suggestions) == 0 {
		t.Fatal("expected rekey subcommand suggestions")
	}
	if got := string(suggestions[0]); got != "ist " {
		t.Fatalf("first suggestion = %q, want ist", got)
	}
}

func TestRekeyRefreshCompletesAddress(t *testing.T) {
	account := crypto.GenerateAccount()
	address := account.Address.String()

	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(address, "ed25519")

	completer := &ContextCompleter{
		signerCache: &signerCache,
		aliasCache:  &cache.AliasCache{Aliases: map[string]string{}},
	}

	input := "rekey refresh " + address[:4]
	suggestions, offset := completer.Do([]rune(input), len(input))
	if offset != 4 {
		t.Fatalf("offset = %d, want 4", offset)
	}
	if len(suggestions) == 0 {
		t.Fatal("expected address suggestions for rekey refresh")
	}

	want := address[4:] + " "
	if got := string(suggestions[0]); got != want {
		t.Fatalf("first suggestion = %q, want %q", got, want)
	}
}

func TestPluginCompletionUsesQuotedCommandParsing(t *testing.T) {
	account := crypto.GenerateAccount()
	address := account.Address.String()

	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(address, "ed25519")

	completer := &ContextCompleter{
		signerCache: &signerCache,
		aliasCache:  &cache.AliasCache{Aliases: map[string]string{}},
		plugins: []PluginSpec{
			{
				Name: "plugin",
				ArgSpecs: []cmdspec.ArgSpec{
					{Type: cmdspec.ArgTypeKeyword, Values: []string{"mode value"}},
					{Type: cmdspec.ArgTypeAddress},
				},
			},
		},
	}

	input := `plugin "mode value" ` + address[:5]
	suggestions, offset := completer.Do([]rune(input), len(input))
	if offset != 5 {
		t.Fatalf("offset = %d, want 5", offset)
	}
	if len(suggestions) == 0 {
		t.Fatal("expected address suggestions after quoted plugin argument")
	}

	want := address[5:] + " "
	if got := string(suggestions[0]); got != want {
		t.Fatalf("first suggestion = %q, want %q", got, want)
	}
}

func TestAliasDeleteCompletesQuotedAliasName(t *testing.T) {
	completer := &ContextCompleter{
		aliasCache: &cache.AliasCache{Aliases: map[string]string{
			"treasury cold": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		}},
	}

	input := `alias delete "tre`
	suggestions, offset := completer.Do([]rune(input), len(input))
	if offset != 3 {
		t.Fatalf("offset = %d, want 3", offset)
	}
	if len(suggestions) == 0 {
		t.Fatal("expected completion suggestions for quoted alias delete")
	}
	if got := string(suggestions[0]); got != "asury cold " {
		t.Fatalf("first suggestion = %q, want asury cold", got)
	}
}

func TestAliasDeleteCompletesSingleQuotedAliasName(t *testing.T) {
	completer := &ContextCompleter{
		aliasCache: &cache.AliasCache{Aliases: map[string]string{
			"treasury cold": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		}},
	}

	input := `alias delete 'tre`
	suggestions, offset := completer.Do([]rune(input), len(input))
	if offset != 3 {
		t.Fatalf("offset = %d, want 3", offset)
	}
	if len(suggestions) == 0 {
		t.Fatal("expected completion suggestions for single quoted alias delete")
	}
	if got := string(suggestions[0]); got != "asury cold " {
		t.Fatalf("first suggestion = %q, want asury cold", got)
	}
}

// completionsFor runs the full completer (context paths plus prefix tree)
// over line and returns the completed words: the typed partial plus each
// suggested remainder, trimmed.
func completionsFor(t *testing.T, line string, addresses ...string) []string {
	t.Helper()
	signerCache := cache.NewSignerCache()
	for _, address := range addresses {
		signerCache.AddAddress(address, "ed25519")
	}
	completer := CreateDynamicCompleter(&cache.AliasCache{Aliases: map[string]string{}}, &cache.ASACache{}, &cache.SetCache{}, &signerCache, nil, nil, nil)
	suggestions, offset := completer.Do([]rune(line), len(line))
	typed := line[len(line)-offset:]
	words := make([]string, 0, len(suggestions))
	for _, suggestion := range suggestions {
		words = append(words, strings.TrimSpace(typed+string(suggestion)))
	}
	sort.Strings(words)
	return words
}

func TestRotateCompletesAccountsCaseInsensitively(t *testing.T) {
	address := crypto.GenerateAccount().Address.String()
	other := crypto.GenerateAccount().Address.String()
	for _, prefix := range []string{"rotate ", "rotate status ", "rotate recover "} {
		for _, typed := range []string{address[:4], strings.ToLower(address[:4])} {
			got := completionsFor(t, prefix+typed, address, other)
			if len(got) != 1 || !strings.EqualFold(got[0], address) {
				t.Errorf("%q completed to %q, want %s", prefix+typed, got, address)
			}
		}
	}
}

// addressAvoidingPrefixes returns a fresh address that starts with none of
// prefixes (case-insensitively), so keyword-prefix cases stay deterministic.
func addressAvoidingPrefixes(prefixes ...string) string {
	for {
		address := crypto.GenerateAccount().Address.String()
		clear := true
		for _, prefix := range prefixes {
			if strings.HasPrefix(address, strings.ToUpper(prefix)) {
				clear = false
			}
		}
		if clear {
			return address
		}
	}
}

func TestRotateCompletesItsForms(t *testing.T) {
	address := addressAvoidingPrefixes("st", "re")
	for _, tc := range []struct {
		line string
		want []string
	}{
		{"rotate ", []string{address, "recover", "status"}},
		{"rotate st", []string{"status"}},
		{"rotate re", []string{"recover"}},
		// The handler takes keywords only in lowercase; readline would append
		// "cover" to "RE", producing a word rotate rejects.
		{"rotate RE", nil},
		{"rotate " + address + " ", []string{"nowait"}},
		{"rotate " + address + " now", []string{"nowait"}},
		{"rotate status ", []string{address}},
		{"rotate status " + address + " ", nil},
		{"rotate recover " + address + " ", []string{"--max-stages", "--stage", "--timeout", "--window", "cancel"}},
		{"rotate recover " + address + " ca", []string{"cancel"}},
		{"rotate recover " + address + " --stage ", nil},
		{"rotate recover " + address + " --stage 4 ", []string{"--max-stages", "--timeout", "--window"}},
		{"rotate recover " + address + " cancel ", nil},
	} {
		got := completionsFor(t, tc.line, address)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%q completed to %q, want %q", tc.line, got, tc.want)
		}
	}
}

func TestSweepOffersOnlyToAfterACompleteSource(t *testing.T) {
	first := addressAvoidingPrefixes("t")
	second := addressAvoidingPrefixes("t")
	for _, source := range []string{first, strings.ToLower(first), "@team", "[" + first + " " + second + "]"} {
		for _, typed := range []string{"", "t"} {
			line := "sweep usdc from " + source + " " + typed
			got := completionsFor(t, line, first, second)
			if len(got) != 1 || got[0] != "to" {
				t.Errorf("%q completed to %q, want only to", line, got)
				continue
			}
			// The completed line must be one the sweep parser accepts.
			args := strings.Fields(strings.TrimPrefix(line[:len(line)-len(typed)]+"to "+second, "sweep "))
			if _, err := ParseSweepCommand(args); err != nil {
				t.Errorf("completed %q does not parse: %v", line, err)
			}
		}
	}
	// A second unbracketed account is not valid sweep syntax, so nothing completes it.
	for _, typed := range []string{second[:4], strings.ToLower(second[:4])} {
		line := "sweep usdc from " + first + " " + typed
		if got := completionsFor(t, line, first, second); len(got) != 0 {
			t.Errorf("%q completed to %q, want nothing", line, got)
		}
	}
	// Inside an open bracket list, later accounts still complete in either case.
	for _, typed := range []string{second[:4], strings.ToLower(second[:4])} {
		line := "sweep usdc from [" + first + " " + typed
		got := completionsFor(t, line, first, second)
		if len(got) != 1 || !strings.EqualFold(got[0], second) {
			t.Errorf("%q completed to %q, want %s", line, got, second)
		}
	}
	// After the destination keyword, the source rule no longer applies.
	if afterSweepSource(newCompletableCommand("sweep usdc from " + first + " to " + second + " ")) {
		t.Error("treated the position after `to <dest>` as following the source")
	}
}
