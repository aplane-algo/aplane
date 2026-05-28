// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package shellrepl

import (
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
