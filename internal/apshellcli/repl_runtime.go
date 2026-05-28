// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/shellrepl"
	"github.com/aplane-algo/aplane/internal/theme"

	"github.com/chzyer/readline"
)

func (r *REPLState) promptString() string {
	return fmt.Sprintf(
		"\033[%sm%s%s%s>\033[0m ",
		theme.Current().PromptColor,
		r.app().ConnectionIndicator(),
		r.app().Network(),
		r.app().ModeFlags(),
	)
}

func (r *REPLState) discoverCompleter() readline.AutoCompleter {
	externalPlugins, _ := discoverExternalPlugins(r)
	deps := r.app().CompleterDeps()
	return shellrepl.CreateDynamicCompleter(
		deps.AliasCache,
		deps.ASACache,
		deps.SetCache,
		deps.SignerCache,
		deps.EnsureSignerCache,
		r.networkCompletions(),
		externalPlugins,
	)
}

func (r *REPLState) networkCompletions() []string {
	seen := make(map[string]struct{})
	add := func(network string) {
		if network == "" {
			return
		}
		if err := apconfig.ValidateNetworkID(network); err != nil {
			return
		}
		seen[network] = struct{}{}
	}

	add(r.Config.Network)
	for _, network := range r.Config.NetworksAllowed {
		add(network)
	}
	for network := range r.Config.Algod {
		add(network)
	}
	for _, network := range []string{apconfig.NetworkMainnet, apconfig.NetworkTestnet, apconfig.NetworkBetanet} {
		add(network)
	}

	out := make([]string, 0, len(seen))
	for network := range seen {
		out = append(out, network)
	}
	sort.Strings(out)
	return out
}

func (r *REPLState) newReadlineConfig() *readline.Config {
	return &readline.Config{
		Prompt:            r.promptString(),
		HistoryFile:       historyFilePath(),
		HistoryLimit:      historyLimit,
		AutoComplete:      r.lockedCompleter(r.discoverCompleter()),
		InterruptPrompt:   "^C",
		EOFPrompt:         "exit",
		HistorySearchFold: true,
	}
}

func (r *REPLState) bindInteractiveIO(rl *readline.Instance) {
	r.LineReader = func() (string, error) {
		return rl.Readline()
	}
	r.SetPrompt = func(p string) {
		rl.SetPrompt(p)
	}
}

func (r *REPLState) refreshCompleter(rl *readline.Instance) {
	rl.Config.AutoComplete = r.lockedCompleter(r.discoverCompleter())
}

func (r *REPLState) executeCommandWithInterrupt(cmd Command, sigCh <-chan os.Signal) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cleanupSignerCtx := r.app().BindSignerClientContext(ctx)
	defer cleanupSignerCtx()
	priorCtx := r.currentCommandCtx
	r.currentCommandCtx = ctx
	defer func() {
		r.currentCommandCtx = priorCtx
	}()

	select {
	case <-sigCh:
	default:
	}

	done := make(chan struct{})
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-done:
		}
	}()

	r.runtimeMu.Lock()
	err := r.executeCommand(cmd)
	r.runtimeMu.Unlock()
	close(done)

	if ctx.Err() == context.Canceled {
		fmt.Println("\nInterrupted")
		return nil
	}
	return err
}

type lockedAutoCompleter struct {
	mu    *sync.Mutex
	inner readline.AutoCompleter
}

func (c lockedAutoCompleter) Do(line []rune, pos int) ([][]rune, int) {
	if c.mu != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
	}
	return c.inner.Do(line, pos)
}

func (r *REPLState) lockedCompleter(inner readline.AutoCompleter) readline.AutoCompleter {
	return lockedAutoCompleter{mu: &r.runtimeMu, inner: inner}
}
