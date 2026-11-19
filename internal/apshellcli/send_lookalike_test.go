// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/config"
)

// At the prompt, a send or a sweep to an address that looks like an
// address-book entry shows both addresses and asks first; anything but yes
// cancels it, and nothing is signed.
func TestSendAndSweepAskBeforeSendingToALookalike(t *testing.T) {
	real, fake := types.Address{1, 2, 3, 4}.String(), types.Address{1, 2, 3, 4, 9, 9, 9}.String()
	eng := newIsolatedTestEngine(t, "testnet")
	eng.AliasCache.Aliases = map[string]string{"cold": real}
	var out bytes.Buffer
	var prompts []string
	state := &REPLState{
		Out: &out, App: apshellapp.New(eng, config.DefaultConfig(), t.TempDir()), currentCommandCtx: context.Background(),
		SetPrompt:  func(p string) { prompts = append(prompts, p) },
		LineReader: func() (string, error) { return "", nil },
	}
	for name, run := range map[string]func() (command.Result, error){
		"send": func() (command.Result, error) {
			return state.runSend([]string{"1", "algo", "from", "cold", "to", fake})
		},
		"sweep": func() (command.Result, error) { return state.runSweep([]string{"algo", "from", "[cold]", "to", fake}) },
	} {
		out.Reset()
		prompts = nil
		result, err := run()
		if err != nil {
			t.Fatalf("%s: error = %v", name, err)
		}
		if err := result.RenderText(&out); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"looks like cold (" + real + ")", fake, "Cancelled."} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("%s: output lacks %q:\n%s", name, want, out.String())
			}
		}
		if len(prompts) == 0 || prompts[0] != "Send anyway? [y/N]: " {
			t.Errorf("%s: prompts = %q, want the send-anyway question", name, prompts)
		}
	}
}
