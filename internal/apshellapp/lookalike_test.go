// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// lookalikeAddresses are two valid addresses that look alike: their keys
// share four bytes, so the addresses share their first six characters.
func lookalikeAddresses() (real, fake string) {
	a, b := types.Address{1, 2, 3, 4}, types.Address{1, 2, 3, 4, 9, 9, 9}
	return a.String(), b.String()
}

func lookalikeTestApp(t *testing.T, aliases map[string]string, held ...string) *App {
	t.Helper()
	eng := engine.NewEngine("testnet")
	eng.AliasCache.Aliases = aliases
	keys := make([]signerapi.KeyInfo, 0, len(held))
	for _, address := range held {
		keys = append(keys, signerapi.KeyInfo{Address: address, KeyType: "falcon1024", AuthorizationKind: "native_pq"})
	}
	if err := eng.PopulateSignerCache(keys); err != nil {
		t.Fatalf("PopulateSignerCache() error = %v", err)
	}
	return New(eng, config.DefaultConfig(), t.TempDir())
}

// A recipient typed as an address that looks like an address-book entry or a
// held account is found before anything is built; one named by alias, the
// known address itself in any case, and an unrelated address are not.
func TestSendFindsARecipientThatLooksLikeAKnownAccount(t *testing.T) {
	real, fake := lookalikeAddresses()
	if real[:6] != fake[:6] || real == fake {
		t.Fatalf("test addresses %s and %s do not look alike", real, fake)
	}
	unrelated := types.Address{0xF0, 0x0F}.String()
	for name, tc := range map[string]struct {
		aliases map[string]string
		held    []string
		to      []string
		want    []RecipientLookalike
	}{
		"an address-book entry": {aliases: map[string]string{"cold": real}, to: []string{fake}, want: []RecipientLookalike{{Typed: fake, Known: real, Alias: "cold"}}},
		"a held account":        {held: []string{real}, to: []string{fake}, want: []RecipientLookalike{{Typed: fake, Known: real}}},
		"typed in lower case":   {held: []string{real}, to: []string{strings.ToLower(fake)}, want: []RecipientLookalike{{Typed: fake, Known: real}}},
		"named by alias":        {aliases: map[string]string{"cold": real, "other": fake}, to: []string{"other"}},
		"the known address":     {held: []string{real}, to: []string{strings.ToLower(real)}},
		"an unrelated address":  {held: []string{real}, to: []string{unrelated}},
	} {
		t.Run(name, func(t *testing.T) {
			app := lookalikeTestApp(t, tc.aliases, tc.held...)
			plan, err := app.PrepareSend(context.Background(), SendRequest{AmountText: "1", AssetRef: "algo", FromRaw: []string{unrelated}, ToRaw: tc.to})
			if err != nil {
				t.Fatalf("PrepareSend() error = %v", err)
			}
			if len(plan.Lookalikes) != len(tc.want) {
				t.Fatalf("lookalikes = %+v, want %+v", plan.Lookalikes, tc.want)
			}
			for i, want := range tc.want {
				if plan.Lookalikes[i] != want {
					t.Errorf("lookalike %d = %+v, want %+v", i, plan.Lookalikes[i], want)
				}
				for _, part := range []string{want.Typed, want.Known} {
					if !strings.Contains(plan.Lookalikes[i].Message(), part) {
						t.Errorf("message lacks %s: %s", part, plan.Lookalikes[i].Message())
					}
				}
			}
		})
	}
}

// Asked about a lookalike recipient, a no stops the send before anything is
// built or signed.
func TestSendDeclinedForALookalikeStopsBeforeSigning(t *testing.T) {
	real, fake := lookalikeAddresses()
	app := lookalikeTestApp(t, map[string]string{"cold": real})
	var asked []RecipientLookalike
	_, err := app.ExecuteSend(context.Background(), SendRequest{
		AmountText: "1", AssetRef: "algo", FromRaw: []string{real}, ToRaw: []string{fake},
		ConfirmLookalikes: func(l []RecipientLookalike) (bool, error) { asked = l; return false, nil },
	})
	if !errors.Is(err, ErrLookalikeDeclined) {
		t.Fatalf("ExecuteSend() error = %v, want ErrLookalikeDeclined", err)
	}
	if len(asked) != 1 || asked[0].Typed != fake {
		t.Fatalf("asked about %+v, want the lookalike recipient", asked)
	}
}
