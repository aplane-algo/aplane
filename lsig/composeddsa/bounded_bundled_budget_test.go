// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/library/templates"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon1024 "github.com/aplane-algo/aplane/lsig/falcon1024"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

func TestBundledBoundedCompiledBudgetMatrix(t *testing.T) {
	falcon1024.RegisterClient()
	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), "")
	if err != nil {
		t.Fatal(err)
	}
	recipients := make([]string, composeddsa.BoundedInlineListMax)
	assetIDs := make([]string, composeddsa.BoundedInlineListMax)
	for i := range recipients {
		address := types.Address{}
		address[0] = byte(i + 1)
		recipients[i] = address.String()
		assetIDs[i] = fmt.Sprintf("%d", i+1)
	}
	adminKey := bytes.Repeat([]byte{0x31}, composeddsa.BoundedAdminPublicKeySize)
	tests := []struct {
		name       string
		publicKey  []byte
		parameters map[string]string
		bytecode   int
		spend      int
		admin      int
		group      int
	}{
		{name: "aplane.falcon1024-allowlist.v1.yaml", publicKey: bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize), parameters: map[string]string{"recipients": strings.Join(recipients, ",")}, bytecode: 3159, spend: 4439, group: 5},
		{name: "aplane.falcon1024-allowlist.v2.yaml", publicKey: bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize), parameters: map[string]string{"recipients": recipients[0]}, bytecode: 2188, spend: 3980, group: 4},
		{name: "aplane.falcon1024-timelock.v1.yaml", publicKey: bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize), parameters: map[string]string{"unlock_round": "18446744073709551615"}, bytecode: 1947, spend: 3227, group: 4},
		{name: "aplane.falcon1024-admin-allowlist.v1.yaml", publicKey: bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize), parameters: map[string]string{
			"recipients": strings.Join(recipients, ","), "asset_ids": strings.Join(assetIDs, ","),
			"max_payment_amount": "18446744073709551615", "max_asset_amount": "18446744073709551615",
			composeddsa.BoundedAdminPublicKeyParameter: hex.EncodeToString(adminKey),
		}, bytecode: 5312, spend: 6592, admin: 7872, group: 8},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := templates.ReadFile(test.name)
			if err != nil {
				t.Fatal(err)
			}
			spec, err := composeddsa.ParseTemplateSpec(data)
			if err != nil {
				t.Fatal(err)
			}
			provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
			if err != nil {
				t.Fatal(err)
			}
			teal, err := provider.GenerateTEAL(test.publicKey, test.parameters)
			if err != nil {
				t.Fatal(err)
			}
			compiled, err := client.TealCompile([]byte(teal)).Do(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			bytecode, err := base64.StdEncoding.DecodeString(compiled.Result)
			if err != nil {
				t.Fatal(err)
			}
			metadata, err := provider.BuildBoundedAuthorizationMetadata(test.publicKey, test.parameters, bytecode)
			if err != nil {
				t.Fatal(err)
			}
			spend := metadata.LogicSigSizeForPath(boundedmeta.PathSpend)
			admin := 0
			maxSize := spend
			if metadata.RequiresAdminKey() {
				admin = metadata.LogicSigSizeForPath(boundedmeta.PathAdminRekey)
				maxSize = admin
			}
			group := (maxSize + 999) / 1000
			if len(bytecode) != test.bytecode || spend != test.spend || admin != test.admin || group != test.group {
				t.Errorf("budget = bytecode %d, spend %d, admin %d, group %d", len(bytecode), spend, admin, group)
			}
		})
	}
}
