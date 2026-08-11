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
	sentryKey := bytes.Repeat([]byte{0x41}, boundedmeta.SentryPublicKeySizeV1)
	tests := []struct {
		name               string
		publicKey          []byte
		parameters         map[string]string
		bytecode           int
		spend              int
		admin              int
		spendGroup         int
		adminGroup         int
		group              int
		spendMinFeeCeiling uint64
		adminMinFeeCeiling uint64
	}{
		{name: "aplane.falcon1024-allowlist.v1.yaml", publicKey: bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize), parameters: map[string]string{"recipients": strings.Join(recipients, ",")}, bytecode: 3155, spend: 4578, spendGroup: 5, group: 5, spendMinFeeCeiling: 2000},
		{name: "aplane.falcon1024-allowlist.v2.yaml", publicKey: bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize), parameters: map[string]string{"recipients": recipients[0]}, bytecode: 2184, spend: 4119, spendGroup: 5, group: 5, spendMinFeeCeiling: 2000},
		{name: "aplane.falcon1024-timelock.v1.yaml", publicKey: bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize), parameters: map[string]string{"unlock_round": "18446744073709551615"}, bytecode: 1943, spend: 3366, spendGroup: 4, group: 4, spendMinFeeCeiling: 2500},
		{name: "aplane.falcon1024-allowlist-alock.v1.yaml", publicKey: bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize), parameters: map[string]string{
			"recipients": strings.Join(recipients, ","), "asset_ids": strings.Join(assetIDs, ","),
			"max_payment_amount": "18446744073709551615", "max_asset_amount": "18446744073709551615",
			composeddsa.BoundedAdminPublicKeyParameter: hex.EncodeToString(adminKey),
		}, bytecode: 5308, spend: 6731, admin: 8154, spendGroup: 7, adminGroup: 9, group: 9, spendMinFeeCeiling: 1428, adminMinFeeCeiling: 1111},
		{name: "aplane.corridor.v1.yaml", publicKey: bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize), parameters: map[string]string{
			"recipients": recipients[0],
			composeddsa.BoundedSentryPublicKeyParameter: hex.EncodeToString(sentryKey),
			composeddsa.BoundedAdminPublicKeyParameter:  hex.EncodeToString(adminKey),
		}, bytecode: 5936, spend: 9294, admin: 8782, spendGroup: 10, adminGroup: 9, group: 10, spendMinFeeCeiling: 1000, adminMinFeeCeiling: 1111},
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
			spend := len(bytecode) + metadata.ArgumentBytesForPath(boundedmeta.PathSpend)
			admin := 0
			maxSize := spend
			if metadata.RequiresAdminKey() {
				admin = len(bytecode) + metadata.ArgumentBytesForPath(boundedmeta.PathAdminRekey)
				if admin > maxSize {
					maxSize = admin
				}
			}
			spendGroup := (spend + 999) / 1000
			adminGroup := 0
			if admin > 0 {
				adminGroup = (admin + 999) / 1000
			}
			group := (maxSize + 999) / 1000
			spendMinFeeCeiling := metadata.MaxFee / uint64(spendGroup)
			adminMinFeeCeiling := uint64(0)
			if adminGroup > 0 {
				adminMinFeeCeiling = metadata.MaxFee / uint64(adminGroup)
			}
			if len(bytecode) != test.bytecode || spend != test.spend || admin != test.admin ||
				spendGroup != test.spendGroup || adminGroup != test.adminGroup || group != test.group ||
				spendMinFeeCeiling != test.spendMinFeeCeiling || adminMinFeeCeiling != test.adminMinFeeCeiling {
				t.Errorf(
					"budget = bytecode %d, spend %d/group %d/min-fee ceiling %d, admin %d/group %d/min-fee ceiling %d, largest group %d",
					len(bytecode), spend, spendGroup, spendMinFeeCeiling, admin, adminGroup, adminMinFeeCeiling, group,
				)
			}
		})
	}
}
