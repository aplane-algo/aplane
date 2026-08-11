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
	"github.com/aplane-algo/aplane/internal/lsigresource"
	txsigning "github.com/aplane-algo/aplane/internal/signing"
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
		name       string
		publicKey  []byte
		parameters map[string]string
		bytecode   int
		spendArgs  int
		adminArgs  int
		spendGroup int
		adminGroup int
		spendFee   uint64
		adminFee   uint64
	}{
		{name: "aplane.falcon1024-allowlist.v1.yaml", publicKey: bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize), parameters: map[string]string{"recipients": strings.Join(recipients, ",")}, bytecode: 3155, spendArgs: 1423, spendGroup: 2, spendFee: 2117},
		{name: "aplane.falcon1024-allowlist.v2.yaml", publicKey: bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize), parameters: map[string]string{"recipients": recipients[0]}, bytecode: 2184, spendArgs: 1935, spendGroup: 2, spendFee: 2019},
		{name: "aplane.falcon1024-timelock.v1.yaml", publicKey: bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize), parameters: map[string]string{"unlock_round": "18446744073709551615"}, bytecode: 1943, spendArgs: 1423, spendGroup: 2, spendFee: 2000},
		{name: "aplane.falcon1024-allowlist-alock.v1.yaml", publicKey: bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize), parameters: map[string]string{
			"recipients": strings.Join(recipients, ","), "asset_ids": strings.Join(assetIDs, ","),
			"max_payment_amount": "18446744073709551615", "max_asset_amount": "18446744073709551615",
			composeddsa.BoundedAdminPublicKeyParameter: hex.EncodeToString(adminKey),
		}, bytecode: 5308, spendArgs: 1423, adminArgs: 2846, spendGroup: 2, adminGroup: 3, spendFee: 2332, adminFee: 3232},
		{name: "aplane.corridor.v1.yaml", publicKey: bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize), parameters: map[string]string{
			"recipients": recipients[0],
			composeddsa.BoundedSentryPublicKeyParameter: hex.EncodeToString(sentryKey),
			composeddsa.BoundedAdminPublicKeyParameter:  hex.EncodeToString(adminKey),
		}, bytecode: 5936, spendArgs: 3358, adminArgs: 2846, spendGroup: 4, adminGroup: 3, spendFee: 4196, adminFee: 3295},
	}
	profile, err := lsigresource.ResolveConsensus("fnet5")
	if err != nil {
		t.Fatal(err)
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
			spendArgs := metadata.ArgumentBytesForPath(boundedmeta.PathSpend)
			spendPlan := solveV42BundledPath(t, profile, len(bytecode), spendArgs)
			adminArgs := 0
			var adminPlan lsigresource.Plan
			if metadata.RequiresAdminKey() {
				adminArgs = metadata.ArgumentBytesForPath(boundedmeta.PathAdminRekey)
				adminPlan = solveV42BundledPath(t, profile, len(bytecode), adminArgs)
			}
			spendFee := v42BundledPathFee(spendPlan)
			adminFee := v42BundledPathFee(adminPlan)
			if len(bytecode) != test.bytecode || spendArgs != test.spendArgs || adminArgs != test.adminArgs ||
				int(spendPlan.GroupSize) != test.spendGroup || int(adminPlan.GroupSize) != test.adminGroup ||
				spendFee != test.spendFee || adminFee != test.adminFee {
				t.Errorf(
					"v42 resources = bytecode %d, spend args %d/group %d/fee %d, admin args %d/group %d/fee %d",
					len(bytecode), spendArgs, spendPlan.GroupSize, spendFee,
					adminArgs, adminPlan.GroupSize, adminFee,
				)
			}
			if spendFee > metadata.MaxFee || adminFee > metadata.MaxFee {
				t.Fatalf("v42 path fee exceeds bounded maximum %d: spend=%d admin=%d", metadata.MaxFee, spendFee, adminFee)
			}
		})
	}
}

func solveV42BundledPath(t *testing.T, profile lsigresource.ConsensusProfile, programBytes, argumentBytes int) lsigresource.Plan {
	t.Helper()
	plan, err := lsigresource.Solve(profile, lsigresource.PlanInput{
		TransactionCount: 1,
		LogicSigs: []lsigresource.Usage{{
			ProgramBytes:  uint64(programBytes),
			ArgumentBytes: uint64(argumentBytes),
			MaxOpcodeCost: lsigresource.SingleTransactionOpcodeCeiling,
		}},
		Dummy: lsigresource.Usage{
			ProgramBytes:  uint64(len(txsigning.EmbeddedDummyTealTok)),
			MaxOpcodeCost: 1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func v42BundledPathFee(plan lsigresource.Plan) uint64 {
	if plan.GroupSize == 0 {
		return 0
	}
	const minFee = uint64(1_000)
	const factorScale = uint64(1_000_000)
	usage := plan.GroupSize*factorScale + plan.ProgramFeeFactorUsage
	return (minFee*usage + factorScale - 1) / factorScale
}
