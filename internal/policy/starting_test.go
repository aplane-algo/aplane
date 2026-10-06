// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"reflect"
	"strings"
	"testing"
)

const startingTestKey = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"

// selfTransferOnly checks that routes hold exactly the starting route: any
// account, any asset, any network, to itself.
func selfTransferOnly(t *testing.T, routes []RouteV1) RouteV1 {
	t.Helper()
	if len(routes) != 1 {
		t.Fatalf("routes = %+v, want the self-transfer route only", routes)
	}
	route := routes[0]
	if route.ID != SelfTransferRouteID || route.AllowClose || route.AllowClawback || len(route.AssetSources) != 0 ||
		len(route.Limits) != 0 || strings.Join(route.Destinations, ",") != "self" ||
		strings.Join(route.Sources, ",") != "*" || strings.Join(route.Assets, ",") != "*" || !route.NetworkWildcard || len(route.Networks) != 0 {
		t.Fatalf("route = %+v, want * sources, * assets, * networks, self destinations, no allowances", route)
	}
	return route
}

func TestInitialSignerPolicyAllowsSelfTransfersOnly(t *testing.T) {
	doc, err := DecodeSignerPolicyV1(InitialSignerPolicy)
	if err != nil {
		t.Fatalf("initial signer policy does not decode: %v", err)
	}
	if doc.TransferPolicy == nil || !doc.TransferPolicy.Enabled || doc.TransferPolicy.OnNoRoute != TransferOnNoRouteReject ||
		len(doc.TransferPolicy.BlockedDestinations) != 0 {
		t.Fatalf("initial signer transfer policy = %+v, want routing on with on_no_route reject", doc.TransferPolicy)
	}
	selfTransferOnly(t, doc.TransferPolicy.Routes)
	// Every other setting is at its default.
	if doc.Description != "" || doc.RejectForeignRekey != nil || doc.RejectCloseRemainder != nil || doc.RejectAssetClose != nil ||
		doc.RejectClawback != nil || doc.AlwaysReviewWarnings != nil || doc.AutoApproveSelfNoOpTransfer != nil ||
		doc.MaxFeeMicroAlgos != nil || len(doc.Limits) != 0 || len(doc.AddressSets) != 0 || len(doc.AssetSets) != 0 || len(doc.KeyOverrides) != 0 {
		t.Fatalf("initial signer policy sets more than routing: %+v", doc)
	}
	if !strings.HasSuffix(string(InitialSignerPolicy), "}\n") {
		t.Fatalf("initial signer policy is not laid out for editing:\n%s", InitialSignerPolicy)
	}
}

func TestStartingCosignerDocumentAllowsSelfTransfersOnly(t *testing.T) {
	document, err := StartingCosignerDocumentV1(startingTestKey)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := DecodeCosignerPolicyV1([]byte(document), startingTestKey)
	if err != nil {
		t.Fatalf("starting document does not decode: %v", err)
	}
	if doc.Key != startingTestKey || len(doc.RekeyPolicy) != 0 || len(doc.BlockedDestinations) != 0 {
		t.Fatalf("starting document = %+v, want the key with no rekey edges", doc)
	}
	route := selfTransferOnly(t, doc.Routes)
	// A note that the policy is a starting one would outlive it once routes
	// are added.
	if doc.Description != "" {
		t.Fatalf("starting document carries the description %q", doc.Description)
	}
	if _, err := doc.Compile(nil); err != nil {
		t.Fatalf("starting document does not compile: %v", err)
	}
	if !strings.HasSuffix(document, "}\n") {
		t.Fatalf("starting document is not laid out for editing:\n%s", document)
	}
	// Both roles start from the same route.
	signer, err := DecodeSignerPolicyV1(InitialSignerPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(signer.TransferPolicy.Routes[0], route) {
		t.Fatalf("signer route %+v differs from cosigner route %+v", signer.TransferPolicy.Routes[0], route)
	}
	if _, err := StartingCosignerDocumentV1("not-a-witness-key-id"); err == nil {
		t.Fatal("starting document accepted an invalid Witness Key ID")
	}
}
