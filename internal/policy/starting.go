// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/aplane-algo/aplane/pkg/policyschema"
)

// The starting documents allow self-transfers only. Their one route lets any
// account send any asset to itself on any network, which is what ASA opt-ins
// and self no-op pings need, and nothing else: a transfer to any other
// address is a route miss, which the signer document rejects through
// on_no_route and a cosigner document always rejects. Close-outs and
// clawbacks match the route without an allowance, so they are rejected too.
// An operator adds routes to let funds leave an account.
//
// The documents carry no description: text saying the policy is a starting
// one would stay behind, and be wrong, once routes are added.

// SelfTransferRouteID is the ID of the starting documents' one route.
const SelfTransferRouteID = "self-transfer"

// selfTransferRouteJSON is the starting route, indented for a document whose
// routes array sits two levels deep.
const selfTransferRouteJSON = `      {
        "id": "` + SelfTransferRouteID + `",
        "description": "Any account may send any asset to itself",
        "networks": ["*"],
        "sources": ["*"],
        "assets": ["*"],
        "destinations": ["self"]
      }`

// InitialSignerPolicy is the signer document a new store starts with: every
// setting at its default, and routing on with the self-transfer route only.
var InitialSignerPolicy = []byte(`{
  "format": "` + policyschema.SignerFormatV1 + `",
  "transfer_policy": {
    "enabled": true,
    "on_no_route": "reject",
    "routes": [
` + selfTransferRouteJSON + `
    ]
  }
}
`)

// StartingCosignerDocumentV1 returns the starting policy document for a
// cosigner key: the self-transfer route and nothing else. It gives an
// operator something to edit that never starts from a permissive policy;
// nothing is stored for the key until a document is applied.
func StartingCosignerDocumentV1(key string) (string, error) {
	var keyJSON bytes.Buffer
	enc := json.NewEncoder(&keyJSON)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(key); err != nil {
		return "", err
	}
	document := fmt.Sprintf(`{
  "format": %q,
  "key": %s,
  "transfer_policy": {
    "routes": [
%s
    ]
  }
}
`, policyschema.CosignerFormatV1, bytes.TrimSpace(keyJSON.Bytes()), selfTransferRouteJSON)
	if _, err := DecodeCosignerPolicyV1([]byte(document), key); err != nil {
		return "", err
	}
	return document, nil
}
