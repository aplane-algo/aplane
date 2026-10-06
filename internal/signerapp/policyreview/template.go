// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyreview

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/pkg/policyschema"
)

// The starting templates are the node's starting documents with one comment
// on the self-transfer route. Removing the comment leaves exactly the
// starting document, so a template opened in the editor and applied unchanged
// changes nothing.

// selfTransferRoute is the starting route as the templates print it, with
// the comment that explains it.
const selfTransferRoute = `      // Lets any account send any asset to itself (ASA opt-ins, self-sends).
      // Every other transfer is rejected until a route allows it.
      {
        "id": "` + policy.SelfTransferRouteID + `",
        "description": "Any account may send any asset to itself",
        "networks": ["*"],
        "sources": ["*"],
        "assets": ["*"],
        "destinations": ["self"]
      }`

// SignerTemplate is the annotated form of the signer starting document.
func SignerTemplate() string {
	return `{
  "format": "` + policyschema.SignerFormatV1 + `",
  "transfer_policy": {
    "enabled": true,
    "on_no_route": "reject",
    "routes": [
` + selfTransferRoute + `
    ]
  }
}
`
}

// CosignerTemplate is the annotated form of a cosigner key's starting
// document, which allows self-transfers only.
func CosignerTemplate(key string) (string, error) {
	// A placeholder key may hold "<" and ">", which must stay readable.
	var keyJSON bytes.Buffer
	enc := json.NewEncoder(&keyJSON)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(key); err != nil {
		return "", err
	}
	return `{
  "format": "` + policyschema.CosignerFormatV1 + `",
  "key": ` + strings.TrimSpace(keyJSON.String()) + `,
  "transfer_policy": {
    "routes": [
` + selfTransferRoute + `
    ]
  }
}
`, nil
}

// StartingTemplate returns the annotated template for the node's starting
// document: the signer template, or the cosigner template for key.
func StartingTemplate(role, key string) (string, error) {
	switch role {
	case "signer":
		return SignerTemplate(), nil
	case "cosigner":
		return CosignerTemplate(key)
	default:
		return "", fmt.Errorf("unknown node role %q", role)
	}
}

// IsStartingDocument reports whether document decodes equal to the node's
// starting document for key: the initial signer policy, or the cosigner
// starting document. Such a document can be shown as its annotated template
// without changing what the policy allows.
func IsStartingDocument(role, key, document string) bool {
	switch role {
	case "signer":
		got, err := policy.DecodeSignerPolicyV1([]byte(document))
		if err != nil {
			return false
		}
		want, err := policy.DecodeSignerPolicyV1(policy.InitialSignerPolicy)
		return err == nil && reflect.DeepEqual(got, want)
	case "cosigner":
		got, err := policy.DecodeCosignerPolicyV1([]byte(document), key)
		if err != nil {
			return false
		}
		starting, err := policy.StartingCosignerDocumentV1(key)
		if err != nil {
			return false
		}
		want, err := policy.DecodeCosignerPolicyV1([]byte(starting), key)
		return err == nil && reflect.DeepEqual(got, want)
	default:
		return false
	}
}
