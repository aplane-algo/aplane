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

// The starting templates are the node's starting documents with every field
// explained in comments and an example route commented out. Removing the
// comments leaves exactly the starting document, so a template opened in the
// editor and applied unchanged changes nothing. Each commented block ends
// with a comma and a real member follows it (the transfer_policy member after
// the setting blocks, the self-transfer route after the example route), so a
// block is enabled by removing its "// " without adding punctuation.

const commentPreamble = `  // Lines starting with // are comments. apadmin removes them before the
  // document reaches the node, so the stored copy (apadmin policy export)
  // has none. Remove the "// " from a block below to enable it. Amounts are
  // decimal strings in base units (microAlgos for ALGO), assets are "algo"
  // or "asa:<id>", and addresses are 58-character Algorand addresses.
  //
  // The one real route lets any account send any asset to itself, which is
  // what ASA opt-ins need. Every other transfer is rejected until a route
  // allows it; the commented route before it shows the pattern.
`

// selfTransferRoute is the starting route as the templates print it.
const selfTransferRoute = `      {
        "id": "` + policy.SelfTransferRouteID + `",
        "description": "Any account may send any asset to itself",
        "networks": ["*"],
        "sources": ["*"],
        "assets": ["*"],
        "destinations": ["self"]
      }`

// exampleRoute is the commented-out example route: one named set of senders
// paying another in ALGO, with the route's own threshold. It comes before the
// real route in the array and ends with a comma, so enabling it needs no
// other edit; threshold is "review_above" for a signer, which may review, and
// "reject_above" for a cosigner, which may not.
func exampleRoute(threshold string) string {
	return `      // {
      //   "id": "treasury-to-ops",
      //   "description": "Treasury tops up ops in ALGO",
      //   "networks": ["mainnet"],
      //   "sources": ["@treasury"],
      //   "assets": ["algo"],
      //   "destinations": ["@ops"],
      //   "limits": { "mainnet": { "algo": { "` + threshold + `": "500000000" } } }
      // },`
}

// SignerTemplate is the annotated form of the signer starting document.
func SignerTemplate() string {
	return `{
  "format": "` + policyschema.SignerFormatV1 + `",

` + commentPreamble + `
  // Notes for reviewers.
  // "description": "Operations signer",

  // Reject a rekey to an address this signer does not hold (default true).
  // "reject_foreign_rekey": false,

  // Reject ALGO close-outs, ASA close-outs, and ASA clawbacks (default false).
  // "reject_close_remainder": true,
  // "reject_asset_close": true,
  // "reject_clawback": true,

  // Send transactions with warning findings to operator review (default false).
  // "always_review_warnings": true,

  // Reject a transaction whose fee is above this many microAlgos.
  // "max_fee_microalgos": "10000",

  // Per-network, per-asset thresholds. review_above sends a larger movement
  // to operator review; reject_above rejects it.
  // "limits": {
  //   "mainnet": {
  //     "algo": { "review_above": "100000000", "reject_above": "1000000000" }
  //   }
  // },

  // Named sets that routes refer to as "@name".
  // "address_sets": {
  //   "treasury": ["<58-character address>"],
  //   "ops": ["<58-character address>"]
  // },

  // Transfer routing. Every movement must match a route; on_no_route
  // ("reject", "review", or "operator_default") decides the rest.
  "transfer_policy": {
    "enabled": true,
    "on_no_route": "reject",
    "routes": [
` + exampleRoute("review_above") + `
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

` + commentPreamble + `
  // Notes for reviewers.
  // "description": "Treasury cosigner",

  // Reject ALGO close-outs, ASA close-outs, and ASA clawbacks (default false).
  // "reject_close_remainder": true,
  // "reject_asset_close": true,
  // "reject_clawback": true,

  // Reject every rekey (default false; otherwise rekey_policy decides).
  // "reject_rekey": true,

  // Reject a transaction whose fee is above this many microAlgos.
  // "max_fee_microalgos": "5000",

  // Per-network, per-asset caps. A cosigner never reviews, so only
  // reject_above is allowed.
  // "limits": {
  //   "mainnet": {
  //     "algo": { "reject_above": "2000000000" }
  //   }
  // },

  // Named sets that routes refer to as "@name".
  // "address_sets": {
  //   "treasury": ["<58-character address>"],
  //   "ops": ["<58-character address>"]
  // },

  // Rekey edges this key witnesses: each sender may rekey to its targets.
  // "rekey_policy": {
  //   "allowed": [
  //     { "sender": "@treasury", "targets": ["<58-character address>"] }
  //   ]
  // },

  // Every movement must match a route; anything else is rejected.
  "transfer_policy": {
    "routes": [
` + exampleRoute("reject_above") + `
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

// UncommentTemplate enables every commented block of a template by removing
// the "// " from each commented line that holds JSON (one that starts with a
// quote, brace, or bracket), leaving the explanatory prose in place. It
// exists for tests, which prove the example blocks are valid policy.
func UncommentTemplate(template string) string {
	lines := strings.Split(template, "\n")
	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " ")
		body, ok := strings.CutPrefix(trimmed, "// ")
		if !ok {
			continue
		}
		if text := strings.TrimLeft(body, " "); text == "" || !strings.ContainsRune(`"{}[]`, rune(text[0])) {
			continue
		}
		lines[i] = line[:len(line)-len(trimmed)] + body
	}
	return strings.Join(lines, "\n")
}
