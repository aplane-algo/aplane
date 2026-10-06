// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"encoding/json"
	"fmt"

	"github.com/aplane-algo/aplane/pkg/policyschema"
)

// LockedCosignerDocumentV1 returns the starting policy document for a cosigner
// key: a valid document with no routes. Cosigner routing is the only positive
// authorization, so a document with no routes rejects every request, exactly
// as a key with no document does. It gives an operator something to edit
// without ever starting from a permissive policy.
//
// The document carries no description: text saying the key is locked would
// stay behind, and be wrong, once routes are added.
func LockedCosignerDocumentV1(key string) (string, error) {
	keyJSON, err := json.Marshal(key)
	if err != nil {
		return "", err
	}
	document := fmt.Sprintf(`{
  "format": %q,
  "key": %s,
  "transfer_policy": {
    "routes": []
  }
}
`, policyschema.CosignerFormatV1, keyJSON)
	if _, err := DecodeCosignerPolicyV1([]byte(document), key); err != nil {
		return "", err
	}
	return document, nil
}
