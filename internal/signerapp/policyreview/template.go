// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyreview

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
)

// A template is the document a key's own policy starts from: the node's
// default policy with the key filled in, so a key that gets a policy of its
// own starts from exactly what it was already doing. The template carries a
// comment saying so; apadmin removes comments before the document reaches
// the node, so a template applied unchanged is the default under the key's
// name. The shipped default stands in when no node is reachable, on an
// explicit request only.

// documentKeyPattern finds the document's top-level "key" member. A quote
// inside a JSON string is escaped, so the unescaped quote the pattern
// requires before "key" cannot occur inside a string value.
var documentKeyPattern = regexp.MustCompile(`(^|[^\\])"key"\s*:\s*"` + policy.DefaultKey + `"`)

// Template renders defaultDocument, a node default for role, as the starting
// document for key. key may be policy.DefaultKey to annotate the default
// itself. The default must decode for role.
func Template(role noderole.Role, key string, defaultDocument []byte) (string, error) {
	if _, err := policy.DecodePolicyV1(defaultDocument, policy.DefaultKey, role); err != nil {
		return "", fmt.Errorf("default policy: %w", err)
	}
	body := string(defaultDocument)
	var header string
	if key == policy.DefaultKey {
		header = fmt.Sprintf("// This node's default policy: the rulebook for every %s key without a\n// policy of its own. Every field is required. Comments are removed on apply.\n", role)
	} else {
		matches := documentKeyPattern.FindAllStringIndex(body, -1)
		if len(matches) != 1 {
			return "", fmt.Errorf("default policy does not carry exactly one top-level \"key\" member")
		}
		match := matches[0]
		prefix := body[:match[0]]
		matched := body[match[0]:match[1]]
		replaced := strings.Replace(matched, `"`+policy.DefaultKey+`"`, fmt.Sprintf("%q", key), 1)
		// The first capture group keeps the character before "key" (or
		// nothing at the start of the text); replace only the value.
		body = prefix + replaced + body[match[1]:]
		header = fmt.Sprintf("// Policy for key %s, started from this node's default policy.\n// This file replaces the default for that key: every field is required,\n// nothing is inherited. Comments are removed on apply.\n", key)
	}
	return header + body, nil
}

// EmbeddedTemplate renders the shipped default for role as the starting
// document for key, for producers working with no node or store.
func EmbeddedTemplate(role noderole.Role, key string) (string, error) {
	def, err := policy.EmbeddedDefault(role)
	if err != nil {
		return "", err
	}
	return Template(role, key, def)
}
