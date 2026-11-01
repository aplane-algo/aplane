// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/aplane-algo/aplane/internal/policy"
)

// CompareMode is how two files were compared: by effective policy when both
// decode, by structure when both parse, and by text otherwise.
type CompareMode string

const (
	ComparePolicy    CompareMode = "policy"
	CompareStructure CompareMode = "structure"
	CompareText      CompareMode = "text"
)

// Change is one difference. Effect is "tightened", "loosened" or "changed"
// in policy mode, and "changed", "added" or "removed" otherwise. Path is a
// JSON Pointer, a route path in policy mode, or "line N" in text mode.
type Change struct {
	Effect  string `json:"effect"`
	Path    string `json:"path"`
	Summary string `json:"summary"`
}

// Comparison is how other differs from base.
type Comparison struct {
	Mode    CompareMode `json:"mode"`
	Changes []Change    `json:"changes"`
	// Identical reports that the two hold the same document. Note explains a
	// comparison that is not what the reader may assume, such as a key's
	// document compared with a default, or a difference with no effect.
	Identical bool   `json:"identical"`
	Note      string `json:"note,omitempty"`
}

// maxTextCompareCells bounds the line diff's work (lines of one file times
// lines of the other); larger files are reported as differing without lines.
const maxTextCompareCells = 4_000_000

// Compare describes how other differs from base. It compares effective
// policy when both decode for the same role (the comparison apadmin policy
// diff makes), the parsed values when both are JSON, and the raw text
// otherwise, so a file another editor left unparsable can still be compared.
func Compare(base, other *File) Comparison {
	switch {
	case base.Document != nil && other.Document != nil && base.Document.Role == other.Document.Role:
		return comparePolicy(base.Document, other.Document)
	case base.Draft != nil && other.Draft != nil:
		var c Comparison
		c.Mode = CompareStructure
		diffNodes(&c, base.Draft.Root(), other.Draft.Root())
		c.Identical = len(c.Changes) == 0
		return c
	default:
		return compareText(base.Loaded, other.Loaded)
	}
}

func comparePolicy(base, other *policy.PolicyV1) Comparison {
	c := Comparison{Mode: ComparePolicy}
	for _, ch := range policy.DiffPolicyV1(base, other) {
		c.Changes = append(c.Changes, Change{Effect: string(ch.Effect), Path: ch.Path, Summary: ch.Summary})
	}
	if base.Key != other.Key {
		c.Note = fmt.Sprintf("compares %s with %s; a key's own document replaces the default wholesale", docName(other.Key), docName(base.Key))
		return c
	}
	c.Identical = reflect.DeepEqual(base, other)
	if len(c.Changes) == 0 && !c.Identical {
		c.Note = "the documents differ, but effective permissions are unchanged"
	}
	return c
}

func docName(key string) string {
	if key == policy.DefaultKey {
		return "the default document"
	}
	return "the document for " + key
}

// diffNodes compares two parsed values by pointer: objects member by member
// (base's order, then members only other has), arrays item by item. Values
// are shown as JSON, so a change of type (false to "false") is visible.
func diffNodes(c *Comparison, a, b policy.DraftNode) {
	switch {
	case !a.Exists() && !b.Exists():
		return
	case !a.Exists():
		c.Changes = append(c.Changes, Change{Effect: "added", Path: b.Pointer(), Summary: compact(b)})
		return
	case !b.Exists():
		c.Changes = append(c.Changes, Change{Effect: "removed", Path: a.Pointer(), Summary: compact(a)})
		return
	case a.Kind() == "object" && b.Kind() == "object":
		seen := map[string]bool{}
		for _, k := range a.Keys() {
			seen[k] = true
			diffNodes(c, a.Member(k), b.Member(k))
		}
		for _, k := range b.Keys() {
			if !seen[k] {
				diffNodes(c, policy.DraftNode{}, b.Member(k))
			}
		}
		return
	case a.Kind() == "array" && b.Kind() == "array":
		ai, bi := a.Items(), b.Items()
		for i := 0; i < max(len(ai), len(bi)); i++ {
			var x, y policy.DraftNode
			if i < len(ai) {
				x = ai[i]
			}
			if i < len(bi) {
				y = bi[i]
			}
			diffNodes(c, x, y)
		}
		return
	}
	if compact(a) != compact(b) {
		c.Changes = append(c.Changes, Change{Effect: "changed", Path: a.Pointer(), Summary: compact(a) + " -> " + compact(b)})
	}
}

// compareText is a line diff of the raw bytes, by longest common subsequence.
func compareText(a, b []byte) Comparison {
	c := Comparison{Mode: CompareText, Identical: string(a) == string(b)}
	if c.Identical {
		return c
	}
	x, y := splitLines(a), splitLines(b)
	if len(x)*len(y) > maxTextCompareCells {
		c.Note = fmt.Sprintf("the files differ; they are too large to compare line by line (%d and %d lines)", len(x), len(y))
		return c
	}
	// lcs[i][j] is the common subsequence length of x[i:] and y[j:].
	lcs := make([][]int, len(x)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(y)+1)
	}
	for i := len(x) - 1; i >= 0; i-- {
		for j := len(y) - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	i, j := 0, 0
	for i < len(x) || j < len(y) {
		switch {
		case i < len(x) && j < len(y) && x[i] == y[j]:
			i, j = i+1, j+1
		case j < len(y) && (i == len(x) || lcs[i][j+1] >= lcs[i+1][j]):
			c.Changes = append(c.Changes, Change{Effect: "added", Path: fmt.Sprintf("line %d", j+1), Summary: y[j]})
			j++
		default:
			c.Changes = append(c.Changes, Change{Effect: "removed", Path: fmt.Sprintf("line %d", i+1), Summary: x[i]})
			i++
		}
	}
	return c
}

func splitLines(data []byte) []string {
	text := strings.TrimSuffix(string(data), "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

// Default returns the workspace's default document, when it holds exactly
// one.
func (w *Workspace) Default() *File {
	var found *File
	for _, f := range w.Files {
		if f.Key == policy.DefaultKey {
			if found != nil {
				return nil
			}
			found = f
		}
	}
	return found
}
