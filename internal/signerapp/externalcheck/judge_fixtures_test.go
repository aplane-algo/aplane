// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package externalcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
)

// judgeFixtureFormat is the format of the judge contract fixtures in
// test/contracts/policy/v1/external.
const judgeFixtureFormat = "aplane.policy-external-judge.v1"

var judgeFixtureDir = filepath.Join("..", "..", "..", "test", "contracts", "policy", "v1", "external")

type judgeFixtureFile struct {
	Format      string             `json:"format"`
	Description string             `json:"description"`
	Cases       []judgeFixtureCase `json:"cases"`
}

// judgeFixtureCase is one check judged against one answer. The answer is
// kept as written, so its number literals reach the reader verbatim.
type judgeFixtureCase struct {
	Name        string            `json:"name"`
	Scope       string            `json:"scope"`
	Require     json.RawMessage   `json:"require"`
	EchoPointer *string           `json:"echo_pointer"`
	RequestID   string            `json:"request_id"`
	Facts       map[string]string `json:"facts"`
	Answer      json.RawMessage   `json:"answer"`
	Expect      struct {
		Result string `json:"result"`
		Detail string `json:"detail"`
	} `json:"expect"`
}

func readJudgeFixture(t *testing.T, path string) judgeFixtureFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f judgeFixtureFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		t.Fatalf("%s: content after the fixture object", path)
	}
	if f.Format != judgeFixtureFormat {
		t.Fatalf("%s: format %q, want %q", path, f.Format, judgeFixtureFormat)
	}
	if strings.TrimSpace(f.Description) == "" || len(f.Cases) == 0 {
		t.Fatalf("%s: a fixture file needs a description and cases", path)
	}
	return f
}

// compileFixtureCheck decodes the case's check through the node's own decoder,
// as the only check of a cosigner document with one https source.
func compileFixtureCheck(t *testing.T, c judgeFixtureCase) (policy.ExternalCheckV1, policy.ExternalSourceV1) {
	t.Helper()
	scope := c.Scope
	if scope == "" {
		scope = string(policy.ExternalScopeMovement)
	}
	scopeJSON, _ := json.Marshal(scope)
	echo := ""
	if c.EchoPointer != nil {
		pointer, _ := json.Marshal(*c.EchoPointer)
		echo = `, "echo_pointer": ` + string(pointer)
	}
	cfg := compileChecks(t, `{"s": {"base_url": "https://s.example"}}`,
		fmt.Sprintf(`[{"id": "c", "source": "s", "scope": %s, "networks": ["*"], "path": "/x"%s, "require": %s}]`, scopeJSON, echo, c.Require))
	return cfg.ExternalChecks[0], cfg.ExternalSources["s"]
}

// TestJudgeFixtures runs every judge contract fixture through the real
// decoder, the answer reader and Judge. The fixtures freeze the rule
// semantics: a changed expectation is a changed contract.
func TestJudgeFixtures(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(judgeFixtureDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no judge fixtures in %s: %v", judgeFixtureDir, err)
	}
	ops := map[policy.ExternalOp]bool{}
	operands := map[string]bool{}
	results := map[string]bool{}
	echoes := 0
	for _, path := range files {
		f := readJudgeFixture(t, path)
		file := filepath.Base(path)
		names := map[string]bool{}
		for _, c := range f.Cases {
			if c.Name == "" || names[c.Name] {
				t.Fatalf("%s: case name %q is empty or used twice", file, c.Name)
			}
			names[c.Name] = true
			want := c.Expect.Result
			if (want != "pass" && want != "fail") || (want == "fail" && c.Expect.Detail == "") || (want == "pass" && c.Expect.Detail != "") {
				t.Fatalf("%s/%s: expect = %+v: want pass, or fail with a detail", file, c.Name, c.Expect)
			}
			if len(c.Answer) == 0 {
				t.Fatalf("%s/%s: the case has no answer", file, c.Name)
			}
			// The check is decoded here, outside the subtest, so the coverage
			// below counts every case whichever subtests run.
			check, source := compileFixtureCheck(t, c)
			for _, rule := range check.Require {
				ops[rule.Op] = true
				for kind, set := range map[string]bool{
					"number": rule.Number != nil, "string": rule.String != nil, "bool": rule.Bool != nil,
					"numbers": rule.Numbers != nil, "strings": rule.Strings != nil, "fact": rule.Fact != "",
				} {
					operands[kind] = operands[kind] || set
				}
			}
			if check.EchoPointer != nil {
				echoes++
			}
			results[want] = true
			t.Run(file+"/"+c.Name, func(t *testing.T) {
				root, err := ParseAnswer(c.Answer, source)
				if err != nil {
					t.Fatalf("the answer is not accepted: %v", err)
				}
				holds, detail := Judge(check, Facts(c.Facts), root, c.RequestID)
				if got := map[bool]string{true: "pass", false: "fail"}[holds]; got != want {
					t.Fatalf("Judge() = %s (%q), want %s", got, detail, want)
				}
				if holds && detail != "" {
					t.Fatalf("a pass carries the detail %q", detail)
				}
				if !strings.Contains(detail, c.Expect.Detail) {
					t.Fatalf("detail = %q, want it to contain %q", detail, c.Expect.Detail)
				}
			})
		}
	}
	for _, op := range []policy.ExternalOp{
		policy.ExternalOpEq, policy.ExternalOpNe, policy.ExternalOpLt, policy.ExternalOpLe, policy.ExternalOpGt,
		policy.ExternalOpGe, policy.ExternalOpIn, policy.ExternalOpNotIn, policy.ExternalOpPresent, policy.ExternalOpAbsent,
	} {
		if !ops[op] {
			t.Errorf("no fixture uses op %s", op)
		}
	}
	for _, kind := range []string{"number", "string", "bool", "numbers", "strings", "fact"} {
		if !operands[kind] {
			t.Errorf("no fixture uses a %s operand", kind)
		}
	}
	if echoes == 0 || !results["pass"] || !results["fail"] {
		t.Errorf("the fixtures need an echo_pointer and both results: %d echoes, results %v", echoes, results)
	}
}
