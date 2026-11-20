// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package generictemplate_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	librarytemplates "github.com/aplane-algo/aplane/library/templates"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

// genericOutputDigest is the digest of what the generic template parser and
// provider produce for the bundled library templates, templates of both modes,
// and a set of refused templates: parse and validation errors, fingerprints,
// parameter definitions and programs.
const genericOutputDigest = "e1fbd2717a41ac7a2b59deb2e8aa1fd6eaeae422647547294ba7e010e105721e"

const genericCharacterizationDumpEnv = "APLANE_GENERIC_CHARACTERIZATION_DUMP"

const genericCharacterizationGeneratedYAML = `schema_version: 1
derivation_version: 3
template_mode: generated
publisher: test
family: characterization-generic
version: 1
display_name: "Characterization Generic"
valid_rekey_target: false
max_opcode_cost: 20000
parameters:
  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: 5
  - name: amounts
    type: uint64[]
    required: true
    min_items: 1
    max_items: 5
  - name: recipient
    type: address
    required: true
  - name: limit
    type: uint64
    required: true
  - name: hash
    type: bytes
    required: true
    max_length: 64
runtime_args:
  - name: preimage
    type: bytes
    max_size: 32
teal: |
  #pragma version 10
  txn Receiver
  addr @recipient
  ==
  {{range @recipients}}
  txn Receiver
  addr {{.}}
  ==
  ||
  {{end}}
  assert
  {{range @amounts}}
  txn Amount
  int {{.}}
  !=
  assert
  {{end}}
  txn Amount
  int @limit
  <=
  assert
  arg 0
  sha256
  byte @hash
  ==
`

const genericCharacterizationStrictYAML = `schema_version: 1
template_mode: strict
publisher: test
family: characterization-generic-strict
version: 1
display_name: "Characterization Generic Strict"
valid_rekey_target: false
max_opcode_cost: 20000
parameters:
  - name: unlock
    type: uint64
    required: true
  - name: recipient
    type: address
    required: true
template_variables:
  - name: unlock
    source: parameter
    parameter: unlock
    type: uint64
    constant: int
  - name: recipient
    source: parameter
    parameter: recipient
    type: address
    constant: byte
teal: |
  #pragma version 10
  txn FirstValid
  $unlock
  >=
  txn Receiver
  $recipient
  ==
  &&
`

func genericCharacterizationTemplates(t *testing.T) map[string]string {
	t.Helper()
	templates := map[string]string{
		"generated": genericCharacterizationGeneratedYAML,
		"strict":    genericCharacterizationStrictYAML,
	}
	entries, err := librarytemplates.FS.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := librarytemplates.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		templates["library "+entry.Name()] = string(data)
	}
	generated := genericCharacterizationGeneratedYAML
	for name, yaml := range map[string]string{
		"refused salt style":          generated + "salt_style: none\n",
		"refused salt style first":    "salt_style: none\n" + generated,
		"refused salt style repeated": "salt_style: none\nsalt_style: none\n" + generated,
		"refused salt style alias":    "salt_style: &a none\nother: *a\n" + generated,
		"refused duplicate key":       generated + "version: 2\n",
		"refused alias":               "x: &a 1\ny: *a\n" + generated,
		"refused not a mapping":       "- a\n",
		"refused empty":               "",
		"refused bad yaml":            "a: [\n",
		"refused schema 0":            strings.Replace(generated, "schema_version: 1", "schema_version: 0", 1),
		"refused schema string":       strings.Replace(generated, "schema_version: 1", "schema_version: \"1\"", 1),
		"refused schema 3":            strings.Replace(generated, "schema_version: 1", "schema_version: 3", 1),
		"refused unknown field":       generated + "mystery: 1\n",
		"refused two documents":       generated + "---\na: 1\n",
		"refused bad range":           strings.Replace(generated, "{{range @amounts}}", "{{range @limit}}", 1),
		"refused unknown construct":   strings.Replace(generated, "{{end}}", "{{else}}", 1),
		"refused unknown variable":    strings.Replace(generated, "@limit", "@missing", 1),
		"refused strict at variable":  strings.Replace(genericCharacterizationStrictYAML, "$unlock", "@unlock", 1),
		"refused no mode":             strings.Replace(generated, "template_mode: generated\n", "", 1),
	} {
		templates[name] = yaml
	}
	return templates
}

type genericRecorder struct{ lines []string }

func (r *genericRecorder) add(name string, value any) {
	var text string
	switch v := value.(type) {
	case nil:
		text = "<nil>"
	case error:
		text = "error: " + v.Error()
	case string:
		text = v
	default:
		encoded, err := json.Marshal(v)
		if err != nil {
			text = "marshal error: " + err.Error()
		} else {
			text = string(encoded)
		}
	}
	r.lines = append(r.lines, name+" = "+text)
}

func (r *genericRecorder) addErr(name string, err error) {
	if err == nil {
		r.add(name, "ok")
		return
	}
	r.add(name, err)
}

func genericCharacterizationValues(t *generictemplate.YAMLTemplate) map[string]string {
	address := func(b byte) string {
		var a types.Address
		a[0], a[31] = b, 7
		return a.String()
	}
	values := map[string]string{}
	for _, def := range t.CreationParams() {
		switch def.Type {
		case "address[]":
			values[def.Name] = address(3) + "," + address(1) + "," + address(2)
		case "uint64[]":
			values[def.Name] = "9,3,5"
		case "address":
			values[def.Name] = address(9)
		case "uint64":
			values[def.Name] = "1234"
		case "bytes":
			values[def.Name] = "0xAB" + strings.Repeat("cd", max(def.MaxLength/2-1, 1))
		default:
			values[def.Name] = "value"
		}
	}
	return values
}

// TestGenericOutputIsUnchanged pins what the generic parser and provider
// produce. See genericOutputDigest.
func TestGenericOutputIsUnchanged(t *testing.T) {
	r := &genericRecorder{}
	templates := genericCharacterizationTemplates(t)
	names := make([]string, 0, len(templates))
	for name := range templates {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		data := []byte(templates[name])
		fingerprint, err := generictemplate.SemanticFingerprint(data)
		if err != nil {
			r.add(name+" semantic fingerprint", err)
		} else {
			r.add(name+" semantic fingerprint", fingerprint)
		}
		spec, err := generictemplate.ParseTemplateSpec(data)
		if err != nil {
			r.add(name+" parse", err)
			continue
		}
		r.add(name+" spec", spec)
		r.addErr(name+" validate", generictemplate.ValidateSpec(spec))
		r.addErr(name+" admission", generictemplate.ValidateSpecAdmission(spec))
		if prepared, err := generictemplate.PrepareKeystoreTemplateRegistration(spec.KeyType(), data); err != nil {
			r.add(name+" registration", err)
		} else {
			r.add(name+" registration", prepared.Fingerprint)
		}
		template := generictemplate.NewYAMLTemplate(spec)
		r.add(name+" fingerprint", template.CompatibilityFingerprint())
		r.add(name+" creation params", template.CreationParams())
		r.add(name+" runtime args", template.RuntimeArgs())
		values := genericCharacterizationValues(template)
		r.addErr(name+" validate values", template.ValidateCreationParams(values))
		teal, err := template.GenerateTEAL(values)
		if err != nil {
			r.add(name+" teal", err)
		} else {
			r.add(name+" teal", teal)
		}
		if _, err := template.GenerateTEAL(map[string]string{}); err != nil {
			r.add(name+" teal no values", err)
		}
	}
	joined := strings.Join(r.lines, "\n") + "\n"
	if path := os.Getenv(genericCharacterizationDumpEnv); path != "" {
		if err := os.WriteFile(path, []byte(joined), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256([]byte(joined))
	if got := hex.EncodeToString(sum[:]); got != genericOutputDigest {
		t.Fatalf("generic output digest = %s, want %s (set %s to a file path to dump the records)", got, genericOutputDigest, genericCharacterizationDumpEnv)
	}
}
