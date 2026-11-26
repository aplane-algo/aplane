// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/ed25519lsig"
	falcon1024 "github.com/aplane-algo/aplane/lsig/falcon1024"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

// composedOutputDigest is the digest of everything the composer produces for a
// set of templates covering both schema versions, both template modes, every
// framework Layer 3 policy, a cosigner, a rekey-to list, runtime arguments, and
// a set of refused templates: admission, registration, fingerprints, parameter
// definitions, metadata, programs, derived bytecode and addresses, and the
// error text of each refusal.
const composedOutputDigest = "c7dec71ea3a223b191508185cd9db57b12523bbf72b2f58eca1995b36e79e8ba"

const composedCharacterizationDumpEnv = "APLANE_COMPOSED_CHARACTERIZATION_DUMP"

const characterizationV1GeneratedYAML = `schema_version: 1
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: generated
publisher: test
family: characterization-generated
version: 1
display_name: "Characterization Generated"
valid_rekey_target: true
max_opcode_cost: 20000
parameters:
  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: 5
  - name: recipient
    type: address
    required: true
  - name: amount
    type: uint64
    required: true
  - name: tag
    type: bytes
    required: true
    max_length: 16
runtime_args:
  - name: preimage
    type: bytes
    max_size: 32
teal: |
  txn Amount
  int @amount
  <=
  assert
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
  arg 1
  sha256
  byte @tag
  !=
  assert
`

const characterizationV1StrictYAML = `schema_version: 1
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: test
family: characterization-strict
version: 1
display_name: "Characterization Strict"
valid_rekey_target: false
parameters:
  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: 3
  - name: unlock
    type: uint64
    required: true
template_variables:
  - name: recipients
    source: parameter
    parameter: recipients
    type: address[]
    constant: byte
  - name: unlock
    source: parameter
    parameter: unlock
    type: uint64
    constant: int
teal: |
  txn FirstValid
  $unlock
  >=
  assert
  $recipients
  pop
`

// characterizationTemplates are the valid templates the digest covers.
func characterizationTemplates() map[string]string {
	templates := map[string]string{
		"v1 generated":        characterizationV1GeneratedYAML,
		"v1 strict":           characterizationV1StrictYAML,
		"fixed allowlist":     composeddsa.FixedAllowlistFixtureYAML,
		"merkle allowlist":    composeddsa.MerkleAllowlistFixtureYAML,
		"custom timelock":     composeddsa.CustomTimelockFixtureYAML,
		"none policy":         noneTemplateYAML,
		"ed25519 bounded":     ed25519BoundedTemplate,
		"falcon cosigner":     falconCosignerTemplate,
		"only these":          onlyTheseTemplateYAML,
		"plus cosigned":       strings.Replace(strings.Replace(falconCosignerTemplate, "  rekey: refused\n", "  rekey: plus_cosigned\n", 1), "required_on: [spend]", "required_on: [spend, spending_rekey]", 1),
		"cosigned only these": strings.Replace(falconCosignerTemplate, "  rekey: refused\n", "  rekey: only_these\n", 1),
		"cosigned spending":   strings.Replace(strings.Replace(falconCosignerTemplate, "  rekey: refused\n", "  rekey: spending_key\n", 1), "required_on: [spend]", "required_on: [spend, spending_rekey]", 1),
	}
	for _, test := range authorAllowlistCases {
		templates["author allowlist "+test.name] = authorAllowlistYAML(test)
	}
	return templates
}

// refusedCharacterizationTemplates are variations each step refuses somewhere.
func refusedCharacterizationTemplates() map[string]string {
	return map[string]string{
		"salt style":             composeddsa.FixedAllowlistFixtureYAML + "salt_style: none\n",
		"salt style first":       "salt_style: none\n" + composeddsa.FixedAllowlistFixtureYAML,
		"salt style duplicate":   "salt_style: none\nsalt_style: none\n" + composeddsa.FixedAllowlistFixtureYAML,
		"duplicate key":          composeddsa.FixedAllowlistFixtureYAML + "version: 2\n",
		"not a mapping":          "- a\n- b\n",
		"bad yaml":               "schema_version: [\n",
		"schema 3":               strings.Replace(composeddsa.FixedAllowlistFixtureYAML, "schema_version: 2", "schema_version: 3", 1),
		"v2 top-level args":      onlyTheseTemplateYAML + "runtime_args:\n  - name: blob\n    type: bytes\n    max_size: 8\n",
		"v1 bounded":             strings.Replace(composeddsa.FixedAllowlistFixtureYAML, "schema_version: 2", "schema_version: 1", 1),
		"no template mode":       strings.Replace(onlyTheseTemplateYAML, "template_mode: strict\n", "", 1),
		"unknown template mode":  strings.Replace(onlyTheseTemplateYAML, "template_mode: strict\n", "template_mode: fancy\n", 1),
		"unknown base":           strings.Replace(onlyTheseTemplateYAML, "aplane.falcon1024.v1", "example.unknown.v1", 1),
		"ed25519 cosigner":       strings.Replace(falconCosignerTemplate, "aplane.falcon1024.v1", ed25519lsig.KeyTypeV1, 1),
		"no rekey target":        strings.Replace(onlyTheseTemplateYAML, "valid_rekey_target: true\n", "", 1),
		"no layer3 or teal":      strings.Replace(onlyTheseTemplateYAML, "teal: |\n  pushint 1\n  assert\n", "", 1),
		"unknown rekey":          strings.Replace(onlyTheseTemplateYAML, "rekey: only_these", "rekey: admin_key", 1),
		"plus cosigned alone":    strings.Replace(onlyTheseTemplateYAML, "rekey: only_these", "rekey: plus_cosigned", 1),
		"own rekey_to":           onlyTheseTemplateYAML + "\nparameters:\n  - name: rekey_to\n    type: address[]\n    required: true\n    min_items: 1\n    max_items: 3\n",
		"oversized runtime arg":  strings.Replace(authorAllowlistYAML(authorAllowlistCases[0]), "max_size: 64", "max_size: 4097", 1),
		"undeclared variable":    strings.Replace(composeddsa.CustomTimelockFixtureYAML, "$unlock_round", "$missing", 1),
		"at variable in strict":  strings.Replace(composeddsa.CustomTimelockFixtureYAML, "$unlock_round", "@unlock_round", 1),
		"go template in strict":  strings.Replace(composeddsa.CustomTimelockFixtureYAML, "$unlock_round", "{{.}}", 1),
		"unreferenced variable":  strings.Replace(composeddsa.CustomTimelockFixtureYAML, "  $unlock_round\n", "  int 1\n", 1),
		"none policy declared":   strings.Replace(composeddsa.FixedAllowlistFixtureYAML, "policy: fixed_allowlist", "policy: none", 1),
		"plain contract":         strings.Replace(onlyTheseTemplateYAML, "contract: bounded2", "contract: plain1", 1),
		"no max fee":             strings.Replace(onlyTheseTemplateYAML, "  max_fee: 10000\n", "", 1),
		"generated bad range":    strings.Replace(characterizationV1GeneratedYAML, "{{range @recipients}}", "{{range @amount}}", 1),
		"generated unknown attr": strings.Replace(characterizationV1GeneratedYAML, "{{end}}", "{{else}}", 1),
	}
}

type composedRecorder struct{ lines []string }

func (r *composedRecorder) add(name string, value any) {
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

func (r *composedRecorder) addErr(name string, err error) {
	if err == nil {
		r.add(name, "ok")
		return
	}
	r.add(name, err)
}

// characterizationValues gives every creation parameter a value of its type.
func characterizationValues(defs []lsigprovider.ParameterDef) map[string]string {
	address := func(b byte) string {
		var a types.Address
		a[0], a[31] = b, 7
		return a.String()
	}
	values := map[string]string{}
	for _, def := range defs {
		switch {
		case def.Name == composeddsa.BoundedCosignerPublicKeyParameter:
			// Hex with the digits a-f, half of it in upper case.
			size := def.MaxLength / 2
			values[def.Name] = strings.ToUpper(strings.Repeat("a5", size/2)) + strings.Repeat("3c", size-size/2)
		case def.Name == composeddsa.BoundedRekeyToParameter:
			values[def.Name] = address(0x61) + "," + address(0x62)
		case def.Type == "address[]":
			values[def.Name] = address(3) + "," + address(1) + "," + address(2)
		case def.Type == "address":
			values[def.Name] = address(9)
		case def.Type == "uint64":
			values[def.Name] = "1234"
		case def.Type == "uint64[]":
			values[def.Name] = "9,3,5"
		case def.Type == "bytes" && def.MaxLength >= 4:
			values[def.Name] = "0xAB" + strings.Repeat("cd", def.MaxLength/2-1)
		case def.Type == "bytes":
			values[def.Name] = "0xABcd"
		default:
			values[def.Name] = "value"
		}
	}
	return values
}

// composedCompiler stands in for algod's compiler. The program it returns is
// the TEAL version 13 byte, the SHA-256 of the TEAL it is sent, and a final
// counter byte chosen to put the address off the curve; the hash it reports is
// that address. So a derived program and address pin the TEAL a derivation
// compiled, and what the derivation made of the reply.
type composedCompiler struct{}

func (composedCompiler) RoundTrip(req *http.Request) (*http.Response, error) {
	reply := func(status int, body string) *http.Response {
		return &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}
	}
	if req.Method != http.MethodPost || req.URL.Path != "/v2/teal/compile" {
		return reply(http.StatusNotFound, `{"message":"unexpected request"}`), nil
	}
	teal, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(teal)
	program := append(append([]byte{13}, sum[:]...), 0)
	for counter := 0; counter < 256; counter++ {
		program[len(program)-1] = byte(counter)
		address := crypto.LogicSigAddress(types.LogicSig{Logic: program})
		if !lsigsalt.IsOnCurve(address) {
			return reply(http.StatusOK, `{"result":"`+base64.StdEncoding.EncodeToString(program)+`","hash":"`+address.String()+`"}`), nil
		}
	}
	return reply(http.StatusBadRequest, `{"message":"no off-curve counter"}`), nil
}

func characterizeComposedTemplate(r *composedRecorder, client *algod.Client, name, yaml string) {
	data := []byte(yaml)
	fingerprint, err := composeddsa.SemanticFingerprint(data)
	if err != nil {
		r.add(name+" semantic fingerprint", err)
	} else {
		r.add(name+" semantic fingerprint", fingerprint)
	}
	spec, err := composeddsa.ParseTemplateSpec(data)
	if err != nil {
		r.add(name+" parse", err)
		// The generic parser reaches templates the composed one refuses.
		if spec, err = generictemplate.ParseTemplateSpec(data); err != nil {
			r.add(name+" generic parse", err)
			return
		}
	}
	r.addErr(name+" validate", composeddsa.ValidateTemplateSpec(spec))
	r.addErr(name+" admission", composeddsa.ValidateTemplateAdmission(spec))
	keyType := spec.KeyType()
	if prepared, err := composeddsa.PrepareKeystoreTemplateRegistration(keyType, data); err != nil {
		r.add(name+" registration", err)
	} else {
		r.add(name+" registration", prepared.Fingerprint)
	}
	if _, err := composeddsa.PrepareKeystoreTemplateRegistration(keyType+"x", data); err != nil {
		r.add(name+" registration other key type", err)
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		r.add(name+" provider", err)
		return
	}
	r.add(name+" key type", provider.KeyType()+" "+provider.BaseKeyType()+" "+provider.RoutingFamily())
	r.add(name+" fingerprint", provider.CompatibilityFingerprint())
	r.add(name+" creation params", provider.CreationParams())
	r.add(name+" runtime args", provider.RuntimeArgs())
	r.add(name+" opcode profile", provider.LogicSigOpcodeProfile())
	r.add(name+" layer3", provider.Layer3PolicyName())
	r.add(name+" bounded profile", provider.BoundedAuthorizationProfile())
	r.add(name+" template metadata", provider.BoundedAuthorizationMetadata())
	layout, described := provider.SignatureArgLayout()
	r.add(name+" signature layout", fmt.Sprintf("%v %v", layout, described))
	publicKey := bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize)
	if spec.BaseKeyType == ed25519lsig.KeyTypeV1 {
		publicKey = bytes.Repeat([]byte{0x21}, 32)
	}
	values := characterizationValues(provider.CreationParams())
	r.addErr(name+" validate values", provider.ValidateCreationParams(values))
	prepared, err := provider.PrepareRekeyList(bytes.Repeat([]byte{0x77}, 64), values)
	if err != nil {
		r.add(name+" prepare rekey list", err)
		prepared = values
	} else {
		r.add(name+" prepare rekey list", prepared)
	}
	teal, err := provider.GenerateTEAL(publicKey, prepared)
	if err != nil {
		r.add(name+" teal", err)
	} else {
		r.add(name+" teal", teal)
	}
	provider.SetAlgodClient(client)
	bytecode, address, err := provider.DeriveLsig(context.Background(), publicKey, prepared)
	if err != nil {
		r.add(name+" derive", err)
	} else {
		r.add(name+" derive", fmt.Sprintf("%x %s", bytecode, address))
	}
	salted, err := provider.DeriveLsigWithSalt(context.Background(), publicKey, prepared)
	if err != nil {
		r.add(name+" derive with salt", err)
	} else {
		r.add(name+" derive with salt", fmt.Sprintf("%x %s %v", salted.Bytecode, salted.Address, salted.CompilerAutoSalted))
	}
	if _, err := provider.GenerateTEAL(publicKey[:len(publicKey)-1], prepared); err != nil {
		r.add(name+" teal short key", err)
	}
	if _, err := provider.GenerateTEAL(publicKey, map[string]string{}); err != nil {
		r.add(name+" teal no values", err)
	}
	if cosigner, ok := prepared[composeddsa.BoundedCosignerPublicKeyParameter]; ok {
		shared := map[string]string{}
		for k, v := range prepared {
			shared[k] = v
		}
		shared[composeddsa.BoundedCosignerPublicKeyParameter] = hex.EncodeToString(publicKey)
		_, err := provider.GenerateTEAL(publicKey, shared)
		r.add(name+" teal shared cosigner", err)
		_, err = provider.BuildBoundedAuthorizationMetadata(publicKey, shared, []byte("program"))
		r.add(name+" metadata shared cosigner", err)
		shared[composeddsa.BoundedCosignerPublicKeyParameter] = cosigner[:len(cosigner)-2]
		_, err = provider.BuildBoundedAuthorizationMetadata(publicKey, shared, []byte("program"))
		r.add(name+" metadata short cosigner", err)
	}
	metadata, err := provider.BuildBoundedAuthorizationMetadata(publicKey, prepared, []byte("program"))
	if err != nil {
		r.add(name+" metadata", err)
	} else {
		r.add(name+" metadata", metadata)
	}
	runtime := map[string][]byte{}
	for _, arg := range provider.RuntimeArgs() {
		runtime[arg.Name] = []byte("runtime-value")
	}
	if args, err := provider.BuildArgs(bytes.Repeat([]byte{0x5a}, 64), runtime); err != nil {
		r.add(name+" build args", err)
	} else {
		r.add(name+" build args", args)
	}
	if metadata != nil {
		declaration, err := metadata.Declaration()
		if err != nil {
			r.add(name+" declaration", err)
		} else {
			r.add(name+" declaration", declaration)
		}
		r.addErr(name+" metadata validate", metadata.Validate())
		unknown := boundedmeta.Clone(metadata)
		unknown.Rekey = "admin_key"
		r.addErr(name+" metadata unknown rekey", unknown.Validate())
	}
}

// TestComposedOutputIsUnchanged pins what the composer produces. See
// composedOutputDigest.
func TestComposedOutputIsUnchanged(t *testing.T) {
	falcon1024.RegisterClient()
	ed25519lsig.RegisterClient()
	r := &composedRecorder{}
	client, err := algod.MakeClientWithTransport("http://characterization-algod", "", nil, composedCompiler{})
	if err != nil {
		t.Fatal(err)
	}
	for _, set := range []map[string]string{characterizationTemplates(), refusedCharacterizationTemplates()} {
		names := make([]string, 0, len(set))
		for name := range set {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			characterizeComposedTemplate(r, client, name, set[name])
		}
	}
	for _, keyType := range []string{boundedmeta.DefaultCosignerComponentKeyType, "aplane.witness-ed25519.v1", "example.unknown.v1"} {
		r.add("cosigner parameter "+keyType, composeddsa.BoundedCosignerParameterDef(keyType))
	}
	joined := strings.Join(r.lines, "\n") + "\n"
	if path := os.Getenv(composedCharacterizationDumpEnv); path != "" {
		if err := os.WriteFile(path, []byte(joined), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256([]byte(joined))
	if got := hex.EncodeToString(sum[:]); got != composedOutputDigest {
		t.Fatalf("composed output digest = %s, want %s (set %s to a file path to dump the records)", got, composedOutputDigest, composedCharacterizationDumpEnv)
	}
}
