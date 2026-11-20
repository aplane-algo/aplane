// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package plainhost_test

import (
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
	sdktypes "github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/plainhost"
)

// plainHostOutputDigest is the digest of everything both plain hosts produce for
// every arrangement and shape, with cosigner keys in digit-only, lower-case and
// upper-case hex, and for a set of refused requests: the resolved instances,
// the programs, the derived bytecode and addresses for a sample of requests,
// the stored metadata and fingerprints, and the error text of each refusal. It
// pins the hosts' output across refactors; a change that moves it changes what
// an account is or what a user is told.
const plainHostOutputDigest = "b0b0c90d64915f8dbba1af939ee05b21552f3e8987505f7930b694c9fd2cf20f"

// characterizationDumpEnv names a file the characterization test writes its
// records to, so two runs can be compared line by line.
const characterizationDumpEnv = "APLANE_PLAINHOST_CHARACTERIZATION_DUMP"

type characterization struct {
	lines []string
}

func (c *characterization) add(name string, value any) {
	var text string
	switch v := value.(type) {
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
	c.lines = append(c.lines, name+" = "+text)
}

func (c *characterization) digest(t *testing.T) string {
	t.Helper()
	joined := strings.Join(c.lines, "\n") + "\n"
	if path := os.Getenv(characterizationDumpEnv); path != "" {
		if err := os.WriteFile(path, []byte(joined), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256([]byte(joined))
	return hex.EncodeToString(sum[:])
}

// characterizationCompiler stands in for algod's compiler. The program it
// returns is the TEAL version 13 byte, the SHA-256 of the TEAL it is sent, and
// a final counter byte chosen to put the address off the curve; the hash it
// reports is that address. So a derived program and address pin the TEAL a
// derivation compiled, and what the derivation made of the reply.
type characterizationCompiler struct{}

func (characterizationCompiler) RoundTrip(req *http.Request) (*http.Response, error) {
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
		address := crypto.LogicSigAddress(sdktypes.LogicSig{Logic: program})
		if !lsigsalt.IsOnCurve(address) {
			return reply(http.StatusOK, `{"result":"`+base64.StdEncoding.EncodeToString(program)+`","hash":"`+address.String()+`"}`), nil
		}
	}
	return reply(http.StatusBadRequest, `{"message":"no off-curve counter"}`), nil
}

func characterizationAlgod(t *testing.T) *algod.Client {
	t.Helper()
	client, err := algod.MakeClientWithTransport("http://characterization-algod", "", nil, characterizationCompiler{})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// withHexCosigner replaces a request's cosigner key with one of the same size
// whose hex has the digits a-f, in upper case when upper is set.
func withHexCosigner(params map[string]string, upper bool) (map[string]string, bool) {
	key, ok := params[composeddsa.BoundedCosignerPublicKeyParameter]
	if !ok {
		return nil, false
	}
	out := make(map[string]string, len(params))
	for name, value := range params {
		out[name] = value
	}
	hexKey := strings.Repeat("a5", len(key)/4) + strings.Repeat("3c", len(key)/2-len(key)/4)
	if upper {
		hexKey = strings.ToUpper(hexKey)
	}
	out[composeddsa.BoundedCosignerPublicKeyParameter] = hexKey
	return out, true
}

// characterizeRequest records what one request produces on one host. With
// derive set it also derives the program through the stand-in compiler.
func characterizeRequest(c *characterization, b base, name string, params map[string]string, derive bool) {
	p := b.provider
	c.add(name+" validate", errText(p.ValidateCreationParams(params)))
	instance, err := p.ResolveInstance(params)
	if err != nil {
		c.add(name+" instance", err)
	} else {
		c.add(name+" instance", instance)
	}
	types, ok := p.CosignerComponentKeyTypes(params)
	c.add(name+" cosigner types", fmt.Sprintf("%v %v", types, ok))
	warnings, err := p.CreationWarnings(params)
	if err != nil {
		c.add(name+" warnings", err)
	} else {
		c.add(name+" warnings", warnings)
	}
	prepared, err := p.PrepareRekeyList(testListKey, params)
	if err != nil {
		c.add(name+" prepared", err)
		prepared = params
	} else {
		c.add(name+" prepared", prepared)
	}
	teal, err := p.GenerateTEAL(b.spendingKey, prepared)
	if err != nil {
		c.add(name+" teal", err)
	} else {
		c.add(name+" teal", teal)
	}
	if derive {
		bytecode, address, err := p.DeriveLsig(context.Background(), b.spendingKey, prepared)
		if err != nil {
			c.add(name+" derive", err)
		} else {
			c.add(name+" derive", fmt.Sprintf("%x %s", bytecode, address))
		}
		salted, err := p.DeriveLsigWithSalt(context.Background(), b.spendingKey, prepared)
		if err != nil {
			c.add(name+" derive with salt", err)
		} else {
			c.add(name+" derive with salt", fmt.Sprintf("%x %s %v", salted.Bytecode, salted.Address, salted.CompilerAutoSalted))
		}
	}
	metadata, err := p.BuildBoundedAuthorizationMetadata(b.spendingKey, prepared, []byte("characterization program"))
	if err != nil {
		c.add(name+" metadata", err)
		return
	}
	c.add(name+" metadata", metadata)
	stored, err := p.StoredFingerprint(prepared, metadata)
	if err != nil {
		c.add(name+" stored fingerprint", err)
	} else {
		c.add(name+" stored fingerprint", stored)
	}
	if metadata == nil {
		return
	}
	// A stored rekey setting the grammar does not know.
	unknown := boundedmeta.Clone(metadata)
	unknown.Rekey = "admin_key"
	if _, err := p.StoredFingerprint(prepared, unknown); err != nil {
		c.add(name+" stored unknown rekey", err)
	} else {
		c.add(name+" stored unknown rekey", "accepted")
	}
}

func errText(err error) string {
	if err == nil {
		return "ok"
	}
	return "error: " + err.Error()
}

// refusedRequests are requests each host refuses, for their error text.
func refusedRequests() map[string]map[string]string {
	inline := func(extra map[string]string) map[string]string {
		params := map[string]string{
			plainhost.ParameterSpendEffects:   "pay,axfer",
			plainhost.ParameterRekeyAuthority: plainhost.RekeySpendingKey,
			plainhost.ParameterListEncoding:   plainhost.EncodingInline,
			plainhost.ParameterRecipients:     testRecipients(3),
		}
		for name, value := range extra {
			if value == "" {
				delete(params, name)
				continue
			}
			params[name] = value
		}
		return params
	}
	return map[string]map[string]string{
		"unknown rekey":              {plainhost.ParameterRekeyAuthority: "admin_key"},
		"unknown parameter":          {plainhost.ParameterRekeyAuthority: plainhost.RekeyRefused, "unknown": "1"},
		"only these without a list":  {plainhost.ParameterRekeyAuthority: plainhost.RekeyOnlyThese},
		"list without only these":    {plainhost.ParameterRekeyAuthority: plainhost.RekeySpendingKey, plainhost.ParameterRekeyTo: testRekeyTo()},
		"cosigner 0x prefix":         {plainhost.ParameterRekeyAuthority: plainhost.RekeyRefused, composeddsa.BoundedCosignerPublicKeyParameter: "0x" + testCosigner},
		"cosigner 0X prefix":         {plainhost.ParameterRekeyAuthority: plainhost.RekeyRefused, composeddsa.BoundedCosignerPublicKeyParameter: "0X" + strings.ToUpper(testCosigner)},
		"cosigner short":             {plainhost.ParameterRekeyAuthority: plainhost.RekeyRefused, composeddsa.BoundedCosignerPublicKeyParameter: "4444"},
		"cosigner not hex":           {plainhost.ParameterRekeyAuthority: plainhost.RekeyRefused, composeddsa.BoundedCosignerPublicKeyParameter: "zz"},
		"cosigner unknown type":      {plainhost.ParameterRekeyAuthority: plainhost.RekeyRefused, composeddsa.BoundedCosignerPublicKeyParameter: testCosigner, boundedmeta.CosignerKeyTypeParameter: "example.unknown.v1"},
		"cosigner type without key":  {plainhost.ParameterRekeyAuthority: plainhost.RekeyRefused, boundedmeta.CosignerKeyTypeParameter: falconCosigner},
		"cosigner is spending key":   {plainhost.ParameterRekeyAuthority: plainhost.RekeyRefused, composeddsa.BoundedCosignerPublicKeyParameter: strings.Repeat("22", boundedmeta.DefaultCosignerPublicKeySize)},
		"bounds without spend":       inline(map[string]string{plainhost.ParameterSpendEffects: ""}),
		"bounds repeated spend":      inline(map[string]string{plainhost.ParameterSpendEffects: "pay,pay"}),
		"bounds unknown spend":       inline(map[string]string{plainhost.ParameterSpendEffects: "keyreg"}),
		"bounds empty recipients":    inline(map[string]string{plainhost.ParameterRecipients: ""}),
		"bounds bad recipient":       inline(map[string]string{plainhost.ParameterRecipients: "nope"}),
		"bounds unknown encoding":    inline(map[string]string{plainhost.ParameterListEncoding: "zip"}),
		"bounds any with recipients": inline(map[string]string{plainhost.ParameterRecipientScope: plainhost.RecipientScopeAny}),
		"bounds bad scope":           inline(map[string]string{plainhost.ParameterRecipientScope: "some"}),
		"bounds bad max fee":         inline(map[string]string{plainhost.ParameterMaxFee: "abc"}),
		"bounds custom max fee":      inline(map[string]string{plainhost.ParameterMaxFee: "2500"}),
		"bounds zero max fee":        inline(map[string]string{plainhost.ParameterMaxFee: "0"}),
		"bounds merkle":              inline(map[string]string{plainhost.ParameterListEncoding: plainhost.EncodingMerkle}),
		"bounds auto":                inline(map[string]string{plainhost.ParameterListEncoding: plainhost.EncodingAuto}),
		"bounds only these no list":  inline(map[string]string{plainhost.ParameterRekeyAuthority: plainhost.RekeyOnlyThese}),
		"bounds 0x cosigner":         inline(map[string]string{composeddsa.BoundedCosignerPublicKeyParameter: "0x" + testCosigner}),
		"empty value":                {plainhost.ParameterRekeyAuthority: plainhost.RekeyRefused, composeddsa.BoundedCosignerPublicKeyParameter: " "},
		"only an unknown parameter":  {"unknown": "1"},
	}
}

// TestPlainHostOutputIsUnchanged pins everything the plain hosts produce. See
// plainHostOutputDigest.
func TestPlainHostOutputIsUnchanged(t *testing.T) {
	c := &characterization{}
	client := characterizationAlgod(t)
	for _, b := range bases(t) {
		p := b.provider
		p.SetAlgodClient(client)
		c.add(b.name+" key type", p.KeyType())
		c.add(b.name+" creation params", p.CreationParams())
		c.add(b.name+" runtime args", p.RuntimeArgs())
		c.add(b.name+" grammar fingerprint", p.GrammarFingerprint())
		fingerprint, ok := lsigprovider.CompatibilityFingerprintOf(p)
		c.add(b.name+" compatibility fingerprint", fmt.Sprintf("%s %v", fingerprint, ok))
		c.add(b.name+" opcode profile", p.BoundedLogicSigOpcodeProfile())
		characterizeRequest(c, b, b.name+" no parameters", nil, true)
		characterizeRequest(c, b, b.name+" empty parameters", map[string]string{}, true)
		for _, arrangement := range plainhost.Arrangements() {
			name := fmt.Sprintf("%s arrangement rekey=%s cosigner=%s", b.name, arrangement.Rekey, arrangement.Cosigner)
			request := requestFor(arrangement)
			characterizeRequest(c, b, name, request, true)
			for _, upper := range []bool{false, true} {
				if hexed, ok := withHexCosigner(request, upper); ok {
					characterizeRequest(c, b, fmt.Sprintf("%s hex cosigner upper=%v", name, upper), hexed, true)
				}
			}
		}
		for i, shape := range plainhost.Shapes() {
			for _, count := range []int{1, 3, 12} {
				if shape.AnyRecipient && count != 1 {
					continue
				}
				name := fmt.Sprintf("%s shape %s encoding=%s recipients=%d", b.name, shape.Descriptor(), shape.Encoding, count)
				request := shapeRequest(shape, testRecipients(count))
				// Derive a few shapes of each kind.
				derive := count != 12 && i%9 == 0
				characterizeRequest(c, b, name, request, derive)
				if count == 3 || shape.AnyRecipient {
					for _, upper := range []bool{false, true} {
						if hexed, ok := withHexCosigner(request, upper); ok {
							characterizeRequest(c, b, fmt.Sprintf("%s hex cosigner upper=%v", name, upper), hexed, derive)
						}
					}
				}
			}
		}
		refused := refusedRequests()
		names := make([]string, 0, len(refused))
		for name := range refused {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			characterizeRequest(c, b, b.name+" request "+name, refused[name], true)
		}
	}
	if got := c.digest(t); got != plainHostOutputDigest {
		t.Fatalf("plain host output digest = %s, want %s (set %s to a file path to dump the records)", got, plainHostOutputDigest, characterizationDumpEnv)
	}
}
