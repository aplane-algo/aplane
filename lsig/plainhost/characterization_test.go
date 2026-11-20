// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package plainhost_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/plainhost"
)

// plainHostOutputDigest is the digest of everything both plain hosts produce for
// every arrangement and shape, and for a set of refused requests: the resolved
// instances, the programs, the stored metadata and fingerprints, and the error
// text of each refusal. It pins the hosts' output across refactors; a change
// that moves it changes what an account is or what a user is told.
const plainHostOutputDigest = "c16e9caa0dc01ee808d481ba91b3ceecd510dfaaea3a69e1e16b923022f2a7ce"

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

// characterizeRequest records what one request produces on one host.
func characterizeRequest(c *characterization, b base, name string, params map[string]string) {
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
	}
}

// TestPlainHostOutputIsUnchanged pins everything the plain hosts produce. See
// plainHostOutputDigest.
func TestPlainHostOutputIsUnchanged(t *testing.T) {
	c := &characterization{}
	for _, b := range bases(t) {
		p := b.provider
		c.add(b.name+" key type", p.KeyType())
		c.add(b.name+" creation params", p.CreationParams())
		c.add(b.name+" runtime args", p.RuntimeArgs())
		c.add(b.name+" grammar fingerprint", p.GrammarFingerprint())
		fingerprint, ok := lsigprovider.CompatibilityFingerprintOf(p)
		c.add(b.name+" compatibility fingerprint", fmt.Sprintf("%s %v", fingerprint, ok))
		c.add(b.name+" opcode profile", p.BoundedLogicSigOpcodeProfile())
		characterizeRequest(c, b, b.name+" no parameters", nil)
		for _, arrangement := range plainhost.Arrangements() {
			name := fmt.Sprintf("%s arrangement rekey=%s cosigner=%s", b.name, arrangement.Rekey, arrangement.Cosigner)
			characterizeRequest(c, b, name, requestFor(arrangement))
		}
		for _, shape := range plainhost.Shapes() {
			for _, count := range []int{1, 3, 12} {
				if shape.AnyRecipient && count != 1 {
					continue
				}
				name := fmt.Sprintf("%s shape %s encoding=%s recipients=%d", b.name, shape.Descriptor(), shape.Encoding, count)
				characterizeRequest(c, b, name, shapeRequest(shape, testRecipients(count)))
			}
		}
		refused := refusedRequests()
		names := make([]string, 0, len(refused))
		for name := range refused {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			characterizeRequest(c, b, b.name+" request "+name, refused[name])
		}
	}
	if got := c.digest(t); got != plainHostOutputDigest {
		t.Fatalf("plain host output digest = %s, want %s (set %s to a file path to dump the records)", got, plainHostOutputDigest, characterizationDumpEnv)
	}
}
