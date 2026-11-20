// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/lsigsalt/lsigsalttest"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
)

// testOps is a stub verifier. Its construction is the zero value unless a test
// registers it under a catalog base name, which must name the same construction.
type testOps struct{ construction sigconstruction.Construction }

func (o testOps) Construction() sigconstruction.Construction { return o.construction }
func (testOps) PublicKeySize() int                           { return 1 }
func (testOps) CryptoSignatureSize() int                     { return 1 }
func (testOps) MnemonicScheme() string                       { return "" }
func (testOps) MnemonicWordCount() int                       { return 0 }
func (testOps) DisplayColor() string                         { return "" }
func (testOps) TEALVersion() int                             { return 12 }
func (testOps) BuildSignatureArgs([]byte) ([][]byte, error)  { return nil, nil }
func (testOps) BuildVerifyTEAL([]byte) (string, error)       { return "int 1\nreturn\n", nil }

type autoSaltTestOps struct{ testOps }

func (autoSaltTestOps) TEALVersion() int { return 13 }

// suffixTestOps stands in for the Falcon base, as boundedTestOps does.
type suffixTestOps struct{}

func (suffixTestOps) Construction() sigconstruction.Construction { return sigconstruction.Falcon1024() }

func (suffixTestOps) PublicKeySize() int                              { return 1 }
func (suffixTestOps) CryptoSignatureSize() int                        { return 1 }
func (suffixTestOps) MnemonicScheme() string                          { return "" }
func (suffixTestOps) MnemonicWordCount() int                          { return 0 }
func (suffixTestOps) DisplayColor() string                            { return "" }
func (suffixTestOps) TEALVersion() int                                { return 12 }
func (suffixTestOps) BuildSignatureArgs(sig []byte) ([][]byte, error) { return [][]byte{sig}, nil }
func (suffixTestOps) BuildVerifyTEAL([]byte) (string, error)          { return "test_verify\n", nil }

type noLayoutV13Ops struct{ suffixTestOps }

func (noLayoutV13Ops) TEALVersion() int { return 13 }

type falconBoundaryTestOps struct{}

func (falconBoundaryTestOps) Construction() sigconstruction.Construction {
	return sigconstruction.Falcon1024()
}

func (falconBoundaryTestOps) PublicKeySize() int       { return 4 }
func (falconBoundaryTestOps) CryptoSignatureSize() int { return 4 }
func (falconBoundaryTestOps) MnemonicScheme() string   { return "" }
func (falconBoundaryTestOps) MnemonicWordCount() int   { return 0 }
func (falconBoundaryTestOps) DisplayColor() string     { return "" }
func (falconBoundaryTestOps) TEALVersion() int         { return 13 }
func (falconBoundaryTestOps) BuildSignatureArgs(sig []byte) ([][]byte, error) {
	return [][]byte{sig}, nil
}
func (falconBoundaryTestOps) BuildVerifyTEAL([]byte) (string, error) {
	return "txn TxID\narg 0\npushbytes 0x01020304\nfalcon_verify\n", nil
}
func (falconBoundaryTestOps) SignatureArgLayout() SignatureArgLayout {
	return SignatureArgLayout{Count: 1, MaxSizes: []int{4}}
}

type compileMockTransport struct {
	bytecode []byte
	hash     string
}

func (m compileMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost || req.URL.Path != "/v2/teal/compile" {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"message":"unexpected request"}`)),
			Request:    req,
		}, nil
	}
	if _, err := io.ReadAll(req.Body); err != nil {
		return nil, err
	}
	hash := m.hash
	if hash == "" {
		hash = "unused"
	}
	body := `{"result":"` + base64.StdEncoding.EncodeToString(m.bytecode) + `","hash":"` + hash + `"}`
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

type countingCompileTransport struct {
	calls int
}

func (m *countingCompileTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	m.calls++
	return &http.Response{
		StatusCode: http.StatusInternalServerError,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"message":"compile should not be called"}`)),
		Request:    req,
	}, nil
}

func TestComposedDSADeriveLsigUsesCallerContext(t *testing.T) {
	dsa := NewComposedDSA(Config{
		KeyType:     "test-v1",
		FamilyName:  "test",
		Version:     1,
		DisplayName: "Test",
		Ops:         testOps{},
		SaltStyle:   lsigsalt.StyleNone,
	})
	client, err := algod.MakeClient("http://127.0.0.1:1", "")
	if err != nil {
		t.Fatalf("MakeClient() error = %v", err)
	}
	dsa.SetAlgodClient(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err = dsa.DeriveLsig(ctx, []byte{1}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("DeriveLsig() error = %v, want context canceled", err)
	}
}

func TestComposedDSADeriveUsesAlgodV13AutoSalt(t *testing.T) {
	dsa := NewComposedDSA(Config{
		KeyType:     "test-auto-v1",
		FamilyName:  "test",
		Version:     1,
		DisplayName: "Test Auto",
		Ops:         autoSaltTestOps{},
		SaltStyle:   lsigsalt.StyleAlgodAutoSalt,
	})
	want := lsigsalttest.OffCurve(t, []byte{13, 0x81, 0}, 2)
	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, compileMockTransport{
		bytecode: want.Bytecode,
		hash:     want.Address.String(),
	})
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}
	dsa.SetAlgodClient(client)

	got, err := dsa.DeriveLsigWithSalt(context.Background(), []byte{1}, nil)
	if err != nil {
		t.Fatalf("DeriveLsigWithSalt() error = %v", err)
	}
	if !got.CompilerAutoSalted || got.Address != want.Address || !bytes.Equal(got.Bytecode, want.Bytecode) {
		t.Fatalf("DeriveLsigWithSalt() = %+v, want compiler-owned result", got)
	}
	teal, err := dsa.GenerateTEAL([]byte{1}, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	if strings.Contains(teal, "Counter byte") || strings.Contains(teal, "bytecblock 0x00") || !strings.Contains(teal, "#pragma version 13") {
		t.Fatalf("auto-salted source contains manual salt anchor or wrong version:\n%s", teal)
	}
}

func TestComposedDSAAutoSaltRejectsPreV13Ops(t *testing.T) {
	dsa := NewComposedDSA(Config{KeyType: "test-auto-v1", FamilyName: "test", Ops: testOps{}, SaltStyle: lsigsalt.StyleAlgodAutoSalt})
	if _, err := dsa.GenerateTEAL([]byte{1}, nil); err == nil || !strings.Contains(err.Error(), "requires TEAL v13+") {
		t.Fatalf("GenerateTEAL() error = %v, want TEAL version rejection", err)
	}
}

func TestComposedDSAExplicitNoSaltStyleUsesUnmodifiedBytecode(t *testing.T) {
	dsa := NewComposedDSA(Config{
		KeyType:      "test-unsalted-v1",
		FamilyName:   "test-unsalted",
		Version:      1,
		DisplayName:  "Test Unsalted",
		Ops:          suffixTestOps{},
		TemplateMode: "generated",
		TEALSuffix:   "int 1\nassert",
		SaltStyle:    lsigsalt.StyleNone,
	})
	compiled := lsigsalttest.OffCurve(t, []byte{0x0c, 0x81, 0x00}, 2).Bytecode
	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, compileMockTransport{bytecode: compiled})
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}
	dsa.SetAlgodClient(client)

	teal, err := dsa.GenerateTEAL([]byte{1}, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	if strings.Contains(teal, "APLANE_LSIG_SALT") || strings.Contains(teal, "bytecblock 0x00") {
		t.Fatalf("unsalted TEAL should not include a generated salt anchor:\n%s", teal)
	}

	want, err := lsigsalt.UseUnmodifiedOffCurve(compiled)
	if err != nil {
		t.Fatalf("UseUnmodifiedOffCurve() error = %v", err)
	}
	got, err := dsa.DeriveLsigWithSalt(context.Background(), []byte{1}, nil)
	if err != nil {
		t.Fatalf("DeriveLsigWithSalt() error = %v", err)
	}
	if got.Address != want.Address || string(got.Bytecode) != string(want.Bytecode) {
		t.Fatalf("DeriveLsigWithSalt() = %+v, want %+v", got, want)
	}
}

// Creating an account refuses a compiled program whose address is on the curve,
// in either salt style: an unsalted program as compiled, and an auto-salted one
// even when the compiler reports that address.
func TestComposedDSARefusesOnCurveCompileReply(t *testing.T) {
	for _, test := range []struct {
		style lsigsalt.Style
		ops   DSAOps
	}{
		{style: lsigsalt.StyleNone, ops: testOps{}},
		{style: lsigsalt.StyleAlgodAutoSalt, ops: autoSaltTestOps{}},
	} {
		t.Run(string(test.style), func(t *testing.T) {
			dsa := NewComposedDSA(Config{KeyType: "test-on-curve-v1", FamilyName: "test", Version: 1, Ops: test.ops, SaltStyle: test.style})
			program, address := lsigsalttest.OnCurve(t, []byte{byte(test.ops.TEALVersion()), 0x81, 0}, 2)
			client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, compileMockTransport{bytecode: program, hash: address.String()})
			if err != nil {
				t.Fatalf("MakeClientWithTransport() error = %v", err)
			}
			dsa.SetAlgodClient(client)
			if _, err := dsa.DeriveLsigWithSalt(context.Background(), []byte{1}, nil); !errors.Is(err, lsigsalt.ErrUnsaltedAddressOnCurve) {
				t.Fatalf("DeriveLsigWithSalt() error = %v, want %v", err, lsigsalt.ErrUnsaltedAddressOnCurve)
			}
			if _, _, err := dsa.DeriveLsig(context.Background(), []byte{1}, nil); !errors.Is(err, lsigsalt.ErrUnsaltedAddressOnCurve) {
				t.Fatalf("DeriveLsig() error = %v, want %v", err, lsigsalt.ErrUnsaltedAddressOnCurve)
			}
		})
	}
}

// A composer derives with algod's TEAL v13 auto-salt or with no salt. Any other
// style, an absent one included, is refused before anything is compiled.
func TestComposedDSARefusesOtherSaltStyles(t *testing.T) {
	for _, style := range []lsigsalt.Style{"", "pushbytes"} {
		t.Run(string(style), func(t *testing.T) {
			dsa := NewComposedDSA(Config{
				KeyType:      "bad-salt-style-v1",
				FamilyName:   "bad-salt-style",
				Version:      1,
				DisplayName:  "Bad Salt Style",
				Ops:          testOps{},
				TemplateMode: "generated",
				TEALSuffix:   "int 1\nassert",
				SaltStyle:    style,
			})
			want := `composed DSA salt style "` + string(style) + `" is not "none" or "algod_v13_auto_salt"`
			if _, err := dsa.GenerateTEAL([]byte{1}, nil); err == nil || err.Error() != want {
				t.Fatalf("GenerateTEAL() error = %v, want %q", err, want)
			}

			transport := &countingCompileTransport{}
			client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, transport)
			if err != nil {
				t.Fatalf("MakeClientWithTransport() error = %v", err)
			}
			dsa.SetAlgodClient(client)
			if _, err := dsa.DeriveLsigWithSalt(context.Background(), []byte{1}, nil); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("DeriveLsigWithSalt() error = %v, want %q", err, want)
			}
			if transport.calls != 0 {
				t.Fatalf("DeriveLsigWithSalt() made %d compile calls, want 0", transport.calls)
			}
		})
	}
}

func TestComposedDSAGenerateTEALExpandsAddressListSuffix(t *testing.T) {
	dsa := addressListProvider()

	teal, err := dsa.GenerateTEAL([]byte{1}, map[string]string{
		"recipients": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ, AEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEA5RCDXMI",
	})
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}

	if !strings.Contains(teal, "byte 0x0000000000000000000000000000000000000000000000000000000000000000") {
		t.Fatalf("GenerateTEAL() missing first expanded address bytes:\n%s", teal)
	}
	if !strings.Contains(teal, "byte 0x0101010101010101010101010101010101010101010101010101010101010101") {
		t.Fatalf("GenerateTEAL() missing second expanded address bytes:\n%s", teal)
	}
	if strings.Index(teal, "test_verify") > strings.Index(teal, "txn Receiver") {
		t.Fatalf("GenerateTEAL() should place DSA verification before suffix checks:\n%s", teal)
	}
	if !strings.HasSuffix(strings.TrimSpace(teal), "int 1\nreturn") {
		t.Fatalf("GenerateTEAL() should end with composer return:\n%s", teal)
	}
}

func TestComposedDSAGenerateTEALCanonicalizesAddressListSuffix(t *testing.T) {
	dsa := addressListProvider()
	addrA := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	addrB := "AEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEA5RCDXMI"

	first, err := dsa.GenerateTEAL([]byte{1}, map[string]string{"recipients": addrA + "," + addrB})
	if err != nil {
		t.Fatalf("GenerateTEAL(first) error = %v", err)
	}
	second, err := dsa.GenerateTEAL([]byte{1}, map[string]string{"recipients": addrB + "," + addrA})
	if err != nil {
		t.Fatalf("GenerateTEAL(second) error = %v", err)
	}

	if first != second {
		t.Fatalf("GenerateTEAL differs for reordered address list:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func TestComposedDSAGenerateTEALRejectsReturnInSuffix(t *testing.T) {
	dsa := NewComposedDSA(Config{
		KeyType:      "bad-suffix-v1",
		FamilyName:   "bad-suffix",
		Version:      1,
		DisplayName:  "Bad Suffix",
		Ops:          suffixTestOps{},
		SaltStyle:    lsigsalt.StyleNone,
		TemplateMode: "generated",
		TEALSuffix:   "int 1\nreturn\n",
		Params: []lsigprovider.ParameterDef{{
			Name:     "recipients",
			Type:     "address[]",
			Required: true,
			MinItems: 1,
			MaxItems: 3,
		}},
	})

	_, err := dsa.GenerateTEAL([]byte{1}, map[string]string{
		"recipients": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
	})
	if err == nil {
		t.Fatal("GenerateTEAL() error = nil, want composed suffix return rejection")
	}
	if !strings.Contains(err.Error(), "must not contain return") {
		t.Fatalf("GenerateTEAL() error = %v, want return rejection", err)
	}
}

// TestComposerVerifierAssertsBeforeUserSuffix locks in the structural
// invariant the composed templates rely on for rekey/close binding: the
// base provider's verifier TEAL must run, an `assert` must follow it, and
// only then may the user suffix execute. Composed templates such as the
// bundled Falcon timelock
// intentionally omit explicit `txn RekeyTo == ZeroAddress` guards in
// their suffix because the base signature-over-txid binding already
// covers them — but only if the wrap order here is preserved. If a
// future refactor moves the user suffix above the verifier or skips the
// `assert`, this test fails before any silent rekey-guard regression can
// ship.
func TestComposerVerifierAssertsBeforeUserSuffix(t *testing.T) {
	const (
		verifierMarker = "// VERIFIER_SENTINEL_d7f9e0\n"
		suffixMarker   = "// SUFFIX_SENTINEL_a3b4c5\n"
	)

	dsa := NewComposedDSA(Config{
		KeyType:      "test-wrap-invariant-v1",
		FamilyName:   "test-wrap-invariant",
		Version:      1,
		DisplayName:  "Test Wrap Invariant",
		Ops:          markerVerifierOps{verifyTEAL: verifierMarker + "int 1\n"},
		SaltStyle:    lsigsalt.StyleNone,
		TemplateMode: "generated",
		TEALSuffix:   suffixMarker + "int 1\n",
	})

	teal, err := dsa.GenerateTEAL([]byte{1}, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}

	verifyIdx := strings.Index(teal, verifierMarker)
	if verifyIdx < 0 {
		t.Fatalf("verifier marker not found in produced TEAL:\n%s", teal)
	}
	suffixIdx := strings.Index(teal, suffixMarker)
	if suffixIdx < 0 {
		t.Fatalf("user suffix marker not found in produced TEAL:\n%s", teal)
	}

	if verifyIdx >= suffixIdx {
		t.Fatalf("verifier output must precede user suffix; got verify@%d suffix@%d:\n%s",
			verifyIdx, suffixIdx, teal)
	}

	between := teal[verifyIdx+len(verifierMarker) : suffixIdx]
	if !strings.Contains(between, "assert") {
		t.Fatalf("expected `assert` between verifier output and user suffix; got:\n%q\nfull TEAL:\n%s",
			between, teal)
	}
}

// markerVerifierOps emits a configurable, marker-bearing verifier TEAL so
// composer-output ordering tests can locate it deterministically.
type markerVerifierOps struct {
	verifyTEAL string
}

func (markerVerifierOps) Construction() sigconstruction.Construction {
	return sigconstruction.Falcon1024()
}

func (markerVerifierOps) PublicKeySize() int                          { return 1 }
func (markerVerifierOps) CryptoSignatureSize() int                    { return 1 }
func (markerVerifierOps) MnemonicScheme() string                      { return "" }
func (markerVerifierOps) MnemonicWordCount() int                      { return 0 }
func (markerVerifierOps) DisplayColor() string                        { return "" }
func (markerVerifierOps) TEALVersion() int                            { return 12 }
func (markerVerifierOps) BuildSignatureArgs([]byte) ([][]byte, error) { return nil, nil }
func (o markerVerifierOps) BuildVerifyTEAL([]byte) (string, error)    { return o.verifyTEAL, nil }

func TestFalconAllowlistTemplateUsesBoundedFixedAllowlist(t *testing.T) {
	registerBaseForTest(t, BaseRegistration{
		BaseKeyType: "aplane.falcon1024.v1", FamilyName: "falcon1024", Version: 1,
		Ops: falconBoundaryTestOps{},
	})
	spec, err := ParseTemplateSpec([]byte(FixedAllowlistFixtureYAML))
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}

	if spec.SchemaVersion != 2 || spec.Bounded == nil || spec.Bounded.Layer3 == nil {
		t.Fatalf("falcon allowlist bounded profile = %#v", spec.Bounded)
	}
	if spec.TEAL != "" {
		t.Fatalf("framework-owned allowlist declares custom TEAL:\n%s", spec.TEAL)
	}
	provider, err := NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("NewProviderFromTemplateSpec() error = %v", err)
	}
	teal, err := provider.GenerateTEAL(make([]byte, provider.ops.PublicKeySize()), map[string]string{
		"recipients": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
	})
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	normalized := strings.Join(strings.Fields(teal), " ")
	for _, want := range []string{
		"txn Fee pushint 10000 <= assert",
		"txn CloseRemainderTo global ZeroAddress == assert",
		"txn AssetCloseTo global ZeroAddress == assert",
		"txn AssetSender global ZeroAddress == assert",
		"txn Receiver callsub __aplane_bounded1_layer3_recipient_allowed assert",
		"txn AssetReceiver callsub __aplane_bounded1_layer3_recipient_allowed assert",
		"txn Amount pushint 0 == assert txn Receiver txn Sender == assert",
	} {
		if !strings.Contains(normalized, want) {
			t.Fatalf("falcon allowlist program missing normalized sequence %q:\n%s", want, teal)
		}
	}
	if strings.Contains(normalized, "int keyreg") || strings.Contains(normalized, "txn AssetCloseTo txn AssetReceiver") {
		t.Fatalf("falcon allowlist program retained an unbounded effect path:\n%s", teal)
	}
}

func TestFalconMerkleAllowlistTemplateRootProofContract(t *testing.T) {
	registerBaseForTest(t, BaseRegistration{
		BaseKeyType: "aplane.falcon1024.v1",
		FamilyName:  "falcon1024",
		Version:     1,
		Ops:         falconBoundaryTestOps{},
	})

	spec, err := ParseTemplateSpec([]byte(MerkleAllowlistFixtureYAML))
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	if spec.TemplateMode != "strict" {
		t.Fatalf("TemplateMode = %q, want strict", spec.TemplateMode)
	}
	if spec.SchemaVersion != 2 || spec.Bounded == nil || len(spec.Bounded.DerivedArgs) != 1 || spec.Bounded.DerivedArgs[0].Kind != "merkle_allowlist_proof" {
		t.Fatalf("bounded Merkle profile = %#v", spec.Bounded)
	}
	if len(spec.TemplateVariables) != 1 || spec.TemplateVariables[0].Name != "root" {
		t.Fatalf("TemplateVariables = %#v, want root variable", spec.TemplateVariables)
	}
	if len(spec.Parameters) != 1 || spec.Parameters[0].Name != "recipients" ||
		spec.Parameters[0].Type != "address[]" {
		t.Fatalf("Parameters = %#v, want recipients address[] parameter", spec.Parameters)
	}
	if len(spec.RuntimeArgs) != 0 {
		t.Fatalf("RuntimeArgs = %#v, want no caller-supplied runtime args", spec.RuntimeArgs)
	}

	accounts := []string{
		algocrypto.GenerateAccount().Address.String(),
		algocrypto.GenerateAccount().Address.String(),
		algocrypto.GenerateAccount().Address.String(),
	}
	outside := algocrypto.GenerateAccount().Address.String()
	root, proofs := merkleAllowlistRootAndProofsForTest(t, accounts)

	for _, addr := range accounts {
		if got := len(proofs[addr]); got != 512 {
			t.Fatalf("proof length for %s = %d, want 512", addr, got)
		}
		if !verifyMerkleAllowlistProofForTest(t, addr, proofs[addr], root) {
			t.Fatalf("proof for allowlisted address %s did not verify", addr)
		}
	}
	if verifyMerkleAllowlistProofForTest(t, outside, proofs[accounts[0]], root) {
		t.Fatalf("proof for %s verified for outsider %s", accounts[0], outside)
	}
	corrupt := append([]byte(nil), proofs[accounts[0]]...)
	corrupt[17] ^= 0xff
	if verifyMerkleAllowlistProofForTest(t, accounts[0], corrupt, root) {
		t.Fatalf("corrupted proof for %s verified", accounts[0])
	}

	provider, err := NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("NewProviderFromTemplateSpec() error = %v", err)
	}
	teal, err := provider.GenerateTEAL([]byte{0, 1, 2, 3}, map[string]string{
		"recipients": strings.Join(accounts, ","),
	})
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}

	for _, want := range []string{
		"// Template constants\nbytecblock 0x" + hex.EncodeToString(root),
		"txn CloseRemainderTo\nglobal ZeroAddress\n==\nassert",
		"txn AssetCloseTo\nglobal ZeroAddress\n==\nassert",
		"txn AssetSender\nglobal ZeroAddress\n==\nassert",
		"arg 1\nlen\nint 512\n==\nassert",
		"pushbytes 0x00\nswap\nconcat\nsha256",
		"pushbytes 0x01\nswap\nconcat\nsha256",
		"txn Receiver\ncallsub verify_member\nassert",
		"txn AssetReceiver\ncallsub verify_member\nassert",
	} {
		if !strings.Contains(teal, want) {
			t.Fatalf("rendered Merkle allowlist TEAL missing %q:\n%s", want, teal)
		}
	}
	if got := strings.Count(teal, "extract3"); got != 16 {
		t.Fatalf("rendered Merkle allowlist extract3 count = %d, want 16:\n%s", got, teal)
	}
	if got := strings.Count(teal, "callsub combine"); got != 16 {
		t.Fatalf("rendered Merkle allowlist combine count = %d, want 16:\n%s", got, teal)
	}
	for _, forbidden := range []string{"txn CloseRemainderTo\ntxn Receiver", "txn AssetCloseTo\ntxn AssetReceiver"} {
		if strings.Contains(teal, forbidden) {
			t.Fatalf("bounded Merkle allowlist retained close-out path %q:\n%s", forbidden, teal)
		}
	}
}

func TestFalconAllowlistTemplateRendersMaxRecipientsWithinComposerBoundary(t *testing.T) {
	registerBaseForTest(t, BaseRegistration{
		BaseKeyType: "aplane.falcon1024.v1",
		FamilyName:  "falcon1024",
		Version:     1,
		Ops:         falconBoundaryTestOps{},
	})

	spec, err := ParseTemplateSpec([]byte(FixedAllowlistFixtureYAML))
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	provider, err := NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("NewProviderFromTemplateSpec() error = %v", err)
	}

	maxRecipients := spec.Parameters[0].MaxItems
	if maxRecipients <= 0 {
		t.Fatalf("falcon allowlist max_items = %d, want positive limit", maxRecipients)
	}
	recipients := make([]string, maxRecipients)
	for i := range recipients {
		account := algocrypto.GenerateAccount()
		recipients[i] = account.Address.String()
	}
	publicKey := make([]byte, provider.ops.PublicKeySize())
	for i := range publicKey {
		publicKey[i] = byte(i % 251)
	}

	teal, err := provider.GenerateTEAL(publicKey, map[string]string{
		"recipients": strings.Join(recipients, ","),
	})
	if err != nil {
		t.Fatalf("GenerateTEAL(max recipients) error = %v", err)
	}

	verifyIdx := strings.Index(teal, "falcon_verify")
	assertIdx := strings.Index(teal, "falcon_verify\nassert")
	suffixIdx := strings.Index(teal, "framework-owned fixed allowlist")
	endIdx := strings.Index(teal, "__aplane_bounded1_layer3_done:")
	finalReturn := strings.LastIndex(teal, "pushint 1\nreturn")
	switch {
	case verifyIdx < 0:
		t.Fatalf("rendered TEAL missing Falcon verification:\n%s", teal)
	case assertIdx < 0:
		t.Fatalf("rendered TEAL must assert Falcon verification before suffix:\n%s", teal)
	case suffixIdx < assertIdx:
		t.Fatalf("rendered TEAL placed suffix before verifier assert:\n%s", teal)
	case endIdx < suffixIdx:
		t.Fatalf("rendered TEAL missing end_checks after suffix:\n%s", teal)
	case finalReturn < endIdx:
		t.Fatalf("rendered TEAL must fall through from end_checks to composer return:\n%s", teal)
	}
	if strings.Count(teal, "pushbytes 0x") != len(recipients)+1 {
		t.Fatalf("rendered TEAL did not expand all recipients as byte literals:\n%s", teal)
	}
	if strings.Contains(teal, "addr 0x") || strings.Contains(teal, "{{.") {
		t.Fatalf("rendered TEAL contains invalid address-list substitution:\n%s", teal)
	}

	lines := strings.Count(teal, "\n")
	if lines > 1200 {
		t.Fatalf("rendered TEAL line count = %d, want <= 1200", lines)
	}
	if len(teal) > 120_000 {
		t.Fatalf("rendered TEAL length = %d, want <= 120000", len(teal))
	}

	_, err = provider.GenerateTEAL(publicKey, map[string]string{
		"recipients": strings.Join(append(recipients, algocrypto.GenerateAccount().Address.String()), ","),
	})
	if err == nil {
		t.Fatalf("GenerateTEAL(%d recipients) error = nil, want max_items rejection", len(recipients)+1)
	}
	if !strings.Contains(err.Error(), "at most "+strconv.Itoa(maxRecipients)) {
		t.Fatalf("GenerateTEAL(%d recipients) error = %v, want max_items rejection", len(recipients)+1, err)
	}
}

func addressListProvider() *ComposedDSA {
	return NewComposedDSA(Config{
		KeyType:      "address-list-v1",
		FamilyName:   "address-list",
		Version:      1,
		DisplayName:  "Address List",
		Ops:          suffixTestOps{},
		SaltStyle:    lsigsalt.StyleNone,
		TemplateMode: "generated",
		TEALSuffix: `txn Receiver
callsub is_allowlisted
assert

is_allowlisted:
    {{range @recipients}}
    dup
    byte {{.}}
    ==
    bnz allowlisted
    {{end}}
    pop
    int 0
    retsub

allowlisted:
    pop
    int 1
    retsub
`,
		Params: []lsigprovider.ParameterDef{{
			Name:     "recipients",
			Type:     "address[]",
			Required: true,
			MinItems: 1,
			MaxItems: 3,
		}},
	})
}

const merkleAllowlistDepthForTest = 16

func merkleAllowlistRootAndProofsForTest(t *testing.T, addresses []string) ([]byte, map[string][]byte) {
	t.Helper()
	if len(addresses) > 1<<merkleAllowlistDepthForTest {
		t.Fatalf("too many addresses: %d", len(addresses))
	}

	type entry struct {
		address string
		pubkey  [32]byte
		leaf    []byte
	}

	entries := make([]entry, 0, len(addresses))
	seen := make(map[[32]byte]struct{}, len(addresses))
	for _, address := range addresses {
		pubkey := decodeAddressPubkeyForTest(t, address)
		if _, ok := seen[pubkey]; ok {
			t.Fatalf("duplicate allowlist address public key: %s", address)
		}
		seen[pubkey] = struct{}{}
		entries = append(entries, entry{
			address: address,
			pubkey:  pubkey,
			leaf:    merkleAllowlistLeafForTest(pubkey),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].pubkey[:], entries[j].pubkey[:]) < 0
	})

	leafCount := 1 << merkleAllowlistDepthForTest
	emptyLeaf := merkleAllowlistEmptyLeafForTest()
	level := make([][]byte, leafCount)
	for i := range level {
		level[i] = emptyLeaf
	}
	indices := make(map[string]int, len(entries))
	proofParts := make(map[string][][]byte, len(entries))
	for i, entry := range entries {
		level[i] = entry.leaf
		indices[entry.address] = i
	}

	for depth := 0; depth < merkleAllowlistDepthForTest; depth++ {
		for address, index := range indices {
			proofParts[address] = append(proofParts[address], level[index^1])
			indices[address] = index / 2
		}

		next := make([][]byte, len(level)/2)
		for i := range next {
			next[i] = merkleAllowlistNodeForTest(level[i*2], level[i*2+1])
		}
		level = next
	}
	if len(level) != 1 {
		t.Fatalf("root level length = %d, want 1", len(level))
	}

	proofs := make(map[string][]byte, len(proofParts))
	for address, parts := range proofParts {
		proof := make([]byte, 0, merkleAllowlistDepthForTest*32)
		for _, part := range parts {
			proof = append(proof, part...)
		}
		proofs[address] = proof
	}
	return level[0], proofs
}

func verifyMerkleAllowlistProofForTest(t *testing.T, address string, proof, root []byte) bool {
	t.Helper()
	if len(root) != 32 || len(proof) != merkleAllowlistDepthForTest*32 {
		return false
	}
	pubkey := decodeAddressPubkeyForTest(t, address)
	hash := merkleAllowlistLeafForTest(pubkey)
	for offset := 0; offset < len(proof); offset += 32 {
		hash = merkleAllowlistNodeForTest(hash, proof[offset:offset+32])
	}
	return bytes.Equal(hash, root)
}

func decodeAddressPubkeyForTest(t *testing.T, address string) [32]byte {
	t.Helper()
	decoded, err := types.DecodeAddress(address)
	if err != nil {
		t.Fatalf("DecodeAddress(%s) error = %v", address, err)
	}
	var out [32]byte
	copy(out[:], decoded[:])
	return out
}

func merkleAllowlistLeafForTest(pubkey [32]byte) []byte {
	data := make([]byte, 0, 33)
	data = append(data, 0x00)
	data = append(data, pubkey[:]...)
	sum := sha256.Sum256(data)
	return sum[:]
}

func merkleAllowlistEmptyLeafForTest() []byte {
	sum := sha256.Sum256([]byte{0x00})
	return sum[:]
}

func merkleAllowlistNodeForTest(left, right []byte) []byte {
	if bytes.Compare(left, right) > 0 {
		left, right = right, left
	}
	data := make([]byte, 0, 65)
	data = append(data, 0x01)
	data = append(data, left...)
	data = append(data, right...)
	sum := sha256.Sum256(data)
	return sum[:]
}
