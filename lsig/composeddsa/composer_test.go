// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/aplane-algo/aplane/internal/addressderive"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
)

type testOps struct{}

func (testOps) PublicKeySize() int                          { return 1 }
func (testOps) CryptoSignatureSize() int                    { return 1 }
func (testOps) MnemonicScheme() string                      { return "" }
func (testOps) MnemonicWordCount() int                      { return 0 }
func (testOps) DisplayColor() string                        { return "" }
func (testOps) TEALVersion() int                            { return 12 }
func (testOps) BuildSignatureArgs([]byte) ([][]byte, error) { return nil, nil }
func (testOps) BuildVerifyTEAL([]byte) (string, error)      { return "int 1\nreturn\n", nil }

type suffixTestOps struct{}

func (suffixTestOps) PublicKeySize() int                              { return 1 }
func (suffixTestOps) CryptoSignatureSize() int                        { return 1 }
func (suffixTestOps) MnemonicScheme() string                          { return "" }
func (suffixTestOps) MnemonicWordCount() int                          { return 0 }
func (suffixTestOps) DisplayColor() string                            { return "" }
func (suffixTestOps) TEALVersion() int                                { return 12 }
func (suffixTestOps) BuildSignatureArgs(sig []byte) ([][]byte, error) { return [][]byte{sig}, nil }
func (suffixTestOps) BuildVerifyTEAL([]byte) (string, error)          { return "test_verify\n", nil }

type falconBoundaryTestOps struct{}

func (falconBoundaryTestOps) PublicKeySize() int                          { return 4 }
func (falconBoundaryTestOps) CryptoSignatureSize() int                    { return 4 }
func (falconBoundaryTestOps) MnemonicScheme() string                      { return "" }
func (falconBoundaryTestOps) MnemonicWordCount() int                      { return 0 }
func (falconBoundaryTestOps) DisplayColor() string                        { return "" }
func (falconBoundaryTestOps) TEALVersion() int                            { return 12 }
func (falconBoundaryTestOps) BuildSignatureArgs([]byte) ([][]byte, error) { return nil, nil }
func (falconBoundaryTestOps) BuildVerifyTEAL([]byte) (string, error) {
	return "txn TxID\narg 0\npushbytes 0x01020304\nfalcon_verify\n", nil
}

type compileMockTransport struct {
	bytecode []byte
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
	body := `{"result":"` + base64.StdEncoding.EncodeToString(m.bytecode) + `","hash":"unused"}`
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

func TestComposedDSADeriveLsigWithSaltReturnsCounter(t *testing.T) {
	dsa := NewComposedDSA(Config{
		KeyType:     "test-v1",
		FamilyName:  "test",
		Version:     1,
		DisplayName: "Test",
		Ops:         testOps{},
	})
	compiled := []byte{0x0c, 0x26, 0x01, 0x01, 0x00, 0x81, 0x01}
	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, compileMockTransport{bytecode: compiled})
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}
	dsa.SetAlgodClient(client)

	want, err := lsigsalt.FindOffCurve(compiled, lsigsalt.BytecblockLocator)
	if err != nil {
		t.Fatalf("FindOffCurve() error = %v", err)
	}
	got, err := dsa.DeriveLsigWithSalt(context.Background(), []byte{1}, nil)
	if err != nil {
		t.Fatalf("DeriveLsigWithSalt() error = %v", err)
	}
	if got.Counter != want.Counter || got.Address != want.Address || string(got.Bytecode) != string(want.Bytecode) {
		t.Fatalf("DeriveLsigWithSalt() = %+v, want %+v", got, want)
	}
	if lsigsalt.IsOnCurve(got.Address) {
		t.Fatal("DeriveLsigWithSalt() returned on-curve address")
	}

	bytecode, address, err := dsa.DeriveLsig(context.Background(), []byte{1}, nil)
	if err != nil {
		t.Fatalf("DeriveLsig() error = %v", err)
	}
	if string(bytecode) != string(want.Bytecode) || address != want.Address.String() {
		t.Fatalf("DeriveLsig() = (%x, %s), want (%x, %s)", bytecode, address, want.Bytecode, want.Address)
	}
}

func TestComposedDSANoSuffixRejectsShiftedBytecblockSaltPreamble(t *testing.T) {
	dsa := NewComposedDSA(Config{
		KeyType:     "test-shifted-bytecblock-v1",
		FamilyName:  "test",
		Version:     1,
		DisplayName: "Test Shifted Bytecblock",
		Ops:         testOps{},
	})
	compiled := []byte{0x0c, 0x81, 0x01, 0x26, 0x01, 0x01, 0x00}
	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, compileMockTransport{bytecode: compiled})
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}
	dsa.SetAlgodClient(client)

	_, err = dsa.DeriveLsigWithSalt(context.Background(), []byte{1}, nil)
	if err == nil {
		t.Fatal("DeriveLsigWithSalt() error = nil, want shifted bytecblock preamble rejection")
	}
	if !strings.Contains(err.Error(), "not found immediately after TEAL version varint") {
		t.Fatalf("DeriveLsigWithSalt() error = %v, want strict bytecblock preamble rejection", err)
	}
}

func TestComposedDSADeriveLsigWithSuffixUsesSourceSaltPreamble(t *testing.T) {
	dsa := NewComposedDSA(Config{
		KeyType:     "test-suffix-v1",
		FamilyName:  "test",
		Version:     1,
		DisplayName: "Test Suffix",
		Ops:         testOps{},
		TEALSuffix:  "int 1\nassert",
	})
	compiled := compiledPushbytesSaltBytecode(0)
	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, compileMockTransport{bytecode: compiled})
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}
	dsa.SetAlgodClient(client)

	teal, err := dsa.GenerateTEAL([]byte{1}, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	preamble, _ := lsigsalt.StylePushbytes.SourcePreamble()
	if !strings.Contains(teal, strings.TrimSpace(preamble)) || strings.Contains(teal, "bytecblock 0x00") {
		t.Fatalf("suffix TEAL should use source salt preamble:\n%s", teal)
	}

	want, err := lsigsalt.FindOffCurve(compiled, lsigsalt.PushbytesLocator)
	if err != nil {
		t.Fatalf("FindOffCurve() error = %v", err)
	}
	got, err := dsa.DeriveLsigWithSalt(context.Background(), []byte{1}, nil)
	if err != nil {
		t.Fatalf("DeriveLsigWithSalt() error = %v", err)
	}
	if got.Counter != want.Counter || got.Address != want.Address || string(got.Bytecode) != string(want.Bytecode) {
		t.Fatalf("DeriveLsigWithSalt() = %+v, want %+v", got, want)
	}
}

func TestComposedDSAExplicitPushbytesSaltStyleWithoutSuffix(t *testing.T) {
	dsa := NewComposedDSA(Config{
		KeyType:     "test-pushbytes-v1",
		FamilyName:  "test",
		Version:     1,
		DisplayName: "Test Pushbytes",
		Ops:         testOps{},
		SaltStyle:   lsigsalt.StylePushbytes,
	})
	compiled := compiledPushbytesSaltBytecode(0)
	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, compileMockTransport{bytecode: compiled})
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}
	dsa.SetAlgodClient(client)

	teal, err := dsa.GenerateTEAL([]byte{1}, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	preamble, _ := lsigsalt.StylePushbytes.SourcePreamble()
	if !strings.Contains(teal, strings.TrimSpace(preamble)) || strings.Contains(teal, "bytecblock 0x00") {
		t.Fatalf("explicit pushbytes TEAL should use source salt preamble:\n%s", teal)
	}

	want, err := lsigsalt.FindOffCurve(compiled, lsigsalt.PushbytesLocator)
	if err != nil {
		t.Fatalf("FindOffCurve() error = %v", err)
	}
	got, err := dsa.DeriveLsigWithSalt(context.Background(), []byte{1}, nil)
	if err != nil {
		t.Fatalf("DeriveLsigWithSalt() error = %v", err)
	}
	if got.Counter != want.Counter || got.Address != want.Address || string(got.Bytecode) != string(want.Bytecode) {
		t.Fatalf("DeriveLsigWithSalt() = %+v, want %+v", got, want)
	}
}

func TestComposedDSAPushbytesSaltDerivationGolden(t *testing.T) {
	dsa := NewComposedDSA(Config{
		KeyType:     "test-pushbytes-golden-v1",
		FamilyName:  "test",
		Version:     1,
		DisplayName: "Test Pushbytes Golden",
		Ops:         testOps{},
		TEALSuffix:  "int 1\nassert",
	})
	compiled := compiledPushbytesSaltBytecode(0)
	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, compileMockTransport{bytecode: compiled})
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}
	dsa.SetAlgodClient(client)

	teal, err := dsa.GenerateTEAL([]byte{1}, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	if _, err := lsigsalt.PushbytesMarkerLocator(compiled); err != nil {
		t.Fatalf("PushbytesMarkerLocator() error = %v", err)
	}
	salted, err := dsa.DeriveLsigWithSalt(context.Background(), []byte{1}, nil)
	if err != nil {
		t.Fatalf("DeriveLsigWithSalt() error = %v", err)
	}
	if lsigsalt.IsOnCurve(salted.Address) {
		t.Fatalf("DeriveLsigWithSalt() returned on-curve address %s", salted.Address.String())
	}

	assertGolden(t, "teal hash", sha256Hex([]byte(teal)), "0f56c3ae451205a764e1d00e61fd81ac17f489747d1fd6743fc0c7a178760f34")
	assertGolden(t, "pre-salt bytecode hash", sha256Hex(compiled), "e4a2c9b35425bc1fc069fe998b40d9fc5e309dcf12f46fb9f6750ec9bb2625c4")
	assertGolden(t, "salt counter", hex.EncodeToString([]byte{salted.Counter}), "00")
	assertGolden(t, "derived address", salted.Address.String(), "J4FAHVLXIZ2PBPTAZ5C6BO77EJDTIHFAVXHCI4LIDXXPU3JKAOJ4KW3BTM")
}

func TestComposedDSATrailingBytecblockSaltStyleWithSuffix(t *testing.T) {
	dsa := NewComposedDSA(Config{
		KeyType:     "test-trailing-bytecblock-v1",
		FamilyName:  "test",
		Version:     1,
		DisplayName: "Test Trailing Bytecblock",
		Ops:         testOps{},
		TEALSuffix:  "int 1\nassert",
		SaltStyle:   lsigsalt.StyleTrailingBytecblock,
	})
	compiled := compiledTrailingBytecblockSaltBytecode(0)
	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, compileMockTransport{bytecode: compiled})
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}
	dsa.SetAlgodClient(client)

	teal, err := dsa.GenerateTEAL([]byte{1}, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	if strings.Contains(teal, "pop") || !strings.HasSuffix(strings.TrimSpace(teal), "bytecblock 0x00") {
		t.Fatalf("trailing bytecblock TEAL should append salt trailer without pushbytes:\n%s", teal)
	}
	if !strings.Contains(teal, "int 1\nreturn\n\n// Counter byte") {
		t.Fatalf("trailing bytecblock TEAL should place salt after composer return:\n%s", teal)
	}

	want, err := lsigsalt.FindOffCurve(compiled, lsigsalt.TrailingBytecblockLocator)
	if err != nil {
		t.Fatalf("FindOffCurve() error = %v", err)
	}
	got, err := dsa.DeriveLsigWithSalt(context.Background(), []byte{1}, nil)
	if err != nil {
		t.Fatalf("DeriveLsigWithSalt() error = %v", err)
	}
	if got.Counter != want.Counter || got.Address != want.Address || string(got.Bytecode) != string(want.Bytecode) {
		t.Fatalf("DeriveLsigWithSalt() = %+v, want %+v", got, want)
	}
}

func TestComposedDSAExplicitNoSaltStyleUsesUnmodifiedBytecode(t *testing.T) {
	dsa := NewComposedDSA(Config{
		KeyType:     "test-unsalted-v1",
		FamilyName:  "test-unsalted",
		Version:     1,
		DisplayName: "Test Unsalted",
		Ops:         suffixTestOps{},
		TEALSuffix:  "int 1\nassert",
		SaltStyle:   lsigsalt.StyleNone,
	})
	compiled := unsaltedOffCurveBytecodeForTest(t)
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
	if got.Counter != want.Counter || got.Address != want.Address || string(got.Bytecode) != string(want.Bytecode) {
		t.Fatalf("DeriveLsigWithSalt() = %+v, want %+v", got, want)
	}
}

func compiledPushbytesSaltBytecode(counter byte) []byte {
	marker := lsigsalt.PushbytesSaltMarker(counter)
	bytecode := []byte{0x0c, 0x80, byte(len(marker))}
	bytecode = append(bytecode, marker...)
	bytecode = append(bytecode, 0x48, 0x81, 0x01)
	return bytecode
}

func compiledTrailingBytecblockSaltBytecode(counter byte) []byte {
	return []byte{0x0c, 0x81, 0x01, 0x43, 0x26, 0x01, 0x01, counter}
}

func unsaltedOffCurveBytecodeForTest(t *testing.T) []byte {
	t.Helper()
	bytecode := []byte{0x0c, 0x81, 0x00}
	for counter := 0; counter < lsigsalt.MaxIterations; counter++ {
		bytecode[2] = byte(counter)
		if _, err := lsigsalt.UseUnmodifiedOffCurve(bytecode); err == nil {
			return append([]byte(nil), bytecode...)
		}
	}
	t.Fatal("failed to find deterministic off-curve unsalted bytecode")
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func assertGolden(t *testing.T, label, got, want string) {
	t.Helper()
	if want == "" {
		t.Fatalf("%s golden: %s", label, got)
	}
	if got != want {
		t.Fatalf("%s = %s, want %s", label, got, want)
	}
}

func TestComposedDSARejectsBytecblockSaltStyleWithSuffix(t *testing.T) {
	dsa := NewComposedDSA(Config{
		KeyType:     "bad-salt-style-v1",
		FamilyName:  "bad-salt-style",
		Version:     1,
		DisplayName: "Bad Salt Style",
		Ops:         testOps{},
		TEALSuffix:  "int 1\nassert",
		SaltStyle:   lsigsalt.StyleBytecblock,
	})

	_, err := dsa.GenerateTEAL([]byte{1}, nil)
	if err == nil {
		t.Fatal("GenerateTEAL() error = nil, want bytecblock suffix rejection")
	}
	if !strings.Contains(err.Error(), "cannot be used with a TEAL suffix") {
		t.Fatalf("GenerateTEAL() error = %v, want salt style rejection", err)
	}

	transport := &countingCompileTransport{}
	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, transport)
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}
	dsa.SetAlgodClient(client)
	_, err = dsa.DeriveLsigWithSalt(context.Background(), []byte{1}, nil)
	if err == nil {
		t.Fatal("DeriveLsigWithSalt() error = nil, want bytecblock suffix rejection")
	}
	if !strings.Contains(err.Error(), "cannot be used with a TEAL suffix") {
		t.Fatalf("DeriveLsigWithSalt() error = %v, want salt style rejection", err)
	}
	if transport.calls != 0 {
		t.Fatalf("DeriveLsigWithSalt() made %d compile calls, want 0", transport.calls)
	}
}

func TestComposedDSAFingerprintNormalizesSaltStyle(t *testing.T) {
	auto := NewComposedDSA(Config{
		KeyType:     "test-v1",
		FamilyName:  "test",
		Version:     1,
		DisplayName: "Test",
		Ops:         testOps{},
	})
	explicitBytecblock := NewComposedDSA(Config{
		KeyType:     "test-v1",
		FamilyName:  "test",
		Version:     1,
		DisplayName: "Test",
		Ops:         testOps{},
		SaltStyle:   lsigsalt.StyleBytecblock,
	})
	explicitPushbytes := NewComposedDSA(Config{
		KeyType:     "test-v1",
		FamilyName:  "test",
		Version:     1,
		DisplayName: "Test",
		Ops:         testOps{},
		SaltStyle:   lsigsalt.StylePushbytes,
	})

	if auto.CompatibilityFingerprint() != explicitBytecblock.CompatibilityFingerprint() {
		t.Fatalf("auto no-suffix fingerprint should normalize to explicit bytecblock")
	}
	if auto.CompatibilityFingerprint() == explicitPushbytes.CompatibilityFingerprint() {
		t.Fatalf("pushbytes salt style should change compatibility fingerprint")
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
// only then may the user suffix execute. Composed templates such as
// aplane.falcon1024-hashlock.v1 and aplane.falcon1024-timelock.v1
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

func (markerVerifierOps) PublicKeySize() int                          { return 1 }
func (markerVerifierOps) CryptoSignatureSize() int                    { return 1 }
func (markerVerifierOps) MnemonicScheme() string                      { return "" }
func (markerVerifierOps) MnemonicWordCount() int                      { return 0 }
func (markerVerifierOps) DisplayColor() string                        { return "" }
func (markerVerifierOps) TEALVersion() int                            { return 12 }
func (markerVerifierOps) BuildSignatureArgs([]byte) ([][]byte, error) { return nil, nil }
func (o markerVerifierOps) BuildVerifyTEAL([]byte) (string, error)    { return o.verifyTEAL, nil }

func TestFalconWhitelistTemplateOnlyAddsDestinationPredicate(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "library", "templates", "aplane.falcon1024-whitelist.v1.yaml"))
	if err != nil {
		t.Fatalf("ReadFile(aplane.falcon1024-whitelist.v1.yaml) error = %v", err)
	}
	spec, err := ParseTemplateSpec(data)
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}

	for _, want := range []string{
		"// Only pay/axfer have destination fields this whitelist constrains.",
		"// Other transaction types keep the base Falcon authorization surface.",
		"asset_path:",
		"pay_path:",
	} {
		if !strings.Contains(spec.TEAL, want) {
			t.Fatalf("falcon whitelist template missing %q:\n%s", want, spec.TEAL)
		}
	}
	normalized := strings.Join(strings.Fields(spec.TEAL), " ")
	for _, want := range []string{
		"txn TypeEnum int pay == bnz pay_path",
		"txn TypeEnum int axfer == bnz asset_path",
		"bnz asset_path b allow",
		"txn AssetReceiver txn Sender == bnz allow_asset_receiver",
		"txn AssetReceiver callsub is_whitelisted bnz allow_asset_receiver",
		"txn AssetCloseTo global ZeroAddress == bnz allow_asset_close",
		"txn AssetCloseTo txn Sender == bnz allow_asset_close",
		"txn AssetCloseTo callsub is_whitelisted bnz allow_asset_close",
		"txn Receiver txn Sender == bnz allow_pay_receiver",
		"txn Receiver callsub is_whitelisted bnz allow_pay_receiver",
		"txn CloseRemainderTo global ZeroAddress == bnz allow_pay_close",
		"txn CloseRemainderTo txn Sender == bnz allow_pay_close",
		"txn CloseRemainderTo callsub is_whitelisted bnz allow_pay_close",
	} {
		if !strings.Contains(normalized, want) {
			t.Fatalf("falcon whitelist template missing normalized sequence %q:\n%s", want, spec.TEAL)
		}
	}
	for _, forbidden := range []string{
		"int keyreg",
		"maybe_self_pay",
		"maybe_self_asset_lifecycle",
		"txn Amount int 0 ==",
		"txn AssetAmount int 0 ==",
		"txn AssetSender",
	} {
		if strings.Contains(normalized, forbidden) {
			t.Fatalf("falcon whitelist template should not add extra Falcon restriction %q:\n%s", forbidden, spec.TEAL)
		}
	}
}

func TestFalconHashlockAndTimelockOnlyAddGatingPredicate(t *testing.T) {
	tests := []struct {
		name         string
		file         string
		required     []string
		forbiddenTxn []string
	}{
		{
			name: "hashlock",
			file: "aplane.falcon1024-hashlock.v1.yaml",
			required: []string{
				"arg 1\nsha256",
				"$hash\n==\nassert",
			},
			forbiddenTxn: []string{
				"txn TypeEnum",
				"txn Receiver",
				"txn CloseRemainderTo",
				"txn RekeyTo",
				"txn AssetReceiver",
				"txn AssetCloseTo",
				"txn AssetSender",
			},
		},
		{
			name: "timelock",
			file: "aplane.falcon1024-timelock.v1.yaml",
			required: []string{
				"txn FirstValid\n$unlock_round\n>=",
			},
			forbiddenTxn: []string{
				"txn TypeEnum",
				"txn Receiver",
				"txn CloseRemainderTo",
				"txn RekeyTo",
				"txn AssetReceiver",
				"txn AssetCloseTo",
				"txn AssetSender",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "library", "templates", tt.file))
			if err != nil {
				t.Fatalf("ReadFile(%s) error = %v", tt.file, err)
			}
			spec, err := ParseTemplateSpec(data)
			if err != nil {
				t.Fatalf("ParseTemplateSpec(%s) error = %v", tt.file, err)
			}
			for _, want := range tt.required {
				if !strings.Contains(spec.TEAL, want) {
					t.Fatalf("%s template missing %q:\n%s", tt.name, want, spec.TEAL)
				}
			}
			for _, forbidden := range tt.forbiddenTxn {
				if strings.Contains(spec.TEAL, forbidden) {
					t.Fatalf("%s template should not add transaction policy %q:\n%s", tt.name, forbidden, spec.TEAL)
				}
			}
		})
	}
}

func TestFalconWhitelistTemplateRendersMaxRecipientsWithinComposerBoundary(t *testing.T) {
	RegisterBase(BaseRegistration{
		BaseKeyType: "aplane.falcon1024.v1",
		FamilyName:  "falcon1024",
		Version:     1,
		Ops:         falconBoundaryTestOps{},
		NewAddressDeriver: func(string) addressderive.Deriver {
			return testDeriver{}
		},
	})

	data, err := os.ReadFile(filepath.Join("..", "..", "library", "templates", "aplane.falcon1024-whitelist.v1.yaml"))
	if err != nil {
		t.Fatalf("ReadFile(aplane.falcon1024-whitelist.v1.yaml) error = %v", err)
	}
	spec, err := ParseTemplateSpec(data)
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	provider, err := NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("NewProviderFromTemplateSpec() error = %v", err)
	}

	recipients := make([]string, 30)
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
	suffixIdx := strings.Index(teal, "Only pay/axfer")
	endIdx := strings.Index(teal, "end_checks:")
	finalReturn := strings.LastIndex(teal, "int 1\nreturn")
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
	if strings.Count(teal, "byte 0x") != len(recipients) {
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
		t.Fatal("GenerateTEAL(31 recipients) error = nil, want max_items rejection")
	}
	if !strings.Contains(err.Error(), "at most "+strconv.Itoa(len(recipients))) {
		t.Fatalf("GenerateTEAL(31 recipients) error = %v, want max_items rejection", err)
	}
}

func addressListProvider() *ComposedDSA {
	return NewComposedDSA(Config{
		KeyType:      "address-list-v1",
		FamilyName:   "address-list",
		Version:      1,
		DisplayName:  "Address List",
		Ops:          suffixTestOps{},
		TemplateMode: "generated",
		TEALSuffix: `txn Receiver
callsub is_whitelisted
assert

is_whitelisted:
    {{range @recipients}}
    dup
    byte {{.}}
    ==
    bnz whitelisted
    {{end}}
    pop
    int 0
    retsub

whitelisted:
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
