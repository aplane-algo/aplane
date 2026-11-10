package daemon

import (
	"encoding/json"
	"testing"

	"github.com/aplane-algo/aplane/pkg/signerapi"
)

type AdminGenerateRequest = signerapi.AdminGenerateRequest
type AdminGenerateResponse = signerapi.AdminGenerateResponse
type AdminDeleteResponse = signerapi.AdminDeleteResponse

func TestSignerAPIAdminGenerateRequestJSONShape(t *testing.T) {
	body, err := json.Marshal(signerapi.AdminGenerateRequest{
		KeyType:    "ed25519",
		Parameters: map[string]string{"foo": "bar"},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	want := `{"key_type":"ed25519","parameters":{"foo":"bar"}}`
	if string(body) != want {
		t.Fatalf("Marshal = %s, want %s", body, want)
	}
}

// Warnings are an optional field of the generate response: absent when the
// signer has none, a list of text otherwise.
func TestSignerAPIAdminGenerateResponseWarningsJSONShape(t *testing.T) {
	quiet, err := json.Marshal(signerapi.AdminGenerateResponse{Address: "ADDR", KeyType: "ed25519"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `{"address":"ADDR","key_type":"ed25519"}`; string(quiet) != want {
		t.Fatalf("Marshal = %s, want %s", quiet, want)
	}
	for _, empty := range [][]string{nil, {}} {
		if body, _ := json.Marshal(signerapi.AdminGenerateResponse{Address: "ADDR", KeyType: "ed25519", Warnings: empty}); string(body) != string(quiet) {
			t.Fatalf("Marshal(no warnings) = %s, want %s", body, quiet)
		}
	}
	body, err := json.Marshal(signerapi.AdminGenerateResponse{
		Address: "ADDR", KeyType: "aplane.falcon1024.v1", Parameters: map[string]string{"max_fee": "0"},
		Warnings: []string{"Fee limit 0 is too low to pay alone.", "a second note"},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"address":"ADDR","key_type":"aplane.falcon1024.v1","parameters":{"max_fee":"0"},"warnings":["Fee limit 0 is too low to pay alone.","a second note"]}`
	if string(body) != want {
		t.Fatalf("Marshal = %s, want %s", body, want)
	}
	var decoded signerapi.AdminGenerateResponse
	if err := json.Unmarshal(body, &decoded); err != nil || len(decoded.Warnings) != 2 || decoded.Warnings[1] != "a second note" {
		t.Fatalf("Unmarshal = %+v, %v", decoded, err)
	}
}

func TestSignerAPIAdminDeleteResponseJSONShape(t *testing.T) {
	body, err := json.Marshal(signerapi.AdminDeleteResponse{Success: true})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	want := `{"success":true}`
	if string(body) != want {
		t.Fatalf("Marshal = %s, want %s", body, want)
	}
}
