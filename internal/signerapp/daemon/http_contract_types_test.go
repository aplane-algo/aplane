package daemon

import (
	"encoding/json"
	"testing"

	"github.com/aplane-algo/aplane/internal/signerapi"
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
