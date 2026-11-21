// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
)

// cosignerDefaultWithSources is the external checks contract fixture as the
// node default: screening and treasury take a token, ops takes none.
func cosignerDefaultWithSources(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "test", "contracts", "policy", "v1", "cosigner_key_external_checks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["key"] = policy.DefaultKey
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// Set, list and remove through a real admin session: the token reaches the
// runtime index and the store, and no response or audit entry carries it.
func TestSourceTokenMessagesThroughTheDaemon(t *testing.T) {
	const secret = "tok-daemon-9c1e"
	server, cleanup := setupTestNode(t, noderole.RoleCosigner, cosignerDefaultWithSources(t))
	defer cleanup()
	ir := server.productRuntime()
	ipcServer := &IPCServer{signer: server}
	recorder := &ipcJSONRecorderConn{}
	session := newBoundTestSession(ipcServer, recorder, ir)

	set := protocol.SourceTokenSetMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSourceTokenSet, ID: "set-1"},
		Selector:    policy.DefaultKey, Source: "screening", Token: protocol.NewSensitiveBytes(secret),
	}
	dispatchIPCMessage(t, session, set)
	if got, ok := ir.SourceTokenFor(policy.DefaultKey, "screening"); !ok || got != secret {
		t.Fatalf("SourceTokenFor() = %q, %v", got, ok)
	}
	dispatchIPCMessage(t, session, protocol.SourceTokenListMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSourceTokenList, ID: "ls-1"},
	})
	dispatchIPCMessage(t, session, protocol.SourceTokenRemoveMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSourceTokenRemove, ID: "rm-1"},
		Selector:    policy.DefaultKey, Source: "screening",
	})
	if _, ok := ir.SourceTokenFor(policy.DefaultKey, "screening"); ok {
		t.Fatal("a removed token is still served")
	}

	recorder.mu.Lock()
	wire := bytes.Clone(recorder.buf.Bytes())
	recorder.mu.Unlock()
	if bytes.Contains(wire, []byte(secret)) {
		t.Fatalf("a response carries the token:\n%s", wire)
	}
	msgs := recorder.messages(t)
	if len(msgs) != 3 || msgs[0]["success"] != true || msgs[1]["success"] != true || msgs[2]["success"] != true {
		t.Fatalf("responses = %#v", msgs)
	}
	selectors, _ := msgs[1]["selectors"].([]any)
	if len(selectors) != 1 {
		t.Fatalf("list = %#v", msgs[1])
	}
	listing := selectors[0].(map[string]any)
	var states []string
	for _, token := range listing["tokens"].([]any) {
		row := token.(map[string]any)
		states = append(states, row["source"].(string)+"="+row["state"].(string))
	}
	if listing["selector"] != "default" || listing["policy"] != "own" || strings.Join(states, " ") != "screening=in_use treasury=needed" {
		t.Fatalf("listing = %#v", listing)
	}

	auditPath := filepath.Join(server.dataDir, "audit.log")
	log, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(log, []byte(secret)) {
		t.Fatal("the audit log carries the token")
	}
	entries := auditEntries(t, auditPath, "SOURCE_TOKEN_CHANGE_INTENT", "SOURCE_TOKEN_SET", "SOURCE_TOKEN_REMOVED", "SOURCE_TOKEN_CHANGE_FAILED")
	var events []string
	for _, entry := range entries {
		events = append(events, entry["event"].(string))
		if entry["policy_selector"] != "default" || entry["external_source"] != "screening" || entry["transport"] != "ipc" {
			t.Fatalf("entry lacks its selector, source or attribution: %#v", entry)
		}
	}
	if strings.Join(events, " ") != "SOURCE_TOKEN_CHANGE_INTENT SOURCE_TOKEN_SET SOURCE_TOKEN_CHANGE_INTENT SOURCE_TOKEN_REMOVED" {
		t.Fatalf("events = %v", events)
	}
}

// A live check through an admin session warns, against the live token index,
// of each source the document takes a token for that its selector has none
// of: the session has policy.update, the authorization that reads token
// names. The service alone, asked without that, names no token.
func TestLivePolicyCheckWarnsOfAMissingSourceToken(t *testing.T) {
	doc := cosignerDefaultWithSources(t)
	server, cleanup := setupTestNode(t, noderole.RoleCosigner, doc)
	defer cleanup()
	keys := server.adminServices().keyApp()
	if result := keys.SetSourceToken(adminproto.SetSourceTokenRequest{Selector: policy.DefaultKey, Source: "screening", Token: []byte("tok-live")}); !result.Success {
		t.Fatalf("SetSourceToken() = %+v", result)
	}
	recorder := &ipcJSONRecorderConn{}
	session := newBoundTestSession(&IPCServer{signer: server}, recorder, server.productRuntime())
	dispatchIPCMessage(t, session, protocol.CheckPolicyMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeCheckPolicy, ID: "check-1"},
		Documents:   []protocol.PolicyDocumentWire{{Key: policy.DefaultKey, Document: doc}},
	})
	msgs := recorder.messages(t)
	if len(msgs) != 1 || msgs[0]["success"] != true || msgs[0]["valid"] != true {
		t.Fatalf("check_policy responses = %#v", msgs)
	}
	var pointers []string
	warnings, _ := msgs[0]["warnings"].([]any)
	for _, w := range warnings {
		if pointer, _ := w.(map[string]any)["pointer"].(string); strings.HasSuffix(pointer, "/token") {
			pointers = append(pointers, pointer)
		}
	}
	if strings.Join(pointers, " ") != "/external_sources/treasury/token" {
		t.Fatalf("token warnings at %v, want treasury's alone: %#v", pointers, warnings)
	}

	result := server.adminServices().adminApp().CheckPolicy(adminproto.CheckPolicyRequest{
		Documents: []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: doc}},
	})
	if !result.Success || !result.Valid {
		t.Fatalf("CheckPolicy() = %+v", result)
	}
	for _, w := range result.Warnings {
		if strings.HasSuffix(w.Pointer, "/token") {
			t.Fatalf("a check not told the session may read token names warned at %s", w.Pointer)
		}
	}
}
