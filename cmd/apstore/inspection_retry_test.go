// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestRequestInspectionWithRetryUsesFreshRequestAfterIdentityBusy(t *testing.T) {
	fake := &fakeApstoreAdminRequester{}
	var ids []string
	fake.requestFunc = func(msg any, out any) error {
		request := msg.(protocol.ListGenerationsMessage)
		ids = append(ids, request.ID)
		result := out.(*protocol.GenerationsListMessage)
		if len(ids) == 1 {
			result.Code = protocol.ResultCodeIdentityBusy
			result.Error = "identity store is busy"
		} else {
			result.Current = "gen-current"
		}
		return nil
	}
	oldSleep := sleepApstoreInspectionRetry
	sleepApstoreInspectionRetry = func(time.Duration) {}
	t.Cleanup(func() { sleepApstoreInspectionRetry = oldSleep })

	result, err := requestInspectionWithRetry(fake, func() any {
		return protocol.ListGenerationsMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListGenerations, ID: newApstoreRequestID("retry-test")},
		}
	}, func(result *protocol.GenerationsListMessage) string { return result.Code })
	if err != nil {
		t.Fatal(err)
	}
	if result.Current != "gen-current" || len(ids) != 2 || ids[0] == ids[1] {
		t.Fatalf("result=%+v ids=%v, want successful retry with fresh ID", result, ids)
	}
}
