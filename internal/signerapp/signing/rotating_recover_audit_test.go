// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"reflect"
	"testing"

	"github.com/aplane-algo/aplane/pkg/signerapi"
)

type recoveryEntry struct {
	action  string
	grantID uint64
	detail  string
}

// recordingRecoveryAudit captures ROTATING_RECOVERY entries.
type recordingRecoveryAudit struct {
	recordingReleaseAudit
	entries []recoveryEntry
}

func (a *recordingRecoveryAudit) LogRotatingRecovery(_ context.Context, _ string, action string, grantID uint64, detail string) {
	a.entries = append(a.entries, recoveryEntry{action, grantID, detail})
}

// A recovery's entries carry the grant by number and describe it once: a
// start gives its budget and any hint, and a cancel says what happened to
// the grant, not which grant it was again.
func TestRotatingRecoveryAuditsTheGrantOnce(t *testing.T) {
	f, _ := newSigningFixtureFor(t, wotscTestType)
	audit := &recordingRecoveryAudit{}
	f.svc.AuditLog = audit
	account := f.account.String()
	recover := func(action string, hint *uint64) *signerapi.RotatingRecoverResponse {
		t.Helper()
		req := signerapi.RotatingRecoverRequest{Account: account, Action: action}
		if action == signerapi.RotatingRecoverActionStart {
			req.MaxStages, req.TimeoutSeconds, req.Stage = 4, 60, hint
			if hint != nil {
				req.Window = 2
			}
		}
		resp, err := f.svc.RecoverRotatingWithContext(context.Background(), req)
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		return resp
	}
	started := recover(signerapi.RotatingRecoverActionStart, nil)
	if started.GrantID == 0 {
		t.Fatal("start returned no grant")
	}
	recover(signerapi.RotatingRecoverActionCancel, nil)
	recover(signerapi.RotatingRecoverActionCancel, nil)
	stage := uint64(3)
	hinted := recover(signerapi.RotatingRecoverActionStart, &stage)
	recover(signerapi.RotatingRecoverActionCancel, nil)

	want := []recoveryEntry{
		{signerapi.RotatingRecoverActionStart, started.GrantID, "max_stages 4, timeout 1m0s"},
		{signerapi.RotatingRecoverActionCancel, started.GrantID, "cancelled"},
		{signerapi.RotatingRecoverActionCancel, 0, "nothing to cancel"},
		{signerapi.RotatingRecoverActionStart, hinted.GrantID, "max_stages 4, timeout 1m0s, hint stage 3, window 2"},
		{signerapi.RotatingRecoverActionCancel, hinted.GrantID, "cancelled"},
	}
	if !reflect.DeepEqual(audit.entries, want) {
		t.Fatalf("entries = %+v, want %+v", audit.entries, want)
	}
}
