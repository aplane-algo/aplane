// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"net/http"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/signerapp/svcerr"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// A key change whose reload entered recovery is recovery_blocked on the admin
// protocol, where its answer names the defect. Over HTTP it stays the API's
// cache_refresh, the code for a change written whose key cache did not
// refresh, and carries none of the store detail.
func TestAKeyChangeThatEnteredRecoveryAnswersCacheRefreshOverHTTP(t *testing.T) {
	got := sanitizeKeyAdminError(&svcerr.Error{
		Kind:    svcerr.KindRecoveryBlocked,
		Message: "the change was written, but ... the signer entered recovery: generation validation failed: keys/junk.txt",
	}, "key generation failed")
	if got.Code() != signerapi.ErrCodeCacheRefresh || got.HTTPStatus() != http.StatusInternalServerError {
		t.Fatalf("HTTP answer = %q %d, want cache_refresh 500", got.Code(), got.HTTPStatus())
	}
	if got.Message != "failed to refresh signer key cache: the signer entered recovery" || strings.Contains(got.Message, "junk.txt") {
		t.Fatalf("HTTP message = %q, want the recovery without the store detail", got.Message)
	}
}
