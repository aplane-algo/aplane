// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package externalcheck

import (
	"fmt"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/strictjson"
)

// This file is what an offline tool needs to judge a check without a source:
// a canned answer has no request ID, and a fail-closed outcome is named
// rather than caused. Nothing here makes a lookup.

// JudgeOffline judges check against a canned answer for a unit with facts.
// No lookup was sent, so there is no request ID for an echo_pointer to
// match: any string at the pointer satisfies it, and echoUnverified reports
// that the echo was taken on trust. A missing value there, or one that is
// not a string, still fails.
//
// The string found is handed to Judge as the request ID, so Judge itself,
// which the cosigner runs with the ID it sent, keeps comparing the echo
// strictly; the offline path changes only what it is compared with.
func JudgeOffline(check policy.ExternalCheckV1, facts Facts, answer *strictjson.Node) (ok bool, detail string, echoUnverified bool) {
	requestID := ""
	if check.EchoPointer != nil {
		where := describePointer(*check.EchoPointer)
		echo, found := answer.Resolve(*check.EchoPointer)
		switch {
		case !found:
			return false, "echo missing: " + where + " holds no request ID", false
		case echo.Kind != strictjson.String:
			return false, "echo missing: " + wrongType(where, echo, "the request ID as a string"), false
		}
		requestID, echoUnverified = echo.Text, true
	}
	ok, detail = Judge(check, facts, answer, requestID)
	return ok, detail, echoUnverified
}

// Named lookup failures: the ways a lookup can fail that an offline case can
// pin, each refusing as the cosigner would.
const (
	FailureTimeout     = "timeout"
	FailureUnreachable = "unreachable"
	FailureStatus      = "status"
	FailureTooLarge    = "too_large"
	FailureNotJSON     = "not_json"
	FailureCertificate = "certificate"
	FailurePinMismatch = "pin_mismatch"
	FailureTokenNotSet = "token_not_set"
)

// Failures lists the named lookup failures.
var Failures = []string{
	FailureTimeout, FailureUnreachable, FailureStatus, FailureTooLarge,
	FailureNotJSON, FailureCertificate, FailurePinMismatch, FailureTokenNotSet,
}

// FailureOf is the refusal outcome (one of the policy package's
// ExternalCheck*Outcome values) and the audit record's detail the cosigner
// gives when a lookup to source fails in the named way. A failure source
// cannot have is an error: a certificate or pin failure of a plain http
// source, a pin mismatch of a source without pins, and a missing token of a
// source that takes none.
func FailureOf(name string, source policy.ExternalSourceV1) (outcome, detail string, err error) {
	unavailable := policy.ExternalCheckUnavailableOutcome
	switch name {
	case FailureTimeout:
		return unavailable, timeoutError(time.Duration(source.TimeoutMS) * time.Millisecond).Error(), nil
	case FailureUnreachable:
		return unavailable, errUnreachable.Error(), nil
	case FailureStatus:
		return unavailable, "status 503", nil
	case FailureTooLarge:
		return unavailable, fmt.Sprintf("body over %d bytes", source.MaxResponseBytes), nil
	case FailureNotJSON:
		return unavailable, errNotJSON.Error(), nil
	case FailureCertificate:
		if isPlainHTTP(source) {
			return "", "", fmt.Errorf("a plain http source has no certificate to refuse")
		}
		return unavailable, errCertificate.Error(), nil
	case FailurePinMismatch:
		if len(source.TLSPins) == 0 {
			return "", "", fmt.Errorf("the source pins no server key, so no pin can mismatch")
		}
		return unavailable, errPinMismatch.Error(), nil
	case FailureTokenNotSet:
		if source.Token == nil {
			return "", "", fmt.Errorf("the source takes no token")
		}
		return policy.ExternalCheckTokenNotSetOutcome, errNoToken.Error(), nil
	}
	return "", "", fmt.Errorf("%q is not a lookup failure", name)
}

func isPlainHTTP(source policy.ExternalSourceV1) bool {
	return strings.HasPrefix(source.BaseURL, "http://")
}
