// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"testing"
	"time"
)

func TestRestoreAttemptLimiterBackoffAndReset(t *testing.T) {
	now := time.Unix(1710000000, 0)
	limiter := NewRestoreAttemptLimiter(func() time.Time { return now })

	if got := limiter.RetryAfter("default", "/backup.tar.gz"); got != 0 {
		t.Fatalf("initial retry after = %v, want 0", got)
	}

	limiter.RecordFailure("default", "/backup.tar.gz")
	if got := limiter.RetryAfter("default", "/backup.tar.gz"); got != time.Second {
		t.Fatalf("first retry after = %v, want 1s", got)
	}

	now = now.Add(time.Second)
	if got := limiter.RetryAfter("default", "/backup.tar.gz"); got != 0 {
		t.Fatalf("retry after elapsed = %v, want 0", got)
	}

	limiter.RecordFailure("default", "/backup.tar.gz")
	if got := limiter.RetryAfter("default", "/backup.tar.gz"); got != 2*time.Second {
		t.Fatalf("second retry after = %v, want 2s", got)
	}

	limiter.RecordSuccess("default", "/backup.tar.gz")
	if got := limiter.RetryAfter("default", "/backup.tar.gz"); got != 0 {
		t.Fatalf("retry after after success = %v, want 0", got)
	}
}
