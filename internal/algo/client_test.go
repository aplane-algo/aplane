// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package algo

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestConvertTokenAmountToBaseUnits(t *testing.T) {
	tests := []struct {
		name     string
		amount   string
		decimals uint64
		want     uint64
		wantErr  bool
	}{
		{
			name:     "whole number with 6 decimals",
			amount:   "1",
			decimals: 6,
			want:     1000000,
			wantErr:  false,
		},
		{
			name:     "decimal amount with 6 decimals",
			amount:   "1.5",
			decimals: 6,
			want:     1500000,
			wantErr:  false,
		},
		{
			name:     "decimals at protocol max",
			amount:   "1",
			decimals: 19,
			want:     10000000000000000000, // 10^19
			wantErr:  false,
		},
		{
			name:     "decimals above protocol max rejected",
			amount:   "1",
			decimals: 20,
			wantErr:  true,
		},
		{
			name:     "pathological decimals rejected before huge alloc",
			amount:   "1",
			decimals: 1 << 40,
			wantErr:  true,
		},
		{
			name:     "zero amount",
			amount:   "0",
			decimals: 6,
			want:     0,
			wantErr:  false,
		},
		{
			name:     "small decimal",
			amount:   "0.000001",
			decimals: 6,
			want:     1,
			wantErr:  false,
		},
		{
			name:     "0 decimals asset",
			amount:   "100",
			decimals: 0,
			want:     100,
			wantErr:  false,
		},
		{
			name:     "large amount",
			amount:   "1000000",
			decimals: 6,
			want:     1000000000000,
			wantErr:  false,
		},
		{
			name:     "invalid amount string",
			amount:   "abc",
			decimals: 6,
			want:     0,
			wantErr:  true,
		},
		{
			name:     "too many decimal places",
			amount:   "1.0000001",
			decimals: 6,
			want:     0,
			wantErr:  true,
		},
		{
			name:     "negative amount",
			amount:   "-1",
			decimals: 6,
			want:     0,
			wantErr:  true,
		},
		{
			name:     "bare decimal point",
			amount:   ".",
			decimals: 6,
			want:     0,
			wantErr:  true,
		},
		{
			name:     "leading decimal amount",
			amount:   ".5",
			decimals: 6,
			want:     500000,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConvertTokenAmountToBaseUnits(tt.amount, tt.decimals)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConvertTokenAmountToBaseUnits() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ConvertTokenAmountToBaseUnits() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWaitForConfirmationPollReturnsOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err := waitForConfirmationPoll(ctx, time.Hour)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForConfirmationPoll() error = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("waitForConfirmationPoll() took %s after cancellation", elapsed)
	}
}
