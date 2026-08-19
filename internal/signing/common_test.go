// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"
	"testing"
)

func TestCleanSubmitError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "logic rejection with struct dump",
			err:  fmt.Errorf(`HTTP 400: {"data":{"eval-states":[{}],"group-index":0,"pc":17},"message":"transaction {_struct:{} Sig:[0 0 0] Lsig:{Logic:[12 38 1]} Args:[[186 0 153]]} Txn:{Type:pay}} invalid : transaction 6XDV3KPBGTZKUWMY7B6AUXUJZKMPQORACVJFF2JU5AR2XWKX6MKQ: rejected by logic err=cannot load arg[1] of 1. Details: pc=17"}`),
			want: "transaction 6XDV3KPBGTZKUWMY7B6AUXUJZKMPQORACVJFF2JU5AR2XWKX6MKQ: rejected by logic err=cannot load arg[1] of 1. Details: pc=17",
		},
		{
			name: "overspend error",
			err:  fmt.Errorf(`HTTP 400: {"message":"transaction {_struct:{} ...} invalid : transaction TXID: overspend"}`),
			want: "transaction TXID: overspend",
		},
		{
			name: "unrelated error passes through",
			err:  fmt.Errorf("connection refused"),
			want: "connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanSubmitError(tt.err)
			if got.Error() != tt.want {
				t.Errorf("cleanSubmitError() = %q, want %q", got.Error(), tt.want)
			}
		})
	}
}
