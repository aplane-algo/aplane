// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"

	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// approvalBinding records what an approval decision covered, so signing can
// prove it signs exactly that: the approval gate binds the plan when it
// passes, and every signing path checks the binding just before it signs.
// Nothing between approval and signing may change the group.
type approvalBinding struct {
	bound  bool
	digest [32]byte
}

// approvalDigest hashes everything an approval decision covers: each
// transaction of the final group, the bytes of every passthrough slot, which
// slots are foreign, and the key that signs each request.
func approvalDigest(req signerapi.GroupSignRequest, plan *PlanResult) [32]byte {
	h := sha256.New()
	writeField := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	writeField([]byte("aplane.approval-binding.v1"))
	writeField(binary.BigEndian.AppendUint64(nil, uint64(len(plan.AllTxns))))
	for _, txn := range plan.AllTxns {
		writeField(txnutil.EncodeWithPrefix(txn))
	}
	writeIndexed := func(label string, indices []int, value func(int) []byte) {
		writeField([]byte(label))
		writeField(binary.BigEndian.AppendUint64(nil, uint64(len(indices))))
		for _, i := range indices {
			writeField(binary.BigEndian.AppendUint64(nil, uint64(i)))
			writeField(value(i))
		}
	}
	writeIndexed("passthrough", sortedKeys(plan.PassthroughIndices), func(i int) []byte { return plan.PassthroughSignedTxns[i] })
	writeIndexed("foreign", sortedKeys(plan.ForeignIndices), func(int) []byte { return nil })
	requests := make([]int, len(req.Requests))
	for i := range requests {
		requests[i] = i
	}
	writeIndexed("auth", requests, func(i int) []byte { return []byte(req.Requests[i].AuthAddress) })
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func sortedKeys(set map[int]bool) []int {
	keys := make([]int, 0, len(set))
	for k, ok := range set {
		if ok {
			keys = append(keys, k)
		}
	}
	sort.Ints(keys)
	return keys
}

// bindApproval records digest, computed before the approval gate ran, as
// what the approval covered.
func (p *PlanResult) bindApproval(digest [32]byte) {
	p.approval = approvalBinding{bound: true, digest: digest}
}

// checkApprovalBinding refuses to sign unless the plan was approved and is
// still exactly what the approval covered.
func checkApprovalBinding(req signerapi.GroupSignRequest, plan *PlanResult) *ServiceError {
	if plan == nil || !plan.approval.bound {
		return internal("refusing to sign: the transaction group has no approval decision")
	}
	if approvalDigest(req, plan) != plan.approval.digest {
		return internal("refusing to sign: the transaction group changed after it was approved")
	}
	return nil
}

// componentApprovalDigest hashes what a user-component approval covers: the
// frozen group's exact bytes, the key that signs, and every target's slot,
// transaction ID, and signed message.
func componentApprovalDigest(plan *ComponentSignPlan) [32]byte {
	h := sha256.New()
	writeField := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	writeField([]byte("aplane.component-approval-binding.v1"))
	writeField([]byte(plan.ComponentKey))
	if plan.Group != nil {
		writeField(plan.Group.GroupHash[:])
		for _, entry := range plan.Group.Entries {
			writeField(entry.Raw)
		}
	}
	for _, target := range plan.Targets {
		writeField(binary.BigEndian.AppendUint64(nil, uint64(target.TargetIndex)))
		writeField([]byte(target.Sender))
		writeField(target.TxID[:])
		writeField(target.Message[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
