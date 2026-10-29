// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// rotatingPhase selects the phase-specific admission rules. Prepare and sign
// share one normalized representation and one admission routine; they
// differ only in what the rotating slot's rekey_to and the group IDs must be.
type rotatingPhase int

const (
	rotatingPrepare rotatingPhase = iota
	rotatingSign
)

// rotatingSlots is a rotating request normalized into the ordinary slot
// grammar, which the shared planning, approval and execution steps consume.
//
//   - Requests are sign-mode slots: every owned slot's AuthAddress is its
//     effective signing key, resolved from an omitted auth_address to the
//     sender before any ordinary classification runs, and the rotating
//     slot's AuthAddress is the rotating account, its policy and signing
//     selector. TxnBytesHex is the presented bytes.
//   - Txns and Raw are the presented transactions and their canonical bytes.
//   - Rotating is the rotating slot's index; Owned the ordinary slots'
//     indexes, ascending.
type rotatingSlots struct {
	Requests []signerapi.SignRequest
	Txns     []types.Transaction
	Raw      [][]byte
	Rotating int
	Owned    []int
}

// normalizeRotatingSlots decodes and admits a rotating request's user slots.
// The rules, in proposal order:
//
//   - Exactly one slot's sender is the rotating account. It carries no
//     auth_address and no lsig_args, and passes validateRotatingSpend.
//   - Every other slot is an owned slot, judged on its effective signing
//     key: held by this signer, not a rotating key type, not a witness or
//     guarded key type, and without bounded-authorization metadata, which
//     ordinary signing would plan rather than refuse and which cannot nest
//     inside this flow. A sender that is not held is fine when its
//     auth_address is.
//   - No slot is passthrough or foreign: signed_txn_hex, lsig_resources and
//     pq_scheme are refused by name.
//   - rekey_to: owned slots never carry one. On prepare the rotating slot
//     must not carry one either; the signer derives and sets it. On sign it
//     must, and the caller verifies it against the derived next stage.
//   - Every slot targets the rotating account's network and shares the
//     rotating slot's validity window exactly; the signer never rewrites a
//     window.
//   - On prepare every slot is ungrouped. On sign the caller compares the
//     presented group with the rebuilt one.
func normalizeRotatingSlots(snapshot PlannerRuntimeSnapshot, account types.Address, genesis []byte, requests []signerapi.SignRequest, phase rotatingPhase) (*rotatingSlots, *ServiceError) {
	slots := &rotatingSlots{
		Requests: make([]signerapi.SignRequest, len(requests)),
		Txns:     make([]types.Transaction, len(requests)),
		Raw:      make([][]byte, len(requests)),
		Rotating: -1,
		Owned:    []int{},
	}
	for i, request := range requests {
		fail := func(format string, args ...any) *ServiceError {
			return badRequest(fmt.Sprintf("transaction %d: ", i+1) + fmt.Sprintf(format, args...))
		}
		switch {
		case request.SignedTxnHex != "":
			return nil, fail("signed_txn_hex is not accepted; rotating groups contain only transactions this signer signs")
		case request.LsigResources != nil:
			return nil, fail("lsig_resources is not accepted; rotating groups contain no foreign or passthrough slots")
		case request.PQScheme != "":
			return nil, fail("pq_scheme is not accepted; rotating groups contain no foreign slots")
		case request.TxnBytesHex == "":
			return nil, fail("txn_bytes_hex is required")
		}
		raw, err := hex.DecodeString(request.TxnBytesHex)
		if err != nil {
			return nil, fail("invalid transaction hex")
		}
		txn, err := canonical.DecodeTXPrefixed(raw)
		if err != nil {
			return nil, fail("%v", err)
		}
		slots.Txns[i], slots.Raw[i] = txn, raw
		normalized := request
		normalized.TxnBytesHex = hex.EncodeToString(raw)
		normalized.TxnSender = txn.Sender.String()

		if txn.Sender == account {
			if slots.Rotating >= 0 {
				return nil, fail("a second transaction from the rotating account; one rotating spend per group is supported, multi-stage groups are not")
			}
			if request.AuthAddress != "" {
				return nil, fail("the rotating account's transaction takes no auth_address; the signer selects its stage")
			}
			if len(request.LsigArgs) > 0 {
				return nil, fail("rotating accounts take no LogicSig arguments")
			}
			if svcErr := validateRotatingSpend(txn, account, genesis); svcErr != nil {
				return nil, fail("%s", svcErr.Message)
			}
			switch {
			case phase == rotatingPrepare && !txn.RekeyTo.IsZero():
				return nil, fail("transaction must not set rekey_to; the signer sets it")
			case phase == rotatingSign && txn.RekeyTo.IsZero():
				return nil, fail("the prepared rotating transaction has no rekey target; prepare the spend again")
			}
			normalized.AuthAddress = account.String()
			slots.Rotating = i
		} else {
			if normalized.AuthAddress == "" {
				normalized.AuthAddress = txn.Sender.String()
			}
			if svcErr := admitOwnedSlot(snapshot, i, normalized.AuthAddress, txn); svcErr != nil {
				return nil, svcErr
			}
			slots.Owned = append(slots.Owned, i)
		}
		if phase == rotatingPrepare && txn.Group != (types.Digest{}) {
			return nil, fail("transaction must be ungrouped; the signer forms the group")
		}
		slots.Requests[i] = normalized
	}
	if slots.Rotating < 0 {
		return nil, badRequest(fmt.Sprintf("no transaction is from the rotating account %s", account))
	}
	spend := slots.Txns[slots.Rotating]
	for _, i := range slots.Owned {
		txn := slots.Txns[i]
		switch {
		case txn.GenesisHash != spend.GenesisHash:
			return nil, badRequest(fmt.Sprintf("transaction %d targets a different network than the rotating account", i+1))
		case txn.FirstValid != spend.FirstValid || txn.LastValid != spend.LastValid:
			return nil, badRequest(fmt.Sprintf("transaction %d has validity rounds %d-%d; every transaction in a rotating group must share the rotating spend's rounds %d-%d", i+1, txn.FirstValid, txn.LastValid, spend.FirstValid, spend.LastValid))
		}
	}
	return slots, nil
}

// admitOwnedSlot applies the owned-slot rules to slot i, signed by authAddr.
func admitOwnedSlot(snapshot PlannerRuntimeSnapshot, i int, authAddr string, txn types.Transaction) *ServiceError {
	fail := func(format string, args ...any) *ServiceError {
		return badRequest(fmt.Sprintf("transaction %d: ", i+1) + fmt.Sprintf(format, args...))
	}
	if _, err := types.DecodeAddress(authAddr); err != nil {
		return fail("invalid auth_address: %v", err)
	}
	if _, held := snapshot.KeyFiles[authAddr]; !held {
		return fail("no key found for address: %s", authAddr)
	}
	keyType := snapshot.KeyTypes[authAddr]
	if keyType == "" {
		return internal(fmt.Sprintf("transaction %d: missing key type metadata for auth address %s", i+1, authAddr))
	}
	if err := rejectRotatingKeyType(i, keyType); err != nil {
		return err
	}
	if message, rejected := cosignerSignRejectMessage(keyType); rejected {
		return fail("%s", message)
	}
	if snapshot.KeyMetadata[authAddr].BoundedAuthorization != nil {
		return fail("bounded authorization keys cannot join a rotating group")
	}
	if !txn.RekeyTo.IsZero() {
		return fail("transactions in a rotating group other than the rotating spend must not set rekey_to")
	}
	return nil
}

// buildRotatingPlan rebuilds the canonical group from normalized slots with
// the shared builder: the same resource solver, fee allocator and group ID
// computation /sign uses, with every LogicSig slot, the rotating one
// included, as a fee target. It works on copies with the group IDs cleared,
// so it is a pure function of the slots' other fields: prepare builds the
// group, and sign proves a presented group is the one it would build.
func (s *Service) buildRotatingPlan(snapshot PlannerRuntimeSnapshot, slots *rotatingSlots) (*PlanResult, *ServiceError) {
	working := make([]types.Transaction, len(slots.Txns))
	copy(working, slots.Txns)
	for i := range working {
		working[i].Group = types.Digest{}
	}
	requests := make([]signerapi.SignRequest, len(slots.Requests))
	copy(requests, slots.Requests)
	final, err := s.Planner.finalizeGroup(groupFinalization{
		Snapshot:           snapshot,
		Requests:           requests,
		Txns:               working,
		PassthroughIndices: map[int]bool{},
		ForeignIndices:     map[int]bool{},
	})
	if err != nil {
		return nil, err
	}
	authKeyTypes := make([]string, len(requests))
	for i, request := range requests {
		authKeyTypes[i] = snapshot.KeyTypes[request.AuthAddress]
	}
	return &PlanResult{
		AllTxns:              final.AllTxns,
		DummyTxns:            final.DummyTxns,
		PassthroughIndices:   map[int]bool{},
		ForeignIndices:       map[int]bool{},
		LsigIndices:          final.LsigIndices,
		DummiesNeeded:        final.DummiesNeeded,
		LogicSigResourcePlan: final.ResourcePlan,
		FeeInfo:              final.FeeInfo,
		NeedsRegroup:         final.NeedsRegroup,
		AuthKeyTypes:         authKeyTypes,
		BoundedItems:         final.BoundedItems,
	}, nil
}

// compareRebuiltRotatingGroup is rule 5 on the group form: every presented
// user slot equals its rebuilt slot byte for byte, and the presented group
// ID is the complete rebuilt group's, dummies included. full is the legacy
// form's complete presented group, compared in full; nil for the group form,
// whose dummies are bound by the group ID instead.
func compareRebuiltRotatingGroup(slots *rotatingSlots, plan *PlanResult, full [][]byte) *ServiceError {
	users := len(slots.Raw)
	if len(plan.AllTxns) < users {
		return internal("rebuilt rotating group is shorter than its user slots")
	}
	if len(plan.AllTxns) > types.MaxTxGroupSize {
		return badRequest(fmt.Sprintf("group has %d transactions, maximum is %d", len(plan.AllTxns), types.MaxTxGroupSize))
	}
	var rebuiltGroup types.Digest
	if len(plan.AllTxns) > 1 {
		rebuiltGroup = plan.AllTxns[0].Group
	}
	for i := 0; i < users; i++ {
		if slots.Txns[i].Group != rebuiltGroup {
			return badRequest(fmt.Sprintf("transaction %d carries a group ID that is not the group the signer would build from these transactions (dummies, fees and group ID must be exactly the prepared ones)", i+1))
		}
		if !bytes.Equal(txnutil.EncodeWithPrefix(plan.AllTxns[i]), slots.Raw[i]) {
			return badRequest(fmt.Sprintf("transaction %d differs from the group the signer would build (dummies, fees and group ID must be exactly the prepared ones)", i+1))
		}
	}
	if full == nil {
		return nil
	}
	if len(full) != len(plan.AllTxns) {
		return badRequest(fmt.Sprintf("group has %d transactions; the spend needs %d", len(full), len(plan.AllTxns)))
	}
	for i := users; i < len(full); i++ {
		if !bytes.Equal(txnutil.EncodeWithPrefix(plan.AllTxns[i]), full[i]) {
			return badRequest(fmt.Sprintf("transaction %d differs from the group the signer would build (dummies, fees and group ID must be exactly the prepared ones)", i+1))
		}
	}
	return nil
}

// rotatingPrepareRequests normalizes a prepare request's two forms into one
// slot list: the single-transaction form is the group form with one entry.
func rotatingPrepareRequests(req signerapi.RotatingPrepareRequest) []signerapi.SignRequest {
	if req.Requests != nil {
		return req.Requests
	}
	return []signerapi.SignRequest{{TxnBytesHex: req.TxnBytesHex}}
}

// rotatingSignRequests normalizes a sign request's two forms into one slot
// list. The legacy form is the complete prepared group: it is validated as a
// complete canonical group first, exactly as before, and its first entry is
// the one user slot. The complete group is returned so rule 5 can compare
// its dummies too; it is nil for the group form.
func rotatingSignRequests(req signerapi.RotatingSignRequest) ([]signerapi.SignRequest, [][]byte, *ServiceError) {
	if req.Requests != nil {
		return req.Requests, nil, nil
	}
	group, err := canonical.DecodeGroupHex(req.Transactions)
	if err != nil {
		return nil, nil, badRequest(err.Error())
	}
	full := make([][]byte, len(group.Entries))
	for i, entry := range group.Entries {
		full[i] = entry.Raw
	}
	return []signerapi.SignRequest{{TxnBytesHex: hex.EncodeToString(full[0])}}, full, nil
}

// rotationSlot reports the rotating slot of a group.
func rotationSlot(index int, stage uint64, target types.Address) signerapi.RotationSlot {
	return signerapi.RotationSlot{Index: index, Stage: stage, Target: stage + 1, RekeyTo: target.String()}
}
