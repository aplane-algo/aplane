// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package authorization validates and completes external bounded-admin
// ceremonies. It is helper-side code and intentionally links Falcon.
package authorization

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	boundedmessage "github.com/aplane-algo/aplane/internal/boundedadmin/message"
	boundedprogram "github.com/aplane-algo/aplane/internal/boundedadmin/program"
	boundedprotocol "github.com/aplane-algo/aplane/internal/boundedadmin/protocol"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/lsig"
	"github.com/aplane-algo/aplane/internal/sentry/canonical"
	"github.com/aplane-algo/aplane/internal/sentry/verify"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/internal/witness"
)

// ValidatedRequest holds decoded ceremony state. Partial is short-lived
// signing authority even though it contains no private key.
type ValidatedRequest struct {
	Request           boundedprotocol.Request
	Group             *canonical.Group
	Partial           types.SignedTxn
	Message           [sha512.Size256]byte
	PublicKey         []byte
	ProgramBinding    [sha512.Size256]byte
	SpendingPublicKey []byte
	NetworkVerified   bool
}

// ValidateRequest independently validates the finalized transaction group,
// bounded program, and signer-produced Falcon spending partial.
func ValidateRequest(request boundedprotocol.Request) (*ValidatedRequest, error) {
	if err := boundedprotocol.ValidateEnvelope(request); err != nil {
		return nil, err
	}
	partial := request.Payload.Partial
	if partial.Schema != signerapi.BoundedAdminPartialSchemaV1 {
		return nil, fmt.Errorf("unsupported signer partial schema %q", partial.Schema)
	}
	if partial.Operation != signerapi.BoundedAdminOperationRekey {
		return nil, fmt.Errorf("unsupported bounded-admin operation %q", partial.Operation)
	}
	if len(partial.Transactions) == 0 || len(partial.Transactions) > types.MaxTxGroupSize || len(partial.PartialSigned) != len(partial.Transactions) || partial.TargetIndex != 0 {
		return nil, fmt.Errorf("bounded-admin partial group shape is invalid")
	}
	group, err := canonical.DecodeGroupHex(partial.Transactions)
	if err != nil {
		return nil, fmt.Errorf("decode bounded-admin group: %w", err)
	}
	genesisHash, err := boundedmeta.DecodeCanonicalHex("genesis hash", request.Payload.GenesisHashHex, len(types.Digest{}), len(types.Digest{}))
	if err != nil {
		return nil, err
	}
	networkVerified, err := validateNetworkContext(request.Payload.Network, genesisHash)
	if err != nil {
		return nil, err
	}
	for i, entry := range group.Entries {
		if !bytes.Equal(entry.Txn.GenesisHash[:], genesisHash) {
			return nil, fmt.Errorf("transaction %d genesis hash does not match request context", i)
		}
	}
	target := group.Entries[0].Txn
	if err := validatePureRekey(target); err != nil {
		return nil, err
	}
	if err := validateDummySlots(group, partial.PartialSigned); err != nil {
		return nil, err
	}
	partialSigned, err := decodePartial(partial.PartialSigned[0], target, partial.Authorization.BaseSignatureArgCount)
	if err != nil {
		return nil, err
	}
	currentAuth, err := types.DecodeAddress(request.Payload.CurrentAuthAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid current authorization address: %w", err)
	}
	if algocrypto.AddressFromProgram(partialSigned.Lsig.Logic) != currentAuth {
		return nil, fmt.Errorf("partial LogicSig address does not match current authorization address")
	}
	publicKey, spendingKey, binding, message, err := validateAuthorizationMetadata(partial.Authorization, target, partialSigned)
	if err != nil {
		return nil, err
	}
	return &ValidatedRequest{
		Request: request, Group: group, Partial: partialSigned, Message: message,
		PublicKey: publicKey, ProgramBinding: binding, SpendingPublicKey: spendingKey,
		NetworkVerified: networkVerified,
	}, nil
}

// Complete validates a helper response, appends the Falcon contract-admin
// signature at k, signs signer-added dummy slots, and returns a complete group.
func Complete(request boundedprotocol.Request, response boundedprotocol.Response) ([][]byte, []types.Transaction, error) {
	validated, err := ValidateRequest(request)
	if err != nil {
		return nil, nil, err
	}
	if response.Schema != boundedprotocol.ResponseSchemaV1 {
		return nil, nil, &boundedprotocol.Error{Code: boundedprotocol.ErrorUnsupportedResponseSchema, Err: fmt.Errorf("unsupported bounded-admin response schema %q", response.Schema)}
	}
	metadata := request.Payload.Partial.Authorization
	if response.RequestHashHex != request.RequestHashHex || response.ContractAdminKeyID != metadata.ContractAdminKeyID {
		return nil, nil, fmt.Errorf("contract-admin signature response does not match request")
	}
	signature, err := boundedmeta.DecodeCanonicalHex("contract-admin signature", response.SignatureHex, 1, boundedmeta.FalconAdminSignatureSize)
	if err != nil {
		return nil, nil, err
	}
	if err := verify.VerifyFalcon1024(validated.PublicKey, validated.Message[:], signature); err != nil {
		return nil, nil, fmt.Errorf("contract-admin signature is invalid: %w", err)
	}

	signed := make([][]byte, len(validated.Group.Entries))
	txns := make([]types.Transaction, len(validated.Group.Entries))
	for i, entry := range validated.Group.Entries {
		txns[i] = entry.Txn
		if i == 0 {
			completed := validated.Partial
			completed.Lsig.Args, err = completeAdminArgs(completed.Lsig.Args, metadata.AdminSignatureArgIndex, signature)
			if err != nil {
				return nil, nil, err
			}
			signed[i] = msgpack.Encode(completed)
			continue
		}
		dummy, err := signing.SignDummyTransaction(entry.Txn)
		if err != nil {
			return nil, nil, fmt.Errorf("sign bounded-admin dummy %d: %w", i, err)
		}
		signed[i] = msgpack.Encode(dummy)
	}
	return signed, txns, nil
}

func completeAdminArgs(partialArgs [][]byte, adminIndex int, signature []byte) ([][]byte, error) {
	if adminIndex < len(partialArgs) {
		return nil, fmt.Errorf("contract-admin argument index does not follow the partial arguments")
	}
	completed := make([][]byte, len(partialArgs), adminIndex+1)
	copy(completed, partialArgs)
	for len(completed) < adminIndex {
		completed = append(completed, []byte{})
	}
	completed = append(completed, bytes.Clone(signature))
	return completed, nil
}

func validatePureRekey(txn types.Transaction) error {
	if txeffects.Classify(txn).Shape != txeffects.ShapePureRekey {
		return fmt.Errorf("bounded-admin target is not a pure rekey self-payment")
	}
	if txn.GenesisID == "" {
		return fmt.Errorf("bounded-admin network context is missing")
	}
	return nil
}

func validateNetworkContext(network string, genesisHash []byte) (bool, error) {
	if err := config.ValidateNetworkID(network); err != nil {
		return false, fmt.Errorf("bounded-admin network context is invalid: %w", err)
	}
	resolved, builtin := config.DefaultGenesisHashNetworkResolver().NetworkForGenesisHashBytes(genesisHash)
	if builtin {
		if network != resolved {
			return false, fmt.Errorf("bounded-admin network %q does not match canonical %s genesis hash", network, resolved)
		}
		return true, nil
	}
	if config.IsReservedNetworkID(network) {
		return false, fmt.Errorf("bounded-admin network %q does not match its canonical genesis hash", network)
	}
	// Custom mappings are requester-local configuration and are unavailable to
	// an air-gapped helper. The exact hash is still verified against every
	// transaction and committed by the request hash; only its display token is
	// explicitly left unverified.
	return false, nil
}

func validateDummySlots(group *canonical.Group, partialSigned []string) error {
	dummyAddress, err := lsig.DummyAddress()
	if err != nil {
		return fmt.Errorf("derive dummy address: %w", err)
	}
	for i := 1; i < len(group.Entries); i++ {
		if partialSigned[i] != "" {
			return fmt.Errorf("unexpected signed partial in dummy slot %d", i)
		}
		txn := group.Entries[i].Txn
		if txn.Type != types.PaymentTx || txn.Sender != dummyAddress || txn.Receiver != dummyAddress || txn.Amount != 0 || txn.Fee != 0 || len(txn.Note) != 1 || txn.Note[0] != byte(i-1) || !txn.RekeyTo.IsZero() || !txn.CloseRemainderTo.IsZero() {
			return fmt.Errorf("transaction %d is not a canonical signer-added budget dummy", i)
		}
	}
	return nil
}

func decodePartial(value string, txn types.Transaction, baseArgCount int) (types.SignedTxn, error) {
	var partial types.SignedTxn
	raw, err := boundedmeta.DecodeCanonicalHex("partial signed transaction", value, 1, boundedprotocol.MaxRequestBytes)
	if err != nil {
		return partial, err
	}
	if err := msgpack.Decode(raw, &partial); err != nil {
		return partial, fmt.Errorf("decode partial signed transaction: %w", err)
	}
	if !bytes.Equal(msgpack.Encode(partial), raw) || !bytes.Equal(txnutil.EncodeWithPrefix(partial.Txn), txnutil.EncodeWithPrefix(txn)) {
		return partial, fmt.Errorf("partial signed transaction is non-canonical or does not match finalized transaction")
	}
	if baseArgCount != 1 || len(partial.Lsig.Logic) == 0 || len(partial.Lsig.Args) != baseArgCount || partial.Lsig.Sig != (types.Signature{}) || len(partial.Lsig.Msig.Subsigs) != 0 || partial.Sig != (types.Signature{}) || len(partial.Msig.Subsigs) != 0 {
		return partial, fmt.Errorf("partial must contain exactly the declared Falcon spending arguments and no contract-admin placeholder")
	}
	return partial, nil
}

func validateAuthorizationMetadata(metadata signerapi.BoundedAdminMetadata, txn types.Transaction, partial types.SignedTxn) ([]byte, []byte, [sha512.Size256]byte, [sha512.Size256]byte, error) {
	var binding [sha512.Size256]byte
	var message [sha512.Size256]byte
	if metadata.AdminSignatureArgIndex < metadata.BaseSignatureArgCount || metadata.AdminSignatureArgIndex > 255 {
		return nil, nil, binding, message, fmt.Errorf("contract-admin argument index is invalid")
	}
	publicKey, err := boundedmeta.DecodeCanonicalHex("contract admin public key", metadata.PublicKeyHex, boundedmeta.FalconAdminPublicKeySize, boundedmeta.FalconAdminPublicKeySize)
	if err != nil {
		return nil, nil, binding, message, err
	}
	wantID, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil || wantID != metadata.ContractAdminKeyID {
		return nil, nil, binding, message, fmt.Errorf("contract admin public identity is invalid")
	}
	spendingKey, err := boundedmeta.DecodeCanonicalHex("Falcon spending public key", metadata.SpendingPublicKeyHex, boundedmeta.FalconAdminPublicKeySize, boundedmeta.FalconAdminPublicKeySize)
	if err != nil {
		return nil, nil, binding, message, err
	}
	bindingBytes, err := boundedmeta.DecodeCanonicalHex("bounded program binding", metadata.ProgramBindingHex, len(binding), len(binding))
	if err != nil {
		return nil, nil, binding, message, err
	}
	copy(binding[:], bindingBytes)
	txID := algocrypto.TransactionID(txn)
	if metadata.TransactionID != algocrypto.TransactionIDString(txn) {
		return nil, nil, binding, message, fmt.Errorf("contract-admin transaction ID does not match finalized transaction")
	}
	message, err = boundedmessage.AdminMessage(boundedmessage.OperationRekey, binding[:], txID[:])
	if err != nil {
		return nil, nil, binding, message, err
	}
	if metadata.MessageHex != hex.EncodeToString(message[:]) {
		return nil, nil, binding, message, fmt.Errorf("contract-admin message does not match recomputed transcript")
	}
	if err := boundedprogram.Validate(partial.Lsig.Logic, boundedprogram.Expected{
		SpendingPublicKey: spendingKey,
		AdminPublicKey:    publicKey,
		ProgramBinding:    binding[:],
		BaseArgCount:      metadata.BaseSignatureArgCount,
		AdminArgIndex:     metadata.AdminSignatureArgIndex,
		MaxFee:            metadata.MaxFee,
		SpendEffects:      metadata.SpendEffects,
	}); err != nil {
		return nil, nil, binding, message, fmt.Errorf("validate bounded1 program: %w", err)
	}
	if err := verify.VerifyFalcon1024(spendingKey, txID[:], partial.Lsig.Args[0]); err != nil {
		return nil, nil, binding, message, fmt.Errorf("bounded1 spending signature is invalid: %w", err)
	}
	return publicKey, spendingKey, binding, message, nil
}
