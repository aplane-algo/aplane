// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package harness

import (
	"context"
	"crypto/sha512"
	"fmt"
	"math"
	"math/bits"
	"os"
	"strings"

	"github.com/algorand/falcon"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	algomnemonic "github.com/algorand/go-algorand-sdk/v2/mnemonic"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	nativefalconops "github.com/aplane-algo/aplane/internal/signing/falcon1024/signerops"
)

const feeFactorScale = uint64(1_000_000)

// TransactionAuthorizer is the integration-harness boundary for an account
// that prepares authorization-dependent fees and signs transactions. Fees
// must be prepared before a group ID is computed.
type TransactionAuthorizer interface {
	GetAddress() string
	PrepareTransaction(txn types.Transaction, minFee uint64) (types.Transaction, error)
	SignTransaction(txn types.Transaction) (string, []byte, error)
}

type nativeFalconAuthorizer struct {
	address    types.Address
	publicKey  falcon.PublicKey
	privateKey falcon.PrivateKey
	salt       byte
}

// FundTestAccount funds test accounts and directly authorizes test-fixture
// transactions. TEST_FUNDING_MNEMONIC always denotes a protocol-native
// Falcon-1024 account; it is never interpreted as an Ed25519 mnemonic.
type FundTestAccount struct {
	client     *algod.Client
	authorizer *nativeFalconAuthorizer
}

// NewFundTestAccount creates a native Falcon funding helper from
// TEST_FUNDING_MNEMONIC.
func NewFundTestAccount(client *algod.Client) (*FundTestAccount, error) {
	mnemonicWords := strings.TrimSpace(os.Getenv("TEST_FUNDING_MNEMONIC"))
	if mnemonicWords == "" {
		return nil, fmt.Errorf("TEST_FUNDING_MNEMONIC not set")
	}
	authorizer, err := nativeFalconAuthorizerFromMnemonic(mnemonicWords)
	if err != nil {
		return nil, fmt.Errorf("invalid native Falcon funding mnemonic: %w", err)
	}
	return &FundTestAccount{client: client, authorizer: authorizer}, nil
}

// NativeFundingAddressFromMnemonic derives the protocol-native Falcon-1024
// address represented by an Algorand 25-word recovery mnemonic.
func NativeFundingAddressFromMnemonic(mnemonicWords string) (string, error) {
	authorizer, err := nativeFalconAuthorizerFromMnemonic(mnemonicWords)
	if err != nil {
		return "", err
	}
	defer authorizer.zero()
	return authorizer.address.String(), nil
}

func nativeFalconAuthorizerFromMnemonic(mnemonicWords string) (*nativeFalconAuthorizer, error) {
	if len(strings.Fields(mnemonicWords)) != nativefalcon.MnemonicWordCount {
		return nil, fmt.Errorf("native Falcon requires exactly %d mnemonic words", nativefalcon.MnemonicWordCount)
	}
	entropy, err := algomnemonic.ToKey(mnemonicWords)
	if err != nil {
		return nil, fmt.Errorf("decode mnemonic: %w", err)
	}
	defer securecrypto.ZeroBytes(entropy)

	seedInput := make([]byte, 0, len("PQK")+len(nativefalcon.Scheme)+len(entropy))
	seedInput = append(seedInput, "PQK"...)
	seedInput = append(seedInput, nativefalcon.Scheme...)
	seedInput = append(seedInput, entropy...)
	workingSeed := sha512.Sum512_256(seedInput)
	securecrypto.ZeroBytes(seedInput)
	defer securecrypto.ZeroBytes(workingSeed[:])

	publicKey, privateKey, err := falcon.GenerateKey(workingSeed[:])
	if err != nil {
		return nil, fmt.Errorf("derive native Falcon key: %w", err)
	}
	salt, address, err := nativefalcon.CanonicalAddress(publicKey[:])
	if err != nil {
		securecrypto.ZeroBytes(privateKey[:])
		return nil, err
	}
	return &nativeFalconAuthorizer{
		address:    address,
		publicKey:  publicKey,
		privateKey: privateKey,
		salt:       salt,
	}, nil
}

func (a *nativeFalconAuthorizer) zero() {
	if a == nil {
		return
	}
	securecrypto.ZeroBytes(a.privateKey[:])
}

// PrepareTransaction adds the native-PQ fee-factor contribution. Callers that
// form a group must prepare every transaction before computing the group ID.
func (f *FundTestAccount) PrepareTransaction(txn types.Transaction, minFee uint64) (types.Transaction, error) {
	if f == nil || f.authorizer == nil {
		return types.Transaction{}, fmt.Errorf("native Falcon funding account is not initialized")
	}
	contribution, err := scaleFeeFactor(minFee, nativefalcon.PQFeeContribution)
	if err != nil {
		return types.Transaction{}, err
	}
	if uint64(txn.Fee) > math.MaxUint64-contribution {
		return types.Transaction{}, fmt.Errorf("native Falcon transaction fee overflows uint64")
	}
	txn.Fee = types.MicroAlgos(uint64(txn.Fee) + contribution)
	return txn, nil
}

func scaleFeeFactor(minFee, factor uint64) (uint64, error) {
	if minFee == 0 {
		minFee = 1_000
	}
	hi, lo := bits.Mul64(minFee, factor)
	if hi >= feeFactorScale {
		return 0, fmt.Errorf("native Falcon fee contribution overflows uint64")
	}
	quotient, remainder := bits.Div64(hi, lo, feeFactorScale)
	if remainder != 0 {
		if quotient == math.MaxUint64 {
			return 0, fmt.Errorf("native Falcon fee contribution overflows uint64")
		}
		quotient++
	}
	return quotient, nil
}

// SignTransaction authorizes a fee-prepared transaction with native Falcon.
func (f *FundTestAccount) SignTransaction(txn types.Transaction) (string, []byte, error) {
	if f == nil || f.authorizer == nil {
		return "", nil, fmt.Errorf("native Falcon funding account is not initialized")
	}
	stxn, err := nativefalconops.AuthorizeTransaction(
		&f.authorizer.privateKey,
		f.authorizer.publicKey[:],
		f.authorizer.salt,
		txn,
		f.authorizer.address,
	)
	if err != nil {
		return "", nil, err
	}
	return crypto.GetTxID(txn), msgpack.Encode(stxn), nil
}

// PrepareAndSignTransaction prepares native-PQ fees and signs a standalone
// transaction. Group callers must use PrepareTransaction before grouping.
func (f *FundTestAccount) PrepareAndSignTransaction(txn types.Transaction, minFee uint64) (string, []byte, error) {
	prepared, err := f.PrepareTransaction(txn, minFee)
	if err != nil {
		return "", nil, err
	}
	return f.SignTransaction(prepared)
}

// FundMicroAlgos sends an exact amount of microAlgos to a test account.
func (f *FundTestAccount) FundMicroAlgos(recipientAddress string, amountMicroAlgos uint64) (string, error) {
	sp, err := f.client.SuggestedParams().Do(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to get suggested params: %w", err)
	}
	txn, err := transaction.MakePaymentTxn(
		f.GetAddress(), recipientAddress, amountMicroAlgos, nil, "", sp,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create payment transaction: %w", err)
	}
	txid, stxnBytes, err := f.PrepareAndSignTransaction(txn, sp.MinFee)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}
	if _, err := f.client.SendRawTransaction(stxnBytes).Do(context.Background()); err != nil {
		return "", fmt.Errorf("failed to submit transaction: %w", err)
	}
	return txid, nil
}

// GetAddress returns the native Falcon funding account address.
func (f *FundTestAccount) GetAddress() string {
	if f == nil || f.authorizer == nil {
		return ""
	}
	return f.authorizer.address.String()
}

// WaitForConfirmation waits for a transaction to be confirmed.
func (f *FundTestAccount) WaitForConfirmation(txid string) error {
	status, err := f.client.Status().Do(context.Background())
	if err != nil {
		return err
	}
	lastRound := status.LastRound
	for {
		txInfo, _, err := f.client.PendingTransactionInformation(txid).Do(context.Background())
		if err != nil {
			return err
		}
		if txInfo.ConfirmedRound > 0 {
			return nil
		}
		status, err = f.client.StatusAfterBlock(lastRound).Do(context.Background())
		if err != nil {
			return err
		}
		lastRound = status.LastRound
	}
}

// FundMicroAlgosAndWait funds an account and waits for confirmation.
func (f *FundTestAccount) FundMicroAlgosAndWait(recipientAddress string, amountMicroAlgos uint64) error {
	txid, err := f.FundMicroAlgos(recipientAddress, amountMicroAlgos)
	if err != nil {
		return err
	}
	if err := f.WaitForConfirmation(txid); err != nil {
		return fmt.Errorf("funding transaction %s failed to confirm: %w", txid, err)
	}
	return nil
}
