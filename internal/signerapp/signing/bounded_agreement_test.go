// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

// The O4 agreement harness (account overlays design, invariant O4). Three places
// classify a bounded transaction: the rendered program, the argument layout's path
// masks, and this package's planner. For every shape of the general bounded type,
// the harness renders the real program, runs it in an offline interpreter on every
// transaction in a corpus under every combination of supplied, wrong and absent
// arguments, and requires the program to accept exactly when:
//
//   - the planner admits the transaction (classifyBoundedPath returns a path),
//   - the host's spending rules hold on that path, as an independent model below
//     (none on a rekey path: O11), and
//   - every slot the planner's assembly fills for that path (the required masks,
//     and a Merkle proof boundedDerivedArgs derives) holds the signer's value.
//
// Slots the planner leaves empty may hold anything: the program checks what each
// path needs and does not assert that an unused slot is empty. Mutants of the
// rendered programs are the negative control: each weakens one check, and must make
// the program accept something the planner refuses.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/avmsim"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/cosigner/message"
	"github.com/aplane-algo/aplane/internal/merkleallowlist"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/lsig/boundedaccount"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon1024 "github.com/aplane-algo/aplane/lsig/falcon1024"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

const (
	agUnlockRound uint64 = 5_000
	// agReportLimit caps the disagreements printed per shape; the count is exact.
	agReportLimit = 40
)

// The renderer's labels, which the layout check and the mutants edit. A renamed
// label makes every mutant that uses it fail, never pass silently.
const (
	agRekeyLabel  = "__aplane_bounded1_rekey"
	agSpendLabel  = "__aplane_bounded1_spend"
	agAcceptLabel = "__aplane_bounded1_accept"
)

var (
	agSpendingKey = bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize)
	agCosignerKey = bytes.Repeat([]byte{0x41}, boundedmeta.CosignerPublicKeySizeV1)
	agSender      = agAddress(0xA0)
	agListedA     = agAddress(0xA1)
	agListedB     = agAddress(0xA2)
	agUnlisted    = agAddress(0xB0)
	agRekeyTarget = agAddress(0xD1)
	// agRecipients is every list shape's recipient list, already in canonical order.
	agRecipients = agListedA.String() + "," + agListedB.String()
	// Close and clawback fields name a listed address, so no list check can be
	// what refuses them.
	agCloseTarget = agListedA
)

func agAddress(b byte) types.Address {
	var a types.Address
	for i := range a {
		a[i] = b
	}
	return a
}

// agTag is the modeled signature: a valid signature by key over data is this tag,
// and anything else is invalid. The two fixed keys are named rather than hashed,
// which keeps millions of runs cheap; any other key is hashed in full.
func agTag(key, data []byte) []byte {
	var id []byte
	switch {
	case bytes.Equal(key, agSpendingKey):
		id = []byte("spending")
	case bytes.Equal(key, agCosignerKey):
		id = []byte("cosigner")
	default:
		sum := sha256.Sum256(key)
		id = sum[:]
	}
	input := append(append([]byte("aplane-o4-signature/"), id...), '/')
	sum := sha256.Sum256(append(input, data...))
	return sum[:]
}

var agHooks = avmsim.Hooks{
	Falcon: func(data, sig, key []byte) bool { return bytes.Equal(sig, agTag(key, data)) },
}

// ---- the corpus ----

type agTxn struct {
	name   string
	txn    types.Transaction
	txid   [32]byte
	fields avmsim.Txn
	// receiver is the pay or axfer recipient; hasReceiver is false for other types.
	receiver    types.Address
	hasReceiver bool
}

// agTypeEnum is the AVM's TypeEnum for each transaction type. A type the inventory
// lists and this table lacks fails the corpus, so a new type gets a decision.
var agTypeEnum = map[types.TxType]uint64{
	"": 0, types.PaymentTx: 1, types.KeyRegistrationTx: 2, types.AssetConfigTx: 3, types.AssetTransferTx: 4,
	types.AssetFreezeTx: 5, types.ApplicationCallTx: 6, types.StateProofTx: 7, types.HeartbeatTx: 8,
}

func agInventoryTypes() ([]types.TxType, error) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "PROTOCOL_EFFECT_INVENTORY.json"))
	if err != nil {
		return nil, err
	}
	var inventory struct {
		TransactionTypes []struct {
			Name string `json:"name"`
			Wire string `json:"wire"`
		} `json:"transaction_types"`
	}
	if err := json.Unmarshal(data, &inventory); err != nil {
		return nil, err
	}
	var out []types.TxType
	for _, entry := range inventory.TransactionTypes {
		txType := types.TxType(entry.Wire)
		if _, ok := agTypeEnum[txType]; !ok {
			return nil, fmt.Errorf("inventory transaction type %q (%s) has no TypeEnum in the harness", entry.Wire, entry.Name)
		}
		out = append(out, txType)
	}
	if len(out) < len(agTypeEnum) {
		return nil, fmt.Errorf("inventory lists %d transaction types, the harness knows %d", len(out), len(agTypeEnum))
	}
	return out, nil
}

func agAddressName(a types.Address) string {
	switch a {
	case agSender:
		return "self"
	case agListedA:
		return "listed A"
	case agListedB:
		return "listed B"
	case agUnlisted:
		return "unlisted"
	}
	return a.String()
}

// agCorpus is every inventory transaction type, with and without each danger
// field; pay and axfer to self, to two listed recipients and to an unlisted one,
// with zero and nonzero amounts (an axfer of zero to self is the opt-in form);
// a fee under, at and over the ceiling; and FirstValid before and at the unlock
// round.
func agCorpus() ([]*agTxn, error) {
	type base struct {
		name     string
		txn      types.Transaction
		receiver *types.Address
	}
	var bases []base
	receivers := []types.Address{agSender, agListedA, agListedB, agUnlisted}
	txTypes, err := agInventoryTypes()
	if err != nil {
		return nil, err
	}
	for _, txType := range txTypes {
		switch txType {
		case types.PaymentTx:
			for _, receiver := range receivers {
				for _, amount := range []uint64{0, 1_000_000} {
					txn := types.Transaction{Type: txType}
					txn.Receiver, txn.Amount = receiver, types.MicroAlgos(amount)
					bases = append(bases, base{fmt.Sprintf("pay %d to %s", amount, agAddressName(receiver)), txn, &receiver})
				}
			}
		case types.AssetTransferTx:
			for _, receiver := range receivers {
				for _, amount := range []uint64{0, 5} {
					txn := types.Transaction{Type: txType}
					txn.XferAsset, txn.AssetReceiver, txn.AssetAmount = 31566704, receiver, amount
					bases = append(bases, base{fmt.Sprintf("axfer %d to %s", amount, agAddressName(receiver)), txn, &receiver})
				}
			}
		default:
			name := string(txType)
			if name == "" {
				name = "unknown type"
			}
			bases = append(bases, base{name, types.Transaction{Type: txType}, nil})
		}
	}
	var corpus []*agTxn
	for _, b := range bases {
		for danger := 0; danger < 16; danger++ {
			for _, fee := range []uint64{1_000, boundedaccount.MaxFee, boundedaccount.MaxFee + 1} {
				for _, firstValid := range []uint64{agUnlockRound - 1, agUnlockRound} {
					txn := b.txn
					txn.Sender = agSender
					txn.Fee = types.MicroAlgos(fee)
					txn.FirstValid, txn.LastValid = types.Round(firstValid), types.Round(firstValid+1_000)
					txn.GenesisID = "o4-harness"
					txn.GenesisHash = [32]byte{0x4f, 0x34}
					name := fmt.Sprintf("%s, fee %d, first valid %d", b.name, fee, firstValid)
					if danger&1 != 0 {
						txn.RekeyTo = agRekeyTarget
						name += ", RekeyTo"
					}
					if danger&2 != 0 {
						txn.CloseRemainderTo = agCloseTarget
						name += ", CloseRemainderTo"
					}
					if danger&4 != 0 {
						txn.AssetCloseTo = agCloseTarget
						name += ", AssetCloseTo"
					}
					if danger&8 != 0 {
						txn.AssetSender = agCloseTarget
						name += ", AssetSender"
					}
					tx := &agTxn{name: name, txn: txn}
					copy(tx.txid[:], algocrypto.TransactionID(txn))
					if b.receiver != nil {
						tx.receiver, tx.hasReceiver = *b.receiver, true
					}
					tx.fields = agFields(txn, tx.txid)
					corpus = append(corpus, tx)
				}
			}
		}
	}
	return corpus, nil
}

// agFields is what the program sees. Fields of another transaction type read as
// their zero values, as on the AVM.
func agFields(txn types.Transaction, txid [32]byte) avmsim.Txn {
	address := func(a types.Address) avmsim.Value { return avmsim.B(bytes.Clone(a[:])) }
	return avmsim.Txn{
		"TxID":             avmsim.B(bytes.Clone(txid[:])),
		"Sender":           address(txn.Sender),
		"Fee":              avmsim.U(uint64(txn.Fee)),
		"FirstValid":       avmsim.U(uint64(txn.FirstValid)),
		"LastValid":        avmsim.U(uint64(txn.LastValid)),
		"TypeEnum":         avmsim.U(agTypeEnum[txn.Type]),
		"RekeyTo":          address(txn.RekeyTo),
		"Receiver":         address(txn.Receiver),
		"Amount":           avmsim.U(uint64(txn.Amount)),
		"CloseRemainderTo": address(txn.CloseRemainderTo),
		"XferAsset":        avmsim.U(uint64(txn.XferAsset)),
		"AssetAmount":      avmsim.U(txn.AssetAmount),
		"AssetReceiver":    address(txn.AssetReceiver),
		"AssetCloseTo":     address(txn.AssetCloseTo),
		"AssetSender":      address(txn.AssetSender),
	}
}

// ---- accounts ----

type agRole int

const (
	agRoleBase agRole = iota
	agRoleProof
	agRoleCosigner
)

// agState is what one argument slot holds.
type agState int

const (
	agAbsent agState = iota
	agValid
	agWrongKey     // a valid-looking signature by the other key
	agWrongMessage // the cosigner's key over the transaction ID instead of its message
	agWrongEntry   // a real proof for another listed recipient
)

var agStateNames = map[agState]string{
	agAbsent: "absent", agValid: "valid", agWrongKey: "wrong key", agWrongMessage: "wrong message", agWrongEntry: "wrong entry",
}

var agRoleNames = map[agRole]string{agRoleBase: "base", agRoleProof: "proof", agRoleCosigner: "cosigner"}

type agSlot struct {
	boundedmeta.ArgumentSlot
	role agRole
}

// agPlan is the expected verdict for one transaction, from the planner and the
// host model.
type agPlan struct {
	admit bool
	// why is the path when admitted, else the planner's or host model's reason.
	why  string
	path boundedPath
	// required marks, by slot index, the slots the signer fills on this path.
	required []bool
	// assembled is the signer's own argument vector, when admitted.
	assembled [][]byte
}

type agAccount struct {
	shape       boundedaccount.Shape
	name        string
	teal        string
	program     *avmsim.Program
	metadata    *boundedmeta.Metadata
	keyMaterial *coresigning.KeyMaterial
	cosignerKey []byte
	listed      map[types.Address]bool
	// proofs holds the list's proof for each listed recipient.
	proofs map[types.Address][]byte
	slots  []agSlot
	plans  []agPlan
}

func agParams(shape boundedaccount.Shape) map[string]string {
	spend := make([]string, len(shape.Spend))
	for i, effect := range shape.Spend {
		spend[i] = string(effect)
	}
	params := map[string]string{
		boundedaccount.ParameterSpendEffects:   strings.Join(spend, ","),
		boundedaccount.ParameterRekeyAuthority: shape.Rekey,
	}
	if shape.Encoding != "" {
		params[boundedaccount.ParameterRecipients] = agRecipients
		params[boundedaccount.ParameterListEncoding] = shape.Encoding
	}
	if shape.Timelock {
		params[boundedaccount.ParameterUnlockRound] = fmt.Sprint(agUnlockRound)
	}
	if shape.Cosigner {
		params[composeddsa.BoundedCosignerPublicKeyParameter] = hex.EncodeToString(agCosignerKey)
	}
	return params
}

// agList is the Merkle list every list shape is built over, with its proofs
// built once: the tree has 65,536 leaves, so building it per shape is slow.
type agList struct {
	recipients string
	proof      map[types.Address][]byte
}

func newAgList() (*agList, error) {
	list := &agList{recipients: agRecipients, proof: map[types.Address][]byte{}}
	for _, listed := range []types.Address{agListedA, agListedB} {
		proof, err := merkleallowlist.ProofForAddressParam(agRecipients, listed)
		if err != nil {
			return nil, err
		}
		list.proof[listed] = proof
	}
	return list, nil
}

// proofs returns the list's proofs for an account's stored recipients, which must
// be the harness's list.
func (list *agList) proofs(stored string) (map[types.Address][]byte, error) {
	if stored != list.recipients {
		return nil, fmt.Errorf("stored recipients %q are not the harness's list %q", stored, list.recipients)
	}
	return list.proof, nil
}

func agBuildAccount(provider *boundedaccount.Provider, list *agList, shape boundedaccount.Shape, corpus []*agTxn) (*agAccount, error) {
	name := shape.Descriptor()
	// Generation resolves the request first and then uses, and persists, only the
	// resolved values; the harness does the same.
	instance, err := provider.ResolveInstance(agParams(shape))
	if err != nil {
		return nil, fmt.Errorf("%s: ResolveInstance: %w", name, err)
	}
	params := instance.Values
	teal, err := provider.GenerateTEAL(agSpendingKey, params)
	if err != nil {
		return nil, fmt.Errorf("%s: GenerateTEAL: %w", name, err)
	}
	program, err := avmsim.Assemble(teal)
	if err != nil {
		return nil, fmt.Errorf("%s: assemble: %w", name, err)
	}
	// The bytecode length only feeds generation's resource backstop; the harness
	// runs the source, so a placeholder of a realistic size stands in for it.
	metadata, err := provider.BuildBoundedAuthorizationMetadata(agSpendingKey, params, make([]byte, 3_000))
	if err != nil {
		return nil, fmt.Errorf("%s: BuildBoundedAuthorizationMetadata: %w", name, err)
	}
	a := &agAccount{
		shape: shape, name: name, teal: teal, program: program, metadata: metadata,
		keyMaterial: &coresigning.KeyMaterial{
			Type: provider.KeyType(), PublicKey: agSpendingKey, Parameters: params, BoundedAuthorization: metadata,
		},
		listed: map[types.Address]bool{}, proofs: map[types.Address][]byte{},
	}
	if len(metadata.RuntimeArgs) != 0 {
		return nil, fmt.Errorf("%s: the harness does not model runtime arguments", name)
	}
	if metadata.Cosigner != nil {
		if a.cosignerKey, err = hex.DecodeString(metadata.Cosigner.PublicKeyHex); err != nil {
			return nil, err
		}
		if !bytes.Equal(a.cosignerKey, agCosignerKey) {
			return nil, fmt.Errorf("%s: stored cosigner key differs from the requested one", name)
		}
	}
	if shape.Encoding != "" {
		for _, listed := range []types.Address{agListedA, agListedB} {
			a.listed[listed] = true
		}
		if shape.Encoding == boundedaccount.EncodingMerkle {
			if a.proofs, err = list.proofs(params[boundedaccount.ParameterRecipients]); err != nil {
				return nil, err
			}
		}
	}
	for _, slot := range metadata.ArgumentLayout {
		s := agSlot{ArgumentSlot: slot}
		switch slot.Source {
		case boundedmeta.ArgSourceBaseSignature:
			s.role = agRoleBase
		case boundedmeta.ArgSourceDerived:
			s.role = agRoleProof
		case boundedmeta.ArgSourceCosigner:
			s.role = agRoleCosigner
		default:
			return nil, fmt.Errorf("%s: slot %q has source %q the harness does not model", name, slot.Name, slot.Source)
		}
		if slot.Index != len(a.slots) {
			return nil, fmt.Errorf("%s: slot %q has index %d, want %d", name, slot.Name, slot.Index, len(a.slots))
		}
		a.slots = append(a.slots, s)
	}
	derivedMemo := map[string]agDerived{}
	for _, tx := range corpus {
		plan, err := a.plan(tx, derivedMemo)
		if err != nil {
			return nil, fmt.Errorf("%s / %s: %w", name, tx.name, err)
		}
		a.plans = append(a.plans, plan)
	}
	return a, nil
}

type agDerived struct {
	values [][]byte
	err    *ServiceError
}

// agHostRule is the host's spending rules, written from the shape rather than read
// from the program: the recipient must be the account itself or on its list, and
// a timelock's unlock round must have arrived. It returns "" when they hold. No
// host rule applies on a rekey path (O11), so only the spend path calls it.
func (a *agAccount) agHostRule(tx *agTxn) string {
	if a.shape.Timelock && uint64(tx.txn.FirstValid) < agUnlockRound {
		return "host: before the unlock round"
	}
	if a.shape.Encoding != "" {
		if !tx.hasReceiver {
			return "host: a spend with no recipient"
		}
		if tx.receiver != tx.txn.Sender && !a.listed[tx.receiver] {
			return "host: recipient is not on the list"
		}
	}
	return ""
}

func (a *agAccount) plan(tx *agTxn, derivedMemo map[string]agDerived) (agPlan, error) {
	path, classifyErr := classifyBoundedPath(tx.txn, a.metadata)
	if classifyErr != nil {
		if classifyErr.Kind != ErrorBadRequest {
			return agPlan{}, fmt.Errorf("classifyBoundedPath failed internally: %s", classifyErr.Message)
		}
		return agPlan{why: "planner: " + classifyErr.Message}, nil
	}
	if path == boundedPathPureSpend {
		if reason := a.agHostRule(tx); reason != "" {
			return agPlan{why: reason, path: path}, nil
		}
	}
	// boundedDerivedArgs depends only on the path, the type and the recipient, and
	// building a Merkle proof is slow, so its results are shared across the corpus.
	key := fmt.Sprintf("%s/%s/%s/%v", path, tx.txn.Type, tx.receiver, tx.receiver == tx.txn.Sender)
	derived, ok := derivedMemo[key]
	if !ok {
		values, err := boundedDerivedArgs(tx.txn, a.keyMaterial, a.metadata, path)
		derived = agDerived{values: values, err: err}
		derivedMemo[key] = derived
	}
	if derived.err != nil {
		return agPlan{why: "planner derived arguments: " + derived.err.Message, path: path}, nil
	}
	plan := agPlan{admit: true, why: string(path), path: path, required: make([]bool, len(a.slots))}
	var base [][]byte
	var cosignerSignature []byte
	derivedIndex := 0
	for _, slot := range a.slots {
		rule := boundedSlotRule(slot.ArgumentSlot, path)
		switch rule {
		case boundedmeta.ArgRequired, boundedmeta.ArgOptional, boundedmeta.ArgForbidden:
		default:
			return agPlan{}, fmt.Errorf("slot %q has no rule on path %s", slot.Name, path)
		}
		switch slot.role {
		case agRoleBase:
			base = append(base, a.value(slot, agValid, tx))
			plan.required[slot.Index] = rule == boundedmeta.ArgRequired
		case agRoleProof:
			filled := derived.values[derivedIndex]
			derivedIndex++
			plan.required[slot.Index] = rule == boundedmeta.ArgRequired || len(filled) != 0
			if len(filled) != 0 && !bytes.Equal(filled, a.value(slot, agValid, tx)) {
				return agPlan{}, fmt.Errorf("the signer's proof differs from the list's proof for %s", agAddressName(tx.receiver))
			}
		case agRoleCosigner:
			plan.required[slot.Index] = rule == boundedmeta.ArgRequired
			if plan.required[slot.Index] {
				cosignerSignature = a.value(slot, agValid, tx)
			}
		}
	}
	item := &boundedPlanItem{Path: path, Metadata: a.metadata}
	assembled, assembleErr := assembleBoundedArgsWithCosigner(a.metadata, item, base, derived.values, cosignerSignature)
	if assembleErr != nil {
		return agPlan{}, fmt.Errorf("the signer's assembly failed: %s", assembleErr.Message)
	}
	plan.assembled = assembled
	return plan, nil
}

// value is what a slot holds in a state, or nil when the state does not exist
// for this transaction (no valid proof for a recipient that is not listed).
func (a *agAccount) value(slot agSlot, state agState, tx *agTxn) []byte {
	// The cosigner signs the signer's own cosigner message for the transaction.
	cosignerMessage := func() []byte {
		digest := message.ComponentMessage(message.RoleCosigner, tx.txid)
		return digest[:]
	}
	switch {
	case state == agAbsent:
		return []byte{}
	case slot.role == agRoleBase && state == agValid:
		return agTag(agSpendingKey, tx.txid[:])
	case slot.role == agRoleBase && state == agWrongKey:
		return agTag(agCosignerKey, tx.txid[:])
	case slot.role == agRoleCosigner && state == agValid:
		return agTag(a.cosignerKey, cosignerMessage())
	case slot.role == agRoleCosigner && state == agWrongKey:
		return agTag(agSpendingKey, cosignerMessage())
	case slot.role == agRoleCosigner && state == agWrongMessage:
		return agTag(a.cosignerKey, tx.txid[:])
	case slot.role == agRoleProof && state == agValid:
		if !tx.hasReceiver {
			return nil
		}
		return a.proofs[tx.receiver]
	case slot.role == agRoleProof && state == agWrongEntry:
		if tx.hasReceiver && tx.receiver == agListedA {
			return a.proofs[agListedB]
		}
		return a.proofs[agListedA]
	}
	return nil
}

// states lists the states worth sending in a slot for this transaction.
func (a *agAccount) states(slot agSlot, tx *agTxn) []agState {
	var candidates []agState
	switch slot.role {
	case agRoleBase:
		candidates = []agState{agValid, agWrongKey, agAbsent}
	case agRoleCosigner:
		candidates = []agState{agValid, agWrongKey, agWrongMessage, agAbsent}
	case agRoleProof:
		candidates = []agState{agValid, agWrongEntry, agAbsent}
	}
	var out []agState
	for _, state := range candidates {
		if a.value(slot, state, tx) != nil {
			out = append(out, state)
		}
	}
	return out
}

var agFixture struct {
	once     sync.Once
	err      error
	corpus   []*agTxn
	accounts []*agAccount
}

func agLoad(t *testing.T) ([]*agTxn, []*agAccount) {
	t.Helper()
	agFixture.once.Do(func() {
		falcon1024.RegisterClient()
		provider, err := boundedaccount.NewProvider()
		if err != nil {
			agFixture.err = err
			return
		}
		corpus, err := agCorpus()
		if err != nil {
			agFixture.err = err
			return
		}
		list, err := newAgList()
		if err != nil {
			agFixture.err = err
			return
		}
		shapes := boundedaccount.Shapes()
		accounts := make([]*agAccount, len(shapes))
		errs := make([]error, len(shapes))
		var wg sync.WaitGroup
		for i, shape := range shapes {
			wg.Add(1)
			go func() {
				defer wg.Done()
				accounts[i], errs[i] = agBuildAccount(provider, list, shape, corpus)
			}()
		}
		wg.Wait()
		agFixture.corpus, agFixture.accounts, agFixture.err = corpus, accounts, errors.Join(errs...)
	})
	if agFixture.err != nil {
		t.Fatal(agFixture.err)
	}
	return agFixture.corpus, agFixture.accounts
}

// ---- running ----

// agRun is one program run: the arguments sent, in the padded form (every slot
// present) or the trimmed form the signer sends (trailing empty slots dropped).
type agRun struct {
	tx      *agTxn
	plan    *agPlan
	states  []agState
	trimmed bool
	got     bool
	fault   error
	want    bool
}

func (r agRun) argsName(a *agAccount) string {
	parts := make([]string, len(r.states))
	for i, state := range r.states {
		parts[i] = agRoleNames[a.slots[i].role] + " " + agStateNames[state]
	}
	form := "padded"
	if r.trimmed {
		form = "trimmed"
	}
	return strings.Join(parts, ", ") + " (" + form + ")"
}

func (r agRun) String(a *agAccount) string {
	verdict := map[bool]string{true: "accepts", false: "rejects"}
	fault := ""
	if r.fault != nil {
		fault = fmt.Sprintf(" (%v)", r.fault)
	}
	return fmt.Sprintf("%s / %s / %s: program %s%s, expected %s (%s)",
		a.name, r.tx.name, r.argsName(a), verdict[r.got], fault, verdict[r.want], r.plan.why)
}

func agTrim(args [][]byte) [][]byte {
	for len(args) > 0 && len(args[len(args)-1]) == 0 {
		args = args[:len(args)-1]
	}
	return args
}

func agExec(t *testing.T, a *agAccount, program *avmsim.Program, tx *agTxn, args [][]byte) (bool, error) {
	ok, err := program.Run(tx.fields, args, agHooks)
	var unsupported *avmsim.UnsupportedError
	if errors.As(err, &unsupported) {
		// An interpreter limit is not a rejection: reading it as one would let
		// every negative case pass on a path the interpreter cannot run.
		t.Fatalf("%s / %s: the program reached something the interpreter cannot run: %v", a.name, tx.name, err)
	}
	if errors.Is(err, avmsim.ErrReject) {
		err = nil
	}
	return ok && err == nil, err
}

// agCompare runs program on every corpus transaction under every argument set,
// in both forms, and passes each run to observe. It stops when observe returns
// false, and returns the number of runs.
func agCompare(t *testing.T, a *agAccount, program *avmsim.Program, corpus []*agTxn, observe func(agRun) bool) int {
	runs := 0
	for i, tx := range corpus {
		plan := &a.plans[i]
		options := make([][]agState, len(a.slots))
		values := make([][][]byte, len(a.slots))
		for s, slot := range a.slots {
			options[s] = a.states(slot, tx)
			for _, state := range options[s] {
				values[s] = append(values[s], a.value(slot, state, tx))
			}
		}
		choice := make([]int, len(a.slots))
		for {
			states := make([]agState, len(a.slots))
			args := make([][]byte, len(a.slots))
			want := plan.admit
			for s := range a.slots {
				states[s], args[s] = options[s][choice[s]], values[s][choice[s]]
				if plan.admit && plan.required[s] && states[s] != agValid {
					want = false
				}
			}
			forms := [][][]byte{args}
			if trimmed := agTrim(args); len(trimmed) != len(args) {
				forms = append(forms, trimmed)
			}
			for f, form := range forms {
				runs++
				got, fault := agExec(t, a, program, tx, form)
				if !observe(agRun{tx: tx, plan: plan, states: states, trimmed: f == 1, got: got, fault: fault, want: want}) {
					return runs
				}
			}
			// Advance the odometer over the slots' states.
			s := 0
			for ; s < len(choice); s++ {
				if choice[s]++; choice[s] < len(options[s]) {
					break
				}
				choice[s] = 0
			}
			if s == len(choice) {
				break
			}
		}
	}
	return runs
}

// TestBoundedPlannerAgreesWithProgram is the O4 agreement check for every shape.
func TestBoundedPlannerAgreesWithProgram(t *testing.T) {
	started := time.Now()
	corpus, accounts := agLoad(t)
	var mu sync.Mutex
	total, accepted, admittedPairs := 0, 0, 0
	t.Cleanup(func() {
		t.Logf("%d shapes x %d transactions (%d admitted pairs), %d program runs (%d accepted), %s",
			len(accounts), len(corpus), admittedPairs, total, accepted, time.Since(started).Round(time.Millisecond))
	})
	for _, a := range accounts {
		t.Run(a.name, func(t *testing.T) {
			t.Parallel()
			disagreements, admitted, rekeysAccepted, acceptedRuns := 0, 0, 0, 0
			for i, tx := range corpus {
				plan := &a.plans[i]
				if !plan.admit {
					continue
				}
				admitted++
				// The signer's own argument vector must be what the harness calls
				// valid-where-required and absent elsewhere, in the trimmed form,
				// and the program must accept it.
				harness := make([][]byte, len(a.slots))
				for s, slot := range a.slots {
					state := agAbsent
					if plan.required[s] {
						state = agValid
					}
					harness[s] = a.value(slot, state, tx)
				}
				if harness := agTrim(harness); !slices.EqualFunc(harness, plan.assembled, bytes.Equal) {
					t.Errorf("%s / %s: the signer assembles %d arguments that differ from the harness's %d", a.name, tx.name, len(plan.assembled), len(harness))
				}
				if got, fault := agExec(t, a, a.program, tx, plan.assembled); !got {
					t.Errorf("%s / %s: the program rejects the signer's own arguments for %s (fault: %v)", a.name, tx.name, plan.path, fault)
				}
			}
			runs := agCompare(t, a, a.program, corpus, func(r agRun) bool {
				if r.got {
					acceptedRuns++
				}
				if r.got != r.want {
					if disagreements++; disagreements <= agReportLimit {
						t.Error(r.String(a))
					}
				}
				// Refused has no rekey path: no argument set opens one, whatever
				// the planner says.
				if r.got && a.shape.Rekey == boundedaccount.RekeyRefused && !r.tx.txn.RekeyTo.IsZero() {
					if rekeysAccepted++; rekeysAccepted <= agReportLimit {
						t.Errorf("%s / %s / %s: a shape that refuses rekeys accepts a rekey", a.name, r.tx.name, r.argsName(a))
					}
				}
				return true
			})
			if disagreements > agReportLimit {
				t.Errorf("%s: %d disagreements in all, the first %d shown", a.name, disagreements, agReportLimit)
			}
			if rekeysAccepted > agReportLimit {
				t.Errorf("%s: %d accepted rekeys in all, the first %d shown", a.name, rekeysAccepted, agReportLimit)
			}
			// A harness that admits nothing proves nothing.
			if admitted == 0 {
				t.Errorf("%s: the planner admits no corpus transaction", a.name)
			}
			mu.Lock()
			total, accepted, admittedPairs = total+runs, accepted+acceptedRuns, admittedPairs+admitted
			mu.Unlock()
		})
	}
}

// ---- layout (O11) ----

type agLine struct {
	label string // set for a label line
	op    string
	args  []string
}

func (l agLine) String() string {
	if l.label != "" {
		return l.label + ":"
	}
	return strings.TrimSpace(l.op + " " + strings.Join(l.args, " "))
}

func agParse(teal string) []agLine {
	var lines []agLine
	for _, raw := range strings.Split(teal, "\n") {
		if i := strings.Index(raw, "//"); i >= 0 {
			raw = raw[:i]
		}
		fields := strings.Fields(raw)
		switch {
		case len(fields) == 0 || fields[0] == "#pragma":
		case len(fields) == 1 && strings.HasSuffix(fields[0], ":"):
			lines = append(lines, agLine{label: strings.TrimSuffix(fields[0], ":")})
		default:
			lines = append(lines, agLine{op: fields[0], args: fields[1:]})
		}
	}
	return lines
}

// agBody returns the instructions from label up to and including the first that
// leaves straight-line code (err, return, or an unconditional branch).
func agBody(lines []agLine, label string) ([]agLine, bool) {
	start := slices.IndexFunc(lines, func(l agLine) bool { return l.label == label })
	if start < 0 {
		return nil, false
	}
	var body []agLine
	for _, l := range lines[start+1:] {
		if l.label != "" {
			continue
		}
		body = append(body, l)
		if l.op == "err" || l.op == "return" || l.op == "b" {
			return body, true
		}
	}
	return nil, false
}

// agCheckRekeyFirst checks O11's layout: the spending signature first (after salt
// pushes and pops only), then the fee gate, then the RekeyTo dispatch, before any
// Layer 3 or cosigner code; and a rekey body that reads no argument and no host
// rule.
func agCheckRekeyFirst(a *agAccount) error {
	lines := agParse(a.teal)
	i := 0
	for i < len(lines) {
		l := lines[i]
		if l.op == "bytecblock" || l.op == "intcblock" {
			i++
			continue
		}
		if (l.op == "byte" || l.op == "pushbytes" || l.op == "pushint" || l.op == "int") && i+1 < len(lines) && lines[i+1].op == "pop" {
			i += 2
			continue
		}
		break
	}
	// The spending verification: straight-line pushes of the transaction ID, the
	// base signature slots and the spending key, then the signature opcode, asserted.
	baseSlots := map[string]bool{}
	for _, slot := range a.slots {
		if slot.role == agRoleBase {
			baseSlots[fmt.Sprint(slot.Index)] = true
		}
	}
	spendingKey := "0x" + hex.EncodeToString(agSpendingKey)
	sawKey := false
	for ; i < len(lines) && lines[i].op != "falcon_verify"; i++ {
		l := lines[i]
		switch {
		case l.op == "txn" && len(l.args) == 1 && l.args[0] == "TxID":
		case l.op == "arg" && len(l.args) == 1 && baseSlots[l.args[0]]:
		case l.op == "pushbytes" && len(l.args) == 1 && l.args[0] == spendingKey:
			sawKey = true
		default:
			return fmt.Errorf("instruction %q precedes the spending signature check", l)
		}
	}
	if i >= len(lines) || !sawKey {
		return fmt.Errorf("the program does not start with the spending key's signature check")
	}
	i++
	expect := func(what string, want ...string) error {
		for _, w := range want {
			if i >= len(lines) || lines[i].String() != w {
				got := "the end"
				if i < len(lines) {
					got = fmt.Sprintf("%q", lines[i])
				}
				return fmt.Errorf("%s: want %q, got %s", what, w, got)
			}
			i++
		}
		return nil
	}
	if err := expect("the spending signature is asserted", "assert"); err != nil {
		return err
	}
	if err := expect("the fee gate follows", "txn Fee", fmt.Sprintf("pushint %d", a.metadata.MaxFee), "<=", "assert"); err != nil {
		return err
	}
	if err := expect("the RekeyTo dispatch follows", "txn RekeyTo", "global ZeroAddress", "!="); err != nil {
		return err
	}
	if i >= len(lines) || lines[i].op != "bnz" || len(lines[i].args) != 1 {
		return fmt.Errorf("the RekeyTo dispatch does not branch")
	}
	rekeyLabel := lines[i].args[0]
	body, ok := agBody(lines, rekeyLabel)
	if !ok {
		return fmt.Errorf("the rekey branch %s has no straight-line body", rekeyLabel)
	}
	last := body[len(body)-1]
	if a.shape.Rekey == boundedaccount.RekeyRefused {
		if len(body) != 1 || last.op != "err" {
			return fmt.Errorf("a refused rekey branch is %q, want err alone", body)
		}
		return nil
	}
	// A spending-key rekey checks only the pure-rekey normal form, itself included,
	// and accepts.
	normalForm := map[string]bool{
		"TypeEnum": true, "Amount": true, "Receiver": true, "Sender": true, "RekeyTo": true,
		"CloseRemainderTo": true, "AssetCloseTo": true, "AssetSender": true,
	}
	readsRekeyTo := false
	for _, l := range body[:len(body)-1] {
		switch {
		case l.op == "txn" && len(l.args) == 1 && normalForm[l.args[0]]:
			readsRekeyTo = readsRekeyTo || l.args[0] == "RekeyTo"
		case l.op == "global" && len(l.args) == 1 && l.args[0] == "ZeroAddress":
		case l.op == "pushint" || l.op == "==" || l.op == "!=" || l.op == "assert":
		default:
			return fmt.Errorf("the rekey branch runs %q, which is not a normal-form check", l)
		}
	}
	if !readsRekeyTo {
		return fmt.Errorf("the rekey branch does not check RekeyTo itself")
	}
	if last.op != "b" || len(last.args) != 1 {
		return fmt.Errorf("the rekey branch ends with %q, want a branch to accept", last)
	}
	accept, ok := agBody(lines, last.args[0])
	if !ok || len(accept) != 2 || accept[0].String() != "pushint 1" || accept[1].op != "return" {
		return fmt.Errorf("the rekey branch ends at %s, which does not accept", last.args[0])
	}
	return nil
}

// TestBoundedProgramChecksRekeyFirst checks O11's layout for every shape.
func TestBoundedProgramChecksRekeyFirst(t *testing.T) {
	_, accounts := agLoad(t)
	for _, a := range accounts {
		if err := agCheckRekeyFirst(a); err != nil {
			t.Errorf("%s: %v", a.name, err)
		}
	}
}

// TestBoundedRekeyFirstCheckRefusesOtherLayouts is the layout check's negative
// control: it must refuse a program that reorders the prelude or lets a rekey reach
// an argument or a host rule, and accept a salt push.
func TestBoundedRekeyFirstCheckRefusesOtherLayouts(t *testing.T) {
	_, accounts := agLoad(t)
	find := func(rekey string, cosigner bool) *agAccount {
		for _, a := range accounts {
			if a.shape.Rekey == rekey && a.shape.Cosigner == cosigner && a.shape.Encoding == boundedaccount.EncodingMerkle {
				return a
			}
		}
		t.Fatalf("no Merkle shape with rekey %s and cosigner %v", rekey, cosigner)
		return nil
	}
	spending, refused := find(boundedaccount.RekeySpendingKey, false), find(boundedaccount.RekeyRefused, true)
	fee := fmt.Sprintf("txn Fee\npushint %d\n<=\nassert\n", boundedaccount.MaxFee)
	dispatch := "txn RekeyTo\nglobal ZeroAddress\n!=\nbnz " + agRekeyLabel + "\n"
	prepend := func(teal, code string) string {
		pragma, rest, _ := strings.Cut(teal, "\n")
		return pragma + "\n" + code + rest
	}
	for _, tc := range []struct {
		name   string
		a      *agAccount
		mutate func(string) string
		ok     bool
	}{
		{"a salt push and pop first", spending, func(teal string) string { return prepend(teal, "pushbytes 0x00\npop\n") }, true},
		{"an argument read before the spending check", refused, func(teal string) string { return prepend(teal, "arg 1\npop\n") }, false},
		{"the fee gate after the dispatch", spending, func(teal string) string {
			return agReplace(t, agReplace(t, teal, "", fee, ""), "", dispatch, dispatch+fee)
		}, false},
		{"a host rule before the dispatch", refused, func(teal string) string {
			return agReplace(t, teal, "", dispatch, "txn Receiver\npop\n"+dispatch)
		}, false},
		{"the rekey branch reads an argument", spending, func(teal string) string {
			return agReplace(t, teal, "", agRekeyLabel+":\n", agRekeyLabel+":\narg 1\npop\n")
		}, false},
		{"the rekey branch runs a host rule", spending, func(teal string) string {
			return agReplace(t, teal, "", agRekeyLabel+":\n", agRekeyLabel+":\ntxn FirstValid\npushint 1\n>=\nassert\n")
		}, false},
		{"the refused rekey branch does more than err", refused, func(teal string) string {
			return agReplace(t, teal, agRekeyLabel, "err\n", "txn Fee\npop\nerr\n")
		}, false},
	} {
		mutated := *tc.a
		mutated.teal = tc.mutate(tc.a.teal)
		if err := agCheckRekeyFirst(&mutated); (err == nil) != tc.ok {
			t.Errorf("%s: layout check error = %v, want ok %v", tc.name, err, tc.ok)
		}
	}
}

// ---- mutants ----

// agSection returns the span of a label's code, from its line to the next label.
func agSection(t *testing.T, teal, label string) (int, int) {
	t.Helper()
	marker := "\n" + label + ":\n"
	start := strings.Index(teal, marker)
	if start < 0 {
		t.Fatalf("mutant marker: label %s not found", label)
	}
	start += len(marker)
	end := len(teal)
	for offset := start; offset < len(teal); {
		next := strings.IndexByte(teal[offset:], '\n')
		if next < 0 {
			break
		}
		line := strings.TrimSpace(teal[offset : offset+next])
		if strings.HasSuffix(line, ":") && !strings.ContainsAny(line, " \t") && !strings.HasPrefix(line, "//") {
			end = offset
			break
		}
		offset += next + 1
	}
	return start, end
}

// agReplace replaces every occurrence of old with new in teal, or within one
// label's section when label is set, and fails the test when there is none.
func agReplace(t *testing.T, teal, label, old, replacement string) string {
	t.Helper()
	start, end := 0, len(teal)
	if label != "" {
		start, end = agSection(t, teal, label)
	}
	section := teal[start:end]
	if !strings.Contains(section, old) {
		where := "the program"
		if label != "" {
			where = label
		}
		t.Fatalf("mutant marker %q not found in %s", old, where)
	}
	return teal[:start] + strings.ReplaceAll(section, old, replacement) + teal[end:]
}

type agMutant struct {
	name    string
	applies func(*agAccount) bool
	mutate  func(*testing.T, *agAccount) string
}

func agHasEffect(a *agAccount, effect txeffects.SpendEffect) bool {
	return slices.Contains(a.shape.Spend, effect)
}

// agObservableEffect returns a spend effect the shape refuses whose opening the
// corpus can see, or "". The allowlists' Layer 3 dispatches on transaction type and
// refuses a type the account never spends, so opening a refused effect at the
// envelope is an equivalent mutant unless Layer 3 has no dispatch (a bare timelock)
// or already handles that type for another effect.
func agObservableEffect(a *agAccount) txeffects.SpendEffect {
	sameType := map[txeffects.SpendEffect]txeffects.SpendEffect{
		txeffects.SpendEffectAxfer:      txeffects.SpendEffectAssetOptIn,
		txeffects.SpendEffectAssetOptIn: txeffects.SpendEffectAxfer,
	}
	for _, effect := range []txeffects.SpendEffect{txeffects.SpendEffectPay, txeffects.SpendEffectAxfer, txeffects.SpendEffectAssetOptIn} {
		if agHasEffect(a, effect) {
			continue
		}
		if sibling, ok := sameType[effect]; a.shape.Encoding == "" || (ok && agHasEffect(a, sibling)) {
			return effect
		}
	}
	return ""
}

// agListReachable reports whether a spend can reach the recipient list: only pay
// and axfer name another recipient. An account that may only opt in to assets
// carries a list no admitted transaction consults, so skipping it is an
// equivalent mutant there.
func agListReachable(a *agAccount) bool {
	return a.shape.Encoding != "" && (agHasEffect(a, txeffects.SpendEffectPay) || agHasEffect(a, txeffects.SpendEffectAxfer))
}

func agRekeyNormalFormMutant(field, assertion string) agMutant {
	return agMutant{
		name:    "the rekey branch drops its " + field + " check",
		applies: func(a *agAccount) bool { return a.shape.Rekey == boundedaccount.RekeySpendingKey },
		mutate: func(t *testing.T, a *agAccount) string {
			return agReplace(t, a.teal, agRekeyLabel, assertion, "")
		},
	}
}

var agMutants = []agMutant{
	{
		name:    "the refused rekey branch accepts",
		applies: func(a *agAccount) bool { return a.shape.Rekey == boundedaccount.RekeyRefused },
		mutate: func(t *testing.T, a *agAccount) string {
			return agReplace(t, a.teal, agRekeyLabel, "err\n", "b "+agAcceptLabel+"\n")
		},
	},
	{
		// On a spending-key shape this also sends pure rekeys to the spend path,
		// which refuses them unless pay is a spend effect, so it would not be a
		// pure weakening there; the normal-form mutants cover those shapes.
		name:    "a refused shape's rekey falls through to the spend path",
		applies: func(a *agAccount) bool { return a.shape.Rekey == boundedaccount.RekeyRefused },
		mutate: func(t *testing.T, a *agAccount) string {
			return agReplace(t, a.teal, "", "txn RekeyTo\nglobal ZeroAddress\n!=\nbnz "+agRekeyLabel+"\n", "")
		},
	},
	{
		name:    "the fee assert is removed",
		applies: func(*agAccount) bool { return true },
		mutate: func(t *testing.T, a *agAccount) string {
			return agReplace(t, a.teal, "", fmt.Sprintf("txn Fee\npushint %d\n<=\nassert\n", a.metadata.MaxFee), "")
		},
	},
	agRekeyNormalFormMutant("amount", "txn Amount\npushint 0\n==\nassert\n"),
	agRekeyNormalFormMutant("receiver", "txn Receiver\ntxn Sender\n==\nassert\n"),
	agRekeyNormalFormMutant("CloseRemainderTo", "txn CloseRemainderTo\nglobal ZeroAddress\n==\nassert\n"),
	agRekeyNormalFormMutant("AssetCloseTo", "txn AssetCloseTo\nglobal ZeroAddress\n==\nassert\n"),
	agRekeyNormalFormMutant("AssetSender", "txn AssetSender\nglobal ZeroAddress\n==\nassert\n"),
	{
		name:    "the cosigner verification always passes",
		applies: func(a *agAccount) bool { return a.shape.Cosigner },
		mutate: func(t *testing.T, a *agAccount) string {
			return agReplace(t, a.teal, agSpendLabel, "falcon_verify\nassert\n", "pop\npop\npop\n")
		},
	},
	{
		name:    "a refused spend effect is allowed",
		applies: func(a *agAccount) bool { return agObservableEffect(a) != "" },
		mutate: func(t *testing.T, a *agAccount) string {
			label := "__aplane_bounded1_effect_" + string(agObservableEffect(a))
			return agReplace(t, a.teal, label, "err\n", "b "+agSpendLabel+"\n")
		},
	},
	{
		name:    "the recipient-list check is skipped",
		applies: agListReachable,
		mutate: func(t *testing.T, a *agAccount) string {
			call := "callsub __aplane_bounded1_layer3_recipient_allowed\nassert\n"
			if a.shape.Encoding == boundedaccount.EncodingMerkle {
				call = "callsub __aplane_bounded1_merkle_verify\nassert\n"
			}
			return agReplace(t, a.teal, "", call, "pop\n")
		},
	},
	{
		name: "the Merkle root comparison is dropped",
		applies: func(a *agAccount) bool {
			return a.shape.Encoding == boundedaccount.EncodingMerkle && agListReachable(a)
		},
		mutate: func(t *testing.T, a *agAccount) string {
			root, err := merkleallowlist.RootHexFromRecipientsParam(a.keyMaterial.Parameters[boundedaccount.ParameterRecipients])
			if err != nil {
				t.Fatal(err)
			}
			// The computed root is the only value on the stack: drop it and approve.
			return agReplace(t, a.teal, "", "pushbytes 0x"+root+"\n==\nretsub\n", "pop\npushint 1\nretsub\n")
		},
	},
	{
		name:    "the timelock check is skipped",
		applies: func(a *agAccount) bool { return a.shape.Timelock },
		mutate: func(t *testing.T, a *agAccount) string {
			return agReplace(t, a.teal, "", fmt.Sprintf("txn FirstValid\npushint %d\n>=\nassert\n", agUnlockRound), "")
		},
	},
}

// TestBoundedAgreementMutantsAreCaught is the harness's negative control. Every
// mutant removes or weakens one check, so on every shape it applies to it must
// accept something the planner refuses; the search stops at the first such run. A
// mutant that rejects something the planner admits before then is a broken edit,
// not a weakened check, and fails too.
func TestBoundedAgreementMutantsAreCaught(t *testing.T) {
	corpus, accounts := agLoad(t)
	for _, m := range agMutants {
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()
			applied := 0
			for _, a := range accounts {
				if !m.applies(a) {
					continue
				}
				applied++
				mutated := m.mutate(t, a)
				if mutated == a.teal {
					t.Errorf("%s: the mutant leaves the program unchanged", a.name)
					continue
				}
				program, err := avmsim.Assemble(mutated)
				if err != nil {
					t.Fatalf("%s: assemble the mutant: %v", a.name, err)
				}
				var caught, broken *agRun
				agCompare(t, a, program, corpus, func(r agRun) bool {
					switch {
					case r.got && !r.want:
						caught = &r
						return false
					case !r.got && r.want && broken == nil:
						broken = &r
					}
					return true
				})
				if broken != nil {
					t.Errorf("%s: the mutant rejects what the planner admits, so the edit breaks the program: %s", m.name, broken.String(a))
				}
				if caught == nil {
					t.Errorf("%s: %s: the mutant survives", m.name, a.name)
					continue
				}
				if applied == 1 {
					t.Logf("%s: caught, for example: %s", m.name, caught.String(a))
				}
			}
			if applied == 0 {
				t.Errorf("%s: the mutant applies to no shape", m.name)
			}
			t.Logf("%s: caught on %d shapes", m.name, applied)
		})
	}
}
