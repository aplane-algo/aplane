// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	signingutil "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// The verdict fixtures in test/contracts/policy/v1/verdicts record what the
// signing paths decide today for a policy and a group: the outcome, the
// review or approval rule, and for a refusal its error kind and exact text.
// They freeze the current behavior before the verdict logic is extracted
// into a shared evaluator, so the extraction can be checked against the old
// code's answers rather than against itself.
//
// go test ./internal/signerapp/signing -run TestVerdictFixtures -update-verdicts
// rewrites every case's expect from the current code. Review the diff: an
// expectation that changes is a behavior change.
var updateVerdicts = flag.Bool("update-verdicts", false, "rewrite verdict fixture expectations from the current code")

const verdictFixtureFormat = "aplane.policy-verdicts.v1"

var verdictFixtureDir = filepath.Join("..", "..", "..", "test", "contracts", "policy", "v1", "verdicts")

type verdictFixtureFile struct {
	Format      string        `json:"format"`
	Description string        `json:"description,omitempty"`
	Cases       []verdictCase `json:"cases"`
}

// verdictCase is one signing request and what the daemon decides for it.
type verdictCase struct {
	Name string `json:"name"`
	// Surface is the signing path: "sign" (/sign: planner output through the
	// approval gates, with Always Approve), "gates" (the shared gate sequence
	// as rotating and bounded cosigner signing drive it), "component_user"
	// (guarded user-role /sign/component) or "cosigner" (cosigner
	// /sign/component).
	Surface string `json:"surface"`
	// Base is the document each policy fragment is merged onto: "minimal"
	// (policytest.Minimal, the default) or "shipped" (the role's shipped
	// default).
	Base string `json:"base,omitempty"`
	// Policies maps a selector ("default", an address alias, or a witness
	// alias) to a fragment merged onto Base; "$A3" or "$W1" inside a fragment
	// is replaced by that address or witness key ID. A selector with no entry
	// resolves to "default"; with no "default" either, it has no policy.
	Policies map[string]json.RawMessage `json:"policies"`
	Group    []verdictTxn               `json:"group"`
	// Requests is the number of caller requests (sign surface); positions
	// after them are signer-added dummies. Zero means every position.
	Requests int `json:"requests,omitempty"`
	// Classes marks positions the signer does not sign: "passthrough" or
	// "foreign" (sign and gates surfaces).
	Classes map[string]string `json:"classes,omitempty"`
	// Auth names the selector whose policy governs each request, by
	// position; the default is the sender's alias.
	Auth map[string]string `json:"auth,omitempty"`
	// Targets are the judged positions on the component surfaces, and
	// ComponentKey their key selector (a witness alias for the cosigner).
	Targets      []int  `json:"targets,omitempty"`
	ComponentKey string `json:"component_key,omitempty"`
	// Known are the addresses this node holds keys for.
	Known                []string     `json:"known,omitempty"`
	ProtocolRekeyTargets []string     `json:"protocol_rekey_targets,omitempty"`
	ForcedReview         string       `json:"forced_review,omitempty"`
	Plan                 *verdictPlan `json:"plan,omitempty"`
	Expect               verdictWant  `json:"expect"`
}

// verdictPlan carries the planner facts Always Approve reads (sign surface).
type verdictPlan struct {
	DummiesNeeded *int `json:"dummies_needed,omitempty"` // nil: the dummy count
	// DummyTxns is how many dummies the plan reports appending, independent
	// of the group: fewer takes the first of the trailing positions, more
	// repeats the last. Nil reports every trailing position.
	DummyTxns       *int   `json:"dummy_txns,omitempty"`
	LsigIndices     []int  `json:"lsig_indices,omitempty"`
	LSigCount       int    `json:"lsig_count,omitempty"`
	TotalFees       uint64 `json:"total_fees,omitempty"`
	ProgramFee      uint64 `json:"program_fee,omitempty"`
	PQFee           uint64 `json:"pq_fee,omitempty"`
	Pregrouped      bool   `json:"pregrouped,omitempty"`
	OmitAuthAddress bool   `json:"omit_auth_address,omitempty"`
}

// verdictTxn describes one transaction. Addresses are aliases: "A<n>" is the
// address with first byte n, "DUMMY" is the signer's dummy LogicSig address.
// A dummy position ("dummy": true) is built in the signer's dummy shape from
// the first transaction.
type verdictTxn struct {
	Dummy         bool    `json:"dummy,omitempty"`
	Type          string  `json:"type,omitempty"`
	Sender        string  `json:"sender,omitempty"`
	Network       string  `json:"network,omitempty"` // testnet (default), mainnet, or unknown
	Fee           *uint64 `json:"fee,omitempty"`     // nil: 1000
	Note          string  `json:"note,omitempty"`
	RekeyTo       string  `json:"rekey_to,omitempty"`
	Receiver      string  `json:"receiver,omitempty"`
	Amount        uint64  `json:"amount,omitempty"`
	CloseTo       string  `json:"close_to,omitempty"`
	Asset         uint64  `json:"asset,omitempty"`
	AssetReceiver string  `json:"asset_receiver,omitempty"`
	AssetAmount   uint64  `json:"asset_amount,omitempty"`
	AssetSender   string  `json:"asset_sender,omitempty"`
	AssetCloseTo  string  `json:"asset_close_to,omitempty"`
	AppID         uint64  `json:"app_id,omitempty"`
}

// verdictWant is what the daemon decided. Outcome is "reject" (a policy
// rejection), "review" (the operator is asked, with RuleID when a review
// rule matched), "approve" (signed without asking, RuleID the approval
// rule), "default" (the operator is asked with no rule), or "error" (refused
// otherwise). Kind and Message are set for "reject" and "error".
type verdictWant struct {
	Outcome string `json:"outcome"`
	RuleID  string `json:"rule_id,omitempty"`
	Kind    string `json:"kind,omitempty"`
	Message string `json:"message,omitempty"`
}

func TestVerdictFixtures(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(verdictFixtureDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no verdict fixtures in %s: %v", verdictFixtureDir, err)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var fixture verdictFixtureFile
			dec := json.NewDecoder(bytes.NewReader(data))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&fixture); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if fixture.Format != verdictFixtureFormat {
				t.Fatalf("format = %q, want %q", fixture.Format, verdictFixtureFormat)
			}
			seen := map[string]bool{}
			for i := range fixture.Cases {
				c := &fixture.Cases[i]
				if seen[c.Name] {
					t.Fatalf("duplicate case name %q", c.Name)
				}
				seen[c.Name] = true
				t.Run(c.Name, func(t *testing.T) {
					got := runVerdictCase(t, c)
					if *updateVerdicts {
						c.Expect = got
						return
					}
					if got != c.Expect {
						t.Fatalf("verdict changed\n got: %+v\nwant: %+v", got, c.Expect)
					}
				})
			}
			if *updateVerdicts {
				out, err := json.MarshalIndent(fixture, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, append(out, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func runVerdictCase(t *testing.T, c *verdictCase) verdictWant {
	t.Helper()
	group := c.buildGroup(t)
	switch c.Surface {
	case "sign":
		return c.runSign(t, group)
	case "gates":
		return c.runGates(t, group)
	case "component_user":
		return c.runComponent(t, group, ComponentSignRoleUser)
	case "cosigner":
		return c.runComponent(t, group, ComponentSignRoleCosigner)
	default:
		t.Fatalf("unknown surface %q", c.Surface)
		return verdictWant{}
	}
}

// verdictRecorder is the approval side of a case: it records whether the
// operator was asked and approves every prompt, and captures the console so
// an Always Approve rule can be read back.
type verdictRecorder struct {
	mu       sync.Mutex
	prompted bool
	console  strings.Builder
}

func (r *verdictRecorder) Printf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fmt.Fprintf(&r.console, format, args...)
}

func (r *verdictRecorder) Println(args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fmt.Fprintln(&r.console, args...)
}

func (r *verdictRecorder) Sync() {}

var autoApprovedLine = regexp.MustCompile(`\[POLICY\] Txn auto-approved \(([^)]*)\)`)

func (r *verdictRecorder) approvalService(known map[string]bool) *ApprovalService {
	off := false
	return &ApprovalService{
		UserAutoApprove:               &off,
		Console:                       r,
		GenerateTxnDescriptionFromTxn: func(types.Transaction) string { return "txn" },
		KnownAddresses:                func() map[string]bool { return known },
		HasClient:                     func() bool { return true },
		EncodeTxnToHex:                func(txn types.Transaction) string { return hex.EncodeToString(msgpack.Encode(txn)) },
		RequestSigningApprovalContext: func(context.Context, string, string, string, string, uint64, uint64, []signerapproval.Violation, time.Duration) (bool, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.prompted = true
			return true, nil
		},
	}
}

// outcome turns what a signing path returned into the recorded verdict.
func (r *verdictRecorder) outcome(ruleID string, err *ServiceError, rejectPrefix string) verdictWant {
	if err != nil {
		outcome := "error"
		if err.Kind == ErrorForbidden && strings.HasPrefix(err.Message, rejectPrefix) {
			outcome = "reject"
		}
		return verdictWant{Outcome: outcome, Kind: string(err.Kind), Message: err.Message}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case r.prompted && ruleID != "":
		return verdictWant{Outcome: "review", RuleID: ruleID}
	case r.prompted:
		return verdictWant{Outcome: "default"}
	default:
		approved := ""
		if m := autoApprovedLine.FindStringSubmatch(r.console.String()); m != nil {
			approved = m[1]
		}
		return verdictWant{Outcome: "approve", RuleID: approved}
	}
}

func (c *verdictCase) runSign(t *testing.T, group []types.Transaction) verdictWant {
	t.Helper()
	requests := c.requestCount(group)
	rec := &verdictRecorder{}
	known := c.addressSet(t, c.Known)
	svc := &Service{
		Approval:                      rec.approvalService(known),
		Console:                       rec,
		GenerateTxnDescriptionFromTxn: func(types.Transaction) string { return "txn" },
		IsUnlocked:                    func() bool { return true },
		BeforeExecute:                 func() (func(), *ServiceError) { return func() {}, nil },
		PolicyFor:                     c.policyResolver(t, noderole.RoleSigner),
	}
	req := signerapi.GroupSignRequest{RequestID: c.Name}
	passthrough, foreign := c.classIndices(t)
	for i := 0; i < requests; i++ {
		sr := signerapi.SignRequest{TxnBytesHex: txnutil.EncodeWithPrefixHex(group[i])}
		if !passthrough[i] && !foreign[i] && (c.Plan == nil || !c.Plan.OmitAuthAddress) {
			sr.AuthAddress = c.authSelector(t, i, group[i])
		}
		req.Requests = append(req.Requests, sr)
	}
	plan := &PlanResult{
		AllTxns:               group,
		DummyTxns:             group[requests:],
		PassthroughIndices:    passthrough,
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        foreign,
		HasPassthrough:        len(passthrough) > 0,
		HasForeign:            len(foreign) > 0,
		DummiesNeeded:         len(group) - requests,
		KnownAddresses:        known,
		ProtocolRekeyTargets:  c.addressSet(t, c.ProtocolRekeyTargets),
	}
	if p := c.Plan; p != nil {
		if p.DummiesNeeded != nil {
			plan.DummiesNeeded = *p.DummiesNeeded
		}
		if p.DummyTxns != nil {
			plan.DummyTxns = reportedDummies(t, group[requests:], *p.DummyTxns)
		}
		plan.LsigIndices = p.LsigIndices
		plan.FeeInfo.LSigCount = p.LSigCount
		plan.FeeInfo.TotalFees = p.TotalFees
		plan.FeeInfo.ProgramFeeContribution = p.ProgramFee
		plan.FeeInfo.NativePQFeeContribution = p.PQFee
		plan.IsPreGrouped = p.Pregrouped
	}
	ruleID, _, err := svc.approveGroupWithPlanContext(context.Background(), req, plan)
	return rec.outcome(ruleID, err, "policy engine rejected request: ")
}

// reportedDummies is the plan's dummy list when it disagrees with the group:
// the first n trailing positions, or all of them with the last repeated.
func reportedDummies(t *testing.T, tail []types.Transaction, n int) []types.Transaction {
	t.Helper()
	if n < 0 {
		t.Fatalf("dummy_txns = %d", n)
	}
	if n <= len(tail) {
		return tail[:n]
	}
	if len(tail) == 0 {
		t.Fatal("dummy_txns above zero needs a dummy position to repeat")
	}
	out := append([]types.Transaction(nil), tail...)
	for len(out) < n {
		out = append(out, tail[len(tail)-1])
	}
	return out
}

func (c *verdictCase) runGates(t *testing.T, group []types.Transaction) verdictWant {
	t.Helper()
	requests := c.requestCount(group)
	rec := &verdictRecorder{}
	svc := &Service{PolicyFor: c.policyResolver(t, noderole.RoleSigner)}
	passthrough, foreign := c.classIndices(t)
	authKeys := make([]string, requests)
	for i := 0; i < requests; i++ {
		if !passthrough[i] && !foreign[i] {
			authKeys[i] = c.authSelector(t, i, group[i])
		}
	}
	ruleID, err := svc.runApprovalGates(context.Background(), gateInput{
		AllTxns:              group,
		EvalCount:            requests,
		PassthroughIndices:   passthrough,
		ForeignIndices:       foreign,
		AuthKeys:             authKeys,
		KnownAddresses:       c.addressSet(t, c.Known),
		ProtocolRekeyTargets: c.addressSet(t, c.ProtocolRekeyTargets),
		ForcedReviewRuleID:   c.ForcedReview,
		RequestOperatorApproval: func(context.Context, string) *ServiceError {
			rec.mu.Lock()
			defer rec.mu.Unlock()
			rec.prompted = true
			return nil
		},
	}, rec)
	return rec.outcome(ruleID, err, "policy engine rejected request: ")
}

func (c *verdictCase) runComponent(t *testing.T, group []types.Transaction, role ComponentSignRole) verdictWant {
	t.Helper()
	rec := &verdictRecorder{}
	nodeRole := noderole.RoleSigner
	if role == ComponentSignRoleCosigner {
		nodeRole = noderole.RoleCosigner
	}
	componentKey := c.selector(t, c.ComponentKey)
	hexes := make([]string, len(group))
	for i, txn := range group {
		hexes[i] = txnutil.EncodeWithPrefixHex(txn)
	}
	plan, err := prepareComponentSigning(componentPlanRequest{
		RequestID:     c.Name,
		Role:          role,
		ComponentKey:  componentKey,
		GroupBytesHex: hexes,
		TargetIndices: c.Targets,
	})
	if err != nil {
		t.Fatalf("prepareComponentSigning() error = %v", err)
	}
	known := c.addressSet(t, c.Known)
	svc := &Service{
		Approval:                      rec.approvalService(known),
		Console:                       rec,
		GenerateTxnDescriptionFromTxn: func(types.Transaction) string { return "txn" },
		PolicyFor:                     c.policyResolver(t, nodeRole),
		HoldsCosignerKey:              holdsAllCosignerKeys,
	}
	if role == ComponentSignRoleCosigner {
		signErr := svc.evaluateCosignerComponentPolicy(plan)
		if signErr == nil {
			return verdictWant{Outcome: "approve"}
		}
		return rec.outcome("", signErr, "cosigner policy rejected request: ")
	}
	ruleID, signErr := svc.gateUserComponentSigning(context.Background(), plan)
	return rec.outcome(ruleID, signErr, "policy engine rejected request: ")
}

func (c *verdictCase) requestCount(group []types.Transaction) int {
	if c.Requests > 0 {
		return c.Requests
	}
	return len(group)
}

func (c *verdictCase) classIndices(t *testing.T) (passthrough, foreign map[int]bool) {
	t.Helper()
	passthrough, foreign = map[int]bool{}, map[int]bool{}
	for key, class := range c.Classes {
		i, err := strconv.Atoi(key)
		if err != nil {
			t.Fatalf("class index %q: %v", key, err)
		}
		switch class {
		case "passthrough":
			passthrough[i] = true
		case "foreign":
			foreign[i] = true
		default:
			t.Fatalf("unknown class %q", class)
		}
	}
	return passthrough, foreign
}

func (c *verdictCase) authSelector(t *testing.T, i int, txn types.Transaction) string {
	t.Helper()
	if alias, ok := c.Auth[strconv.Itoa(i)]; ok {
		return c.selector(t, alias)
	}
	return txn.Sender.String()
}

// selector resolves a policy selector: "default" stays, an address alias
// becomes its address, and "W<n>" becomes a witness key ID.
func (c *verdictCase) selector(t *testing.T, alias string) string {
	t.Helper()
	switch {
	case alias == policy.DefaultKey:
		return alias
	case strings.HasPrefix(alias, "W"):
		n, err := strconv.Atoi(alias[1:])
		if err != nil || n <= 0 || n > 255 {
			t.Fatalf("witness alias %q", alias)
		}
		return testFalconComponentSelector(t, byte(n))
	default:
		return verdictAddress(t, alias).String()
	}
}

// verdictAliasRef is an alias inside a policy fragment: "$A3" is that
// address and "$W1" that witness key ID.
var verdictAliasRef = regexp.MustCompile(`\$[AW][0-9]+`)

// policyResolver compiles each policy fragment and resolves selectors the
// way the node does: a key's own document, else the default, else none.
func (c *verdictCase) policyResolver(t *testing.T, role noderole.Role) PolicyResolver {
	t.Helper()
	own := map[string]*policy.Config{}
	var def *policy.Config
	names := make([]string, 0, len(c.Policies))
	for name := range c.Policies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		key := c.selector(t, name)
		fragment := verdictAliasRef.ReplaceAllStringFunc(string(c.Policies[name]), func(ref string) string {
			return c.selector(t, ref[1:])
		})
		cfg := compileVerdictPolicy(t, role, key, c.Base, json.RawMessage(fragment))
		if name == policy.DefaultKey {
			def = cfg
		} else {
			own[key] = cfg
		}
	}
	return func(selector string) *policy.Config {
		if cfg, ok := own[selector]; ok {
			return cfg
		}
		return def
	}
}

func compileVerdictPolicy(t *testing.T, role noderole.Role, key, base string, fragment json.RawMessage) *policy.Config {
	t.Helper()
	var doc string
	switch base {
	case "", "minimal":
		var err error
		doc, err = policytest.Document(role, key, string(fragment))
		if err != nil {
			t.Fatal(err)
		}
	case "shipped":
		var m map[string]any
		if err := json.Unmarshal([]byte(policytest.EmbeddedDefault(t, role)), &m); err != nil {
			t.Fatal(err)
		}
		var extra map[string]any
		if err := json.Unmarshal(fragment, &extra); err != nil {
			t.Fatalf("policy fragment: %v", err)
		}
		for k, v := range extra {
			m[k] = v
		}
		m["key"] = key
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		doc = string(out)
	default:
		t.Fatalf("unknown base %q", base)
	}
	decoded, err := policy.DecodePolicyV1([]byte(doc), key, role)
	if err != nil {
		t.Fatalf("DecodePolicyV1() error = %v\n%s", err, doc)
	}
	cfg, err := decoded.Compile(policy.DefaultConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	return cfg
}

func (c *verdictCase) addressSet(t *testing.T, aliases []string) map[string]bool {
	t.Helper()
	if len(aliases) == 0 {
		return nil
	}
	out := make(map[string]bool, len(aliases))
	for _, alias := range aliases {
		out[verdictAddress(t, alias).String()] = true
	}
	return out
}

func verdictAddress(t *testing.T, alias string) types.Address {
	t.Helper()
	switch {
	case alias == "":
		return types.Address{}
	case alias == "DUMMY":
		addr, err := signingutil.DummyAddress()
		if err != nil {
			t.Fatal(err)
		}
		return addr
	case strings.HasPrefix(alias, "A"):
		n, err := strconv.Atoi(alias[1:])
		if err != nil || n <= 0 || n > 255 {
			t.Fatalf("address alias %q", alias)
		}
		return types.Address{byte(n)}
	default:
		addr, err := types.DecodeAddress(alias)
		if err != nil {
			t.Fatalf("address %q: %v", alias, err)
		}
		return addr
	}
}

// buildGroup builds the transactions as the signing path sees them after
// finalization: a group of more than one shares its computed group ID.
func (c *verdictCase) buildGroup(t *testing.T) []types.Transaction {
	t.Helper()
	if len(c.Group) == 0 {
		t.Fatal("case has no transactions")
	}
	group := make([]types.Transaction, len(c.Group))
	dummies := 0
	for i, spec := range c.Group {
		if spec.Dummy {
			if i == 0 {
				t.Fatal("the first position cannot be a dummy")
			}
			group[i] = verdictDummy(t, group[0], dummies)
			dummies++
			continue
		}
		group[i] = spec.build(t)
	}
	if len(group) > 1 {
		gid, err := algocrypto.ComputeGroupID(group)
		if err != nil {
			t.Fatalf("ComputeGroupID() error = %v", err)
		}
		for i := range group {
			group[i].Group = gid
		}
	}
	return group
}

func verdictDummy(t *testing.T, first types.Transaction, n int) types.Transaction {
	t.Helper()
	addr := verdictAddress(t, "DUMMY")
	return types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      addr,
			FirstValid:  first.FirstValid,
			LastValid:   first.LastValid,
			GenesisID:   first.GenesisID,
			GenesisHash: first.GenesisHash,
			Note:        []byte{byte(n)},
		},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: addr},
	}
}

func (spec verdictTxn) build(t *testing.T) types.Transaction {
	t.Helper()
	fee := uint64(1000)
	if spec.Fee != nil {
		fee = *spec.Fee
	}
	txn := types.Transaction{
		Header: types.Header{
			Sender:     verdictAddress(t, spec.Sender),
			Fee:        types.MicroAlgos(fee),
			FirstValid: 10,
			LastValid:  20,
			RekeyTo:    verdictAddress(t, spec.RekeyTo),
		},
	}
	if spec.Note != "" {
		txn.Note = []byte(spec.Note)
	}
	switch spec.Network {
	case "", "testnet":
		txn.GenesisID = "testnet-v1.0"
		txn.GenesisHash = verdictGenesis(t, apconfig.AlgorandTestnetGenesisHash)
	case "mainnet":
		txn.GenesisID = "mainnet-v1.0"
		txn.GenesisHash = verdictGenesis(t, apconfig.AlgorandMainnetGenesisHash)
	case "unknown":
		txn.GenesisID = "unknown-v1"
		txn.GenesisHash = types.Digest{0xee}
	default:
		t.Fatalf("unknown network %q", spec.Network)
	}
	switch spec.Type {
	case "pay":
		txn.Type = types.PaymentTx
		txn.Receiver = verdictAddress(t, spec.Receiver)
		txn.Amount = types.MicroAlgos(spec.Amount)
		txn.CloseRemainderTo = verdictAddress(t, spec.CloseTo)
	case "axfer":
		txn.Type = types.AssetTransferTx
		txn.XferAsset = types.AssetIndex(spec.Asset)
		txn.AssetReceiver = verdictAddress(t, spec.AssetReceiver)
		txn.AssetAmount = spec.AssetAmount
		txn.AssetSender = verdictAddress(t, spec.AssetSender)
		txn.AssetCloseTo = verdictAddress(t, spec.AssetCloseTo)
	case "appl":
		txn.Type = types.ApplicationCallTx
		txn.ApplicationID = types.AppIndex(spec.AppID)
	case "keyreg":
		txn.Type = types.KeyRegistrationTx
	default:
		t.Fatalf("unknown transaction type %q", spec.Type)
	}
	return txn
}

func verdictGenesis(t *testing.T, encoded string) types.Digest {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var out types.Digest
	copy(out[:], decoded)
	return out
}
