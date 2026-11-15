// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package chainread

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/rotatingstage"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// LookupOutcome is what a stage lookup found. Only LookupCandidate gives the
// caller something to try; every other outcome means the search goes on as
// it would without an Indexer.
type LookupOutcome string

const (
	// LookupCandidate: the account's newest outgoing rekey hands it to the
	// authorizer, signed by a stage program; StageLookup.Stage is the stage
	// to try.
	LookupCandidate LookupOutcome = "candidate"
	// LookupNoIndexer: no Indexer is configured for the account's network.
	// Nothing was asked.
	LookupNoIndexer LookupOutcome = "no_indexer"
	// LookupUnavailable: a timeout, connection or HTTP error, or a malformed
	// or oversized response.
	LookupUnavailable LookupOutcome = "unavailable"
	// LookupNoOutgoingRekey: the Indexer shows no rekey sent by the account
	// among the results examined.
	LookupNoOutgoingRekey LookupOutcome = "no_outgoing_rekey"
	// LookupNotCurrent: the newest outgoing rekey does not hand the account
	// to the authorizer, as when the Indexer has not caught up with algod.
	LookupNotCurrent LookupOutcome = "not_current"
	// LookupNotAStageProgram: the newest outgoing rekey was not signed by a
	// stage program alone, or its stage has no representable successor.
	LookupNotAStageProgram LookupOutcome = "not_a_stage_program"
	// LookupWrongNetwork: the Indexer answered for another chain.
	LookupWrongNetwork LookupOutcome = "wrong_network"
)

// Limits of one stage lookup: one request, for at most eight results,
// within ten seconds, the body read included; the body capped; one attempt
// per grant (the caller's).
const (
	// DefaultLookupTimeout bounds the whole lookup, the body read included.
	DefaultLookupTimeout = 10 * time.Second
	// MaxIndexerResponseBytes caps the response body. Eight results fit in
	// it many times over: a stage-program spend is about 20 KB of JSON (a
	// program of at most 2,877 bytes and arguments of at most 9,343, both
	// base64 encoded), with room left for what the Indexer adds to an
	// application call. A longer answer is unavailable, and the search runs
	// without it.
	MaxIndexerResponseBytes = 1 << 20
	// lookupLimit is the results asked for in the one request; a response
	// that begins one more is refused. It is eight, not one, because the
	// Indexer's sender role also matches a clawback's asset sender: whoever
	// holds clawback rights over an asset the account opted into can send a
	// zero-amount clawback that rekeys its own sender, the clawback address,
	// and so put a result the account did not send ahead of its last spend
	// whenever it likes. A one-result query would then see no outgoing
	// rekey; eight results in the same request see past such results at no
	// cost. The lookup never asks for a further page.
	lookupLimit = 8

	// indexerTokenHeader carries the Indexer API token, as the SDK sends it.
	indexerTokenHeader = "X-Indexer-API-Token"
)

// StageLookup is the result of one LookupLastRotation. It holds no
// credential: Network is the network token and Host the configured server's
// host, which is all a message about the lookup names.
type StageLookup struct {
	Outcome LookupOutcome
	Network string
	Host    string
	// Stage is the stage to try, n + 1 for a spend signed by stage n, when
	// Outcome is LookupCandidate.
	Stage uint64
	// TxID and Round identify the spend that was read, once one on the
	// account's chain was picked. TxID is empty when the Indexer's ID is not
	// a transaction ID.
	TxID  string
	Round uint64
	// Reason says, in fixed words, why a lookup was unavailable or what was
	// wrong with the spend; empty for a candidate.
	Reason string
}

// LookupLastRotation reads the account's newest outgoing rekey from the
// Indexer configured for the network serving genesisHash, and from the stage
// number in the program that signed it proposes the stage now in control:
// n + 1 for a spend signed by stage n. It proposes, never establishes: the
// caller derives the candidate from the seed and accepts it only if its
// address is the authorizer the caller read from its own algod.
//
// The lookup makes one request, for at most eight results, within
// DefaultLookupTimeout (or LookupTimeout), the body read included; it reads
// at most MaxIndexerResponseBytes, never asks for a further page, and keeps
// only the fields it checks (lookup_decode.go). It never uses a spend older
// than the newest the account sent: that one must hand the account to
// authorizer, which is also what makes an Indexer lagging behind algod
// harmless.
//
// It returns an error only for a caller mistake (an argument missing). Every
// condition of the Indexer or the chain is an outcome.
func (r Reader) LookupLastRotation(ctx context.Context, genesisHash []byte, account, authorizer types.Address) (StageLookup, error) {
	if len(genesisHash) != 32 || account.IsZero() || authorizer.IsZero() {
		return StageLookup{}, errors.New("stage lookup needs the account's genesis hash, the account and its authorizer")
	}
	out := StageLookup{Outcome: LookupNoIndexer}
	if r.Resolver == nil || r.IndexerConfig == nil {
		return out, nil
	}
	network, ok := r.Resolver().NetworkForGenesisHashBytes(genesisHash)
	if !ok {
		return out, nil
	}
	out.Network = network
	cfg := r.IndexerConfig(network)
	if cfg == nil || cfg.Server == "" {
		return out, nil
	}
	server, err := url.Parse(cfg.Server)
	if err != nil || server.Host == "" {
		// Configuration loading refuses this; a reader built otherwise
		// gets the same answer as an Indexer that cannot be reached.
		out.Outcome, out.Reason = LookupUnavailable, "the configured server is not a URL"
		return out, nil
	}
	out.Host = server.Host
	base := r.IndexerTransport
	if base == nil {
		base = http.DefaultTransport
	}
	search := indexerSearch{client: &http.Client{Transport: indexerTransport{base: base}}, server: *server, token: cfg.Token}
	timeout := r.LookupTimeout
	if timeout <= 0 {
		timeout = DefaultLookupTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	spend, reason := search.newestOutgoingRekey(ctx, account)
	switch {
	case reason != "":
		out.Outcome, out.Reason = LookupUnavailable, reason
		return out, nil
	case spend == nil:
		out.Outcome = LookupNoOutgoingRekey
		return out, nil
	case spend.ConfirmedRound == 0:
		out.Outcome, out.Reason = LookupUnavailable, "the Indexer returned a transaction without a confirmed round"
		return out, nil
	case !bytes.Equal(spend.GenesisHash, genesisHash):
		out.Outcome = LookupWrongNetwork
		return out, nil
	}
	out.Round = spend.ConfirmedRound
	if id := string(spend.ID); isTxID(id) {
		out.TxID = id
	}
	if string(spend.RekeyTo) != authorizer.String() {
		out.Outcome, out.Reason = LookupNotCurrent, "the newest outgoing rekey hands the account to another address"
		return out, nil
	}
	stage, reason := signingStage(spend, account)
	if reason != "" {
		out.Outcome, out.Reason = LookupNotAStageProgram, reason
		return out, nil
	}
	out.Outcome, out.Stage = LookupCandidate, stage+1
	return out, nil
}

// indexerSearch asks one Indexer for an account's outgoing rekeys.
type indexerSearch struct {
	client *http.Client
	server url.URL
	token  string
}

// newestOutgoingRekey returns the newest result, among the at most eight
// the one request returns, whose top-level sender is the account. Results
// sent by another address are skipped: the sender role also matches a
// clawback's asset sender (see lookupLimit). Inner transactions are not
// looked at. nil with no reason means none of the results was sent by the
// account; a reason means the Indexer could not be read.
func (s indexerSearch) newestOutgoingRekey(ctx context.Context, account types.Address) (*indexerTxn, string) {
	txn, err := s.newest(ctx, account.String())
	if err != nil {
		return nil, unavailableReason(ctx, err)
	}
	return txn, ""
}

// newest makes the lookup's one request, for the account's newest outgoing
// rekeys, and decodes the first sent by the account from the capped body.
func (s indexerSearch) newest(ctx context.Context, sender string) (*indexerTxn, error) {
	u := s.server
	u.Path = strings.TrimRight(u.Path, "/") + "/v2/transactions"
	q := url.Values{}
	q.Set("address", sender)
	q.Set("address-role", "sender")
	q.Set("rekey-to", "true")
	q.Set("limit", strconv.Itoa(lookupLimit))
	if u.RawQuery != "" {
		u.RawQuery += "&" + q.Encode()
	} else {
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(indexerTokenHeader, s.token)
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	return decodeNewest(resp.Body, sender)
}

// signingStage checks that the spend was signed by a stage program and
// nothing else, that the program is the account's signer, and that its stage
// prefix fits that signer, and returns the program's stage. A reason means
// it is not a stage program's spend.
func signingStage(spend *indexerTxn, account types.Address) (uint64, string) {
	sig := spend.Signature
	lsig := sig.Logicsig
	if len(lsig.Logic) == 0 {
		return 0, "the spend was not signed by a program"
	}
	if sig.Sig || sig.Multisig || sig.Pqsig || lsig.Signature || lsig.MultisigSignature || lsig.LogicMultisigSignature || lsig.Pqsig {
		return 0, "the spend carries a signature besides its program"
	}
	signer := account
	if spend.AuthAddr != "" {
		authAddr, err := types.DecodeAddress(string(spend.AuthAddr))
		if err != nil {
			return 0, "the spend names an invalid signer"
		}
		signer = authAddr
	}
	if crypto.AddressFromProgram(lsig.Logic) != signer {
		return 0, "the program is not the spend's signer"
	}
	stage, err := rotatingstage.ReadStage(lsig.Logic)
	if err != nil {
		return 0, "the program carries no stage number"
	}
	if (spend.AuthAddr == "") != (stage == 0) {
		return 0, fmt.Sprintf("a stage %d program does not fit the spend's signer", stage)
	}
	// The stage table refuses a stage at or past MaxUint64 - 1, and n + 1
	// must be below it.
	if stage >= math.MaxUint64-2 {
		return 0, fmt.Sprintf("stage %d has no representable successor", stage)
	}
	return stage, ""
}

// isTxID reports whether id has the form of a transaction ID: 52 characters
// of unpadded base32. Only the form is checked; the ID is shown, not used.
func isTxID(id string) bool {
	if len(id) != 52 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; (c < 'A' || c > 'Z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
}

var (
	errResponseTooLarge = errors.New("indexer response too large")
	errBadStatus        = errors.New("indexer answered an HTTP error")
)

// unavailableReason words why the Indexer could not be read, in fixed
// phrases: nothing of the error's own text, which could carry what a
// hostile server sent, reaches a message.
func unavailableReason(ctx context.Context, err error) string {
	var status statusError
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "the Indexer did not answer in time"
	case ctx.Err() != nil:
		return "the lookup was cancelled"
	case errors.Is(err, errResponseTooLarge):
		return fmt.Sprintf("the Indexer's response exceeded %d bytes", MaxIndexerResponseBytes)
	case errors.Is(err, errTooManyResults):
		return fmt.Sprintf("the Indexer returned more than the %d results asked", lookupLimit)
	case errors.Is(err, errFieldTooLong):
		return "a field of the Indexer's response exceeded its bound"
	case errors.As(err, &status):
		return fmt.Sprintf("the Indexer answered HTTP %d", int(status))
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return "the Indexer could not be reached"
	}
	return "the Indexer's response was malformed"
}

// statusError is a response outside 2xx. Its body is not read.
type statusError int

func (e statusError) Error() string { return fmt.Sprintf("HTTP %d", int(e)) }
func (e statusError) Unwrap() error { return errBadStatus }

// indexerTransport refuses every response outside 2xx, redirects among
// them, so the lookup makes only the requests it counts and only to the host
// configured, and caps every body it hands on.
type indexerTransport struct{ base http.RoundTripper }

func (t indexerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_ = resp.Body.Close()
		return nil, statusError(resp.StatusCode)
	}
	resp.Body = &cappedBody{body: resp.Body}
	return resp, nil
}

// cappedBody reads at most one byte past MaxIndexerResponseBytes, and fails
// with errResponseTooLarge once the body proves longer than the cap.
type cappedBody struct {
	body io.ReadCloser
	read int64
}

func (b *cappedBody) Read(p []byte) (int, error) {
	if room := MaxIndexerResponseBytes + 1 - b.read; int64(len(p)) > room {
		p = p[:room]
	}
	n, err := b.body.Read(p)
	b.read += int64(n)
	if b.read > MaxIndexerResponseBytes {
		return 0, errResponseTooLarge
	}
	return n, err
}

func (b *cappedBody) Close() error { return b.body.Close() }
