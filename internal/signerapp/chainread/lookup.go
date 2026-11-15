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
	"net"
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
	// MaxIndexerResponseBytes caps the response body, which is read whole
	// before it is decoded. A stage-program spend is about 20 KB of JSON (a
	// program of at most 2,877 bytes and arguments of at most 9,343, both
	// base64 encoded), so lookupLimit of them take about 160 KB; 256 KiB
	// leaves a margin. A longer answer is unavailable, and the search runs
	// without it.
	MaxIndexerResponseBytes = 256 << 10
	// lookupLimit is the results asked for in the one request; a response
	// that holds one more is refused. The lookup never asks for a further
	// page. More than one, because the Indexer's sender role also matches a
	// clawback's asset sender, and a zero-amount clawback needs no opt-in by
	// the account it names: any address that is the clawback address of any
	// asset can send one naming any account as asset sender, rekeying its
	// own sender, and so put a result the account did not send ahead of its
	// last spend. lookupLimit such transactions sent after the spend hide it
	// from the lookup, at one minimum fee each, and the worker then searches
	// as it would without an Indexer. The limit raises the cost of
	// suppressing the shortcut; it does not prevent it, and suppressing it
	// gains nothing else. Tests and docs derive the number from here.
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
func (r Reader) LookupLastRotation(ctx context.Context, genesisHash []byte, account, authorizer types.Address) (out StageLookup, err error) {
	if len(genesisHash) != 32 || account.IsZero() || authorizer.IsZero() {
		return StageLookup{}, errors.New("stage lookup needs the account's genesis hash, the account and its authorizer")
	}
	out = StageLookup{Outcome: LookupNoIndexer}
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
	if until, paused := r.Pause.paused(network); paused {
		out.Outcome = LookupUnavailable
		out.Reason = fmt.Sprintf("the Indexer failed a lookup less than %s ago; not asked again before %s", IndexerPauseAfterFailure, until.UTC().Format(time.RFC3339))
		return out, nil
	}
	// A request that ends unavailable pauses the network's Indexer, unless
	// the caller's own context ended it (a lock, a shutdown).
	parent := ctx
	defer func() {
		if out.Outcome == LookupUnavailable && parent.Err() == nil {
			r.Pause.fail(network)
		}
	}()
	base := r.IndexerTransport
	if base == nil {
		base = indexerHTTP
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
	if isTxID(spend.ID) {
		out.TxID = spend.ID
	}
	if spend.RekeyTo != authorizer.String() {
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
	// The whole body first, into one buffer of the cap and a byte: a longer
	// body is refused before anything is decoded.
	body := make([]byte, MaxIndexerResponseBytes+1)
	n, err := io.ReadFull(resp.Body, body)
	switch {
	case err == nil:
		return nil, errResponseTooLarge
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
	default:
		return nil, err
	}
	return decodeNewest(body[:n], sender)
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
		authAddr, err := types.DecodeAddress(spend.AuthAddr)
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
	case errors.Is(err, errDuplicateKey):
		return "the Indexer's response repeated a key"
	case errors.Is(err, errEscapedKey):
		return "the Indexer's response wrote a key with an escape sequence"
	case errors.Is(err, errFieldNotAString):
		return "the Indexer's response held a field in the wrong form"
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

// indexerHTTP carries every Indexer request. It is the lookup's own, not
// http.DefaultTransport: keep-alives are off, so each lookup opens its one
// connection and net/http never replays the token-bearing GET on a reused
// connection that died; response headers are capped like the body; and the
// dial, TLS handshake and wait for headers each have a timeout inside the
// lookup's overall deadline. No compression is asked for, so the body read
// is the body sent.
var indexerHTTP = &http.Transport{
	Proxy:                  http.ProxyFromEnvironment,
	DialContext:            (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	TLSHandshakeTimeout:    5 * time.Second,
	ResponseHeaderTimeout:  8 * time.Second,
	MaxResponseHeaderBytes: maxIndexerHeaderBytes,
	DisableKeepAlives:      true,
	DisableCompression:     true,
}

// maxIndexerHeaderBytes caps the response headers.
const maxIndexerHeaderBytes = 16 << 10

// indexerTransport refuses every response outside 2xx, redirects among
// them, so the lookup makes only the request it counts and only to the host
// configured.
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
	return resp, nil
}
