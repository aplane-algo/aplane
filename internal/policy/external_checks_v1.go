// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/strictjson"
)

// This file decodes and validates a cosigner document's external sources and
// external checks (docs/ARCH_POLICY.md). A check is a REST lookup whose JSON
// answer must satisfy the check's rules before the cosigner signs. Checks only
// refuse: they run after the policy would sign and can never allow what it
// rejects. A source is where a check's lookups go. Its token, when it needs
// one, is never in the document.

// Bounds on a document's external sources and checks.
const (
	MaxExternalSources        = 8
	MaxExternalSourceName     = 64
	MaxExternalChecks         = 8
	MaxExternalRules          = 8
	MaxExternalListOperand    = 64
	MaxExternalStringOperand  = 1024
	MaxExternalNumberDigits   = 40
	MaxExternalTLSPins        = 8
	MaxExternalTokenPrefix    = 32
	MaxExternalPathLength     = 512
	MaxExternalQueryParams    = 16
	MaxExternalQueryValue     = 256
	MaxExternalPointerLength  = 512
	MinExternalTimeoutMS      = 100
	MaxExternalTimeoutMS      = 10_000
	DefaultExternalTimeoutMS  = 2_000
	MaxExternalResponseBytes  = 1 << 20
	DefaultExternalRespBytes  = 64 << 10
	externalBaseURLMaxLength  = 512
	externalHeaderNameMaxSize = 64
)

// ExternalCheckScope says what one lookup of a check is for.
type ExternalCheckScope string

const (
	// ExternalScopeRequest runs a check once per component request.
	ExternalScopeRequest ExternalCheckScope = "request"
	// ExternalScopeTransaction runs it once per transaction the cosigner signs.
	ExternalScopeTransaction ExternalCheckScope = "transaction"
	// ExternalScopeMovement runs it once per transfer movement of such a
	// transaction, in the model transfer routing uses.
	ExternalScopeMovement ExternalCheckScope = "movement"
)

// ExternalOp is a rule's comparison of the answer's value with its operand.
type ExternalOp string

const (
	ExternalOpEq      ExternalOp = "eq"
	ExternalOpNe      ExternalOp = "ne"
	ExternalOpLt      ExternalOp = "lt"
	ExternalOpLe      ExternalOp = "le"
	ExternalOpGt      ExternalOp = "gt"
	ExternalOpGe      ExternalOp = "ge"
	ExternalOpIn      ExternalOp = "in"
	ExternalOpNotIn   ExternalOp = "not_in"
	ExternalOpPresent ExternalOp = "present"
	ExternalOpAbsent  ExternalOp = "absent"
)

// ExternalFact describes one transaction fact a template or a rule can use.
type ExternalFact struct {
	Name    string
	Scope   ExternalCheckScope
	Numeric bool
}

// ExternalFacts lists every fact, outermost scope first. A scope has its own
// facts and those of the scopes before it.
var ExternalFacts = []ExternalFact{
	{Name: "network", Scope: ExternalScopeRequest},
	{Name: "witness_key", Scope: ExternalScopeRequest},
	{Name: "sender", Scope: ExternalScopeTransaction},
	{Name: "txid", Scope: ExternalScopeTransaction},
	{Name: "type", Scope: ExternalScopeTransaction},
	{Name: "fee", Scope: ExternalScopeTransaction, Numeric: true},
	{Name: "rekey_to", Scope: ExternalScopeTransaction},
	{Name: "kind", Scope: ExternalScopeMovement},
	{Name: "source", Scope: ExternalScopeMovement},
	{Name: "asset_source", Scope: ExternalScopeMovement},
	{Name: "destination", Scope: ExternalScopeMovement},
	{Name: "asset", Scope: ExternalScopeMovement},
	{Name: "asset_id", Scope: ExternalScopeMovement, Numeric: true},
	{Name: "amount", Scope: ExternalScopeMovement, Numeric: true},
}

// externalScopeDepth orders the scopes: a check sees the facts of its own
// scope and of every shallower one.
var externalScopeDepth = map[ExternalCheckScope]int{
	ExternalScopeRequest:     0,
	ExternalScopeTransaction: 1,
	ExternalScopeMovement:    2,
}

// LookupExternalFact returns the fact named name when a check of scope can
// use it.
func LookupExternalFact(scope ExternalCheckScope, name string) (ExternalFact, bool) {
	depth, ok := externalScopeDepth[scope]
	if !ok {
		return ExternalFact{}, false
	}
	for _, fact := range ExternalFacts {
		if fact.Name == name && externalScopeDepth[fact.Scope] <= depth {
			return fact, true
		}
	}
	return ExternalFact{}, false
}

// ExternalMovementKinds lists the movement kinds a check can name, in the
// order transfer routing extracts them.
var ExternalMovementKinds = []TransferMovementKind{
	TransferMovementPay,
	TransferMovementPayClose,
	TransferMovementAxfer,
	TransferMovementAxferOptIn,
	TransferMovementAssetClose,
	TransferMovementClawback,
}

// ExternalTokenV1 says how a source's token is sent. The token itself is kept
// in the store with the key, never in the document.
type ExternalTokenV1 struct {
	Header string
	Prefix string
}

// ExternalSourceV1 is one REST source of a document.
type ExternalSourceV1 struct {
	// BaseURL is the URL as the document writes it: scheme, host, optional
	// port and path prefix.
	BaseURL string
	// Token is nil when the source takes no token.
	Token *ExternalTokenV1
	// TimeoutMS and MaxResponseBytes are the document's values, or the
	// defaults when it sets none.
	TimeoutMS        int
	MaxResponseBytes int
	// TLSPins are SHA-256 hashes of acceptable server SubjectPublicKeyInfo
	// values. Empty means the system roots decide.
	TLSPins [][32]byte
}

// ExternalTemplatePart is literal text or one fact placeholder of a template.
type ExternalTemplatePart struct {
	Literal string
	Fact    string // set for a placeholder; Literal is then empty
}

// ExternalTemplateV1 is a parsed path or query-value template.
type ExternalTemplateV1 struct {
	Text  string
	Parts []ExternalTemplatePart
}

// Facts returns the names of the facts the template uses, in order of first
// use.
func (t ExternalTemplateV1) Facts() []string {
	var out []string
	for _, part := range t.Parts {
		if part.Fact != "" && !slices.Contains(out, part.Fact) {
			out = append(out, part.Fact)
		}
	}
	return out
}

// ExternalQueryParamV1 is one query parameter of a check.
type ExternalQueryParamV1 struct {
	Name  string
	Value ExternalTemplateV1
}

// ExternalRuleV1 is one requirement on a check's answer: the value at Pointer,
// compared by Op with the operand. Exactly one operand field is set, and none
// for present and absent.
type ExternalRuleV1 struct {
	Pointer string
	Op      ExternalOp
	Number  *string
	String  *string
	Bool    *bool
	Numbers []string
	Strings []string
	Fact    string
}

// ExternalCheckV1 is one external check of a document.
type ExternalCheckV1 struct {
	ID              string
	Description     string
	Source          string
	Scope           ExternalCheckScope
	NetworkWildcard bool
	Networks        []string
	// MovementKinds is nil when the check covers every kind.
	MovementKinds []TransferMovementKind
	Path          ExternalTemplateV1
	// Query is in name order, the order parameters are written in.
	Query []ExternalQueryParamV1
	// EchoPointer is nil when the check requires no echo.
	EchoPointer *string
	Require     []ExternalRuleV1
}

// CoversNetwork reports whether the check applies on network.
func (c ExternalCheckV1) CoversNetwork(network string) bool {
	return c.NetworkWildcard || slices.Contains(c.Networks, network)
}

// CoversMovementKind reports whether a movement check applies to kind.
func (c ExternalCheckV1) CoversMovementKind(kind TransferMovementKind) bool {
	return c.MovementKinds == nil || slices.Contains(c.MovementKinds, kind)
}

// UsedFacts returns every fact the check's templates and rules use, in order
// of first use.
func (c ExternalCheckV1) UsedFacts() []string {
	out := c.Path.Facts()
	add := func(name string) {
		if name != "" && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	for _, param := range c.Query {
		for _, name := range param.Value.Facts() {
			add(name)
		}
	}
	for _, rule := range c.Require {
		add(rule.Fact)
	}
	return out
}

var (
	externalHeaderPattern    = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
	externalQueryNamePattern = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
	externalNumberPattern    = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`)
	externalPlaceholderName  = regexp.MustCompile(`^[a-z_]+$`)
)

// externalReservedHeaders are headers the cosigner sets itself; a token cannot
// be sent in one. Names are lowercase.
var externalReservedHeaders = []string{
	"host", "content-length", "content-type", "accept", "cache-control",
	"user-agent", "x-aplane-request-id",
}

// externalChecks reads external_sources and external_checks, which only a
// cosigner document may carry.
func (d *policyV1Decoder) externalChecks() error {
	if d.signer {
		for _, name := range []string{"external_sources", "external_checks"} {
			if err := rejectRoleField(d.r, name, d.role); err != nil {
				return err
			}
		}
		return nil
	}
	var err error
	if n := d.r.field("external_sources"); n != nil {
		if d.doc.ExternalSources, err = decodeExternalSources(n); err != nil {
			return err
		}
	}
	if n := d.r.field("external_checks"); n != nil {
		if d.doc.ExternalChecks, err = decodeExternalChecks(n); err != nil {
			return err
		}
	}
	return nil
}

// IsExternalSourceName reports whether name is a valid source name: at most
// 64 lowercase letters, digits, '_' or '-', starting with a letter or digit.
func IsExternalSourceName(name string) bool {
	return len(name) <= MaxExternalSourceName && policyTokenPattern.MatchString(name)
}

func decodeExternalSources(node *jsonNode) (map[string]ExternalSourceV1, error) {
	r, err := readJSONObject(node, "external_sources")
	if err != nil {
		return nil, err
	}
	if len(node.keys) == 0 {
		return nil, docErrorf(node.pointer, "external_sources must name at least one source")
	}
	if len(node.keys) > MaxExternalSources {
		return nil, docErrorf(node.pointer, "at most %d external sources are allowed", MaxExternalSources)
	}
	out := make(map[string]ExternalSourceV1, len(node.keys))
	for _, name := range node.keys {
		sn := r.field(name)
		if !IsExternalSourceName(name) {
			return nil, docErrorf(sn.pointer, "source name %q must be lowercase letters, digits, '_' or '-', starting with a letter or digit", name)
		}
		source, err := decodeExternalSource(sn)
		if err != nil {
			return nil, err
		}
		out[name] = source
	}
	return out, nil
}

func decodeExternalSource(node *jsonNode) (ExternalSourceV1, error) {
	r, err := readJSONObject(node, "external source")
	if err != nil {
		return ExternalSourceV1{}, err
	}
	source := ExternalSourceV1{TimeoutMS: DefaultExternalTimeoutMS, MaxResponseBytes: DefaultExternalRespBytes}
	urlNode, err := r.required("base_url")
	if err != nil {
		return ExternalSourceV1{}, err
	}
	if source.BaseURL, err = jsonString(urlNode); err != nil {
		return ExternalSourceV1{}, err
	}
	plainHTTP, err := validateExternalBaseURL(urlNode.pointer, source.BaseURL)
	if err != nil {
		return ExternalSourceV1{}, err
	}
	if n := r.field("token"); n != nil {
		if source.Token, err = decodeExternalToken(n); err != nil {
			return ExternalSourceV1{}, err
		}
	}
	if n := r.field("timeout_ms"); n != nil {
		if source.TimeoutMS, err = decodeBoundedInt(n, MinExternalTimeoutMS, MaxExternalTimeoutMS); err != nil {
			return ExternalSourceV1{}, err
		}
	}
	if n := r.field("max_response_bytes"); n != nil {
		if source.MaxResponseBytes, err = decodeBoundedInt(n, 1, MaxExternalResponseBytes); err != nil {
			return ExternalSourceV1{}, err
		}
	}
	if n := r.field("tls_spki_sha256"); n != nil {
		if plainHTTP {
			return ExternalSourceV1{}, docErrorf(n.pointer, "an http source has no TLS key to pin")
		}
		if source.TLSPins, err = decodeExternalTLSPins(n); err != nil {
			return ExternalSourceV1{}, err
		}
	}
	return source, r.finish()
}

// validateExternalBaseURL checks a source's base URL and reports whether it is
// plain http, which only a loopback host may use.
func validateExternalBaseURL(pointer, raw string) (plainHTTP bool, err error) {
	if len(raw) > externalBaseURLMaxLength {
		return false, docErrorf(pointer, "base_url is longer than %d characters", externalBaseURLMaxLength)
	}
	u, parseErr := url.Parse(raw)
	if parseErr != nil || u.Host == "" || u.Hostname() == "" || u.Opaque != "" {
		return false, docErrorf(pointer, "base_url must be an https URL with a host, or an http URL to a loopback host")
	}
	if u.User != nil {
		return false, docErrorf(pointer, "base_url must not carry user info")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return false, docErrorf(pointer, "base_url must not have a query or a fragment")
	}
	if err := validateExternalLiteralPath(u.EscapedPath()); err != nil {
		return false, docErrorf(pointer, "base_url path %v", err)
	}
	if port := u.Port(); port != "" {
		if n, convErr := strconv.Atoi(port); convErr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return false, docErrorf(pointer, "base_url port %q is not a port number", port)
		}
	}
	switch u.Scheme {
	case "https":
		return false, nil
	case "http":
		if !IsExternalLoopbackHost(u.Hostname()) {
			return false, docErrorf(pointer, "an http base_url must name localhost or a loopback address; use https for %q", u.Hostname())
		}
		return true, nil
	default:
		return false, docErrorf(pointer, "base_url must be an https URL with a host, or an http URL to a loopback host")
	}
}

// IsExternalLoopbackHost reports whether host is "localhost" or a loopback
// address literal. It judges the name only: the cosigner also checks the
// address it dials.
func IsExternalLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func decodeExternalToken(node *jsonNode) (*ExternalTokenV1, error) {
	r, err := readJSONObject(node, "token")
	if err != nil {
		return nil, err
	}
	token := &ExternalTokenV1{}
	headerNode, err := r.required("header")
	if err != nil {
		return nil, err
	}
	if token.Header, err = jsonString(headerNode); err != nil {
		return nil, err
	}
	if len(token.Header) > externalHeaderNameMaxSize || !externalHeaderPattern.MatchString(token.Header) {
		return nil, docErrorf(headerNode.pointer, "%q is not a header name", token.Header)
	}
	if slices.Contains(externalReservedHeaders, strings.ToLower(token.Header)) {
		return nil, docErrorf(headerNode.pointer, "header %q is set by the cosigner and cannot carry a token", token.Header)
	}
	if n := r.field("prefix"); n != nil {
		if token.Prefix, err = jsonString(n); err != nil {
			return nil, err
		}
		if len(token.Prefix) > MaxExternalTokenPrefix || !isPrintableASCII(token.Prefix, true) {
			return nil, docErrorf(n.pointer, "prefix must be at most %d printable ASCII characters", MaxExternalTokenPrefix)
		}
	}
	return token, r.finish()
}

// isPrintableASCII reports whether s holds only visible ASCII, and spaces
// when allowSpace is set.
func isPrintableASCII(s string, allowSpace bool) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' && allowSpace {
			continue
		}
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// decodeBoundedInt decodes a JSON integer written without sign, fraction,
// exponent or leading zeros, within [low, high].
func decodeBoundedInt(node *jsonNode, low, high int) (int, error) {
	if node.kind != nodeNumber {
		return 0, docErrorf(node.pointer, "must be a whole number from %d through %d, not %s", low, high, node.kind)
	}
	v, err := parseCanonicalUint64(node.text)
	if err != nil || v < uint64(low) || v > uint64(high) {
		return 0, docErrorf(node.pointer, "must be a whole number from %d through %d", low, high)
	}
	return int(v), nil
}

func decodeExternalTLSPins(node *jsonNode) ([][32]byte, error) {
	items, err := jsonArrayItems(node, 1)
	if err != nil {
		return nil, err
	}
	if len(items) > MaxExternalTLSPins {
		return nil, docErrorf(node.pointer, "at most %d pins are allowed", MaxExternalTLSPins)
	}
	pins := make([][32]byte, 0, len(items))
	for _, item := range items {
		raw, err := jsonString(item)
		if err != nil {
			return nil, err
		}
		pin, ok := ParseExternalTLSPin(raw)
		if !ok {
			return nil, docErrorf(item.pointer, "a pin must be the padded standard base64 of a 32-byte SHA-256")
		}
		if slices.Contains(pins, pin) {
			return nil, docErrorf(item.pointer, "duplicate pin")
		}
		pins = append(pins, pin)
	}
	return pins, nil
}

func decodeExternalChecks(node *jsonNode) ([]ExternalCheckV1, error) {
	items, err := jsonArrayItems(node, 1)
	if err != nil {
		return nil, err
	}
	if len(items) > MaxExternalChecks {
		return nil, docErrorf(node.pointer, "at most %d external checks are allowed", MaxExternalChecks)
	}
	checks := make([]ExternalCheckV1, 0, len(items))
	for _, item := range items {
		check, err := decodeExternalCheck(item)
		if err != nil {
			return nil, err
		}
		checks = append(checks, check)
	}
	return checks, nil
}

func decodeExternalCheck(node *jsonNode) (ExternalCheckV1, error) {
	r, err := readJSONObject(node, "external check")
	if err != nil {
		return ExternalCheckV1{}, err
	}
	var check ExternalCheckV1
	idNode, err := r.required("id")
	if err != nil {
		return ExternalCheckV1{}, err
	}
	if check.ID, err = jsonString(idNode); err != nil {
		return ExternalCheckV1{}, err
	}
	if len(check.ID) > 64 || !policyTokenPattern.MatchString(check.ID) {
		return ExternalCheckV1{}, docErrorf(idNode.pointer, "check id must be lowercase letters, digits, '_' or '-', starting with a letter or digit")
	}
	if check.Description, err = optionalDescription(r); err != nil {
		return ExternalCheckV1{}, err
	}
	sourceNode, err := r.required("source")
	if err != nil {
		return ExternalCheckV1{}, err
	}
	if check.Source, err = jsonString(sourceNode); err != nil {
		return ExternalCheckV1{}, err
	}
	scopeNode, err := r.required("scope")
	if err != nil {
		return ExternalCheckV1{}, err
	}
	rawScope, err := jsonString(scopeNode)
	if err != nil {
		return ExternalCheckV1{}, err
	}
	check.Scope = ExternalCheckScope(rawScope)
	if _, ok := externalScopeDepth[check.Scope]; !ok {
		return ExternalCheckV1{}, docErrorf(scopeNode.pointer, "must be one of request, transaction, movement")
	}
	networksNode, err := r.required("networks")
	if err != nil {
		return ExternalCheckV1{}, err
	}
	if check.NetworkWildcard, check.Networks, err = decodeRouteNetworks(networksNode); err != nil {
		return ExternalCheckV1{}, err
	}
	if n := r.field("movement_kinds"); n != nil {
		if check.Scope != ExternalScopeMovement {
			return ExternalCheckV1{}, docErrorf(n.pointer, "movement_kinds is only for a check of scope movement")
		}
		if check.MovementKinds, err = decodeExternalMovementKinds(n); err != nil {
			return ExternalCheckV1{}, err
		}
	}
	pathNode, err := r.required("path")
	if err != nil {
		return ExternalCheckV1{}, err
	}
	if check.Path, err = decodeExternalPath(pathNode, check.Scope); err != nil {
		return ExternalCheckV1{}, err
	}
	if n := r.field("query"); n != nil {
		if check.Query, err = decodeExternalQuery(n, check.Scope); err != nil {
			return ExternalCheckV1{}, err
		}
	}
	if n := r.field("echo_pointer"); n != nil {
		pointer, err := decodeExternalPointer(n)
		if err != nil {
			return ExternalCheckV1{}, err
		}
		check.EchoPointer = &pointer
	}
	requireNode, err := r.required("require")
	if err != nil {
		return ExternalCheckV1{}, err
	}
	rules, err := jsonArrayItems(requireNode, 1)
	if err != nil {
		return ExternalCheckV1{}, err
	}
	if len(rules) > MaxExternalRules {
		return ExternalCheckV1{}, docErrorf(requireNode.pointer, "at most %d rules are allowed", MaxExternalRules)
	}
	for _, item := range rules {
		rule, err := decodeExternalRule(item, check.Scope)
		if err != nil {
			return ExternalCheckV1{}, err
		}
		check.Require = append(check.Require, rule)
	}
	return check, r.finish()
}

// ParseExternalTLSPin reads one tls_spki_sha256 pin: the padded standard
// base64 of a 32-byte SHA-256, written canonically.
func ParseExternalTLSPin(raw string) ([32]byte, bool) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(raw)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != raw {
		return [32]byte{}, false
	}
	return [32]byte(decoded), true
}

func decodeExternalMovementKinds(node *jsonNode) ([]TransferMovementKind, error) {
	items, err := jsonArrayItems(node, 1)
	if err != nil {
		return nil, err
	}
	kinds := make([]TransferMovementKind, 0, len(items))
	for _, item := range items {
		raw, err := jsonString(item)
		if err != nil {
			return nil, err
		}
		kind := TransferMovementKind(raw)
		if !slices.Contains(ExternalMovementKinds, kind) {
			return nil, docErrorf(item.pointer, "unknown movement kind %q; expected %s", raw, strings.Join(ExternalMovementKindNames(), ", "))
		}
		if slices.Contains(kinds, kind) {
			return nil, docErrorf(item.pointer, "duplicate movement kind %q", raw)
		}
		kinds = append(kinds, kind)
	}
	return kinds, nil
}

// ExternalMovementKindNames lists the movement kinds a check can name, as
// written in a document, in ExternalMovementKinds order.
func ExternalMovementKindNames() []string {
	names := make([]string, len(ExternalMovementKinds))
	for i, kind := range ExternalMovementKinds {
		names[i] = string(kind)
	}
	return names
}

// decodeExternalPath decodes a check's path template: literal URL path text
// with fact placeholders, starting with "/".
func decodeExternalPath(node *jsonNode, scope ExternalCheckScope) (ExternalTemplateV1, error) {
	raw, err := jsonString(node)
	if err != nil {
		return ExternalTemplateV1{}, err
	}
	if len(raw) > MaxExternalPathLength {
		return ExternalTemplateV1{}, docErrorf(node.pointer, "path is longer than %d characters", MaxExternalPathLength)
	}
	tmpl, err := parseExternalTemplate(node.pointer, raw, scope)
	if err != nil {
		return ExternalTemplateV1{}, err
	}
	if !strings.HasPrefix(raw, "/") {
		return ExternalTemplateV1{}, docErrorf(node.pointer, "path must start with \"/\"")
	}
	// A placeholder stands for one escaped segment's worth of text, so the
	// shape of the path is judged with a letter in its place.
	var shape strings.Builder
	for _, part := range tmpl.Parts {
		if part.Fact != "" {
			shape.WriteByte('x')
			continue
		}
		shape.WriteString(part.Literal)
	}
	if err := validateExternalLiteralPath(shape.String()); err != nil {
		return ExternalTemplateV1{}, docErrorf(node.pointer, "path %v", err)
	}
	return tmpl, nil
}

// validateExternalLiteralPath checks literal URL path text: RFC 3986 path
// characters and "/", with no percent-encoding, no "." or ".." segment and no
// empty segment. The empty path and a single trailing "/" are allowed.
func validateExternalLiteralPath(path string) error {
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("-._~!$&'()*+,;=:@/", c) >= 0:
		case c == '%':
			return fmt.Errorf("must not contain %q: percent-encoding is not accepted", "%")
		default:
			return fmt.Errorf("must not contain %q", string(rune(c)))
		}
	}
	if strings.Contains(path, "//") {
		return fmt.Errorf("must not contain an empty segment (\"//\")")
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("must not contain a %q segment", segment)
		}
	}
	return nil
}

func decodeExternalQuery(node *jsonNode, scope ExternalCheckScope) ([]ExternalQueryParamV1, error) {
	r, err := readJSONObject(node, "query")
	if err != nil {
		return nil, err
	}
	if len(node.keys) > MaxExternalQueryParams {
		return nil, docErrorf(node.pointer, "at most %d query parameters are allowed", MaxExternalQueryParams)
	}
	params := make([]ExternalQueryParamV1, 0, len(node.keys))
	for _, name := range node.keys {
		vn := r.field(name)
		if len(name) > 64 || !externalQueryNamePattern.MatchString(name) {
			return nil, docErrorf(vn.pointer, "query parameter name %q must be letters, digits, '.', '_', '~' or '-'", name)
		}
		raw, err := jsonString(vn)
		if err != nil {
			return nil, err
		}
		if len(raw) > MaxExternalQueryValue {
			return nil, docErrorf(vn.pointer, "query value is longer than %d characters", MaxExternalQueryValue)
		}
		for i := 0; i < len(raw); i++ {
			if raw[i] < 0x20 || raw[i] == 0x7f {
				return nil, docErrorf(vn.pointer, "query value must not contain control characters")
			}
		}
		value, err := parseExternalTemplate(vn.pointer, raw, scope)
		if err != nil {
			return nil, err
		}
		params = append(params, ExternalQueryParamV1{Name: name, Value: value})
	}
	slices.SortFunc(params, func(a, b ExternalQueryParamV1) int { return strings.Compare(a.Name, b.Name) })
	return params, nil
}

// parseExternalTemplate splits text into literal parts and "{fact}"
// placeholders. Every placeholder must name a fact of scope, and braces have
// no other use.
func parseExternalTemplate(pointer, text string, scope ExternalCheckScope) (ExternalTemplateV1, error) {
	tmpl := ExternalTemplateV1{Text: text}
	rest := text
	for rest != "" {
		open := strings.IndexAny(rest, "{}")
		if open < 0 {
			tmpl.Parts = append(tmpl.Parts, ExternalTemplatePart{Literal: rest})
			break
		}
		if rest[open] == '}' {
			return ExternalTemplateV1{}, docErrorf(pointer, "\"}\" without a matching \"{\"")
		}
		if open > 0 {
			tmpl.Parts = append(tmpl.Parts, ExternalTemplatePart{Literal: rest[:open]})
		}
		end := strings.IndexByte(rest[open:], '}')
		if end < 0 {
			return ExternalTemplateV1{}, docErrorf(pointer, "\"{\" without a matching \"}\"")
		}
		name := rest[open+1 : open+end]
		if !externalPlaceholderName.MatchString(name) {
			return ExternalTemplateV1{}, docErrorf(pointer, "%q is not a placeholder; write {fact}", "{"+name+"}")
		}
		if _, ok := LookupExternalFact(scope, name); !ok {
			return ExternalTemplateV1{}, docErrorf(pointer, "%s", unknownFactMessage(name, scope))
		}
		tmpl.Parts = append(tmpl.Parts, ExternalTemplatePart{Fact: name})
		rest = rest[open+end+1:]
	}
	return tmpl, nil
}

// unknownFactMessage says why name is not a fact a check of scope can use.
func unknownFactMessage(name string, scope ExternalCheckScope) string {
	for _, fact := range ExternalFacts {
		if fact.Name == name {
			return fmt.Sprintf("fact %q belongs to scope %s and is not available to a check of scope %s", name, fact.Scope, scope)
		}
	}
	return fmt.Sprintf("unknown fact %q", name)
}

// decodeExternalPointer decodes an RFC 6901 JSON Pointer: "" or a sequence of
// "/token" where "~" appears only as "~0" or "~1".
func decodeExternalPointer(node *jsonNode) (string, error) {
	raw, err := jsonString(node)
	if err != nil {
		return "", err
	}
	if len(raw) > MaxExternalPointerLength {
		return "", docErrorf(node.pointer, "pointer is longer than %d characters", MaxExternalPointerLength)
	}
	if err := strictjson.ValidatePointer(raw); err != nil {
		return "", docErrorf(node.pointer, "%v", err)
	}
	return raw, nil
}

// externalOperandNames are a rule's operand fields, in canonical order.
var externalOperandNames = []string{"number", "string", "bool", "numbers", "strings", "fact"}

func decodeExternalRule(node *jsonNode, scope ExternalCheckScope) (ExternalRuleV1, error) {
	r, err := readJSONObject(node, "rule")
	if err != nil {
		return ExternalRuleV1{}, err
	}
	var rule ExternalRuleV1
	pointerNode, err := r.required("pointer")
	if err != nil {
		return ExternalRuleV1{}, err
	}
	if rule.Pointer, err = decodeExternalPointer(pointerNode); err != nil {
		return ExternalRuleV1{}, err
	}
	opNode, err := r.required("op")
	if err != nil {
		return ExternalRuleV1{}, err
	}
	rawOp, err := jsonString(opNode)
	if err != nil {
		return ExternalRuleV1{}, err
	}
	rule.Op = ExternalOp(rawOp)
	var present []string
	for _, name := range externalOperandNames {
		if r.field(name) != nil {
			present = append(present, name)
		}
	}
	if err := r.finish(); err != nil {
		return ExternalRuleV1{}, err
	}
	allowed, known := externalOperandsFor(rule.Op)
	if !known {
		return ExternalRuleV1{}, docErrorf(opNode.pointer, "must be one of eq, ne, lt, le, gt, ge, in, not_in, present, absent")
	}
	if len(allowed) == 0 {
		if len(present) > 0 {
			return ExternalRuleV1{}, docErrorf(node.members[present[0]].pointer, "%s takes no operand", rule.Op)
		}
		return rule, nil
	}
	if len(present) != 1 {
		return ExternalRuleV1{}, docErrorf(node.pointer, "%s needs exactly one of %s", rule.Op, strings.Join(allowed, ", "))
	}
	operand := node.members[present[0]]
	if !slices.Contains(allowed, present[0]) {
		return ExternalRuleV1{}, docErrorf(operand.pointer, "%s takes %s, not %s", rule.Op, strings.Join(allowed, ", "), present[0])
	}
	switch present[0] {
	case "number":
		v, err := decodeExternalNumber(operand)
		if err != nil {
			return ExternalRuleV1{}, err
		}
		rule.Number = &v
	case "string":
		v, err := decodeExternalString(operand)
		if err != nil {
			return ExternalRuleV1{}, err
		}
		rule.String = &v
	case "bool":
		v, err := jsonBool(operand)
		if err != nil {
			return ExternalRuleV1{}, err
		}
		rule.Bool = &v
	case "numbers":
		if rule.Numbers, err = decodeExternalList(operand, decodeExternalNumber); err != nil {
			return ExternalRuleV1{}, err
		}
	case "strings":
		if rule.Strings, err = decodeExternalList(operand, decodeExternalString); err != nil {
			return ExternalRuleV1{}, err
		}
	case "fact":
		if rule.Fact, err = jsonString(operand); err != nil {
			return ExternalRuleV1{}, err
		}
		fact, ok := LookupExternalFact(scope, rule.Fact)
		if !ok {
			return ExternalRuleV1{}, docErrorf(operand.pointer, "%s", unknownFactMessage(rule.Fact, scope))
		}
		if externalOpOrders(rule.Op) && !fact.Numeric {
			return ExternalRuleV1{}, docErrorf(operand.pointer, "%s compares numbers, and fact %q is not a number", rule.Op, rule.Fact)
		}
	}
	return rule, nil
}

// externalOperandsFor returns the operand fields op accepts, empty for an op
// that takes none, and whether op is known.
func externalOperandsFor(op ExternalOp) ([]string, bool) {
	switch op {
	case ExternalOpEq, ExternalOpNe:
		return []string{"number", "string", "bool", "fact"}, true
	case ExternalOpLt, ExternalOpLe, ExternalOpGt, ExternalOpGe:
		return []string{"number", "fact"}, true
	case ExternalOpIn, ExternalOpNotIn:
		return []string{"numbers", "strings"}, true
	case ExternalOpPresent, ExternalOpAbsent:
		return nil, true
	default:
		return nil, false
	}
}

func externalOpOrders(op ExternalOp) bool {
	switch op {
	case ExternalOpLt, ExternalOpLe, ExternalOpGt, ExternalOpGe:
		return true
	}
	return false
}

// decodeExternalNumber decodes a number operand: a decimal string, so the
// document never depends on how a JSON number is read.
func decodeExternalNumber(node *jsonNode) (string, error) {
	if node.kind == nodeNumber {
		return "", docErrorf(node.pointer, "a number operand must be a decimal string, e.g. %q", node.text)
	}
	raw, err := jsonString(node)
	if err != nil {
		return "", err
	}
	digits := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] >= '0' && raw[i] <= '9' {
			digits++
		}
	}
	if !externalNumberPattern.MatchString(raw) || digits > MaxExternalNumberDigits {
		return "", docErrorf(node.pointer, "number %q must be a plain decimal of at most %d digits, without exponent or leading zeros", raw, MaxExternalNumberDigits)
	}
	return raw, nil
}

func decodeExternalString(node *jsonNode) (string, error) {
	raw, err := jsonString(node)
	if err != nil {
		return "", err
	}
	if len(raw) > MaxExternalStringOperand {
		return "", docErrorf(node.pointer, "string is longer than %d bytes", MaxExternalStringOperand)
	}
	return raw, nil
}

func decodeExternalList(node *jsonNode, decode func(*jsonNode) (string, error)) ([]string, error) {
	items, err := jsonArrayItems(node, 1)
	if err != nil {
		return nil, err
	}
	if len(items) > MaxExternalListOperand {
		return nil, docErrorf(node.pointer, "at most %d entries are allowed", MaxExternalListOperand)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		v, err := decode(item)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// validateExternalChecks applies the rules that span sources and checks: the
// two fields come together, IDs are unique, every check names a source of the
// document and every source is used.
func (d *PolicyV1) validateExternalChecks() error {
	if len(d.ExternalSources) == 0 && len(d.ExternalChecks) == 0 {
		return nil
	}
	if len(d.ExternalChecks) == 0 {
		return docErrorf("/external_sources", "external_sources needs external_checks: a source no check uses is not accepted")
	}
	if len(d.ExternalSources) == 0 {
		return docErrorf("/external_checks", "external_checks needs external_sources")
	}
	seen := make(map[string]bool, len(d.ExternalChecks))
	used := make(map[string]bool, len(d.ExternalSources))
	for i, check := range d.ExternalChecks {
		cp := fmt.Sprintf("/external_checks/%d", i)
		if seen[check.ID] {
			return docErrorf(cp+"/id", "duplicate check id %q", check.ID)
		}
		seen[check.ID] = true
		if _, ok := d.ExternalSources[check.Source]; !ok {
			return docErrorf(cp+"/source", "unknown external source %q", check.Source)
		}
		used[check.Source] = true
	}
	for _, name := range d.ExternalSourceNames() {
		if !used[name] {
			return docErrorf("/external_sources/"+escapeJSONPointer(name), "no check uses source %q", name)
		}
	}
	return nil
}

// ExternalSourceNames returns the document's source names in order.
func (d *PolicyV1) ExternalSourceNames() []string {
	names := make([]string, 0, len(d.ExternalSources))
	for name := range d.ExternalSources {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
