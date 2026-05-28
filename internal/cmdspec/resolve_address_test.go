// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cmdspec

import (
	"errors"
	"reflect"
	"testing"
)

type stubListResolver struct {
	inputs []string
	result []string
	err    error
}

func (s *stubListResolver) ResolveList(inputs []string) ([]string, error) {
	s.inputs = append([]string(nil), inputs...)
	if s.err != nil {
		return nil, s.err
	}
	return append([]string(nil), s.result...), nil
}

type stubSingleResolver struct {
	input string
	addr  string
	err   error
}

func (s *stubSingleResolver) ResolveSingle(input string) (string, error) {
	s.input = input
	if s.err != nil {
		return "", s.err
	}
	return s.addr, nil
}

func TestResolveAddressList(t *testing.T) {
	resolver := &stubListResolver{result: []string{"ADDR1", "ADDR2"}}
	got, err := ResolveAddressList([]string{"alice", "@friends"}, resolver)
	if err != nil {
		t.Fatalf("ResolveAddressList() error = %v", err)
	}
	if !reflect.DeepEqual(got, []string{"ADDR1", "ADDR2"}) {
		t.Fatalf("ResolveAddressList() = %v", got)
	}
	if !reflect.DeepEqual(resolver.inputs, []string{"alice", "@friends"}) {
		t.Fatalf("ResolveList inputs = %v", resolver.inputs)
	}
}

func TestResolveAddressList_Empty(t *testing.T) {
	resolver := &stubListResolver{result: []string{}}
	_, err := ResolveAddressList([]string{"alice"}, resolver)
	if err == nil {
		t.Fatal("expected error for empty result")
	}
}

func TestResolveSingleAddress(t *testing.T) {
	resolver := &stubSingleResolver{addr: "ADDR1"}
	got, err := ResolveSingleAddress("alice", resolver)
	if err != nil {
		t.Fatalf("ResolveSingleAddress() error = %v", err)
	}
	if got != "ADDR1" {
		t.Fatalf("ResolveSingleAddress() = %v", got)
	}
	if resolver.input != "alice" {
		t.Fatalf("ResolveSingle input = %v", resolver.input)
	}
}

func TestResolveSingleAddress_Error(t *testing.T) {
	resolver := &stubSingleResolver{err: errors.New("boom")}
	_, err := ResolveSingleAddress("alice", resolver)
	if err == nil {
		t.Fatal("expected error")
	}
}
