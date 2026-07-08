// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"reflect"
	"testing"

	"github.com/aplane-algo/aplane/internal/signerapi"
)

type stubAddressListResolver struct {
	inputs []string
	result []string
	err    error
}

func (s *stubAddressListResolver) ResolveList(inputs []string) ([]string, error) {
	s.inputs = append([]string(nil), inputs...)
	if s.err != nil {
		return nil, s.err
	}
	return append([]string(nil), s.result...), nil
}

func TestExpandGenerateAddressListParams_ExpandsSetForAddressListParam(t *testing.T) {
	keyTypes := []signerapi.KeyTypeInfo{
		{
			KeyType: "aplane.whitelist.v1",
			CreationParams: []signerapi.CreationParamInfo{
				{Name: "recipients", Type: "address[]"},
			},
		},
	}
	resolver := &stubAddressListResolver{
		result: []string{"ADDR1", "ADDR2", "ADDR3"},
	}

	got, err := expandGenerateAddressListParams(
		"aplane.whitelist.v1",
		map[string]string{"recipients": "@friends"},
		keyTypes,
		resolver,
	)
	if err != nil {
		t.Fatalf("expandGenerateAddressListParams returned error: %v", err)
	}
	if !reflect.DeepEqual(resolver.inputs, []string{"@friends"}) {
		t.Fatalf("ResolveList inputs = %v, want [@friends]", resolver.inputs)
	}
	want := map[string]string{"recipients": "ADDR1,ADDR2,ADDR3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expanded params = %v, want %v", got, want)
	}
}

func TestExpandGenerateAddressListParams_ResolvesMixedAddressList(t *testing.T) {
	keyTypes := []signerapi.KeyTypeInfo{
		{
			KeyType: "aplane.whitelist.v1",
			CreationParams: []signerapi.CreationParamInfo{
				{Name: "recipients", Type: "address[]"},
			},
		},
	}
	resolver := &stubAddressListResolver{result: []string{"ADDR1", "ADDR2", "ADDR3"}}
	input := map[string]string{"recipients": "ADDR1, @friends, alice"}

	got, err := expandGenerateAddressListParams("aplane.whitelist.v1", input, keyTypes, resolver)
	if err != nil {
		t.Fatalf("expandGenerateAddressListParams returned error: %v", err)
	}
	if !reflect.DeepEqual(resolver.inputs, []string{"ADDR1", "@friends", "alice"}) {
		t.Fatalf("ResolveList inputs = %v, want [ADDR1 @friends alice]", resolver.inputs)
	}
	want := map[string]string{"recipients": "ADDR1,ADDR2,ADDR3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expanded params = %v, want %v", got, want)
	}
}

func TestExpandGenerateAddressListParams_SortsAddressListByDefault(t *testing.T) {
	keyTypes := []signerapi.KeyTypeInfo{
		{
			KeyType: "aplane.whitelist.v1",
			CreationParams: []signerapi.CreationParamInfo{
				{Name: "recipients", Type: "address[]"},
			},
		},
	}
	resolver := &stubAddressListResolver{result: []string{"ADDR2", "ADDR1", "ADDR3"}}

	got, err := expandGenerateAddressListParams(
		"aplane.whitelist.v1",
		map[string]string{"recipients": "@friends"},
		keyTypes,
		resolver,
	)
	if err != nil {
		t.Fatalf("expandGenerateAddressListParams returned error: %v", err)
	}
	want := map[string]string{"recipients": "ADDR1,ADDR2,ADDR3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expanded params = %v, want %v", got, want)
	}
}

func TestExpandGenerateAddressListParams_LeavesNonAddressListParamsUnchanged(t *testing.T) {
	keyTypes := []signerapi.KeyTypeInfo{
		{
			KeyType: "aplane.timed-whitelist.v1",
			CreationParams: []signerapi.CreationParamInfo{
				{Name: "expiry", Type: "uint64"},
			},
		},
	}
	resolver := &stubAddressListResolver{}
	input := map[string]string{"expiry": "@notaset"}

	got, err := expandGenerateAddressListParams("aplane.timed-whitelist.v1", input, keyTypes, resolver)
	if err != nil {
		t.Fatalf("expandGenerateAddressListParams returned error: %v", err)
	}
	if resolver.inputs != nil {
		t.Fatalf("ResolveList should not have been called, got %v", resolver.inputs)
	}
	if !reflect.DeepEqual(got, input) {
		t.Fatalf("expanded params = %v, want %v", got, input)
	}
}

func TestExpandGenerateAddressListParams_UnknownKeyType(t *testing.T) {
	_, err := expandGenerateAddressListParams(
		"missing-v1",
		map[string]string{"recipients": "@friends"},
		nil,
		&stubAddressListResolver{},
	)
	if err == nil {
		t.Fatal("expected error for unknown key type")
	}
}
