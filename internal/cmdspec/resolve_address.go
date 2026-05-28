// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cmdspec

import "fmt"

type AddressListResolver interface {
	ResolveList(inputs []string) ([]string, error)
}

type SingleAddressResolver interface {
	ResolveSingle(input string) (string, error)
}

func ResolveAddressList(raw []string, resolver AddressListResolver) ([]string, error) {
	addresses, err := resolver.ResolveList(raw)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no addresses resolved")
	}
	return addresses, nil
}

func ResolveSingleAddress(raw string, resolver SingleAddressResolver) (string, error) {
	return resolver.ResolveSingle(raw)
}
