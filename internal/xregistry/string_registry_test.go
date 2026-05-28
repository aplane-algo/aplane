// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package xregistry

import (
	"sync"
	"testing"
)

func TestStringRegistryBasic(t *testing.T) {
	r := NewStringRegistry[int]()

	if !r.Set("a", 1) {
		t.Error("expected Set to return true for new key")
	}
	if r.Set("a", 2) {
		t.Error("expected Set to return false for existing key")
	}

	v, ok := r.Get("a")
	if !ok || v != 1 {
		t.Errorf("expected Get(a) = (1, true), got (%d, %v)", v, ok)
	}

	_, ok = r.Get("nonexistent")
	if ok {
		t.Error("expected Get(nonexistent) to return false")
	}
}

func TestStringRegistryHas(t *testing.T) {
	r := NewStringRegistry[string]()
	r.Set("key", "value")

	if !r.Has("key") {
		t.Error("expected Has(key) to return true")
	}
	if r.Has("missing") {
		t.Error("expected Has(missing) to return false")
	}
}

func TestStringRegistryKeys(t *testing.T) {
	r := NewStringRegistry[int]()
	r.Set("cherry", 3)
	r.Set("apple", 1)
	r.Set("banana", 2)

	keys := r.Keys()
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}

	expected := []string{"apple", "banana", "cherry"}
	for i, k := range keys {
		if k != expected[i] {
			t.Errorf("expected keys[%d] = %s, got %s", i, expected[i], k)
		}
	}
}

func TestStringRegistryValues(t *testing.T) {
	r := NewStringRegistry[int]()
	r.Set("cherry", 3)
	r.Set("apple", 1)
	r.Set("banana", 2)

	values := r.Values()
	if len(values) != 3 {
		t.Fatalf("expected 3 values, got %d", len(values))
	}

	expected := []int{1, 2, 3}
	for i, v := range values {
		if v != expected[i] {
			t.Errorf("expected values[%d] = %d, got %d", i, expected[i], v)
		}
	}
}

func TestStringRegistryConcurrent(t *testing.T) {
	r := NewStringRegistry[int]()
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r.Set(string(rune('a'+i%26)), i)
		}(i)
	}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r.Get(string(rune('a' + i%26)))
			r.Has(string(rune('a' + i%26)))
			r.Keys()
			r.Values()
		}(i)
	}

	wg.Wait()

	if len(r.Keys()) > 26 {
		t.Errorf("expected at most 26 keys, got %d", len(r.Keys()))
	}
}
