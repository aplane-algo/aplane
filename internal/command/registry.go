// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package command

import (
	"fmt"
	"sort"
	"sync"
)

type Registry struct {
	commands map[string]*Command
	primary  []*Command
	mu       sync.RWMutex
}

func NewRegistry() *Registry {
	return &Registry{
		commands: make(map[string]*Command),
		primary:  make([]*Command, 0),
	}
}

func (r *Registry) Register(cmd *Command) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if cmd == nil {
		return fmt.Errorf("command is nil")
	}
	if cmd.Name == "" {
		return fmt.Errorf("command name is required")
	}
	if cmd.Handler == nil {
		return fmt.Errorf("command %q handler is required", cmd.Name)
	}

	if existing, exists := r.commands[cmd.Name]; exists {
		return fmt.Errorf("command %q already registered", existing.Name)
	}

	seenAliases := make(map[string]struct{}, len(cmd.Aliases))
	for _, alias := range cmd.Aliases {
		if alias == "" {
			return fmt.Errorf("command %q has empty alias", cmd.Name)
		}
		if existing, exists := r.commands[alias]; exists {
			return fmt.Errorf("alias %q conflicts with existing command %q",
				alias, existing.Name)
		}
		if alias == cmd.Name {
			return fmt.Errorf("alias %q conflicts with command %q", alias, cmd.Name)
		}
		if _, exists := seenAliases[alias]; exists {
			return fmt.Errorf("command %q has duplicate alias %q", cmd.Name, alias)
		}
		seenAliases[alias] = struct{}{}
	}

	r.commands[cmd.Name] = cmd
	r.primary = append(r.primary, cmd)

	for _, alias := range cmd.Aliases {
		r.commands[alias] = cmd
	}

	return nil
}

func (r *Registry) Lookup(name string) (*Command, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cmd, ok := r.commands[name]
	return cmd, ok
}

func (r *Registry) All() []*Command {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*Command, len(r.primary))
	copy(result, r.primary)
	return result
}

func (r *Registry) ByCategory() map[string][]*Command {
	r.mu.RLock()
	defer r.mu.RUnlock()

	categories := make(map[string][]*Command)
	for _, cmd := range r.primary {
		categories[cmd.Category] = append(categories[cmd.Category], cmd)
	}

	for _, cmds := range categories {
		sort.Slice(cmds, func(i, j int) bool {
			return cmds[i].Name < cmds[j].Name
		})
	}

	return categories
}
