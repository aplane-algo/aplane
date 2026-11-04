// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientlog

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aplane-algo/aplane/internal/termsafe"
)

const (
	// maxLineBytes bounds a rendered line, measured after escaping and including
	// the prefix and truncation marker.
	maxLineBytes     = 4096
	truncationMarker = " ...[truncated]"

	// defaultComponent names a record that didn't say where it came from.
	defaultComponent = "aplane"

	componentKey = "component"
	// A record from a plugin has component "plugin" and names the plugin in its
	// own attribute. A plugin chooses its name, so using it as the component would
	// let one call itself "cache" and pass as the host. Plugin output is therefore
	// always shown under the fixed prefix "[plugin <name> <stream>]".
	pluginComponent = "plugin"
	pluginKey       = "plugin"
	streamKey       = "stream"
)

// field is one attribute, flattened: key holds the full dotted group path.
type field struct {
	key      string
	value    string
	topLevel bool
}

// handler renders records for people to read:
//
//	[cache] warning: failed to save auth cache error="disk full"
//	[plugin mithras stderr] cannot find module foo
//
// A handler is immutable; WithAttrs and WithGroup return new ones.
type handler struct {
	pipeline *pipeline
	fields   []field
	group    string
}

var _ slog.Handler = (*handler)(nil)

func (h *handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.pipeline.level.Level()
}

func (h *handler) Handle(_ context.Context, record slog.Record) error {
	fields := h.fields[:len(h.fields):len(h.fields)]
	record.Attrs(func(attr slog.Attr) bool {
		fields = appendAttr(fields, h.group, attr)
		return true
	})
	return h.pipeline.write(Record{
		Level: record.Level,
		Line:  render(record.Level, record.Message, fields),
	})
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	fields := h.fields[:len(h.fields):len(h.fields)]
	for _, attr := range attrs {
		fields = appendAttr(fields, h.group, attr)
	}
	return &handler{pipeline: h.pipeline, fields: fields, group: h.group}
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &handler{pipeline: h.pipeline, fields: h.fields, group: h.group + name + "."}
}

// appendAttr flattens attr under group. slog's rules apply: an empty attribute
// and an empty group vanish, and a group with no key is inlined.
func appendAttr(fields []field, group string, attr slog.Attr) []field {
	value := attr.Value.Resolve()
	if attr.Equal(slog.Attr{}) {
		return fields
	}
	if value.Kind() == slog.KindGroup {
		inner := group
		if attr.Key != "" {
			inner = group + attr.Key + "."
		}
		for _, member := range value.Group() {
			fields = appendAttr(fields, inner, member)
		}
		return fields
	}
	return append(fields, field{
		key:      group + attr.Key,
		value:    value.String(),
		topLevel: group == "",
	})
}

func lastTopLevel(fields []field, key string) string {
	for i := len(fields) - 1; i >= 0; i-- {
		if fields[i].topLevel && fields[i].key == key {
			return fields[i].value
		}
	}
	return ""
}

func prefix(component string, fields []field) string {
	switch component {
	case "":
		return defaultComponent
	case pluginComponent:
		parts := []string{pluginComponent}
		for _, key := range []string{pluginKey, streamKey} {
			if value := lastTopLevel(fields, key); value != "" {
				parts = append(parts, value)
			}
		}
		return strings.Join(parts, " ")
	}
	return component
}

// consumed reports whether a field is already shown in the prefix. Only the
// top-level attributes qualify, so a grouped field of the same name is kept.
func consumed(f field, component string) bool {
	if !f.topLevel {
		return false
	}
	if f.key == componentKey {
		return true
	}
	return component == pluginComponent && (f.key == pluginKey || f.key == streamKey)
}

func render(level slog.Level, message string, fields []field) string {
	component := lastTopLevel(fields, componentKey)

	var line strings.Builder
	line.WriteByte('[')
	line.WriteString(prefix(component, fields))
	line.WriteString("] ")
	switch {
	case level >= slog.LevelError:
		line.WriteString("error: ")
	case level >= slog.LevelWarn:
		line.WriteString("warning: ")
	}
	line.WriteString(message)
	for _, f := range fields {
		if consumed(f, component) {
			continue
		}
		line.WriteByte(' ')
		line.WriteString(quoted(f.key))
		line.WriteByte('=')
		line.WriteString(quoted(f.value))
	}
	// Names, values, and errors can all carry text from outside this program, so
	// the whole line is escaped, not only the parts that look untrusted.
	return capLine(termsafe.Line(line.String()))
}

// quoted follows slog's TextHandler: plain words stay bare.
func quoted(s string) string {
	if s == "" {
		return `""`
	}
	for _, r := range s {
		if r == '=' || r == '"' || unicode.IsSpace(r) || !unicode.IsPrint(r) {
			return strconv.Quote(s)
		}
	}
	return s
}

// capLine shortens a line to maxLineBytes, cutting on a character boundary. The
// result is a new string, so a retained line doesn't pin a larger one.
func capLine(line string) string {
	if len(line) <= maxLineBytes {
		return line
	}
	cut := maxLineBytes - len(truncationMarker)
	for cut > 0 && !utf8.RuneStart(line[cut]) {
		cut--
	}
	return line[:cut] + truncationMarker
}
