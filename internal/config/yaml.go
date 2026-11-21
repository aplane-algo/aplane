// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"

	"gopkg.in/yaml.v3"
)

var yamlUnknownFieldRE = regexp.MustCompile(`field ([^ ]+) not found`)

func UnmarshalKnownFields(data []byte, out interface{}) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	return decoder.Decode(out)
}

// DecodeConfigFile strictly decodes the config.yaml read from path. A file
// that holds no YAML document, being empty, blank or only comments, is
// refused with its own message rather than read as the defaults: a signer
// config truncated to nothing would otherwise start without the settings it
// held. An operator who wants the defaults deletes the file or writes {}.
func DecodeConfigFile(path string, data []byte, out any) error {
	if err := UnmarshalKnownFields(data, out); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("config file %s is empty", path)
		}
		return fmt.Errorf("failed to parse config file %s: %w", path, wrapUnknownConfigFieldError(err))
	}
	return nil
}

// wrapUnknownConfigFieldError names the field a strict decode refused and
// says what to do. The field is misspelled or one this version does not
// read, often one an earlier version wrote before the setting moved or went
// away; either way the file has to drop it.
func wrapUnknownConfigFieldError(err error) error {
	matches := yamlUnknownFieldRE.FindStringSubmatch(err.Error())
	if len(matches) != 2 {
		return err
	}
	return fmt.Errorf("config field %q is unknown or no longer supported; remove it from the file: %w", matches[1], err)
}
