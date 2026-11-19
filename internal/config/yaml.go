// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"bytes"
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

const ConfigSchemaVersion = 1

var yamlUnknownFieldRE = regexp.MustCompile(`field ([^ ]+) not found`)

func UnmarshalKnownFields(data []byte, out interface{}) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	return decoder.Decode(out)
}

func UnmarshalKnownConfigFields(data []byte, out interface{}) error {
	if err := UnmarshalKnownFields(data, out); err != nil {
		return wrapUnknownConfigFieldError(err)
	}
	return nil
}

func NormalizeConfigSchemaVersion(version int) int {
	if version == 0 {
		return ConfigSchemaVersion
	}
	return version
}

func ValidateConfigSchemaVersion(label string, version int) error {
	version = NormalizeConfigSchemaVersion(version)
	if version != ConfigSchemaVersion {
		return fmt.Errorf("%s schema_version = %d, want %d", label, version, ConfigSchemaVersion)
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
