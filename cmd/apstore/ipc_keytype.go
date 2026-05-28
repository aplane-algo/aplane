// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/protocol"
)

func cmdActivateKeyType(keyType string) error {
	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()

	var result protocol.ActivateKeyTypeResultMessage
	err = client.request(protocol.ActivateKeyTypeMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeActivateKeyType, ID: newApstoreRequestID("keytype-activate")},
		KeyType:     keyType,
	}, &result)
	if err != nil {
		return err
	}
	if !result.Success {
		return resultError("key type activation failed", result.Code, result.Error)
	}
	if result.AlreadyExists {
		logInfof("key type %s was already activated", displayKeyType(result.KeyType))
		return nil
	}
	logInfof("key type %s activated", displayKeyType(result.KeyType))
	return nil
}

func cmdDeactivateKeyType(keyType string) error {
	if !confirmDeactivateKeyType(keyType) {
		return fmt.Errorf("key type deactivation cancelled")
	}

	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()

	var result protocol.DeactivateKeyTypeResultMessage
	err = client.request(protocol.DeactivateKeyTypeMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeDeactivateKeyType, ID: newApstoreRequestID("keytype-deactivate")},
		KeyType:     keyType,
	}, &result)
	if err != nil {
		return err
	}
	if !result.Success {
		return resultError("key type deactivation failed", result.Code, result.Error)
	}
	if result.Removed {
		logInfof("key type %s deactivated", displayKeyType(result.KeyType))
		return nil
	}
	logInfof("key type %s was already deactivated", displayKeyType(result.KeyType))
	return nil
}
