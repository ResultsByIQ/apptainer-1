// Copyright (c) 2021 Apptainer a Series of LF Projects LLC
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2020, Control Command Inc. All rights reserved.
// Copyright (c) 2020-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package sypgp

import (
	"context"
	"github.com/ProtonMail/go-crypto/openpgp"
)

// PublicKeyRing retrieves the Apptainer public KeyRing.
func PublicKeyRing() (openpgp.KeyRing, error) {
	return NewHandle("").LoadPubKeyring()
}

// hybridKeyRing is keyring made up of a local keyring as well as a keyserver. The type satisfies
// the openpgp.KeyRing interface.
type hybridKeyRing struct {
	local openpgp.KeyRing // Local keyring.
	ctx   context.Context // Context, for use when retrieving keys remotely.
}

// KeysById returns the set of keys that have the given key id.
//nolint:revive  // golang/x/crypto uses Id instead of ID so we have to too
func (kr *hybridKeyRing) KeysById(id uint64) []openpgp.Key {
	if keys := kr.local.KeysById(id); len(keys) > 0 {
		return keys
	}
	return nil
}

// KeysByIdUsage returns the set of keys with the given id that also meet the key usage given by
// requiredUsage. The requiredUsage is expressed as the bitwise-OR of packet.KeyFlag* values.
//nolint:revive  // golang/x/crypto uses Id instead of ID so we have to too
func (kr *hybridKeyRing) KeysByIdUsage(id uint64, requiredUsage byte) []openpgp.Key {
	if keys := kr.local.KeysByIdUsage(id, requiredUsage); len(keys) > 0 {
		return keys
	}
	return nil
}

// DecryptionKeys returns all private keys that are valid for decryption.
func (kr *hybridKeyRing) DecryptionKeys() []openpgp.Key {
	return kr.local.DecryptionKeys()
}

type multiKeyRing struct {
	keyrings []openpgp.KeyRing
}

// NewMultiKeyRing returns a keyring backed by different public keyring.
func NewMultiKeyRing(keyrings ...openpgp.KeyRing) openpgp.KeyRing {
	return &multiKeyRing{keyrings: keyrings}
}

// KeysById returns the set of keys that have the given key id.
//nolint:revive  // golang/x/crypto uses Id instead of ID so we have to too
func (mkr *multiKeyRing) KeysById(id uint64) []openpgp.Key {
	for _, kr := range mkr.keyrings {
		if keys := kr.KeysById(id); len(keys) > 0 {
			return keys
		}
	}
	return nil
}

// KeysByIdUsage returns the set of keys with the given id that also meet the key usage given by
// requiredUsage. The requiredUsage is expressed as the bitwise-OR of packet.KeyFlag* values.
//nolint:revive  // golang/x/crypto uses Id instead of ID so we have to too
func (mkr *multiKeyRing) KeysByIdUsage(id uint64, requiredUsage byte) []openpgp.Key {
	for _, kr := range mkr.keyrings {
		if keys := kr.KeysByIdUsage(id, requiredUsage); len(keys) > 0 {
			return keys
		}
	}
	return nil
}

// DecryptionKeys returns all private keys that are valid for decryption.
func (mkr *multiKeyRing) DecryptionKeys() []openpgp.Key {
	for _, kr := range mkr.keyrings {
		if keys := kr.DecryptionKeys(); len(keys) > 0 {
			return keys
		}
	}
	return nil
}
