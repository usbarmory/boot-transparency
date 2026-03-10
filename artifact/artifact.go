// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package artifact

import (
	"crypto/sha256"
	"fmt"
	"hash"
)

// Supported artifact category UIDs.
const (
	// 0x0001 - 0x7FFF reserved for boot artifacts.
	LinuxKernel uint = iota + 0x0001
	Initrd
	Dtb
	UEFIBinary
	WindowsBootMgr
	_end_boot_categories = 0x8000

	// 0x8001 - 0x9FFF reserved for generic artifacts.
	CVE
	_end_generic_categories = 0xA000

	// 0xA001 - 0xFFFF reserved.
	//_end_reserved = 0xFFFF
)

// Handler represents a high-level interface for artifact handlers.
//
// This interface abstracts the functionalities implemented by the
// underlying artifact category package.
type Handler interface {
	// Parse serialized JSON containing requirements for a given artifact.
	ParseRequirements(jsonRequirements []byte) (interface{}, error)
	// Parse serialized JSON containing claims for a given artifact.
	ParseClaims(jsonClaims []byte) (interface{}, error)
	// Validate matching between requirements and claims for a given artifact.
	Validate(requirements interface{}, claims interface{}) error
}

// List of registered artifact handlers.
var handlers = make(map[uint]*Handler)

// Add an artifact handler for a given category.
func Add(h Handler, c uint) {
	handlers[c] = &h
}

// GetHandler returns the registered artifact handler, if any, for a given category.
func GetHandler(c uint) (Handler, error) {
	h := handlers[c]
	if h == nil {
		return nil, fmt.Errorf("Handler not registered for %q artifact category", c)
	}

	return *h, nil
}

// Library hasher. Set to crypto/sha256 by default.
var hasher = sha256.New()

// Boot-transparency supports by-default SHA-256 hashing algorithm
// implemented by the crypto standard library.
// SetHasher allows library users to override the default hasher with
// any custom implementation of the hash.Hash interface.
func SetHasher(newHasher func() hash.Hash) {
	if newHasher == nil {
		return
	}

	hasher = newHasher()
}

// HashSize returns the hash size for the boot-transparency
// artifacts, which depends by the selected hashing algorithm.
func HashSize() int {
	return hasher.Size()
}

// Sum returns the checksum of the data computed by the
// library hasher, that can be configured via SetHasher.
func Sum(data []byte) []byte {
	hasher.Reset()
	hasher.Write(data)

	return hasher.Sum(nil)
}
