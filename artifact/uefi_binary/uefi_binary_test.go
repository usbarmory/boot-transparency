// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package uefi_binary

import (
	"testing"

	"github.com/usbarmory/boot-transparency/artifact"
)

func TestUEFIBinaryParseRequirements(t *testing.T) {
	r := []byte(`{"min_version": "v2.0", "architecture":"x64"}`)

	h, err := artifact.GetHandler(artifact.UEFIBinary)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.ParseRequirements(r); err != nil {
		t.Fatal(err)
	}
}

func TestUEFIBinaryParseClaims(t *testing.T) {
	c := []byte(`{"file_name": "boot64.efi", "hash": "8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59", "version":"v2.1"}`)

	h, err := artifact.GetHandler(artifact.UEFIBinary)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.ParseClaims(c); err != nil {
		t.Fatal(err)
	}
}

func TestNegativeUEFIBinaryParseClaims(t *testing.T) {
	c := []byte(`{"hash": [ "8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59" ], "version":"v2.1"}"`)

	h, err := artifact.GetHandler(artifact.UEFIBinary)
	if err != nil {
		t.Fatal(err)
	}

	// error is expected: "hash" cannot be an array
	if _, err := h.ParseClaims(c); err == nil {
		t.Fatal(err)
	}
}

func TestUEFIBinaryCheck(t *testing.T) {
	r := []byte(`{"min_version": "v2.0"}`)

	c := []byte(`{"file_name": "boot64.efi", "hash": "8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59", "version":"v2.1"}`)

	h, err := artifact.GetHandler(artifact.UEFIBinary)
	if err != nil {
		t.Fatal(err)
	}

	parsedRequirements, err := h.ParseRequirements(r)
	if err != nil {
		t.Fatal(err)
	}

	parsedClaims, err := h.ParseClaims(c)
	if err != nil {
		t.Fatal(err)
	}

	if err = h.Check(parsedRequirements, parsedClaims); err != nil {
		t.Fatal(err)
	}
}

func TestNegativeUEFIBinaryCheck(t *testing.T) {
	r := []byte(`{"min_version": "v3.0", "architecture":"x64"}`)

	c := []byte(`{"file_name": "boot64.efi", "hash": "8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59", "version":"v2.1"}`)

	h, err := artifact.GetHandler(artifact.UEFIBinary)
	if err != nil {
		t.Fatal(err)
	}

	parsedRequirements, err := h.ParseRequirements(r)
	if err != nil {
		t.Fatal(err)
	}

	parsedClaims, err := h.ParseClaims(c)
	if err != nil {
		t.Fatal(err)
	}

	// error expected: the claimed "version" does not met requirements
	if err = h.Check(parsedRequirements, parsedClaims); err == nil {
		t.Fatal(err)
	}
}
