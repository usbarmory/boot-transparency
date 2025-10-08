// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package uefi_bios

import (
	"testing"

	"github.com/usbarmory/boot-transparency/artifact"
)

func TestUEFIBIOSParseRequirements(t *testing.T) {
	r := []byte(`{"min_uefi_revision":"v2.7.0", "firmware_vendor":["Lenovo"], "min_firmware_revision":"0x1560"}`)

	h, err := artifact.GetHandler(artifact.UEFIBIOS)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.ParseRequirements(r); err != nil {
		t.Fatal(err)
	}
}

func TestNegativeUEFIBIOSParseRequirements(t *testing.T) {
	r := []byte(`{"min_uefi_revision":"v2.7.0", "firmware_vendor":"Lenovo", "min_firmware_revision":"0x1560"}`)

	h, err := artifact.GetHandler(artifact.UEFIBIOS)
	if err != nil {
		t.Fatal(err)
	}

	// error expected: "firmware vendor" must be an array
	if _, err := h.ParseRequirements(r); err == nil {
		t.Fatal(err)
	}
}

func TestUEFIBIOSParseClaims(t *testing.T) {
	c := []byte(`{"uefi_revision":"v2.7.0", "firmware_vendor":"Lenovo", "firmware_revision":"0x1560"}`)

	h, err := artifact.GetHandler(artifact.UEFIBIOS)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.ParseClaims(c); err != nil {
		t.Fatal(err)
	}
}

func TestNegativeUEFIBIOSParseClaims(t *testing.T) {
	c := []byte(`{"uefi_revision":"v2.7.0", "firmware_vendor":[ "Lenovo" ], "firmware_revision":"0x1560"}`)

	h, err := artifact.GetHandler(artifact.UEFIBIOS)
	if err != nil {
		t.Fatal(err)
	}

	// error expected: "firmware_vendor" cannot be an array
	if _, err := h.ParseClaims(c); err == nil {
		t.Fatal(err)
	}
}

func TestUEFIBIOSCheck(t *testing.T) {
	r := []byte(`{"min_uefi_revision":"v2.7.0", "firmware_vendor":[ "Lenovo" ], "min_firmware_revision":"0x1560"}`)
	c := []byte(`{"uefi_revision":"v2.7.0", "firmware_vendor":"Lenovo" , "firmware_revision":"0x1560"}`)

	h, err := artifact.GetHandler(artifact.UEFIBIOS)
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

func TestNegativeUEFIBIOSCheck(t *testing.T) {
	r := []byte(`{"min_uefi_revision":"v2.7.0", "firmware_vendor":[ "Lenovo" ], "min_firmware_revision":"0x1560"}`)
	c := []byte(`{"uefi_revision":"v2.7.0", "firmware_vendor":"Unknown", "firmware_revision":"0x1560"}`)

	h, err := artifact.GetHandler(artifact.UEFIBIOS)
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

	// error expected: the claimed "vendor" are not present in the required ones
	if err = h.Check(parsedRequirements, parsedClaims); err == nil {
		t.Fatal(err)
	}
}
