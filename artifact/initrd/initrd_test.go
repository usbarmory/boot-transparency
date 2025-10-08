// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package initrd

import (
	"testing"

	"github.com/usbarmory/boot-transparency/artifact"
)

func TestInitrdParseRequirements(t *testing.T) {
	r := []byte(`{"min_version": "v6.14.0", "architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "min_timestamp": "2025-01-01T23:20:50.52Z", "metadata": "CONFIG_STACKPROTECTOR_STRONG=y" }`)

	h, err := artifact.GetHandler(artifact.Initrd)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.ParseRequirements(r); err != nil {
		t.Fatal(err)
	}
}

func TestInitrdParseClaims(t *testing.T) {
	c := []byte(`{"file_name": "initrd.img-6.14.0-29-generic", "hash": "9f5db8bc106c426a6654aa53ada75db307adb6dcb59291aa0a874898bc197b3dad8d2ebef985936bba94e9ae34b52a79e8f9045346cde2326baf4feba73ab66c", "version":"v6.14.0-29-generic" ,"architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "timestamp": "2025-10-21T23:20:50.52Z", "metadata": "CONFIG_STACKPROTECTOR_STRONG=y" }`)

	h, err := artifact.GetHandler(artifact.Initrd)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.ParseClaims(c); err != nil {
		t.Fatal(err)
	}
}

func TestNegativeInitrdParseClaims(t *testing.T) {
	c := []byte(`{"hash": ["9f5db8bc106c426a6654aa53ada75db307adb6dcb59291aa0a874898bc197b3dad8d2ebef985936bba94e9ae34b52a79e8f9045346cde2326baf4feba73ab66c"], "version":"v6.14.0-29-generic" ,"architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "timestamp": "2025-10-21T23:20:50.52Z", "metadata": "CONFIG_STACKPROTECTOR_STRONG=y" }`)

	h, err := artifact.GetHandler(artifact.Initrd)
	if err != nil {
		t.Fatal(err)
	}

	// error is expected: "hash" cannot be an array
	if _, err := h.ParseClaims(c); err == nil {
		t.Fatal(err)
	}
}

func TestInitrdCheck(t *testing.T) {
	r := []byte(`{"min_version": "v6.14.0-29-generic", "architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "min_timestamp": "2025-01-01T23:20:50.52Z", "metadata": "CONFIG_STACKPROTECTOR_STRONG=y" }`)

	c := []byte(`{"file_name": "initrd.img-6.14.0-29-generic", "hash": "9f5db8bc106c426a6654aa53ada75db307adb6dcb59291aa0a874898bc197b3dad8d2ebef985936bba94e9ae34b52a79e8f9045346cde2326baf4feba73ab66c","version":"v6.14.0-29-generic" ,"architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "timestamp": "2025-10-21T23:20:50.52Z", "metadata": "CONFIG_STACKPROTECTOR_STRONG=y" }`)

	h, err := artifact.GetHandler(artifact.Initrd)
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

func TestNegativeInitrdCheck(t *testing.T) {
	r := []byte(`{"min_version": "v6.12.0-10-generic", "architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "min_timestamp": "2025-01-01T23:20:50.52Z", "metadata": "CONFIG_STACKPROTECTOR_STRONG=y" }`)

	c := []byte(`{"file_name": "initrd.img-6.14.0-29-generic", "hash": "9f5db8bc106c426a6654aa53ada75db307adb6dcb59291aa0a874898bc197b3dad8d2ebef985936bba94e9ae34b52a79e8f9045346cde2326baf4feba73ab66c","version":"v6.14.0-29-generic" ,"architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "timestamp": "2025-10-21T23:20:50.52Z" }`)

	h, err := artifact.GetHandler(artifact.Initrd)
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

	// error expected: the claimed "metadata" is not matching the required one
	if err = h.Check(parsedRequirements, parsedClaims); err == nil {
		t.Fatal(err)
	}
}
