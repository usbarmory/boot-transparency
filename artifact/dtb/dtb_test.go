// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package dtb

import (
	"testing"

	"github.com/usbarmory/boot-transparency/artifact"
)

func TestDtbParseRequirements(t *testing.T) {
	r := []byte(`{"min_version": "v6.14.0", "architecture":"x64", "license": ["GPL-2.0-only"], "min_timestamp": "2025-01-01T23:20:50.52Z", "metadata": {"dts_url": "https://android.googlesource.com/kernel/common/+/5fc6ed1831ca5/arch/arm/boot/dts/imx53-usbarmory.dts"}}`)

	h, err := artifact.GetHandler(artifact.Dtb)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.ParseRequirements(r); err != nil {
		t.Fatal(err)
	}
}

func TestDtbParseClaims(t *testing.T) {
	c := []byte(`{"file_name": "imx53-usbarmory.dtb", "file_hash": "337630b74e55eae241f460faadf5a2f9a2157d6de2853d4106c35769e4acf538", "version":"v6.14.0-29-generic" ,"architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "timestamp": "2025-10-21T23:20:50.52Z"}`)

	h, err := artifact.GetHandler(artifact.Dtb)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.ParseClaims(c); err != nil {
		t.Fatal(err)
	}
}

func TestNegativeDtbParseClaims(t *testing.T) {
	c := []byte(`{"file_hash": [ "8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59" ]}`)

	h, err := artifact.GetHandler(artifact.Dtb)
	if err != nil {
		t.Fatal(err)
	}

	// error is expected: "hash" cannot be an array
	if _, err := h.ParseClaims(c); err == nil {
		t.Fatal(err)
	}
}

func TestDtbValidate(t *testing.T) {
	r := []byte(`{"min_version": "v6.14.0-29", "architecture":"x64", "metadata":{"model": "Inverse Path USB armory"}}`)

	c := []byte(`{"file_name": "test.dtb", "file_hash": "337630b74e55eae241f460faadf5a2f9a2157d6de2853d4106c35769e4acf538", "version":"v6.14.0-29-generic" ,"architecture":"x64", "metadata":{"model":"USB armory"}}`)

	h, err := artifact.GetHandler(artifact.Dtb)
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

	if err = h.Validate(parsedRequirements, parsedClaims); err != nil {
		t.Fatal(err)
	}
}

func TestNegativeDtbValidate(t *testing.T) {
	r := []byte(`{"min_version": "v6.14.0-29", "architecture":"x64", "metadata":{"model": "Inverse Path USB armory"}}`)

	c := []byte(`{"file_name": "test.dtb", "file_hash": "337630b74e55eae241f460faadf5a2f9a2157d6de2853d4106c35769e4acf538", "version":"v6.14.0-29-generic" ,"architecture":"x64", "metadata":{"model":"something else"}}`)

	h, err := artifact.GetHandler(artifact.Dtb)
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
	if err = h.Validate(parsedRequirements, parsedClaims); err == nil {
		t.Fatal(err)
	}
}
