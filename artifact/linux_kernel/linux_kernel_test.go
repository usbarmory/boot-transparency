// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package linux_kernel

import (
	"testing"

	"github.com/usbarmory/boot-transparency/artifact"
)

func TestLinuxKernelParseRequirements(t *testing.T) {
	r := []byte(`{"min_version": "v6.14.0", "architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "min_timestamp": "2025-01-01T23:20:50.52Z", "metadata": "CONFIG_STACKPROTECTOR_STRONG=y" }`)

	h, err := artifact.GetHandler(artifact.LinuxKernel)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.ParseRequirements(r); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxKernelParseClaims(t *testing.T) {
	c := []byte(`{"file_name": "vmlinuz-6.14.0-29-generic", "hash": "8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59", "version":"v6.14.0-29-generic" ,"architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "timestamp": "2025-10-21T23:20:50.52Z", "metadata": "CONFIG_STACKPROTECTOR_STRONG=y" }`)

	h, err := artifact.GetHandler(artifact.LinuxKernel)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.ParseClaims(c); err != nil {
		t.Fatal(err)
	}
}

func TestNegativeLinuxKernelParseClaims(t *testing.T) {
	c := []byte(`{"hash": [ "8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59" ], "version":"v6.14.0-29-generic" ,"architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "timestamp": "2025-10-21T23:20:50.52Z", "metadata": "CONFIG_STACKPROTECTOR_STRONG=y" }`)

	h, err := artifact.GetHandler(artifact.LinuxKernel)
	if err != nil {
		t.Fatal(err)
	}

	// error is expected: "hash" cannot be an array
	if _, err := h.ParseClaims(c); err == nil {
		t.Fatal(err)
	}
}

func TestLinuxKernelCheck(t *testing.T) {
	r := []byte(`{"min_version": "v6.14.0-28-generic", "architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "min_timestamp": "2025-01-01T23:20:50.52Z", "metadata": "CONFIG_STACKPROTECTOR_STRONG=y" }`)

	c := []byte(`{"file_name": "vmlinuz-6.14.0-29-generic", "hash": "8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59", "version":"v6.14.0-29-generic" ,"architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "timestamp": "2025-10-21T23:20:50.52Z", "metadata": "CONFIG_STACKPROTECTOR_STRONG=y" }`)

	h, err := artifact.GetHandler(artifact.LinuxKernel)
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

func TestNegativeLinuxKernelCheck(t *testing.T) {
	r := []byte(`{"min_version": "v6.14.0-29", "architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "min_timestamp": "2025-01-01T23:20:50.52Z", "metadata": "CONFIG_STACKPROTECTOR_STRONG=y" }`)

	c := []byte(`{"file_name": "vmlinuz-6.14.0-29-generic", "hash": "8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59", "version":"v6.14.0-29-generic" ,"architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "timestamp": "2025-10-21T23:20:50.52Z"}`)

	h, err := artifact.GetHandler(artifact.LinuxKernel)
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
