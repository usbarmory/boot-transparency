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
	r := []byte(`{"min_version": "v6.14.0", "architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "min_timestamp": "2025-01-01T23:20:50.52Z", "build_args": {"CONFIG_STACKPROTECTOR_STRONG": "y"}}`)

	h, err := artifact.GetHandler(artifact.LinuxKernel)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.ParseRequirements(r); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxKernelParseClaims(t *testing.T) {
	c := []byte(`{"file_name": "vmlinuz-6.14.0-36-generic", "file_hash": "4551848b4ab43cb4321c4d6ba98e1d215f950cee21bfd82c8c82ab64e34ec9a6", "version":"v6.14.0-36-generic" ,"architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "timestamp": "2025-10-21T23:20:50.52Z", "build_args": {"CONFIG_STACKPROTECTOR_STRONG": "y"}}`)

	h, err := artifact.GetHandler(artifact.LinuxKernel)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.ParseClaims(c); err != nil {
		t.Fatal(err)
	}
}

func TestNegativeLinuxKernelParseClaims(t *testing.T) {
	c := []byte(`{"file_hash": ["4551848b4ab43cb4321c4d6ba98e1d215f950cee21bfd82c8c82ab64e34ec9a6" ], "version":"v6.14.0-29-generic" ,"architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "timestamp": "2025-10-21T23:20:50.52Z", "build_args": {"CONFIG_STACKPROTECTOR_STRONG": "y"}}`)

	h, err := artifact.GetHandler(artifact.LinuxKernel)
	if err != nil {
		t.Fatal(err)
	}

	// Error expected: "file_hash" cannot be an array.
	if _, err := h.ParseClaims(c); err == nil {
		t.Fatal(err)
	}
}

func TestLinuxKernelValidate(t *testing.T) {
	r := []byte(`{"min_version": "v6.14.0-28-generic", "file_hash": "4551848b4ab43cb4321c4d6ba98e1d215f950cee21bfd82c8c82ab64e34ec9a6", "architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "min_timestamp": "2025-01-01T23:20:50.52Z", "build_args": {"CONFIG_STACKPROTECTOR_STRONG": "^y$"}}`)

	c := []byte(`{"file_name": "vmlinuz-6.14.0-36-generic", "file_hash": "4551848b4ab43cb4321c4d6ba98e1d215f950cee21bfd82c8c82ab64e34ec9a6", "version":"v6.14.0-36-generic" ,"architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "timestamp": "2025-10-21T23:20:50.52Z", "build_args": {"CONFIG_STACKPROTECTOR_STRONG": "y"}}`)

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

	if err = h.Validate(parsedRequirements, parsedClaims); err != nil {
		t.Fatal(err)
	}
}

func TestNegativeLinuxKernelValidate(t *testing.T) {
	r := []byte(`{"min_version": "v6.14.0-29", "architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "min_timestamp": "2025-01-01T23:20:50.52Z", "build_args": {"CONFIG_STACKPROTECTOR_STRONG": "^y$"}}`)

	c := []byte(`{"file_name": "vmlinuz-6.14.0-36-generic", "hash": "4551848b4ab43cb4321c4d6ba98e1d215f950cee21bfd82c8c82ab64e34ec9a6", "version":"v6.14.0-29-generic" ,"architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "timestamp": "2025-10-21T23:20:50.52Z", "build_args": {"CONFIG_STACKPROTECTOR_STRONG": "yes"}}`)

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

	// Error expected: the claimed "build_args" is not matching the required one.
	if err = h.Validate(parsedRequirements, parsedClaims); err == nil {
		t.Fatal(err)
	}
}
