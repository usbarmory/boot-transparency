// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package uefi_bios

// Supported claims for UEFIBIOS artifact
type Claims struct {
	// UEFI revision, expressed using Semantic Versioning 2.0.0 (see semver.org)
	UEFIRevision string `json:"uefi_revision,omitempty"`

	// firmware vendor
	FirmwareVendor string `json:"firmware_vendor,omitempty"`

	// firmware revision, expressed as a string containing the revision in hex format (e.g. 0x1560)
	FirmwareRevision string `json:"firmware_revision,omitempty"`
}
