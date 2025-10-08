// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package uefi_bios

// Supported policy requirements for UEFIBIOS artifact
type Requirements struct {
	// required minimum UEFI revision, expressed using Semantic Versioning 2.0.0 (see semver.org)
	MinUEFIRevision string `json:"min_uefi_revision,omitempty"`

	// maximum allowed UEFI revision, expressed using Semantic Versioning 2.0.0 (see semver.org)
	MaxUEFIRevision string `json:"max_uefi_revision,omitempty"`

	// allow the boot only on systems where the UEFI bios is from a certain list of trusted vendors
	FirmwareVendor []string `json:"firmware_vendor,omitempty"`

	// required minimum firmware revision, expressed in hex format (e.g. 0x1560)
	MinFirmwareRevision string `json:"min_firmware_revision,omitempty"`

	// maximum allowed firmware revision, expressed in hex format (e.g. 0x1560)
	MaxFirmwareRevision string `json:"max_firmware_revision,omitempty"`
}
