// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package uefi_binary

// Claims represents the supported claims for UEFIBinary artifact.
type Claims struct {
	// Filename of the artifact.
	FileName string `json:"file_name,omitempty"`

	// SHA-256 hash of the artifact.
	FileHash string `json:"file_hash,omitempty"`

	// Artifact version, using Semantic Versioning 2.0.0 (see semver.org).
	Version string `json:"version,omitempty"`

	// The architecture vocabulary is the one defined by the EFI specification (i.e. IA32, x64, IA64, ARM, AA64, ...).
	Architecture string `json:"architecture,omitempty"`

	// true if the binary is reproducible
	Reproducible bool `json:"reproducible,omitempty"`

	// License(s) associated to this artifact.
	// Where applicable, licenses should be expressed as SPDX short-form IDs
	// (e.g.MIT, GPL-2.0-or-later, BSD-2-Clause)
	// https://spdx.github.io/spdx-spec/v2.3/SPDX-license-list/ .
	License []string `json:"license,omitempty"`

	// Selected sub-set of build arguments that are considered by the claimant
	// potentially relevant·to authorize the artifact.
	BuildArgs map[string]string `json:"build_args,omitempty"`

	// Information on the toolchain used to build the artifact
	ToolChain string `json:"tool_chain,omitempty"`

	// Timestamp in RFC3339 format (e.g. "1985-04-12T23:20:50.52Z"): "2025-10-12T23:20:50.52Z".
	// The claimant can use this field to expose any relevant timestamp for the artifact
	// (e.g. the releasing date, the last source modification) that should be verified by the boot policy.
	Timestamp string `json:"timestamp,omitempty"`

	// Contains ancillary information on the artifact.
	// As an example, the complete information required to reproduce the build of the binary
	// artifacts could be accessible through the buildinfo file linked in the metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}
