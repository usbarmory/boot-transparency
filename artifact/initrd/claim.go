// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package initrd

// Supported claims for Initrd artifact.
type Claims struct {
	// Filename of the artifact.
	FileName string `json:"file_name,omitempty"`

	// SHA-512 hash of the artifact
	Hash string `json:"hash,omitempty"`

	// Artifact version, using Semantic Versioning 2.0.0 (see semver.org).
	Version string `json:"version,omitempty"`

	// The architecture vocabulary is the one defined by the EFI specification (i.e. IA32, x64, IA64, ARM, AA64, ...).
	Architecture string `json:"architecture,omitempty"`

	// true if the init ram disk contains any tainted kernel module.
	Tainted bool `json:"tainted,omitempty"`

	// License(s) associated to this artifact.
	// Where applicable, licenses should be expressed as SPDX short-form IDs
	// (e.g.MIT, GPL-2.0-or-later, BSD-2-Clause):
	// https://spdx.github.io/spdx-spec/v2.3/SPDX-license-list/ .
	License []string `json:"license,omitempty"`

	// Timestamp in RFC3339 format (e.g. "1985-04-12T23:20:50.52Z"): "2025-10-12T23:20:50.52Z".
	// The claimant can use this field to expose any relevant timestamp for the artifact
	// (e.g. the releasing date, the last source modification, ...) that should be verified
	// by the boot policy.
	Timestamp string `json:"timestamp,omitempty"`

	// Public URLs to download the source code required to build the artifact.
	SourceURLs []string `json:"source_urls,omitempty"`

	// Serialized JSON containing arbitrary artifact information.
	// As an example, developers could include among metadata relevant arguments, configuration flags,
	// toolchain information, or any other detail used during the building of the artifact.
	Metadata string `json:"metadata,omitempty"`
}
