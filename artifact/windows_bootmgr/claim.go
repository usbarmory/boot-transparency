// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package windows_bootmgr

// Claims represents the supported claims for WindowsBootMgr artifact.
// Where applicable, the JSON keys are reflecting the ones used in the Microsoft Revocation list:
// https://uefi.org/revocationlistfile
// https://github.com/microsoft/secureboot_objects/blob/main/PreSignedObjects/DBX/HashesJsonSchema.json
type Claims struct {
	// Authenticode hash of the artifact using the PE Authenticode hashing standard.
	Authenticode string `json:"authenticodeHash,omitempty"`

	// Hash type (only SHA256 seems to be supported in the HashesJsonSchema.json).
	HashType string `json:"hashType,omitempty"`

	// Hash of the artifact.
	FileHash string `json:"flatHash,omitempty"`

	// Filename of the artifact.
	FileName string `json:"filename,omitempty"`

	// Company, or organization, distributing the artifact.
	CompanyName string `json:"companyName,omitempty"`

	// CA used to sign the artifact.
	// e.g. "CN = Microsoft Windows Production PCA 2011"
	SigningAuthority string `json:"signingAuthority,omitempty"`

	// Architecture (i.e. supported architectures are: amd64, x86, arm64, arm).
	Architecture string `json:"architecture,omitempty"`

	// Artifact version.
	// It can be expressed as semantic version (see·semver.org)
	// or following the latest Windows version (i.e. ddHd, e.g. 20H2, 25H2)
	Version string `json:"version,omitempty"`

	// true if the artifact is included in the latest Forbidden Signature Db (DBX)
	// see https://uefi.org/revocationlistfile .
	Revoked bool `json:"revoked,omitempty"`

	// Secure Version Number (SVN) built into the bootmanager, if present.
	SVN string `json:"svn,omitempty"`

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

	// Information on the toolchain used to build the artifact.
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
