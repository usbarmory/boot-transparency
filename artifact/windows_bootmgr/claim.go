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
	// Authenticode represents the authenticode hash of the artifact according
	// to the PE Authenticode hashing standard.
	Authenticode string `json:"authenticodeHash,omitempty"`

	// HashType represents the hash type (only SHA256 seems to be supported in the HashesJsonSchema.json).
	HashType string `json:"hashType,omitempty"`

	// FileHash represents the hash of the artifact.
	FileHash string `json:"flatHash,omitempty"`

	// Filename represents the artifact filename.
	FileName string `json:"filename,omitempty"`

	// CompanyName represents the company, or organization, distributing the artifact.
	CompanyName string `json:"companyName,omitempty"`

	// SigningAuthority represents the CA used to sign the artifact.
	// e.g. "CN = Microsoft Windows Production PCA 2011"
	SigningAuthority string `json:"signingAuthority,omitempty"`

	// Architecture represents the artifact architecture (supported architectures are: amd64, x86, arm64, arm).
	Architecture string `json:"architecture,omitempty"`

	// Version represents the artifact version.
	// The version can be expressed as semantic version (see·semver.org)
	// or following the latest Windows versioning conventions (i.e. ddHd, e.g. 20H2, 25H2)
	Version string `json:"version,omitempty"`

	// Revoked represents the revocation status of the artifact:
	// it should be set to true if the artifact is included in the latest Forbidden Signature Db (DBX)
	// see https://uefi.org/revocationlistfile .
	Revoked bool `json:"revoked,omitempty"`

	// SVN represents the Secure Version Number (SVN) built into the bootmanager, if present.
	SVN string `json:"svn,omitempty"`

	// Reproducible represents the reproducibility of the artifact binary.
	Reproducible bool `json:"reproducible,omitempty"`

	// License represents the licenses associated to this artifact.
	// Where applicable, licenses should be expressed as SPDX short-form IDs
	// (e.g.MIT, GPL-2.0-or-later, BSD-2-Clause):
	// https://spdx.github.io/spdx-spec/v2.3/SPDX-license-list/ .
	License []string `json:"license,omitempty"`

	// BuildArgs represents a sub-set of build arguments considered by the claimant
	// potentially relevant·to authorize the artifact.
	BuildArgs map[string]string `json:"build_args,omitempty"`

	// ToolChain represents the information on the toolchain used to build the artifact.
	ToolChain string `json:"tool_chain,omitempty"`

	// Timestamp represents the timestamp associated to the artifact in RFC3339 format
	// (e.g. "1985-04-12T23:20:50.52Z"): "2025-10-12T23:20:50.52Z".
	// The claimant can decide to use this field to expose any relevant timestamp for the artifact
	// (e.g. the releasing date, tha building time) that should be verified by the boot policy.
	Timestamp string `json:"timestamp,omitempty"`

	// Metadata represents ancillary information on the artifact.
	// As an example, the complete information required to reproduce the build of the artifact
	// could be included, or linked, in the metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}
