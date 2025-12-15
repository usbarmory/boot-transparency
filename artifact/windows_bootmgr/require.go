// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package windows_bootmgr

// Requirements represents the supported policy requirements for WindowsBootMgr artifact.
type Requirements struct {
	// Required Authenticode hash of the artifact.
	Authenticode string `json:"authenticodeHash,omitempty"`

	// Required SHA-256 hash of the artifact.
	FileHash string `json:"flatHash,omitempty"`

	// Required minimum version.
	// It can be expressed as semantic version (see·semver.org)
	// or following the latest Windows version (i.e. ddHd, e.g. 20H2, 25H2)
	MinVersion string `json:"min_version,omitempty"`

	// It can be expressed as semantic version (see·semver.org)
	// or following the latest Windows version (i.e. ddHd, e.g. 20H2, 25H2)
	MaxVersion string `json:"max_version,omitempty"`

	// Allowed architecture (supported architectures are: amd64, x86, arm64, arm)
	Architecture string `json:"architecture,omitempty"`

	// List of allowed licenses.
	// Where applicable licenses should be expressed as SPDX short-form IDs
	// (e.g.MIT, GPL-2.0-or-later, BSD-2-Clause):
	// https://spdx.github.io/spdx-spec/v2.3/SPDX-license-list/ .
	License []string `json:"license,omitempty"`

	// List of allowed signing CAs.
	SigningAuthority []string `json:"signingAuthority,omitempty"`

	// List of allowed companies, or organizations, distributing the artifact.
	CompanyName []string `json:"companyName,omitempty"`

	// If true also revoked artifact are allowed (i.e. boot managers that
	// are present in the Forbidden Signature Db - DBX).
	Revoked bool `json:"revoked,omitempty"`

	// Require a minimum Secure Version Number (SVN) built into the bootmanager.
	MinSVN string `json:"min_snv,omitempty"`

	// If true, only reproducible bootmanagers are allowed.
	Reproducible bool `json:"reproducible,omitempty"`

	// Allow only artifacts that have been built with certain building arguments.
	// The matching rules are expressed via map[string]string where the keys are
	// the build arguments, and the values are the regular expressions that are tested
	// via regexp.MatchString() against the correspondent keys.
	// If a given key is "only" specified in the requirements, but it is not present in the
	// claims, the test will fail as the matching rule cannot be tested.
	BuildArgs map[string]string `json:"build_args,omitempty"`

	// Allow only artifacts that have been built with a certain toolchain.
	// The requirement is a regular expression that is tested via regexp.MatchString()
	// against the claimed tool_chain string.
	ToolChain string `json:"tool_chain,omitempty"`

	// Allow only artifacts where the claimed timestamp is more recent than the one specified here
	// in RFC3339 format (e.g. "1985-04-12T23:20:50.52Z").
	MinTimestamp string `json:"min_timestamp,omitempty"`

	// Allow only artifacts that are claiming a given set of metadata.
	// The matching rules are expressed via map[string]string where the keys are
	// the build arguments, and the values are the regular expressions that are tested
	// via regexp.MatchString() against the correspondent keys.
	// If a given key is "only" specified in the requirements, but it is not present in the
	// claims, the test will fail as the matching rule cannot be tested.
	Metadata map[string]string `json:"metadata,omitempty"`
}
