// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package initrd

// Supported policy requirements for Initrd artifact
type Requirements struct {
	// required minimum version, expressed using Semantic Versioning 2.0.0 (see semver.org)
	MinVersion string `json:"min_version,omitempty"`

	// maximum allowed version, expressed using Semantic Versioning 2.0.0 (see semver.org)
	MaxVersion string `json:"max_version,omitempty"`

	// allowed architecture, the architecture vocabulary is the one defined by the EFI specification (i.e. IA32, x64, IA64, ARM, AA64, ...)
	Architecture string `json:"architecture,omitempty"`

	// true if init ram disk containing any tainted kernel module are allowed
	Tainted bool `json:"tainted,omitempty"`

	// list of allowed licenses.
	// Where applicable licenses should be expressed as SPDX short-form IDs
	// (e.g.MIT, GPL-2.0-or-later, BSD-2-Clause)
	// https://spdx.github.io/spdx-spec/v2.3/SPDX-license-list/
	License []string `json:"license,omitempty"`

	// allow only artifacts where the claimed timestamp is more recent than the one specified here
	// in RFC3339 format (e.g. "1985-04-12T23:20:50.52Z")
	MinTimestamp string `json:"min_timestamp,omitempty"`

	// allow only artifacts that are claiming a given set of metadata (i.e. match check)
	Metadata string `json:"metadata,omitempty"`

	// allow only artifacts that are claiming a given set of metadata which is including
	// all the string(s) specified here (i.e. AND of inclusion checks)
	MetadataInclude []string `json:"metadata_include,omitempty"`

	// allow only artifacts that are claiming a given set of metadata which is not including
	// any of the string(s) specified here (i.e. AND of negated inclusion checks)
	MetadataNotInclude []string `json:"metadata_not_include,omitempty"`
}
