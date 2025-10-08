// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package windows_bootmgr

// Supported policy requirements for WindowsBootMgr artifact
type Requirements struct {
	// required minimum version
	MinVersion string `json:"min_version,omitempty"`

	// maximum allowed version
	MaxVersion string `json:"max_version,omitempty"`
}
