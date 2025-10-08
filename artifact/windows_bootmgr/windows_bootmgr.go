// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package windows_bootmgr

import (
	"encoding/json"
	"fmt"

	"github.com/usbarmory/boot-transparency/artifact"
)

// Define the WindowsBootMgr handler
type WindowsBootMgr struct{}

// Register the handler for the WindowsBootMgr category
func init() {
	h := WindowsBootMgr{}
	artifact.Add(&h, artifact.WindowsBootMgr)
}

// Parse requirements for the WindowsBootMgr category
func (h *WindowsBootMgr) ParseRequirements(jsonRequirements []byte) (interface{}, error) {
	var r Requirements

	if err := json.Unmarshal(jsonRequirements, &r); err != nil {
		return nil, err
	}

	return &r, nil
}

// Parse claims for the WindowsBootMgr category
func (h *WindowsBootMgr) ParseClaims(jsonClaims []byte) (interface{}, error) {
	var c Claims

	if err := json.Unmarshal(jsonClaims, &c); err != nil {
		return nil, err
	}

	return &c, nil
}

// Check matching between requirements and claims for the WindowsBootMgr category
func (h *WindowsBootMgr) Check(require interface{}, claim interface{}) (err error) {
	if _, ok := require.(*Requirements); !ok {
		return fmt.Errorf("invalid·policy requirements for WindowsBootMgr")
	}

	if _, ok := claim.(*Claims); !ok {
		return fmt.Errorf("invalid·claims for WindowsBootMgr")
	}

	r := require.(*Requirements)
	c := claim.(*Claims)

	// FIXME: windows boot manager does not use semantic versioning
	// check all the supported policy requirements for WindowsBootMgr
	if err = artifact.CheckMinVersion(r.MinVersion, c.Version); err != nil {
		return
	}

	if err = artifact.CheckMaxVersion(r.MaxVersion, c.Version); err != nil {
		return
	}

	return
}
