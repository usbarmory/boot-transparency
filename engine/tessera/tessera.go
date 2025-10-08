// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package tessera

import (
	"github.com/usbarmory/boot-transparency/transparency"
)

// Defines the Tessera transparency engine and its configuration parameters
type TesseraEngine struct {
	Network bool // true if the engine does have access to the network and all the
	// transparency proof verifications must be performed on-line, default is false.
//	logPubkey     []string // list of public keys to verify log signatures
//	submitPubkey  []string // list of public keys to verify leaf signatures
//	witnessPubkey []string // list of public keys to verify cosignatures according to the witness policy, if any
//	witnessPolicy []byte   // the witness policy, the actual format should be aligned with the one supported one by the chosen transparency engine
}

func (te *TesseraEngine) GetProof(origin string, p *transparency.ProofBundle) (err error) {
	return
}

func (te *TesseraEngine) ParseWitnessPolicy(wp []byte) (interface{}, error) {
	return nil, nil
}

func (te *TesseraEngine) SetKey(logKey []string, submitKey []string, witnessKey []string) (err error) {
	return
}

func (te *TesseraEngine) SetWitnessPolicy(wp interface{}) (err error) {
	return
}

func (te *TesseraEngine) VerifyProof(p *transparency.ProofBundle) (err error) {
	return
}
