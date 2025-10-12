// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package tessera

import (
	"testing"

	"github.com/usbarmory/boot-transparency/transparency"
)

func TestTesseraEngineSetKey(t *testing.T) {
	logKey := []string{"PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW"}
	// Tessera does not use the submit key in the verification process
	submitKey := []string{}

	e := Engine{Network: false}

	err := e.SetKey(logKey, submitKey)

	if err != nil {
		t.Fatal(err)
	}
}

func TestNegativeTesseraEngineSetKey(t *testing.T) {
	// invalid vkey: malformed verifier id
	logKey := []string{"PeterNeumann+c74f203+ARpc2QcUPDhMQegwxbzKqiBfsVkmqq/LDE4izWy10TW"}
	// Tessera does not use the submit key in the verification process
	submitKey := []string{}

	e := Engine{Network: false}

	err := e.SetKey(logKey, submitKey)

	if err == nil {
		t.Fatal(err)
	}
}

func TestTesseraEngineParseWitnessPolicy(t *testing.T) {
	policy := []byte(`
witness w1 sigsum.org+e4ade967+AZuUY6B08pW3QVHu8uvsrxWPcAv9nykap2Nb4oxCee+r https://sigsum.org/witness/
witness w2 example.com+3753d3de+AebBhMcghIUoavZpjuDofa4sW6fYHyVn7gvwDBfvkvuM https://example.com/witness/
group g1 all w1 w2
quorum g1
`)

	e := Engine{Network: false}

	p, err := e.ParseWitnessPolicy(policy)

	if err != nil {
		t.Fatal(err)
	}

	err = e.SetWitnessPolicy(p)

	if err != nil {
		t.Fatal(err)
	}
}

func TestSigsumEngineNegativeNoCosignaturesVerifyProof(t *testing.T) {
	statement := []byte(`{"Description":"doesn't matter"}`)

	proof := []byte(`[
    "lqKW0iTyhcZ77pPDD4owkVfw2qNdxbh+QQt4YwoJz8c=",
    "Xwg/ChozygdqlSeYMlgNs+DvRYS9/x9UyKNg9Q3jAx4=",
    "a0eq8p7jwq+a+Im8H7klTavTEXfxYjLdaqsDXKOb9uQ="
]`)

	probe := []byte(`{"leafIdx":0, "treeSize": 8, "root": "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=", "log_public_key": "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW"}`)

	// test support for multiple keys configured in the transparency engine:
	// in this example only the last keys are the correct ones for verifying
	// the test statement proof
	logKey := []string{"PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW"}

	pb := transparency.ProofBundle{
		Statement: statement,
		Proof:     proof,
		Probe:     probe,
	}

	e := Engine{Network: false}

	err := e.SetKey(logKey, []string{})
	if err != nil {
		t.Fatal(err)
	}

	err = e.VerifyProof(&pb)
	// error expected here the leaf hash calculated from the statement
	// doesn't match one of the proof
	if err == nil {
		t.Fatal(err)
	}
}
