// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package tessera

import (
	"strings"
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

func TestTesseraEngineNegativeNoCosignaturesVerifyProof(t *testing.T) {
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
		Format:    transparency.TesseraBundle,
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

	// error expected here as the log public key will pass log signature verification
	if err != nil && !strings.Contains(err.Error(), "does not match expected root") {
		t.Fatal(err)
	}
}

func TestTesseraEngineParseProof(t *testing.T) {
	statement := []byte(`{"Description":"doesn't matter"}`)

	proof := []byte(`[
    "lqKW0iTyhcZ77pPDD4owkVfw2qNdxbh+QQt4YwoJz8c=",
    "Xwg/ChozygdqlSeYMlgNs+DvRYS9/x9UyKNg9Q3jAx4=",
    "a0eq8p7jwq+a+Im8H7klTavTEXfxYjLdaqsDXKOb9uQ="
]`)

	probe := []byte(`{"leafIdx":0, "treeSize": 8, "root": "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=", "log_public_key": "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW"}`)

	pb := transparency.ProofBundle{
		Format:    transparency.TesseraBundle,
		Statement: statement,
		Probe:     probe,
		Proof:     proof,
	}

	e := Engine{Network: true}

	if err := e.ParseProof(&pb); err != nil {
		t.Fatal(err)
	}
}

func TestSigsumEngineParseNilProof(t *testing.T) {
	statement := []byte(`{"Description":"doesn't matter"}`)

	probe := []byte(`{"leafIdx":0, "treeSize": 8, "root": "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=", "log_public_key": "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW"}`)

	pb := transparency.ProofBundle{
		Format:    transparency.TesseraBundle,
		Statement: statement,
		Probe:     probe,
	}

	e := Engine{Network: true}

	if err := e.ParseProof(&pb); err != nil {
		t.Fatal(err)
	}
}

func TestSigsumEngineNegativeParseProof(t *testing.T) {
	statement := []byte(`{"Description":"Linux bundle","Version":"v1","Artifacts":[{"Category":1,"Version":"v6.14.0-29-generic","FileName":"vmlinuz-6.14.0-29-generic","Hash":"8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59","Architecture":"x64","Tainted":false,"OpenSource":true,"BuildTimestamp":"2025-10-12T23:20:50.52Z","BuildArgs":"build args example kernel","SourceURLs":["http://source-code-url-1.com","http://source-code-url-2.com"]},{"Category":2,"Version":"","FileName":"initrd.img-6.14.0-29-generic","Hash":"9f5db8bc106c426a6654aa53ada75db307adb6dcb59291aa0a874898bc197b3dad8d2ebef985936bba94e9ae34b52a79e8f9045346cde2326baf4feba73ab66c","Architecture":"x64","Tainted":false,"OpenSource":true,"BuildTimestamp":"2025-10-12T23:20:50.52Z","BuildArgs":"/usr/bin/dracut --kver 6.14.0-29-generic","SourceURLs":["http://source-code-url-1.com"]}],"Signatures":[{"PubKey":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP5rbNcIOcwqBHzLOhJEfdKFHa+pIs10idfTm8c+HDnK","Signature":"1ebda694a4517486b4681c4c61db944a13b67d98667771ab06e2f7b1d97def682feeeb356737c39b6aeb528c8a0a15844597c50ffc4337b6167fb8af3108f101"},{"PubKey":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0zV5fSWzzXa4R7Kpk6RAXkvWsJGpvkQ+9/xxpHC49J","Signature":"42de0420040e8d4e742004b0a99c43d8fb8d0b0c817bddb96e3ca26b390d874c8e665e0b0ee860a360f27f9d1a8f306c56923e55febb9e38a36e8a2481a1dd02"}]}`)

	probe := []byte(`{"origin": "https://test.sigsum.org/barreleye", "leaf_signature":"e0163de36e40b821893ea6fe49f1285164b5f6c72bfe5646adb4ae843b1bee7d30c631e40fcb3e4d9711f9ca5470568fb59ab26716757756be7c69b90360880b", "log_public_key_hash": "4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d", "submit_public_key_hash": "302928c2e0e01da52e3b161c54906de9b55ce250f0f47e80e022d04036e2765c"}`)

	proof := []byte(`[
    "lqKW0iAAAadswevervfAAAAAZ77pPDD4owkVfw2qNdxbh+QQt4YwoJz8c=",
    "Xwg/ChozygdqlSeYMlgNs+DvRYS9/x9UyKNg9Q3jAx4=",
    "a0eq8p7jwq+a+Im8H7klTavTEXfxYjLdaqsDXKOb9uQ="
]`)

	pb := transparency.ProofBundle{
		Format:    transparency.TesseraBundle,
		Statement: statement,
		Probe:     probe,
		Proof:     proof,
	}

	e := Engine{Network: true}

	// error is expected here as the proof is containing invalid base64 data
	err := e.ParseProof(&pb)

	if err != nil && !strings.Contains(err.Error(), "illegal base64 data") {
		t.Fatal(err)
	}
}
