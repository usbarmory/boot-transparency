// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package policy

import (
	"testing"

	"github.com/usbarmory/boot-transparency/statement"
)

func TestParse(t *testing.T) {
	p := []byte(`[{
    "artifacts": [
        {
            "category": 1,
            "requirements": {
                "architecture":"x64"
            }
        },
        {
            "category": 2,
            "requirements": {}
        }
    ],
    "signatures": {
        "signers": [
            {
                "name": "Linux signatory A",
                "pub_key": "ba45ed33..."
            },
            {
                "name": "Linux signatory B",
                "pub_key": "a9e92ded..."
            },
            {
                "name": "Linux signatory C",
                "pub_key": "ffedad67..."
            }
        ],
        "quorum": 2
    }
}]`)

	if _, err := Parse(p); err != nil {
		t.Fatal(err)
	}
}

func TestCheck(t *testing.T) {
	p := []byte(`[
{
    "artifacts": [
        {
            "category": 1,
            "requirements": {
                "min_version": "v6.14.0-29",
                "tainted": false,
                "architecture": "x64",
                "license":["GPL"]
            }
        },
        {
            "category": 2,
            "requirements": {
                "architecture": "x64",
                "tainted": false
            }
        }
    ],
    "signatures": {
        "signers": [
            {
                "name": "signatory I",
                "pub_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP5rbNcIOcwqBHzLOhJEfdKFHa+pIs10idfTm8c+HDnK"
            },
            {
                "name": "signatory II",
                "pub_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0zV5fSWzzXa4R7Kpk6RAXkvWsJGpvkQ+9/xxpHC49J"
            }
        ],
        "quorum": 2
    }
},
{
    "artifacts": [
        {
            "category": 1,
            "requirements": {
                "min_version": "v6.14.0-29",
                "architecture": "x64"
            }
        }
    ]
}]`)

	s := []byte(`{
    "description": "Linux bundle",
    "version": "v1",
    "artifacts": [
        {
            "category": 1,
            "claims": {
                "file_name": "vmlinuz-6.14.0-29-generic",
                "hash": "8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59",
                "version": "v6.14.0-29-generic",
                "architecture": "x64",
                "tainted": false,
                "license": ["GPL-2.0"]
            }
        },
        {
            "category": 2,
            "claims": {
                "file_name": "initrd.img-6.14.0-29-generic",
                "hash": "9f5db8bc106c426a6654aa53ada75db307adb6dcb59291aa0a874898bc197b3dad8d2ebef985936bba94e9ae34b52a79e8f9045346cde2326baf4feba73ab66c",
                "architecture": "x64",
                "tainted": false
            }
        }
    ],
    "signatures": [
        {
            "pub_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP5rbNcIOcwqBHzLOhJEfdKFHa+pIs10idfTm8c+HDnK",
            "signature":"1ebda694a4517486b4681c4c61db944a13b67d98667771ab06e2f7b1d97def682feeeb356737c39b6aeb528c8a0a15844597c50ffc4337b6167fb8af3108f101"
        },
        {
            "pub_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0zV5fSWzzXa4R7Kpk6RAXkvWsJGpvkQ+9/xxpHC49J",
            "signature":"42de0420040e8d4e742004b0a99c43d8fb8d0b0c817bddb96e3ca26b390d874c8e665e0b0ee860a360f27f9d1a8f306c56923e55febb9e38a36e8a2481a1dd02"
        }
    ]
}`)

	policy, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}

	statement, err := statement.Parse(s)
	if err != nil {
		t.Fatal(err)
	}

	if err = Check(policy, statement); err != nil {
		t.Fatal(err)
	}
}
