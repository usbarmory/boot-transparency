// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package policy

import (
	"errors"
	"testing"

	"github.com/usbarmory/boot-transparency/artifact"
)

func TestParseRequirements(t *testing.T) {
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

	if _, err := ParseRequirements(p); err != nil {
		t.Fatal(err)
	}
}

func TestValidate(t *testing.T) {
	p := []byte(`[
{
    "artifacts": [
        {
            "category": 1,
            "requirements": {
                "min_version": "v6.14.0-29",
                "tainted": false,
                "build_args": {
                    "CONFIG_STACKPROTECTOR_STRONG": "y"
                }
            }
        },
        {
            "category": 2,
            "requirements": {
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
}]`)

	s := []byte(`{
	"header": {
		"description": "Linux bundle",
		"revision": "v1"
	},
	"artifacts": [
		{
			"category": 1,
			"claims": {
				"file_name": "test-vmlinuz-6.14.0-29-generic",
				"file_hash": "5e6d8e01d75e3e0396d672b0e8c3e31f78532eef9fa2a3f464299ee7cc44a12e",
				"version": "v6.14.0-29-generic",
				"tainted": false,
				"build_args": {
					"CONFIG_STACKPROTECTOR_STRONG": "y"
				}
			}
		},
		{
			"category": 2,
			"claims": {
				"file_name": "test-initrd.img-6.14.0-29-generic",
				"file_hash": "b868d20383e979c588e7b16d24b9d3fcb9c1213c89135e6c656edf94cbf31542",
				"version": "v6.14.0-29-generic",
				"tainted": false
			}
		}
	],
	"signatures": [
		{
			"pub_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP5rbNcIOcwqBHzLOhJEfdKFHa+pIs10idfTm8c+HDnK",
			"signature": "8d984b482ab45de5a2f0171a338b6ce8e64d95a70d6ea14b9d2a5f772c21d339d4cd51091b8f4c93f6dc289ee32ad94d048c8badb4fc3cc0a3136bfb4886ba0f"
		},
		{
			"pub_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0zV5fSWzzXa4R7Kpk6RAXkvWsJGpvkQ+9/xxpHC49J",
			"signature": "99af82c7c559cf98902ac299f10a608353f2447729115667e924719d4ffb2b3cf80dc6715959afafaa5d255ae45e880351245cba6233ae093716136670b7d409"
		}
	]
}`)

	bootEntry := BootEntry{
		BootArtifact{
			Category: artifact.LinuxKernel,
			Data:     []byte(`test linux kernel`),
		},
		BootArtifact{
			Category: artifact.Initrd,
			Data:     []byte(`test initrd`),
		},
	}

	policy, err := ParseRequirements(p)
	if err != nil {
		t.Fatal(err)
	}

	statement, err := ParseStatement(s)
	if err != nil {
		t.Fatal(err)
	}

	// success expected here: the claims match the (unique) policy entry
	if err = Validate(policy, statement, &bootEntry); err != nil {
		t.Fatal(err)
	}
}

func TestValidateMultiplePolicyEntries(t *testing.T) {
	p := []byte(`[
{
    "artifacts": [
        {
            "category": 1,
            "requirements": {
                "min_version": "v6.14.0-29",
                "tainted": false,
                "architecture": "x64",
                "license":["GPL"],
                "metadata_include":[ "I WANT CANDY"]
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
                "file_hash": "5e6d8e01d75e3e0396d672b0e8c3e31f78532eef9fa2a3f464299ee7cc44a12e",
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
                "file_hash": "b868d20383e979c588e7b16d24b9d3fcb9c1213c89135e6c656edf94cbf31542",
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

	bootEntry := BootEntry{
		BootArtifact{
			Category: artifact.LinuxKernel,
			Data:     []byte(`test linux kernel`),
		},
		BootArtifact{
			Category: artifact.Initrd,
			Data:     []byte(`test initrd`),
		},
	}

	policy, err := ParseRequirements(p)
	if err != nil {
		t.Fatal(err)
	}

	statement, err := ParseStatement(s)
	if err != nil {
		t.Fatal(err)
	}

	// success expected here: the claims match the second policy entry
	if err = Validate(policy, statement, &bootEntry); err != nil {
		t.Fatal(err)
	}
}

func TestNegativeValidate(t *testing.T) {
	p := []byte(`[
{
    "artifacts": [
        {
            "category": 1,
            "requirements": {
                "min_version": "v6.14.0-29",
                "tainted": false,
                "architecture": "x64",
                "license":["GPL"],
                "metadata_include":[ "I WANT CANDY"]
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
}]`)

	s := []byte(`{
    "description": "Linux bundle",
    "version": "v1",
    "artifacts": [
        {
            "category": 1,
            "claims": {
                "file_name": "vmlinuz-6.14.0-29-generic",
                "file_hash": "5e6d8e01d75e3e0396d672b0e8c3e31f78532eef9fa2a3f464299ee7cc44a12e",
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
                "file_hash": "b868d20383e979c588e7b16d24b9d3fcb9c1213c89135e6c656edf94cbf31542",
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

	bootEntry := BootEntry{
		BootArtifact{
			Category: artifact.LinuxKernel,
			Data:     []byte(`test linux kernel`),
		},
		BootArtifact{
			Category: artifact.Initrd,
			Data:     []byte(`test initrd`),
		},
	}

	policy, err := ParseRequirements(p)
	if err != nil {
		t.Fatal(err)
	}

	statement, err := ParseStatement(s)
	if err != nil {
		t.Fatal(err)
	}

	// error expected here: the claims do not match the (single) policy entry
	if err = Validate(policy, statement, &bootEntry); err == nil || !errors.Is(err, ErrValidate) {
		t.Fatal("missing policy validation error")
	}
}

func TestNegativeValidateInvalidBootEntry(t *testing.T) {
	p := []byte(`[
{
    "artifacts": [
        {
            "category": 1,
            "requirements": {
                "min_version": "v6.14.0-29",
                "tainted": false,
                "architecture": "x64",
                "license":["GPL"],
                "metadata_include":[ "I WANT CANDY"]
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
                "file_hash": "5e6d8e01d75e3e0396d672b0e8c3e31f78532eef9fa2a3f464299ee7cc44a12e",
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
                "file_hash": "b868d20383e979c588e7b16d24b9d3fcb9c1213c89135e6c656edf94cbf31542",
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

	bootEntry := BootEntry{
		BootArtifact{
			Category: artifact.LinuxKernel,
			Data:     []byte(`test linux kernel`),
		},
		BootArtifact{
			Category: artifact.Initrd,
			// missing Initrd data here
		},
	}

	policy, err := ParseRequirements(p)
	if err != nil {
		t.Fatal(err)
	}

	statement, err := ParseStatement(s)
	if err != nil {
		t.Fatal(err)
	}

	// error expected here: the boot entry is not valid
	if err = Validate(policy, statement, &bootEntry); err == nil || !errors.Is(err, ErrInvalidBootEntry) {
		t.Fatal("missing invalid boot entry error")
	}
}
