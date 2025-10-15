> [!WARNING]
> This repository contains incomplete and non-working code.
>
> All the code, and documentation, should be treated as work in progress material.

Introduction
============

The `boot-transparency` project is a Go library which enables interaction with
transparency ecosystems for boot loading operations.

The goal is to enhance selection, authentication and policy enforcement on
booted artifacts (e.g. kernels, UEFI binaries, ram disks).

The library is designed to be used also outside the bootloader context, for
example imported from userspace kernel update tools, and supporting
transparency proof verification on-line as well as off-line.

API
===

The `boot-transparency` API is designed with the following high-level goals:

* Make it easy to check a boot policy
    * Support verification for the matching of the claimed data and
      the configured boot policy
    * Support signing policy quorums
    * Support a built-in set of artifact categories that are
      commonly present in boot bundles
    * Enable support to expand the policy capabilities, by adding
      newer artifact categories in the future
* Enable support for multiple underlying transparency engines,
  (e.g. Tessera and Sigsum)
    * Support configuration for the transparency engine
    * Support configuration of transparency log, submitter
      and witness keys

* Make it easy to verify a given proof at transparency layer
    * Support (inclusion) proof verification
    * Support witness policy
    * The proof verification could be performed within a bootloader
      that does not have network access.

The functions exported by the library are documented in
[boot-transparency/wiki/API](https://github.com/usbarmory/boot-transparency/wiki/API)

Usage
=====

```go
// Authorize the boot only if the bundle includes:
//   - a Linux kernel that meets the following requirements:
//     - it is more recent than a certain version (e.g. 6.14.0-29)
//     - it is not tainted
//     - it has been compiled with a given configuration option (CONFIG_STACKPROTECTOR_STRONG=y)
//   - an init ram disk that meets the following requirement:
//     - it is not containing any tainted module
//   - such artifact categories have been claimed in the log
//   - the claims have been signed by a sufficient number of trusted signers to satisfy the required quorum (e.g. 2)
bootPolicy = []byte(`[
{
    "artifacts": [
        {
            "category": 1,
            "_comment": "0x0001 -> LinuxKernel",
            "requirements": {
                "min_version": "v6.14.0-29",
                "tainted": false,
                "metadata_include": [
                    "CONFIG_STACKPROTECTOR_STRONG=y"
                ]
            }
        },
        {
            "category": 2,
            "_comment": "0x0002 -> Initrd",
            "requirements": {
                "tainted": false
            }
        }
    ],
    "signatures": {
        "signers": [
            {
                "name": "signatory I",
                "pub_key": "ssh-ed25519·AAAAC3NzaC1lZDI1NTE5AAAAIP5rbNcIOcwqBHzLOhJEfdKFHa+pIs10idfTm8c+HDnK"
            },
            {
                "name": "signatory II",
                "pub_key": "ssh-ed25519·AAAAC3NzaC1lZDI1NTE5AAAAIL0zV5fSWzzXa4R7Kpk6RAXkvWsJGpvkQ+9/xxpHC49J"
            }
        ],
        "quorum": 2
    }
}]`)

// list of trusted log and submitter public keys
logKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKwmwKhVrEUaZTlHjhoWA4jwJLOF8TY+/NpHAXAHbAHl"}
submitKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMdLcxVjCAQUHbD4jCfFP+f8v1nmyjWkq6rXiexrK8II"}

// configure an off-line Sigsum transparency engine
te, err := transparency.GetEngine(transparency.Sigsum)
if err != nil {
	// handle error: transparency engine is not supported
}

// set public keys
if err := te.SetKey(logKey, submitKey); err != nil {
    // handle error: unable to parse the log or submitter keys
}

// parse and set the witness policy
witnessPolicy := []byte(`log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye

witness poc.sigsum.org/nisse 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c
witness rgdd.se/poc-witness  28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806

group  demo-quorum-rule any poc.sigsum.org/nisse rgdd.se/poc-witness
quorum demo-quorum-rule
`)

wp, err := te.ParseWitnessPolicy(witnessPolicy)
if err != nil {
    // handle error: unable to parse witness policy
}

if err = te.SetWitnessPolicy(wp); err != nil {
    // handle error: unable to set witness policy
}

// parse the proof bundle containing the logged statement and the inclusion proof
pb, _, err := te.ParseProof(jsonProofBundle)

// transparency verification:
// inclusion proof verification according with the quorum defined in the witness policy
if err := te.VerifyProof(pb); err != nil {
    // handle error: boot bundle not allowed - transparency check failed
}

// boot policy verification:
// check if the logged claims are matching the requirements from the policy
p, err := policy.Parse(bootPolicy)
if err != nil {
    // handle error: boot policy parsing failed
}

s, err := statement.Parse(pb.Statement)
if err != nil {
    // handle error: boot bundle parsing failed, cannot parse claims
}

if err = policy.Check(p, s); err != nil {
    // handle error: boot bundle not authorized
}

// all checks passed, the bundle can boot
```
