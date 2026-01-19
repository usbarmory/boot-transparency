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

* Make it easy to validate a boot policy
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
//   - the claims have been signed by a sufficient number of trusted signers to satisfy the required quorum (e.g. 2).
bootPolicy = []byte(`[
{
    "artifacts": [
        {
            "category": 1,
            "_comment": "0x0001 -> LinuxKernel",
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

// List of trusted log and submitter public keys.
logKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKwmwKhVrEUaZTlHjhoWA4jwJLOF8TY+/NpHAXAHbAHl"}
submitKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMdLcxVjCAQUHbD4jCfFP+f8v1nmyjWkq6rXiexrK8II"}

// Select Sigsum as transparency engine.
te, err := transparency.GetEngine(transparency.Sigsum)
if err != nil {
	// Handle error: transparency engine is not supported.
}

// Set public keys.
if err := te.SetKey(logKey, submitKey); err != nil {
	// Handle error: unable to parse the log or submitter keys.
}

witnessPolicy := []byte(`log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye

witness poc.sigsum.org/nisse 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c
witness rgdd.se/poc-witness  28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806

group  demo-quorum-rule any poc.sigsum.org/nisse rgdd.se/poc-witness
quorum demo-quorum-rule
`)

// Set witness policy.
if err = te.SetWitnessPolicy(wp); err != nil {
	// Handle error: unable to set witness policy.
}

// Parse the proof bundle, which is expected to contain,
// the logged statement, its inclusion proof and the probing information.
format, statement, proof, probe, _, err := transparency.ParseProofBundle(proofBundle)
if err != nil {
	// Handle error: unable to parse proof bundle.
	return err
}
if format != transparency.Sigsum {
	// Handle error: invalid proof bundle format.
}

// If online, the inclusion proof verification is performed against a
// fresh copy of the proof fetched directly from the remote log.
if online {
	proof, err = te.GetProof(statement, probe)
	if err != nil {
		// Handle error: unable to fetch a fresh inclusion proof.
	}
}

// Inclusion proof verification, including the co-signing quorum verification
// as defined in the witness policy.
err = te.VerifyProof(statement, proof, nil)
if err != nil {
	// Handle error: inclusion proof verification failed.
}

r, err := policy.ParseRequirements(bootPolicy)
if err != nil {
	// Handle error: unable to parse the requirements from the boot policy.
}

c, err := policy.ParseStatement(statement)
if err != nil {
	// Handle error: unable to parse the claims from the boot policy.
}

// Ensure the artifacts loaded during the booting process are matching
// the ones referenced in the proof bundle (i.e. file hash matching).
b := BootEntry{
	Artifact{
		Category: artifact.LinuxKernel,
		Hash:     "4551848b4ab43cb4321c4d6ba98e1d215f950cee21bfd82c8c82ab64e34ec9a6",
	},
	Artifact{
		Category: artifact.Initrd,
		Hash:     "337630b74e55eae241f460faadf5a2f9a2157d6de2853d4106c35769e4acf538",
	},
}

if err = b.validateProofHashes(c); err != nil {
	// Handle error: file hashes are not matching the ones included in the logged statement.
}

// Validate the matching bewteen the logged claims and the policy requirements.
if err = policy.Validate(r, c); err != nil {
	// Handle error: the boot bundle is NOT authorized for boot.
}

// boot-transparency validation passed.
```
