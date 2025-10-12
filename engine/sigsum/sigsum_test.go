// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package sigsum

import (
	"testing"

	"github.com/usbarmory/boot-transparency/transparency"
)

func TestSigsumEngineSetKey(t *testing.T) {
	logKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKwmwKhVrEUaZTlHjhoWA4jwJLOF8TY+/NpHAXAHbAHl"}
	submitKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMdLcxVjCAQUHbD4jCfFP+f8v1nmyjWkq6rXiexrK8II"}

	e := Engine{Network: false}

	err := e.SetKey(logKey, submitKey)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSigsumEngineParseWitnessPolicy(t *testing.T) {
	policy := []byte(`
# example config
log aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa http://sigsum.example.org

witness A1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1
witness A2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2
witness A3 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3
witness B1 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1
witness B2 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2
witness B3 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb3

group A-group 1 A1 A2 A3
group B-group 2 B1 B2 B3
group G any A-group B-group

quorum G
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

func TestSigsumEngineNoCosignaturesVerifyProof(t *testing.T) {
	statement := []byte(`{"Description":"Linux bundle","Version":"v1","Artifacts":[{"Category":1,"Version":"v6.14.0-29-generic","FileName":"vmlinuz-6.14.0-29-generic","Hash":"8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59","Architecture":"x64","Tainted":false,"OpenSource":true,"BuildTimestamp":"2025-10-12T23:20:50.52Z","BuildArgs":"build args example kernel","SourceURLs":["http://source-code-url-1.com","http://source-code-url-2.com"]},{"Category":2,"Version":"","FileName":"initrd.img-6.14.0-29-generic","Hash":"9f5db8bc106c426a6654aa53ada75db307adb6dcb59291aa0a874898bc197b3dad8d2ebef985936bba94e9ae34b52a79e8f9045346cde2326baf4feba73ab66c","Architecture":"x64","Tainted":false,"OpenSource":true,"BuildTimestamp":"2025-10-12T23:20:50.52Z","BuildArgs":"/usr/bin/dracut --kver 6.14.0-29-generic","SourceURLs":["http://source-code-url-1.com"]}],"Signatures":[{"PubKey":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP5rbNcIOcwqBHzLOhJEfdKFHa+pIs10idfTm8c+HDnK","Signature":"1ebda694a4517486b4681c4c61db944a13b67d98667771ab06e2f7b1d97def682feeeb356737c39b6aeb528c8a0a15844597c50ffc4337b6167fb8af3108f101"},{"PubKey":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0zV5fSWzzXa4R7Kpk6RAXkvWsJGpvkQ+9/xxpHC49J","Signature":"42de0420040e8d4e742004b0a99c43d8fb8d0b0c817bddb96e3ca26b390d874c8e665e0b0ee860a360f27f9d1a8f306c56923e55febb9e38a36e8a2481a1dd02"}]}`)

	proof := []byte(`version=2
log=4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d
leaf=302928c2e0e01da52e3b161c54906de9b55ce250f0f47e80e022d04036e2765c e0163de36e40b821893ea6fe49f1285164b5f6c72bfe5646adb4ae843b1bee7d30c631e40fcb3e4d9711f9ca5470568fb59ab26716757756be7c69b90360880b

size=8584
root_hash=bb34cc0973915383f9efc4c70f8c6b6f95b74cc630444fa83182e285f894e900
signature=a2ec51ebe80597a967a6de0f6cc0304036e43a1b752dac7ff45dae90a140c6aa0a3be1869f42dd56f1dd1dc7b9101b6d3a37dc68d976aef82f5cec9711b2680e
cosignature=0d4f46a219ab309cea48cde9712e7d8486fc99802f873175eeab70fb84b4f5a4 1759136853 f2b68b8aabd1231b14887eee6604b43999834e78c9d2608fc72cdda0d006b6ff6cf65fb6f049373e3392a3a8459ca26595cec6fa7bb1d92ff57e19a6429f2d07
cosignature=1c997261f16e6e81d13f420900a2542a4b6a049c2d996324ee5d82a90ca3360c 1759136853 1445c28958d6020bc5d0122275185391dfc036461c795bdf5fc51ac79a200d7cfe7a5739e206b6877f42dd40a3f5d687ce826b0f41ca1862a9ce0db3c07f390e
cosignature=49c4cd6124b7c572f3354d854d50b2a4b057a750f786cf03103c09de339c4ea3 1759136853 42cb573533981cf6b01900c6b0d404aa94785973073b30257fd39957f558b1cb95a9a862291d850efc2430c251014c5a78e48cf3bf4ee9de5d9d763ee5d9a20b
cosignature=42351ad474b29c04187fd0c8c7670656386f323f02e9a4ef0a0055ec061ecac8 1759136853 7615b391a45d62695155c1eab5988c3e007a5ad8d6d30377b17d7415b1726c7b54375a04980af04a2a8d8e9310f574bd6bba257414087729cba59a5375921703
cosignature=70b861a010f25030de6ff6a5267e0b951e70c04b20ba4a3ce41e7fba7b9b7dfc 1759136853 4d65baf0f8d60522ee19884fbb091e5e814f7111c67fd568fc74947fdcea97c52687deb832fea8ad2752db6786a0bb3663ef5fefc74425b086460ea70775ae00
cosignature=b95ef35a9ffb3cf516f423a04128d37d3bffc74d4096bd5e967990c53d09678a 1759136853 8f04b7084b907e66e2f4dd0bdf0d4ca23f395ea73e64efd455de51ee0d91b9d09881a35d85e6adb20851913d5294782e7338193cae4e0e064c1ece956db3410d

leaf_index=8583
node_hash=24ef95594b1f4368e11e5ec32b9c1b4d9580a71b73a0b326898b56b12c23cbec
node_hash=9f367672551985daf90a16177583a9e20615e57ff9134d6d33fbd01792b21e0b
node_hash=86e8e86ea0e0cd80112f7dc8b50218b24f335c775368d16d3e3544a4c1bf4245
node_hash=94e38802079aacf4233de2928ebb665bdc9dde2f0cae3d7a56b66ad39dc5f32f
node_hash=d6c985286fe41f3c75065b18a783a06d66a21b426e829b89fe98f36e3bca912d
node_hash=e8bb977d7ae35a4b7e591ded5e3d7fad0afee0b958d6309a52f48fe46c679c36
`)

	// test support for multiple keys configured in the transparency engine:
	// in this example only the last keys are the correct ones for verifying
	// the test statement proof
	logKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKwmwKhVrEUaZTlHjhoWA4jwJLOF8TY+/NpHAXAHbAHl",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN6kw3w2BWjlKLdrtnv4IaN+zg8/RpKGA98AbbTwjpdQ",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZEryq9QPSJWgA7yjUPnVkSqzAaScd/E+W22QXCCl/m"}
	submitKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMCMTGNMNe1HP2us/dR5dBpyrSPDgPQ9mX5j9iqbLIS+",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqym9S/tFn6B/Eri5hGJiEV8BpGumEPcm65uxC+FG6K"}

	pb := transparency.ProofBundle{
		Statement: statement,
		Proof:     proof,
	}

	e := Engine{Network: false}

	err := e.SetKey(logKey, submitKey)
	if err != nil {
		t.Fatal(err)
	}

	err = e.VerifyProof(&pb)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSigsumEngineCosignaturesVerifyProof(t *testing.T) {
	statement := []byte(`{"Description":"Linux bundle","Version":"v1","Artifacts":[{"Category":1,"Version":"v6.14.0-29-generic","FileName":"vmlinuz-6.14.0-29-generic","Hash":"8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59","Architecture":"x64","Tainted":false,"OpenSource":true,"BuildTimestamp":"2025-10-12T23:20:50.52Z","BuildArgs":"build args example kernel","SourceURLs":["http://source-code-url-1.com","http://source-code-url-2.com"]},{"Category":2,"Version":"","FileName":"initrd.img-6.14.0-29-generic","Hash":"9f5db8bc106c426a6654aa53ada75db307adb6dcb59291aa0a874898bc197b3dad8d2ebef985936bba94e9ae34b52a79e8f9045346cde2326baf4feba73ab66c","Architecture":"x64","Tainted":false,"OpenSource":true,"BuildTimestamp":"2025-10-12T23:20:50.52Z","BuildArgs":"/usr/bin/dracut --kver 6.14.0-29-generic","SourceURLs":["http://source-code-url-1.com"]}],"Signatures":[{"PubKey":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP5rbNcIOcwqBHzLOhJEfdKFHa+pIs10idfTm8c+HDnK","Signature":"1ebda694a4517486b4681c4c61db944a13b67d98667771ab06e2f7b1d97def682feeeb356737c39b6aeb528c8a0a15844597c50ffc4337b6167fb8af3108f101"},{"PubKey":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0zV5fSWzzXa4R7Kpk6RAXkvWsJGpvkQ+9/xxpHC49J","Signature":"42de0420040e8d4e742004b0a99c43d8fb8d0b0c817bddb96e3ca26b390d874c8e665e0b0ee860a360f27f9d1a8f306c56923e55febb9e38a36e8a2481a1dd02"}]}`)

	proof := []byte(`version=2
log=4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d
leaf=302928c2e0e01da52e3b161c54906de9b55ce250f0f47e80e022d04036e2765c e0163de36e40b821893ea6fe49f1285164b5f6c72bfe5646adb4ae843b1bee7d30c631e40fcb3e4d9711f9ca5470568fb59ab26716757756be7c69b90360880b

size=8584
root_hash=bb34cc0973915383f9efc4c70f8c6b6f95b74cc630444fa83182e285f894e900
signature=a2ec51ebe80597a967a6de0f6cc0304036e43a1b752dac7ff45dae90a140c6aa0a3be1869f42dd56f1dd1dc7b9101b6d3a37dc68d976aef82f5cec9711b2680e
cosignature=0d4f46a219ab309cea48cde9712e7d8486fc99802f873175eeab70fb84b4f5a4 1759136853 f2b68b8aabd1231b14887eee6604b43999834e78c9d2608fc72cdda0d006b6ff6cf65fb6f049373e3392a3a8459ca26595cec6fa7bb1d92ff57e19a6429f2d07
cosignature=1c997261f16e6e81d13f420900a2542a4b6a049c2d996324ee5d82a90ca3360c 1759136853 1445c28958d6020bc5d0122275185391dfc036461c795bdf5fc51ac79a200d7cfe7a5739e206b6877f42dd40a3f5d687ce826b0f41ca1862a9ce0db3c07f390e
cosignature=49c4cd6124b7c572f3354d854d50b2a4b057a750f786cf03103c09de339c4ea3 1759136853 42cb573533981cf6b01900c6b0d404aa94785973073b30257fd39957f558b1cb95a9a862291d850efc2430c251014c5a78e48cf3bf4ee9de5d9d763ee5d9a20b
cosignature=42351ad474b29c04187fd0c8c7670656386f323f02e9a4ef0a0055ec061ecac8 1759136853 7615b391a45d62695155c1eab5988c3e007a5ad8d6d30377b17d7415b1726c7b54375a04980af04a2a8d8e9310f574bd6bba257414087729cba59a5375921703
cosignature=70b861a010f25030de6ff6a5267e0b951e70c04b20ba4a3ce41e7fba7b9b7dfc 1759136853 4d65baf0f8d60522ee19884fbb091e5e814f7111c67fd568fc74947fdcea97c52687deb832fea8ad2752db6786a0bb3663ef5fefc74425b086460ea70775ae00
cosignature=b95ef35a9ffb3cf516f423a04128d37d3bffc74d4096bd5e967990c53d09678a 1759136853 8f04b7084b907e66e2f4dd0bdf0d4ca23f395ea73e64efd455de51ee0d91b9d09881a35d85e6adb20851913d5294782e7338193cae4e0e064c1ece956db3410d

leaf_index=8583
node_hash=24ef95594b1f4368e11e5ec32b9c1b4d9580a71b73a0b326898b56b12c23cbec
node_hash=9f367672551985daf90a16177583a9e20615e57ff9134d6d33fbd01792b21e0b
node_hash=86e8e86ea0e0cd80112f7dc8b50218b24f335c775368d16d3e3544a4c1bf4245
node_hash=94e38802079aacf4233de2928ebb665bdc9dde2f0cae3d7a56b66ad39dc5f32f
node_hash=d6c985286fe41f3c75065b18a783a06d66a21b426e829b89fe98f36e3bca912d
node_hash=e8bb977d7ae35a4b7e591ded5e3d7fad0afee0b958d6309a52f48fe46c679c36
`)
	policy := []byte(`log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye

witness poc.sigsum.org/nisse 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c
witness rgdd.se/poc-witness  28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806

group  demo-quorum-rule any poc.sigsum.org/nisse rgdd.se/poc-witness
quorum demo-quorum-rule
`)

	pb := transparency.ProofBundle{
		Statement: statement,
		Proof:     proof,
	}

	e := Engine{Network: false}

	logKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZEryq9QPSJWgA7yjUPnVkSqzAaScd/E+W22QXCCl/m"}
	submitKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqym9S/tFn6B/Eri5hGJiEV8BpGumEPcm65uxC+FG6K"}

	err := e.SetKey(logKey, submitKey)
	if err != nil {
		t.Fatal(err)
	}

	p, err := e.ParseWitnessPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}

	err = e.SetWitnessPolicy(p)
	if err != nil {
		t.Fatal(err)
	}

	err = e.VerifyProof(&pb)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSigsumEngineCosignaturesVerifyProofInvalidLogKey(t *testing.T) {
	statement := []byte(`{"Description":"Linux bundle","Version":"v1","Artifacts":[{"Category":1,"Version":"v6.14.0-29-generic","FileName":"vmlinuz-6.14.0-29-generic","Hash":"8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59","Architecture":"x64","Tainted":false,"OpenSource":true,"BuildTimestamp":"2025-10-12T23:20:50.52Z","BuildArgs":"build args example kernel","SourceURLs":["http://source-code-url-1.com","http://source-code-url-2.com"]},{"Category":2,"Version":"","FileName":"initrd.img-6.14.0-29-generic","Hash":"9f5db8bc106c426a6654aa53ada75db307adb6dcb59291aa0a874898bc197b3dad8d2ebef985936bba94e9ae34b52a79e8f9045346cde2326baf4feba73ab66c","Architecture":"x64","Tainted":false,"OpenSource":true,"BuildTimestamp":"2025-10-12T23:20:50.52Z","BuildArgs":"/usr/bin/dracut --kver 6.14.0-29-generic","SourceURLs":["http://source-code-url-1.com"]}],"Signatures":[{"PubKey":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP5rbNcIOcwqBHzLOhJEfdKFHa+pIs10idfTm8c+HDnK","Signature":"1ebda694a4517486b4681c4c61db944a13b67d98667771ab06e2f7b1d97def682feeeb356737c39b6aeb528c8a0a15844597c50ffc4337b6167fb8af3108f101"},{"PubKey":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0zV5fSWzzXa4R7Kpk6RAXkvWsJGpvkQ+9/xxpHC49J","Signature":"42de0420040e8d4e742004b0a99c43d8fb8d0b0c817bddb96e3ca26b390d874c8e665e0b0ee860a360f27f9d1a8f306c56923e55febb9e38a36e8a2481a1dd02"}]}`)

	proof := []byte(`version=2
log=4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d
leaf=302928c2e0e01da52e3b161c54906de9b55ce250f0f47e80e022d04036e2765c e0163de36e40b821893ea6fe49f1285164b5f6c72bfe5646adb4ae843b1bee7d30c631e40fcb3e4d9711f9ca5470568fb59ab26716757756be7c69b90360880b

size=8584
root_hash=bb34cc0973915383f9efc4c70f8c6b6f95b74cc630444fa83182e285f894e900
signature=a2ec51ebe80597a967a6de0f6cc0304036e43a1b752dac7ff45dae90a140c6aa0a3be1869f42dd56f1dd1dc7b9101b6d3a37dc68d976aef82f5cec9711b2680e
cosignature=0d4f46a219ab309cea48cde9712e7d8486fc99802f873175eeab70fb84b4f5a4 1759136853 f2b68b8aabd1231b14887eee6604b43999834e78c9d2608fc72cdda0d006b6ff6cf65fb6f049373e3392a3a8459ca26595cec6fa7bb1d92ff57e19a6429f2d07
cosignature=1c997261f16e6e81d13f420900a2542a4b6a049c2d996324ee5d82a90ca3360c 1759136853 1445c28958d6020bc5d0122275185391dfc036461c795bdf5fc51ac79a200d7cfe7a5739e206b6877f42dd40a3f5d687ce826b0f41ca1862a9ce0db3c07f390e
cosignature=49c4cd6124b7c572f3354d854d50b2a4b057a750f786cf03103c09de339c4ea3 1759136853 42cb573533981cf6b01900c6b0d404aa94785973073b30257fd39957f558b1cb95a9a862291d850efc2430c251014c5a78e48cf3bf4ee9de5d9d763ee5d9a20b
cosignature=42351ad474b29c04187fd0c8c7670656386f323f02e9a4ef0a0055ec061ecac8 1759136853 7615b391a45d62695155c1eab5988c3e007a5ad8d6d30377b17d7415b1726c7b54375a04980af04a2a8d8e9310f574bd6bba257414087729cba59a5375921703
cosignature=70b861a010f25030de6ff6a5267e0b951e70c04b20ba4a3ce41e7fba7b9b7dfc 1759136853 4d65baf0f8d60522ee19884fbb091e5e814f7111c67fd568fc74947fdcea97c52687deb832fea8ad2752db6786a0bb3663ef5fefc74425b086460ea70775ae00
cosignature=b95ef35a9ffb3cf516f423a04128d37d3bffc74d4096bd5e967990c53d09678a 1759136853 8f04b7084b907e66e2f4dd0bdf0d4ca23f395ea73e64efd455de51ee0d91b9d09881a35d85e6adb20851913d5294782e7338193cae4e0e064c1ece956db3410d

leaf_index=8583
node_hash=24ef95594b1f4368e11e5ec32b9c1b4d9580a71b73a0b326898b56b12c23cbec
node_hash=9f367672551985daf90a16177583a9e20615e57ff9134d6d33fbd01792b21e0b
node_hash=86e8e86ea0e0cd80112f7dc8b50218b24f335c775368d16d3e3544a4c1bf4245
node_hash=94e38802079aacf4233de2928ebb665bdc9dde2f0cae3d7a56b66ad39dc5f32f
node_hash=d6c985286fe41f3c75065b18a783a06d66a21b426e829b89fe98f36e3bca912d
node_hash=e8bb977d7ae35a4b7e591ded5e3d7fad0afee0b958d6309a52f48fe46c679c36
`)
	policy := []byte(`log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye

witness poc.sigsum.org/nisse 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c
witness rgdd.se/poc-witness  28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806

group  demo-quorum-rule any poc.sigsum.org/nisse rgdd.se/poc-witness
quorum demo-quorum-rule
`)

	pb := transparency.ProofBundle{
		Statement: statement,
		Proof:     proof,
	}

	e := Engine{Network: false}

	// invalid log key (i.e. the only allowed key is not matching the log keyhash in the proof)
	logKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKwmwKhVrEUaZTlHjhoWA4jwJLOF8TY+/NpHAXAHbAHl"}
	submitKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqym9S/tFn6B/Eri5hGJiEV8BpGumEPcm65uxC+FG6K"}

	err := e.SetKey(logKey, submitKey)
	if err != nil {
		t.Fatal(err)
	}

	p, err := e.ParseWitnessPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}

	err = e.SetWitnessPolicy(p)
	if err != nil {
		t.Fatal(err)
	}

	err = e.VerifyProof(&pb)
	// VerifyProof must return the log keyhash mismatch error
	if err != nil && err.Error() != "unknown log key hash" {
		t.Fatal(err)
	}
}

func TestSigsumEngineCosignaturesVerifyProofInvalidSubmitKey(t *testing.T) {
	statement := []byte(`{"Description":"Linux bundle","Version":"v1","Artifacts":[{"Category":1,"Version":"v6.14.0-29-generic","FileName":"vmlinuz-6.14.0-29-generic","Hash":"8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59","Architecture":"x64","Tainted":false,"OpenSource":true,"BuildTimestamp":"2025-10-12T23:20:50.52Z","BuildArgs":"build args example kernel","SourceURLs":["http://source-code-url-1.com","http://source-code-url-2.com"]},{"Category":2,"Version":"","FileName":"initrd.img-6.14.0-29-generic","Hash":"9f5db8bc106c426a6654aa53ada75db307adb6dcb59291aa0a874898bc197b3dad8d2ebef985936bba94e9ae34b52a79e8f9045346cde2326baf4feba73ab66c","Architecture":"x64","Tainted":false,"OpenSource":true,"BuildTimestamp":"2025-10-12T23:20:50.52Z","BuildArgs":"/usr/bin/dracut --kver 6.14.0-29-generic","SourceURLs":["http://source-code-url-1.com"]}],"Signatures":[{"PubKey":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP5rbNcIOcwqBHzLOhJEfdKFHa+pIs10idfTm8c+HDnK","Signature":"1ebda694a4517486b4681c4c61db944a13b67d98667771ab06e2f7b1d97def682feeeb356737c39b6aeb528c8a0a15844597c50ffc4337b6167fb8af3108f101"},{"PubKey":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0zV5fSWzzXa4R7Kpk6RAXkvWsJGpvkQ+9/xxpHC49J","Signature":"42de0420040e8d4e742004b0a99c43d8fb8d0b0c817bddb96e3ca26b390d874c8e665e0b0ee860a360f27f9d1a8f306c56923e55febb9e38a36e8a2481a1dd02"}]}`)

	proof := []byte(`version=2
log=4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d
leaf=302928c2e0e01da52e3b161c54906de9b55ce250f0f47e80e022d04036e2765c e0163de36e40b821893ea6fe49f1285164b5f6c72bfe5646adb4ae843b1bee7d30c631e40fcb3e4d9711f9ca5470568fb59ab26716757756be7c69b90360880b

size=8584
root_hash=bb34cc0973915383f9efc4c70f8c6b6f95b74cc630444fa83182e285f894e900
signature=a2ec51ebe80597a967a6de0f6cc0304036e43a1b752dac7ff45dae90a140c6aa0a3be1869f42dd56f1dd1dc7b9101b6d3a37dc68d976aef82f5cec9711b2680e
cosignature=0d4f46a219ab309cea48cde9712e7d8486fc99802f873175eeab70fb84b4f5a4 1759136853 f2b68b8aabd1231b14887eee6604b43999834e78c9d2608fc72cdda0d006b6ff6cf65fb6f049373e3392a3a8459ca26595cec6fa7bb1d92ff57e19a6429f2d07
cosignature=1c997261f16e6e81d13f420900a2542a4b6a049c2d996324ee5d82a90ca3360c 1759136853 1445c28958d6020bc5d0122275185391dfc036461c795bdf5fc51ac79a200d7cfe7a5739e206b6877f42dd40a3f5d687ce826b0f41ca1862a9ce0db3c07f390e
cosignature=49c4cd6124b7c572f3354d854d50b2a4b057a750f786cf03103c09de339c4ea3 1759136853 42cb573533981cf6b01900c6b0d404aa94785973073b30257fd39957f558b1cb95a9a862291d850efc2430c251014c5a78e48cf3bf4ee9de5d9d763ee5d9a20b
cosignature=42351ad474b29c04187fd0c8c7670656386f323f02e9a4ef0a0055ec061ecac8 1759136853 7615b391a45d62695155c1eab5988c3e007a5ad8d6d30377b17d7415b1726c7b54375a04980af04a2a8d8e9310f574bd6bba257414087729cba59a5375921703
cosignature=70b861a010f25030de6ff6a5267e0b951e70c04b20ba4a3ce41e7fba7b9b7dfc 1759136853 4d65baf0f8d60522ee19884fbb091e5e814f7111c67fd568fc74947fdcea97c52687deb832fea8ad2752db6786a0bb3663ef5fefc74425b086460ea70775ae00
cosignature=b95ef35a9ffb3cf516f423a04128d37d3bffc74d4096bd5e967990c53d09678a 1759136853 8f04b7084b907e66e2f4dd0bdf0d4ca23f395ea73e64efd455de51ee0d91b9d09881a35d85e6adb20851913d5294782e7338193cae4e0e064c1ece956db3410d

leaf_index=8583
node_hash=24ef95594b1f4368e11e5ec32b9c1b4d9580a71b73a0b326898b56b12c23cbec
node_hash=9f367672551985daf90a16177583a9e20615e57ff9134d6d33fbd01792b21e0b
node_hash=86e8e86ea0e0cd80112f7dc8b50218b24f335c775368d16d3e3544a4c1bf4245
node_hash=94e38802079aacf4233de2928ebb665bdc9dde2f0cae3d7a56b66ad39dc5f32f
node_hash=d6c985286fe41f3c75065b18a783a06d66a21b426e829b89fe98f36e3bca912d
node_hash=e8bb977d7ae35a4b7e591ded5e3d7fad0afee0b958d6309a52f48fe46c679c36
`)
	policy := []byte(`log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye

witness poc.sigsum.org/nisse 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c
witness rgdd.se/poc-witness  28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806

group  demo-quorum-rule any poc.sigsum.org/nisse rgdd.se/poc-witness
quorum demo-quorum-rule
`)

	pb := transparency.ProofBundle{
		Statement: statement,
		Proof:     proof,
	}

	e := Engine{Network: false}

	logKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZEryq9QPSJWgA7yjUPnVkSqzAaScd/E+W22QXCCl/m"}
	submitKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMdLcxVjCAQUHbD4jCfFP+f8v1nmyjWkq6rXiexrK8II"}

	err := e.SetKey(logKey, submitKey)
	if err != nil {
		t.Fatal(err)
	}

	p, err := e.ParseWitnessPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}

	err = e.SetWitnessPolicy(p)
	if err != nil {
		t.Fatal(err)
	}

	err = e.VerifyProof(&pb)
	// VerifyProof must return the leaf key hash (i.e. submitter's key) mismatch error
	if err != nil && err.Error() != "unknown leaf key hash" {
		t.Fatal(err)
	}
}

func TestSigsumEngineGetProof(t *testing.T) {
	policy := []byte(`log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye

witness poc.sigsum.org/nisse 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c
witness rgdd.se/poc-witness  28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806

group  demo-quorum-rule any poc.sigsum.org/nisse rgdd.se/poc-witness
quorum demo-quorum-rule
`)

	statement := []byte(`{"Description":"Linux bundle","Version":"v1","Artifacts":[{"Category":1,"Version":"v6.14.0-29-generic","FileName":"vmlinuz-6.14.0-29-generic","Hash":"8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59","Architecture":"x64","Tainted":false,"OpenSource":true,"BuildTimestamp":"2025-10-12T23:20:50.52Z","BuildArgs":"build args example kernel","SourceURLs":["http://source-code-url-1.com","http://source-code-url-2.com"]},{"Category":2,"Version":"","FileName":"initrd.img-6.14.0-29-generic","Hash":"9f5db8bc106c426a6654aa53ada75db307adb6dcb59291aa0a874898bc197b3dad8d2ebef985936bba94e9ae34b52a79e8f9045346cde2326baf4feba73ab66c","Architecture":"x64","Tainted":false,"OpenSource":true,"BuildTimestamp":"2025-10-12T23:20:50.52Z","BuildArgs":"/usr/bin/dracut --kver 6.14.0-29-generic","SourceURLs":["http://source-code-url-1.com"]}],"Signatures":[{"PubKey":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP5rbNcIOcwqBHzLOhJEfdKFHa+pIs10idfTm8c+HDnK","Signature":"1ebda694a4517486b4681c4c61db944a13b67d98667771ab06e2f7b1d97def682feeeb356737c39b6aeb528c8a0a15844597c50ffc4337b6167fb8af3108f101"},{"PubKey":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0zV5fSWzzXa4R7Kpk6RAXkvWsJGpvkQ+9/xxpHC49J","Signature":"42de0420040e8d4e742004b0a99c43d8fb8d0b0c817bddb96e3ca26b390d874c8e665e0b0ee860a360f27f9d1a8f306c56923e55febb9e38a36e8a2481a1dd02"}]}`)

	pb := transparency.ProofBundle{
		Statement: statement,
		Probe:     []byte(`{"origin": "https://test.sigsum.org/barreleye", "leaf_signature":"e0163de36e40b821893ea6fe49f1285164b5f6c72bfe5646adb4ae843b1bee7d30c631e40fcb3e4d9711f9ca5470568fb59ab26716757756be7c69b90360880b", "log_public_key_hash": "4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d", "submit_public_key_hash": "302928c2e0e01da52e3b161c54906de9b55ce250f0f47e80e022d04036e2765c"}`),
	}

	e := Engine{Network: true}

	logKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZEryq9QPSJWgA7yjUPnVkSqzAaScd/E+W22QXCCl/m"}
	submitKey := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqym9S/tFn6B/Eri5hGJiEV8BpGumEPcm65uxC+FG6K"}

	err := e.SetKey(logKey, submitKey)
	if err != nil {
		t.Fatal(err)
	}

	p, err := e.ParseWitnessPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}

	err = e.SetWitnessPolicy(p)
	if err != nil {
		t.Fatal(err)
	}

	if err = e.GetProof(&pb); err != nil {
		t.Fatal(err)
	}
}
