GO ?= go

check:
	@${GO} vet ./...
	@${GOPATH}/bin/staticcheck ./...
	@${GOPATH}/bin/errcheck ./...

test:
	@cd artifact/dtb && ${GO} test -cover -v
	@cd artifact/initrd && ${GO} test -cover -v
	@cd artifact/linux_kernel && ${GO} test -cover -v
	@cd artifact/uefi_binary && ${GO} test -cover -v
	@cd artifact/uefi_bios && ${GO} test -cover -v
	@cd artifact/windows_bootmgr && ${GO} test -cover -v
	@cd engine/sigsum && ${GO} test -cover -v
	@cd policy && ${GO} test -cover -v

docs:
	@${GOPATH}/bin/gomarkdoc artifact/artifact.go policy/policy.go transparency/transparency.go statement/statement.go > ./doc/API.md

tools:
	@cd cmd/bt-statement && ${GO} build
	@cd cmd/bt-policy && ${GO} build
