// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package policy

import (
	_ "github.com/usbarmory/boot-transparency/artifact/dtb"
	_ "github.com/usbarmory/boot-transparency/artifact/initrd"
	_ "github.com/usbarmory/boot-transparency/artifact/linux_kernel"
	_ "github.com/usbarmory/boot-transparency/artifact/uefi_bios"
	_ "github.com/usbarmory/boot-transparency/artifact/uefi_binary"
	_ "github.com/usbarmory/boot-transparency/artifact/windows_bootmgr"
)
