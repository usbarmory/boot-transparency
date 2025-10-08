// https://github.com/usbarmory/boot-transparency
//
// Copyright (c) The boot-transparency authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package dtb

import (
	"testing"

	"github.com/usbarmory/boot-transparency/artifact"
)

func TestDtbParseRequirements(t *testing.T) {
	r := []byte(`{"min_version": "v6.14.0", "architecture":"x64", "license": ["GPL-2.0-only"], "min_timestamp": "2025-01-01T23:20:50.52Z", "dts_include": ["model = \"Inverse Path USB armory\";"]}`)

	h, err := artifact.GetHandler(artifact.Dtb)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.ParseRequirements(r); err != nil {
		t.Fatal(err)
	}
}

func TestDtbParseClaims(t *testing.T) {
	c := []byte(`{"file_name": "imx53-usbarmory.dtb", "hash": "8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59", "version":"v6.14.0-29-generic" ,"architecture":"x64", "tainted": false, "license": ["GPL-2.0-only"], "timestamp": "2025-10-21T23:20:50.52Z", "dts": "/*\n * USB armory MkI device tree file\n * https://inversepath.com/usbarmory\n *\n * Copyright (C) 2015, Inverse Path\n * Andrej Rosano <andrej@inversepath.com>\n *\n * This file is dual-licensed: you can use it either under the terms\n * of the GPL or the X11 license, at your option. Note that this dual\n * licensing only applies to this file, and not this project as a\n * whole.\n *\n *  a) This file is free software; you can redistribute it and/or\n *     modify it under the terms of the GNU General Public License as\n *     published by the Free Software Foundation; either version 2 of the\n *     License, or (at your option) any later version.\n *\n *     This file is distributed in the hope that it will be useful,\n *     but WITHOUT ANY WARRANTY; without even the implied warranty of\n *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n *     GNU General Public License for more details.\n *\n * Or, alternatively,\n *\n *  b) Permission is hereby granted, free of charge, to any person\n *     obtaining a copy of this software and associated documentation\n *     files (the \"Software\"), to deal in the Software without\n *     restriction, including without limitation the rights to use,\n *     copy, modify, merge, publish, distribute, sublicense, and/or\n *     sell copies of the Software, and to permit persons to whom the\n *     Software is furnished to do so, subject to the following\n *     conditions:\n *\n *     The above copyright notice and this permission notice shall be\n *     included in all copies or substantial portions of the Software.\n *\n *     THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND,\n *     EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES\n *     OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND\n *     NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT\n *     HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,\n *     WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING\n *     FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR\n *     OTHER DEALINGS IN THE SOFTWARE.\n */\n\n/dts-v1/;\n#include \"imx53.dtsi\"\n\n/ {\n\tmodel = \"Inverse Path USB armory\";\n\tcompatible = \"inversepath,imx53-usbarmory\", \"fsl,imx53\";\n};\n\n/ {\n\tchosen {\n\t\tstdout-path = &uart1;\n\t};\n\n\tmemory@70000000 {\n\t\tdevice_type = \"memory\";\n\t\treg = <0x70000000 0x20000000>;\n\t};\n\n\tleds {\n\t\tcompatible = \"gpio-leds\";\n\t\tpinctrl-names = \"default\";\n\t\tpinctrl-0 = <&pinctrl_led>;\n\n\t\tuser {\n\t\t\tlabel = \"LED\";\n\t\t\tgpios = <&gpio4 27 GPIO_ACTIVE_LOW>;\n\t\t\tlinux,default-trigger = \"heartbeat\";\n\t\t};\n\t};\n};\n\n/*\n * Not every i.MX53 P/N supports clock > 800MHz.\n * As USB armory does not mount a specific P/N set a safe clock upper limit.\n */\n&cpu0 {\n\toperating-points = <\n\t\t/* kHz */\n\t\t166666  850000\n\t\t400000  900000\n\t\t800000 1050000\n\t>;\n};\n\n&esdhc1 {\n\tpinctrl-names = \"default\";\n\tpinctrl-0 = <&pinctrl_esdhc1>;\n\tstatus = \"okay\";\n};\n\n&iomuxc {\n\tpinctrl_esdhc1: esdhc1grp {\n\t\tfsl,pins = <\n\t\t\tMX53_PAD_SD1_DATA0__ESDHC1_DAT0\t\t0x1d5\n\t\t\tMX53_PAD_SD1_DATA1__ESDHC1_DAT1\t\t0x1d5\n\t\t\tMX53_PAD_SD1_DATA2__ESDHC1_DAT2\t\t0x1d5\n\t\t\tMX53_PAD_SD1_DATA3__ESDHC1_DAT3\t\t0x1d5\n\t\t\tMX53_PAD_SD1_CMD__ESDHC1_CMD\t\t0x1d5\n\t\t\tMX53_PAD_SD1_CLK__ESDHC1_CLK\t\t0x1d5\n\t\t>;\n\t};\n\n\tpinctrl_i2c1_pmic: i2c1grp {\n\t\tfsl,pins = <\n\t\t\tMX53_PAD_EIM_D21__I2C1_SCL\t0x80\n\t\t\tMX53_PAD_EIM_D28__I2C1_SDA\t0x80\n\t\t>;\n\t};\n\n\tpinctrl_led: ledgrp {\n\t\tfsl,pins = <\n\t\t\tMX53_PAD_DISP0_DAT6__GPIO4_27 0x1e4\n\t\t>;\n\t};\n\n\t/*\n\t * UART mode pin header configration\n\t * 3 - GPIO5[26], pull-down 100K\n\t * 4 - GPIO5[27], pull-down 100K\n\t * 5 - TX, pull-up 100K\n\t * 6 - RX, pull-up 100K\n\t * 7 - GPIO5[30], pull-down 100K\n\t */\n\tpinctrl_uart1: uart1grp {\n\t\tfsl,pins = <\n\t\t\tMX53_PAD_CSI0_DAT8__GPIO5_26\t\t0xc0\n\t\t\tMX53_PAD_CSI0_DAT9__GPIO5_27\t\t0xc0\n\t\t\tMX53_PAD_CSI0_DAT10__UART1_TXD_MUX\t0x1e4\n\t\t\tMX53_PAD_CSI0_DAT11__UART1_RXD_MUX\t0x1e4\n\t\t\tMX53_PAD_CSI0_DAT12__GPIO5_30\t\t0xc0\n\t\t>;\n\t};\n};\n\n&i2c1 {\n\tpinctrl-0 = <&pinctrl_i2c1_pmic>;\n\tstatus = \"okay\";\n\n\tltc3589: pmic@34 {\n\t\tcompatible = \"lltc,ltc3589-2\";\n\t\treg = <0x34>;\n\n\t\tregulators {\n\t\t\tsw1_reg: sw1 {\n\t\t\t\tregulator-min-microvolt = <591930>;\n\t\t\t\tregulator-max-microvolt = <1224671>;\n\t\t\t\tlltc,fb-voltage-divider = <100000 158000>;\n\t\t\t\tregulator-ramp-delay = <7000>;\n\t\t\t\tregulator-boot-on;\n\t\t\t\tregulator-always-on;\n\t\t\t};\n\n\t\t\tsw2_reg: sw2 {\n\t\t\t\tregulator-min-microvolt = <704123>;\n\t\t\t\tregulator-max-microvolt = <1456803>;\n\t\t\t\tlltc,fb-voltage-divider = <180000 191000>;\n\t\t\t\tregulator-ramp-delay = <7000>;\n\t\t\t\tregulator-boot-on;\n\t\t\t\tregulator-always-on;\n\t\t\t};\n\n\t\t\tsw3_reg: sw3 {\n\t\t\t\tregulator-min-microvolt = <1341250>;\n\t\t\t\tregulator-max-microvolt = <2775000>;\n\t\t\t\tlltc,fb-voltage-divider = <270000 100000>;\n\t\t\t\tregulator-ramp-delay = <7000>;\n\t\t\t\tregulator-boot-on;\n\t\t\t\tregulator-always-on;\n\t\t\t};\n\n\t\t\tbb_out_reg: bb-out {\n\t\t\t\tregulator-min-microvolt = <3387341>;\n\t\t\t\tregulator-max-microvolt = <3387341>;\n\t\t\t\tlltc,fb-voltage-divider = <511000 158000>;\n\t\t\t\tregulator-boot-on;\n\t\t\t\tregulator-always-on;\n\t\t\t};\n\n\t\t\tldo1_reg: ldo1 {\n\t\t\t\tregulator-min-microvolt = <1306329>;\n\t\t\t\tregulator-max-microvolt = <1306329>;\n\t\t\t\tlltc,fb-voltage-divider = <100000 158000>;\n\t\t\t\tregulator-boot-on;\n\t\t\t\tregulator-always-on;\n\t\t\t};\n\n\t\t\tldo2_reg: ldo2 {\n\t\t\t\tregulator-min-microvolt = <704123>;\n\t\t\t\tregulator-max-microvolt = <1456806>;\n\t\t\t\tlltc,fb-voltage-divider = <180000 191000>;\n\t\t\t\tregulator-ramp-delay = <7000>;\n\t\t\t\tregulator-boot-on;\n\t\t\t\tregulator-always-on;\n\t\t\t};\n\n\t\t\tldo3_reg: ldo3 {\n\t\t\t\tregulator-min-microvolt = <2800000>;\n\t\t\t\tregulator-max-microvolt = <2800000>;\n\t\t\t\tregulator-boot-on;\n\t\t\t};\n\n\t\t\tldo4_reg: ldo4 {\n\t\t\t\tregulator-min-microvolt = <1200000>;\n\t\t\t\tregulator-max-microvolt = <3200000>;\n\t\t\t};\n\t\t};\n\t};\n};\n\n&uart1 {\n\tpinctrl-names = \"default\";\n\tpinctrl-0 = <&pinctrl_uart1>;\n\tstatus = \"okay\";\n};\n\n&usbotg {\n\tdr_mode = \"peripheral\";\n\tstatus = \"okay\";\n};\n\n" }`)

	h, err := artifact.GetHandler(artifact.Dtb)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.ParseClaims(c); err != nil {
		t.Fatal(err)
	}
}

func TestNegativeDtbParseClaims(t *testing.T) {
	c := []byte(`{"hash": [ "8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59" ]}`)

	h, err := artifact.GetHandler(artifact.Dtb)
	if err != nil {
		t.Fatal(err)
	}

	// error is expected: "hash" cannot be an array
	if _, err := h.ParseClaims(c); err == nil {
		t.Fatal(err)
	}
}

func TestDtbCheck(t *testing.T) {
	r := []byte(`{"min_version": "v6.14.0-29", "architecture":"x64", "dts_include":["model = \"Inverse Path USB armory\";"]}`)

	c := []byte(`{"file_name": "test.dtb", "hash": "8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59", "version":"v6.14.0-29-generic" ,"architecture":"x64", "dts":"/*\n * USB armory MkI device tree file\n * https://inversepath.com/usbarmory\n *\n * Copyright (C) 2015, Inverse Path\n * Andrej Rosano <andrej@inversepath.com>\n *\n * This file is dual-licensed: you can use it either under the terms\n * of the GPL or the X11 license, at your option. Note that this dual\n * licensing only applies to this file, and not this project as a\n * whole.\n *\n *  a) This file is free software; you can redistribute it and/or\n *     modify it under the terms of the GNU General Public License as\n *     published by the Free Software Foundation; either version 2 of the\n *     License, or (at your option) any later version.\n *\n *     This file is distributed in the hope that it will be useful,\n *     but WITHOUT ANY WARRANTY; without even the implied warranty of\n *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n *     GNU General Public License for more details.\n *\n * Or, alternatively,\n *\n *  b) Permission is hereby granted, free of charge, to any person\n *     obtaining a copy of this software and associated documentation\n *     files (the \"Software\"), to deal in the Software without\n *     restriction, including without limitation the rights to use,\n *     copy, modify, merge, publish, distribute, sublicense, and/or\n *     sell copies of the Software, and to permit persons to whom the\n *     Software is furnished to do so, subject to the following\n *     conditions:\n *\n *     The above copyright notice and this permission notice shall be\n *     included in all copies or substantial portions of the Software.\n *\n *     THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND,\n *     EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES\n *     OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND\n *     NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT\n *     HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,\n *     WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING\n *     FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR\n *     OTHER DEALINGS IN THE SOFTWARE.\n */\n\n/dts-v1/;\n#include \"imx53.dtsi\"\n\n/ {\n\tmodel = \"Inverse Path USB armory\";\n\tcompatible = \"inversepath,imx53-usbarmory\", \"fsl,imx53\";\n};\n\n/ {\n\tchosen {\n\t\tstdout-path = &uart1;\n\t};\n\n\tmemory@70000000 {\n\t\tdevice_type = \"memory\";\n\t\treg = <0x70000000 0x20000000>;\n\t};\n\n\tleds {\n\t\tcompatible = \"gpio-leds\";\n\t\tpinctrl-names = \"default\";\n\t\tpinctrl-0 = <&pinctrl_led>;\n\n\t\tuser {\n\t\t\tlabel = \"LED\";\n\t\t\tgpios = <&gpio4 27 GPIO_ACTIVE_LOW>;\n\t\t\tlinux,default-trigger = \"heartbeat\";\n\t\t};\n\t};\n};\n\n/*\n * Not every i.MX53 P/N supports clock > 800MHz.\n * As USB armory does not mount a specific P/N set a safe clock upper limit.\n */\n&cpu0 {\n\toperating-points = <\n\t\t/* kHz */\n\t\t166666  850000\n\t\t400000  900000\n\t\t800000 1050000\n\t>;\n};\n\n&esdhc1 {\n\tpinctrl-names = \"default\";\n\tpinctrl-0 = <&pinctrl_esdhc1>;\n\tstatus = \"okay\";\n};\n\n&iomuxc {\n\tpinctrl_esdhc1: esdhc1grp {\n\t\tfsl,pins = <\n\t\t\tMX53_PAD_SD1_DATA0__ESDHC1_DAT0\t\t0x1d5\n\t\t\tMX53_PAD_SD1_DATA1__ESDHC1_DAT1\t\t0x1d5\n\t\t\tMX53_PAD_SD1_DATA2__ESDHC1_DAT2\t\t0x1d5\n\t\t\tMX53_PAD_SD1_DATA3__ESDHC1_DAT3\t\t0x1d5\n\t\t\tMX53_PAD_SD1_CMD__ESDHC1_CMD\t\t0x1d5\n\t\t\tMX53_PAD_SD1_CLK__ESDHC1_CLK\t\t0x1d5\n\t\t>;\n\t};\n\n\tpinctrl_i2c1_pmic: i2c1grp {\n\t\tfsl,pins = <\n\t\t\tMX53_PAD_EIM_D21__I2C1_SCL\t0x80\n\t\t\tMX53_PAD_EIM_D28__I2C1_SDA\t0x80\n\t\t>;\n\t};\n\n\tpinctrl_led: ledgrp {\n\t\tfsl,pins = <\n\t\t\tMX53_PAD_DISP0_DAT6__GPIO4_27 0x1e4\n\t\t>;\n\t};\n\n\t/*\n\t * UART mode pin header configration\n\t * 3 - GPIO5[26], pull-down 100K\n\t * 4 - GPIO5[27], pull-down 100K\n\t * 5 - TX, pull-up 100K\n\t * 6 - RX, pull-up 100K\n\t * 7 - GPIO5[30], pull-down 100K\n\t */\n\tpinctrl_uart1: uart1grp {\n\t\tfsl,pins = <\n\t\t\tMX53_PAD_CSI0_DAT8__GPIO5_26\t\t0xc0\n\t\t\tMX53_PAD_CSI0_DAT9__GPIO5_27\t\t0xc0\n\t\t\tMX53_PAD_CSI0_DAT10__UART1_TXD_MUX\t0x1e4\n\t\t\tMX53_PAD_CSI0_DAT11__UART1_RXD_MUX\t0x1e4\n\t\t\tMX53_PAD_CSI0_DAT12__GPIO5_30\t\t0xc0\n\t\t>;\n\t};\n};\n\n&i2c1 {\n\tpinctrl-0 = <&pinctrl_i2c1_pmic>;\n\tstatus = \"okay\";\n\n\tltc3589: pmic@34 {\n\t\tcompatible = \"lltc,ltc3589-2\";\n\t\treg = <0x34>;\n\n\t\tregulators {\n\t\t\tsw1_reg: sw1 {\n\t\t\t\tregulator-min-microvolt = <591930>;\n\t\t\t\tregulator-max-microvolt = <1224671>;\n\t\t\t\tlltc,fb-voltage-divider = <100000 158000>;\n\t\t\t\tregulator-ramp-delay = <7000>;\n\t\t\t\tregulator-boot-on;\n\t\t\t\tregulator-always-on;\n\t\t\t};\n\n\t\t\tsw2_reg: sw2 {\n\t\t\t\tregulator-min-microvolt = <704123>;\n\t\t\t\tregulator-max-microvolt = <1456803>;\n\t\t\t\tlltc,fb-voltage-divider = <180000 191000>;\n\t\t\t\tregulator-ramp-delay = <7000>;\n\t\t\t\tregulator-boot-on;\n\t\t\t\tregulator-always-on;\n\t\t\t};\n\n\t\t\tsw3_reg: sw3 {\n\t\t\t\tregulator-min-microvolt = <1341250>;\n\t\t\t\tregulator-max-microvolt = <2775000>;\n\t\t\t\tlltc,fb-voltage-divider = <270000 100000>;\n\t\t\t\tregulator-ramp-delay = <7000>;\n\t\t\t\tregulator-boot-on;\n\t\t\t\tregulator-always-on;\n\t\t\t};\n\n\t\t\tbb_out_reg: bb-out {\n\t\t\t\tregulator-min-microvolt = <3387341>;\n\t\t\t\tregulator-max-microvolt = <3387341>;\n\t\t\t\tlltc,fb-voltage-divider = <511000 158000>;\n\t\t\t\tregulator-boot-on;\n\t\t\t\tregulator-always-on;\n\t\t\t};\n\n\t\t\tldo1_reg: ldo1 {\n\t\t\t\tregulator-min-microvolt = <1306329>;\n\t\t\t\tregulator-max-microvolt = <1306329>;\n\t\t\t\tlltc,fb-voltage-divider = <100000 158000>;\n\t\t\t\tregulator-boot-on;\n\t\t\t\tregulator-always-on;\n\t\t\t};\n\n\t\t\tldo2_reg: ldo2 {\n\t\t\t\tregulator-min-microvolt = <704123>;\n\t\t\t\tregulator-max-microvolt = <1456806>;\n\t\t\t\tlltc,fb-voltage-divider = <180000 191000>;\n\t\t\t\tregulator-ramp-delay = <7000>;\n\t\t\t\tregulator-boot-on;\n\t\t\t\tregulator-always-on;\n\t\t\t};\n\n\t\t\tldo3_reg: ldo3 {\n\t\t\t\tregulator-min-microvolt = <2800000>;\n\t\t\t\tregulator-max-microvolt = <2800000>;\n\t\t\t\tregulator-boot-on;\n\t\t\t};\n\n\t\t\tldo4_reg: ldo4 {\n\t\t\t\tregulator-min-microvolt = <1200000>;\n\t\t\t\tregulator-max-microvolt = <3200000>;\n\t\t\t};\n\t\t};\n\t};\n};\n\n&uart1 {\n\tpinctrl-names = \"default\";\n\tpinctrl-0 = <&pinctrl_uart1>;\n\tstatus = \"okay\";\n};\n\n&usbotg {\n\tdr_mode = \"peripheral\";\n\tstatus = \"okay\";\n};\n\n" }`)

	h, err := artifact.GetHandler(artifact.Dtb)
	if err != nil {
		t.Fatal(err)
	}

	parsedRequirements, err := h.ParseRequirements(r)
	if err != nil {
		t.Fatal(err)
	}

	parsedClaims, err := h.ParseClaims(c)
	if err != nil {
		t.Fatal(err)
	}

	if err = h.Check(parsedRequirements, parsedClaims); err != nil {
		t.Fatal(err)
	}
}

func TestNegativeDtbCheck(t *testing.T) {
	r := []byte(`{"min_version": "v6.14.0-29", "architecture":"x64", "dts_include":["model = \"Inverse Path USB armory\";"]}`)

	c := []byte(`{"file_name": "vmlinuz-6.14.0-29-generic", "hash": "8ba6bc3d9ccfe9c17ad7482d6c0160150c7d1da4b4a4f464744ce069291d6174ea9949574002f022e18585df04f57c192431794f36f40659930bd5c0b470eb59", "version":"v6.14.0-29-generic"}`)

	h, err := artifact.GetHandler(artifact.Dtb)
	if err != nil {
		t.Fatal(err)
	}

	parsedRequirements, err := h.ParseRequirements(r)
	if err != nil {
		t.Fatal(err)
	}

	parsedClaims, err := h.ParseClaims(c)
	if err != nil {
		t.Fatal(err)
	}

	// error expected: the claimed "metadata" is not matching the required one
	if err = h.Check(parsedRequirements, parsedClaims); err == nil {
		t.Fatal(err)
	}
}
