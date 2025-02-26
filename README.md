# Support

* If you like my work, you can support me through https://ko-fi.com/DualTachyon

# Random tools to generate OTP secure boot data and to quickly pack and sign initial bootloaders

I'm not a fan of going through a settings.ini file to configure the RockChip signing tool, so I wrote my own to make my development workflow more efficient.
I also do not wish to embed 2 loaders every time, like some of their tools require.

Also included is a Secure Boot OTP data generator, which RockChip doesn't make easy to figure out. See [here](https://github.com/DualTachyon/rk3588-secure-boot) for more details on this topic.

# Requirements

- This repository builds correctly in Ubuntu 24.04. Other distributions may require slight tweaks to the Makefile.

# Building

```
$ make
```

# Sample usage

- Pack an image for flash on non-secure RK3588/RK3588S and then flash it. Not valid for USB/MaskROM boot.

```
# This loader.bin is always based at 0xFF001000.
$ ./rk-packsign --rkss --471 loader.bin -o loader.flash.bin

# If you don't have a miniloader image, make one from https://github.com/rockchip-linux/rkbin
$ ./tools/boot_merger RKBOOT/RK3588MINIALL_RAMBOOT.ini

# Launch the RockChip miniloader from MaskROM BOOT MODE.
$ rkdeveloptool db path_to/miniloader.bin # loader can be created in the previous step

# 64 below is valid for EMMC, untested on MicroSD and FSPI but should also work.
$ rkdeveloptool wl 64 loader.flash.bin

# If you also want DDR training to happen, base your loader.bin to 0x00000000.
# The -s parameter is currently not yet implemented for USB images.
$ ./rk-packsign --rkss --472 loader.bin -o loader.flash.bin --471 path_to/rkbin/bin/rk35/rk3588_ddr_lp4_2112MHz_lp5_2736MHz_v1.12.bin
$ rkdeveloptool db loader.flash.bin
```

- Pack an image for USB boot on non-secure RK3588/RK3588S and then upload it.

```
# This loader.bin is always based at 0xFF001000.
$ ./rk-packsign --usb --471 loader.bin -o loader.usb.bin
$ rkdeveloptool db loader.usb.bin
```

- To add signing to any of the above steps, add --key to the command line. For example:

```
$ ./rk-packsign --key private_key.pem --rkldr --471 loader.bin -o loader.usb.bin
```

# Generating the OTP data for Secure Boot enablement

Full instructions to enable Secure Boot on RK3588/RK3588S are available [here](https://github.com/DualTachyon/rk3588-secure-boot).

To generate OTP data:

```
$ ./rk-genotp -i loader.usb.bin
```

and follow instructions.

# License

Copyright 2024 Dual Tachyon
https://github.com/DualTachyon

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

