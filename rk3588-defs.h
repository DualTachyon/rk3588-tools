/* Copyright 2024 Dual Tachyon
 * https://github.com/DualTachyon
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 */

#ifndef RK3588_DEFINITIONS_H
#define RK3588_DEFINITIONS_H

#define RK3588_LBA_SIZE			512

#define RK3588_IMAGE_LDR		1
#define RK3588_IMAGE_RKSS		2

#define RK3588_MAGIC_BOOT		0x2052444CU
#define RK3588_MAGIC_IMAGE		0x53534B52U

#define RK3588_FLAGS_HASH_MASK		0x0000000FU
#define RK3588_FLAGS_HASH_SHA256	0x00000001U
//#define RK3588_FLAGS_HASH_SM3		0x00000003U

#define RK3588_FLAGS_SIGN_MASK		0x000000F0U
#define RK3588_FLAGS_SIGN_RSA2048	0x00000010U
#define RK3588_FLAGS_SIGN_RSA4096	0x00000020U
//#define RK3588_FLAGS_SIGN_SM2		0x00000030U
//#define RK3588_FLAGS_SIGN_ECC		0x00000040U

#define RK3588_FLAGS_ENCRYPTED		0x00001000U
#define RK3588_FLAGS_SIGNED		0x00002000U

#endif

