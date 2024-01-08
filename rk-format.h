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

#ifndef RK_FORMAT_H
#define RK_FORMAT_H

#include <stdint.h>

#pragma pack(push)
#pragma pack(1)

typedef struct {
	uint8_t EntrySize;
	uint32_t Type;
	uint16_t Name[20];
	uint32_t Offset;
	uint32_t Size;
	uint32_t Delay;
} RK_BootEntry_t;

typedef struct {
	uint32_t Magic;
	uint16_t Size;
	uint32_t Version;
	uint32_t MergeVersion;
	uint8_t Timestamp[7];
	uint32_t ChipType;
	struct {
		uint8_t Count;
		uint32_t Offset;
		uint8_t Size;
	} Entry471, Entry472, EntryLoader;
	uint8_t SignFlag;
	uint8_t Rc4Flag;
	uint8_t Reserved[57];
	RK_BootEntry_t Entries[2];
} RK_BootHeader_t;

typedef struct {
	struct {
		uint32_t Magic;
		uint32_t _0x0004;
		uint32_t _0x0008;
		uint32_t Flags;
		uint32_t _0x0010;
		uint16_t RollbackVersion;
		uint16_t RollbackVersionOTP;
		union {
			uint64_t Counter;
			uint8_t Nonce[8];
		};
		// 0x0020
		uint8_t _0x0020[16];
		// 0x0030
		uint32_t MediaFlag; // Used for enabling fast mode
		// 0x0034
		uint8_t _0x0034[36];
		// 0x0058
		uint8_t ImageArguments[32];
		// 0x0078
		struct {
			uint16_t Lba;
			uint16_t Count;
			uint32_t _0x0004; // Shows as 0xFFFFFFFF but not checked
			uint32_t _0x0008;
			uint8_t Nonce[4];
			uint32_t _0x0010;
			uint32_t _0x0014;
			uint8_t Hash[64];
		} Table[4];
		// 0x01C8
		uint8_t _0x01C8[40];
		struct {
			// 0x0200
			uint8_t Modulus[512];
			// 0x0400
			uint8_t Exponent[16];
			uint8_t NP[32];
		} Key;
		uint8_t _0x0450[464];
	} Signed;
	// 0x0600
	uint8_t Signature[512];
} RK_SignedHeader_t;

#pragma pack(pop)

#endif

