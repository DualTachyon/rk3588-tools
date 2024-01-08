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

#include <stdbool.h>
#include "rk-crc.h"

static uint32_t Crc32Table[256];

void Crc32Init(void)
{
	uint32_t Poly = 0x04C10DB7; // 1 bit difference polynomial than standard!
	uint32_t i, j, c;

	for (i = 0; i < 256; i++) {
		c = i << 24;
		for (j = 0; j < 8; j++) {
			bool bIsSet;

			bIsSet = (c & 0x80000000);
			c <<= 1;
			if (bIsSet) {
				c ^= Poly;
			}
		}
		Crc32Table[i] = c;
	}
}

uint32_t Crc32(uint32_t c, const void *pBuffer, size_t Length)
{
	const uint8_t *pBytes = (const uint8_t *)pBuffer;
	size_t i;

	for (i = 0; i < Length; i++) {
		c = (c << 8) ^ Crc32Table[(c >> 24) ^ pBytes[i]];
	}

	return c;
}

