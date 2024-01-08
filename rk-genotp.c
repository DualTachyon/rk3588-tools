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

#include <mbedtls/aes.h>
#include <mbedtls/bignum.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "rk-crc.h"
#include "rk-format.h"
#include "rk3588-defs.h"

#define ARGUMENT_TYPE_BOOL		1
#define ARGUMENT_TYPE_XU32		2
#define ARGUMENT_TYPE_STRING		3

typedef struct {
	const char *pArgument;
	uint32_t Type;
	uint32_t Value;
	void *pResult;
} Argument_t;

static const char *pInputFile;

static const Argument_t RK_Arguments[] = {
	{ "-i",		ARGUMENT_TYPE_STRING,	0,			&pInputFile },
	{ NULL },
};

static void Usage(const char *pExecutable)
{
	printf("Usage:\n");
	printf("\t%s -i input\n", pExecutable);
	printf("\n");
}

static int ParseArguments(int argc, char *argv[], const Argument_t *pArguments)
{
	bool *pBool;
	uint32_t *pU32;
	const char **ppString;
	size_t i, j;

	for (i = 0; pArguments[i].pArgument; i++) {

		switch (pArguments[i].Type) {
		case ARGUMENT_TYPE_BOOL:
			pBool = (bool *)pArguments[i].pResult;
			*pBool = false;
			break;

		case ARGUMENT_TYPE_XU32:
			pU32 = (uint32_t *)pArguments[i].pResult;
			*pU32 = 0U;
			break;

		case ARGUMENT_TYPE_STRING:
			ppString = (const char **)pArguments[i].pResult;
			*ppString = NULL;
			break;
		}
	}

	for (i = 1; i < argc; i++) {
		for (j = 0; pArguments[j].pArgument; j++) {
			if (strcmp(argv[i], pArguments[j].pArgument) == 0) {
				break;
			}
		}
		if (!pArguments[j].pArgument) {
			printf("Unexpected argument: %s\n", argv[i]);
			return -1;
		}
		switch (pArguments[j].Type) {
		case ARGUMENT_TYPE_BOOL:
			pBool = (bool *)pArguments[j].pResult;
			*pBool = true;
			break;

		case ARGUMENT_TYPE_XU32:
			pU32 = (uint32_t *)pArguments[j].pResult;
			if (*pU32 && *pU32 != pArguments[j].Value) {
				printf("Conflicting argument %s!\n", argv[i]);
				return -1;
			}
			*pU32 = pArguments[j].Value;
			break;

		case ARGUMENT_TYPE_STRING:
			if (i + 1 == argc) {
				printf("Missing parameter for argument %s!\n", argv[i]);
				return -1;
			}
			ppString = (const char **)pArguments[j].pResult;
			*ppString = argv[i + 1];
			i++;
			break;
		}
	}

	return 0;
}

static void *LoadFile(const char *pFilename, size_t *pAlignedSize)
{
	FILE *fp;
	size_t Size, AlignedSize;
	void *pBuffer;

	fp = fopen(pFilename, "rb");
	if (!fp) {
		perror(pFilename);
		return NULL;
	}

	fseek(fp, 0, SEEK_END);
	Size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if (!Size) {
		printf("File %s is empty!", pFilename);
		fclose(fp);
		return NULL;
	}

	AlignedSize = (Size + RK3588_LBA_SIZE - 1) & ~(RK3588_LBA_SIZE - 1);
	pBuffer = calloc(1, AlignedSize);
	if (!pBuffer) {
		printf("Failed to allocate memory!\n");
		fclose(fp);
		return NULL;
	}
	if (fread(pBuffer, 1, Size, fp) != Size) {
		printf("Failed to read file %s !\n", pFilename);
		free(pBuffer);
		fclose(fp);
		return NULL;
	}

	if (pAlignedSize) {
		*pAlignedSize = AlignedSize;
	}

	fclose(fp);

	return pBuffer;
}

static int CheckArguments(int argc, char *argv[])
{
	if (argc == 1 || ParseArguments(argc, argv, RK_Arguments) < 0) {
		Usage(argv[0]);
		return -1;
	}

	if (!pInputFile) {
		printf("Missing input file!\n\n");
		Usage(argv[0]);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	const RK_BootHeader_t *pBootHeader;
	const RK_SignedHeader_t *pHeader;
	mbedtls_sha256_context Sha;
	mbedtls_rsa_context Rsa;
	mbedtls_mpi Modulus;
	mbedtls_mpi Exponent;
	uint8_t Signature[sizeof(pHeader->Signature)];
	uint8_t Hash[32];
	void *pImage;
	size_t Size, i;
	uint32_t Mask, Check;
	FILE *fp;
	int ret;

	printf("RK3588 Secure Boot OTP generator. Copyright 2024 Dual Tachyon\n\n");

	if (CheckArguments(argc, argv) < 0) {
		return 1;
	}

	pImage = LoadFile(pInputFile, &Size);
	if (!pImage) {
		return 1;
	}

	pBootHeader = (const RK_BootHeader_t *)pImage;
	if (pBootHeader->Magic == RK3588_MAGIC_BOOT) {
		uint32_t Offset = pBootHeader->Entries[0].Offset;

		if (Offset + sizeof(RK_SignedHeader_t) > Size) {
			printf("Invalid image file!\n");
			goto Error;
		}
		pHeader = (const RK_SignedHeader_t *)((uintptr_t)pImage + Offset);
	} else {
		pHeader = (const RK_SignedHeader_t *)pImage;
	}

	if (pHeader->Signed.Magic != RK3588_MAGIC_IMAGE) {
		printf("Unexpected image!\n");
		goto Error;
	}

	if ((pHeader->Signed.Flags & RK3588_FLAGS_SIGNED) == 0) {
		printf("Image is not signed!\n");
		goto Error;
	}

	if ((pHeader->Signed.Flags & RK3588_FLAGS_HASH_MASK) != RK3588_FLAGS_HASH_SHA256) {
		printf("Hash algorithm is not SHA256!\n");
		goto Error;
	}

	Mask = pHeader->Signed.Flags & RK3588_FLAGS_SIGN_MASK;
	if (Mask != RK3588_FLAGS_SIGN_RSA2048 && Mask != RK3588_FLAGS_SIGN_RSA4096) {
		printf("Sign algorithm is not supported!\n");
		goto Error;
	}

	mbedtls_sha256_init(&Sha);
	mbedtls_sha256_starts(&Sha, 0);
	mbedtls_sha256_update(&Sha, (uint8_t *)&pHeader->Signed, sizeof(pHeader->Signed));
	mbedtls_sha256_finish(&Sha, Hash);

	mbedtls_rsa_init(&Rsa);
	mbedtls_mpi_init(&Modulus);
	mbedtls_mpi_init(&Exponent);

	mbedtls_mpi_read_binary_le(&Modulus, pHeader->Signed.Key.Modulus, sizeof(pHeader->Signed.Key.Modulus));
	mbedtls_mpi_read_binary_le(&Exponent, pHeader->Signed.Key.Exponent, sizeof(pHeader->Signed.Key.Exponent));

	ret = mbedtls_rsa_import(&Rsa, &Modulus, NULL, NULL, NULL, &Exponent);
	if (ret) {
		printf("Failed to regenerate the RSA public key! Error: -%X\n", ret);
		goto Error;
	}

	ret = mbedtls_rsa_check_pubkey(&Rsa);
	if (ret) {
		printf("Failed to validate the RSA public key! Error: -%X\n", ret);
		goto Error;
	}

	Size = mbedtls_rsa_get_len(&Rsa);
	for (i = 0; i < Size; i++) {
		Signature[i] = pHeader->Signature[Size - 1 - i];
	}

	ret = mbedtls_rsa_rsassa_pss_verify(&Rsa, MBEDTLS_MD_SHA256, 32, Hash, Signature);
	if (ret) {
		printf("Failed to verify the embedded signature! Error: -%X\n", ret);
		goto Error;
	}

	mbedtls_sha256_init(&Sha);
	mbedtls_sha256_starts(&Sha, 0);
	mbedtls_sha256_update(&Sha, (uint8_t *)&pHeader->Signed.Key, sizeof(pHeader->Signed.Key));
	mbedtls_sha256_finish(&Sha, Hash);

	printf("Paste the following line inside BootKeyHash[]:\n\t");
	Check = 0U;
	for (i = 0; i < sizeof(Hash); i += 4) {
		const uint32_t Word = (Hash[i + 3] << 24) | (Hash[i + 2] << 16) | (Hash[i + 1] << 8) | Hash[i + 0];

		Check ^= Word;
		printf("0x%08X, ", Word);
	}
	printf("\n\n");
	printf("Paste the following inside BootHashCheck: 0x%08X\n", Check);
	printf("\n");

	free(pImage);

	return 0;

Error:
	free(pImage);

	return 1;
}

