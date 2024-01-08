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
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "rk-crc.h"
#include "rk-format.h"
#include "rk3588-defs.h"

#define PERSONALISATION			"RK3588"

#define ARGUMENT_TYPE_BOOL		1
#define ARGUMENT_TYPE_XU32		2
#define ARGUMENT_TYPE_STRING		3

typedef struct {
	const char *pArgument;
	uint32_t Type;
	uint32_t Value;
	void *pResult;
} Argument_t;

static const char *pKeyFile;
static const char *pInputFile;
static const char *pOutputFile;
static const char *pLoaderFile;
static uint32_t ImageType;

static const Argument_t RK_Arguments[] = {
	{ "-i",		ARGUMENT_TYPE_STRING,	0,			&pInputFile },
	{ "-s",		ARGUMENT_TYPE_STRING,	0,			&pLoaderFile },
	{ "-o",		ARGUMENT_TYPE_STRING,	0,			&pOutputFile },
	{ "--usb",	ARGUMENT_TYPE_XU32,	RK3588_IMAGE_USB,	&ImageType },
	{ "--flash",	ARGUMENT_TYPE_XU32,	RK3588_IMAGE_FLASH,	&ImageType },
	{ "--key",	ARGUMENT_TYPE_STRING,	0,			&pKeyFile },
	{ NULL },
};

static int MyRandom(void *pPrivate, uint8_t *pOutput, size_t Length)
{
	if (pOutput) {
		memset(pOutput, 0x55, Length);
	}

	return 0;
}

static void Usage(const char *pExecutable)
{
	printf("Usage:\n");
	printf("\t%s --flash -i input -o output\n", pExecutable);
	printf("\t%s --usb -i input [-s loader] -o output\n", pExecutable);
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

	if (!Size || Size > 33553920) {
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
	if (!pOutputFile) {
		printf("Missing output file!\n\n");
		Usage(argv[0]);
		return -1;
	}
	if (!ImageType) {
		printf("Missing image type!\n\n");
		Usage(argv[0]);
		return -1;
	}

	if (pLoaderFile && ImageType == RK3588_IMAGE_USB) {
		printf("Loader file not supported in USB image!\n");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	RK_BootHeader_t BootHeader;
	RK_SignedHeader_t Header;
	mbedtls_sha256_context Sha;
	mbedtls_pk_context Pk;
	void *pImage;
	void *pLoader = NULL;
	size_t AlignedSize;
	size_t LoaderAlignedSize;
	uint32_t CRC;
	FILE *fp;
	int ret;

	printf("RK3588 Loader Packer and Signer. Copyright 2024 Dual Tachyon\n\n");

	if (CheckArguments(argc, argv) < 0) {
		return 1;
	}

	pImage = LoadFile(pInputFile, &AlignedSize);
	if (!pImage) {
		return 1;
	}

	memset(&Header, 0, sizeof(Header));
	Header.Signed.Magic = RK3588_MAGIC_IMAGE;
	Header.Signed.Flags = RK3588_FLAGS_HASH_SHA256;
	if (pKeyFile) {
		Header.Signed.Flags |= RK3588_FLAGS_SIGNED;
	}
	Header.Signed.Table[0].Lba = 4;
	Header.Signed.Table[0].Count = (uint16_t)(AlignedSize / RK3588_LBA_SIZE);

	mbedtls_sha256_init(&Sha);
	mbedtls_sha256_starts(&Sha, 0);
	mbedtls_sha256_update(&Sha, (uint8_t *)pImage, AlignedSize);
	mbedtls_sha256_finish(&Sha, Header.Signed.Table[0].Hash);

	if (pLoaderFile) {
		pLoader = LoadFile(pLoaderFile, &LoaderAlignedSize);
		if (!pLoader) {
			free(pImage);
			return 1;
		}

		Header.Signed.Table[1].Lba = Header.Signed.Table[0].Lba + Header.Signed.Table[0].Count;
		Header.Signed.Table[1].Count = (uint16_t)(LoaderAlignedSize / RK3588_LBA_SIZE);

		mbedtls_sha256_init(&Sha);
		mbedtls_sha256_starts(&Sha, 0);
		mbedtls_sha256_update(&Sha, (uint8_t *)pLoader, LoaderAlignedSize);
		mbedtls_sha256_finish(&Sha, Header.Signed.Table[1].Hash);
	}

	if (Header.Signed.Flags & RK3588_FLAGS_SIGNED) {
		mbedtls_rsa_context *pRsa;
		mbedtls_mpi Np;
		size_t KeyLength;

		mbedtls_pk_init(&Pk);
		ret = mbedtls_pk_parse_keyfile(&Pk, pKeyFile, NULL, NULL, NULL);
		if (ret) {
			printf("Failed to load key file!\n");
			goto Error;
		}

		if (!mbedtls_pk_can_do(&Pk, MBEDTLS_PK_RSASSA_PSS)) {
			printf("Key is not RSA!");
			goto Error;
		}

		KeyLength = mbedtls_pk_get_bitlen(&Pk);
		if (KeyLength == 2048) {
			Header.Signed.Flags |= RK3588_FLAGS_SIGN_RSA2048;
		} else if (KeyLength == 4096) {
			Header.Signed.Flags |= RK3588_FLAGS_SIGN_RSA4096;
		} else {
			printf("RSA %zu is unsupported!\n", KeyLength);
			goto Error;
		}

		pRsa = mbedtls_pk_rsa(Pk);

		mbedtls_rsa_set_padding(pRsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
		mbedtls_mpi_write_binary_le(&pRsa->private_N, Header.Signed.Key.Modulus, sizeof(Header.Signed.Key.Modulus));
		mbedtls_mpi_init(&Np);
		mbedtls_mpi_lset(&Np, 2);
		if (KeyLength == 2048) {
			mbedtls_mpi_shift_l(&Np, 2180 - 1);
		} else {
			mbedtls_mpi_shift_l(&Np, 4228 - 1);
		}
		mbedtls_mpi_div_mpi(&Np, NULL, &Np, &pRsa->private_N);
		mbedtls_mpi_write_binary_le(&Np, Header.Signed.Key.NP, sizeof(Header.Signed.Key.NP));
		mbedtls_mpi_write_binary_le(&pRsa->private_E, Header.Signed.Key.Exponent, sizeof(Header.Signed.Key.Exponent));
	}

	mbedtls_sha256_init(&Sha);
	mbedtls_sha256_starts(&Sha, 0);
	mbedtls_sha256_update(&Sha, (uint8_t *)&Header.Signed, sizeof(Header.Signed));
	mbedtls_sha256_finish(&Sha, Header.Signature);

	if (Header.Signed.Flags & RK3588_FLAGS_SIGNED) {
		uint8_t Signature[sizeof(Header.Signature)];
		size_t Length = 0;
		size_t i, KeyLength;

		ret = mbedtls_pk_sign(&Pk, MBEDTLS_MD_SHA256, Header.Signature, 0, Signature, sizeof(Signature), &Length, MyRandom, NULL);
		if (ret) {
			printf("Failed to sign with error: -0x%04X", -ret);
		}

		KeyLength = mbedtls_pk_get_bitlen(&Pk) / 8;
		for (i = 0; i < KeyLength; i++) {
			Header.Signature[i] = Signature[KeyLength - 1 - i];
		}
	}

	Crc32Init();

	CRC = 0;
	if (ImageType == RK3588_IMAGE_USB) {
		memset(&BootHeader, 0, sizeof(BootHeader));
		BootHeader.Magic = RK3588_MAGIC_BOOT;
		BootHeader.ChipType = 0x33353838;
		BootHeader.Entry471.Count = 2;
		BootHeader.Entry471.Offset = sizeof(BootHeader) - sizeof(BootHeader.Entries);
		BootHeader.Entry471.Size = sizeof(BootHeader.Entries[0]);
		BootHeader.Entries[0].EntrySize = sizeof(BootHeader.Entries[0]);
		BootHeader.Entries[0].Type = 1;
		BootHeader.Entries[0].Offset = sizeof(BootHeader);
		BootHeader.Entries[0].Size = (uint32_t)sizeof(Header);
		BootHeader.Entries[1].EntrySize = sizeof(BootHeader.Entries[1]);
		BootHeader.Entries[1].Type = 1;
		BootHeader.Entries[1].Offset = sizeof(BootHeader) + sizeof(Header);
		BootHeader.Entries[1].Size = (uint32_t)AlignedSize;
		CRC = Crc32(CRC, &BootHeader, sizeof(BootHeader));
	}
	CRC = Crc32(CRC, &Header, sizeof(Header));
	CRC = Crc32(CRC, pImage, AlignedSize);
	if (pLoader) {
		CRC = Crc32(CRC, pLoader, LoaderAlignedSize);
	}

	fp = fopen(pOutputFile, "wb");
	if (!fp) {
		perror(pOutputFile);
		return 1;
	}

	if (ImageType == RK3588_IMAGE_USB) {
		fwrite(&BootHeader, 1, sizeof(BootHeader), fp);
	}
	fwrite(&Header, 1, sizeof(Header), fp);
	fwrite(pImage, 1, AlignedSize, fp);
	if (pLoader) {
		fwrite(pLoader, 1, LoaderAlignedSize, fp);
	}
	fwrite(&CRC, 1, sizeof(CRC), fp);
	fclose(fp);

	if (pLoader) {
		free(pLoader);
	}

	free(pImage);

	return 0;

Error:
	if (pLoader) {
		free(pLoader);
	}
	free(pImage);

	return 1;
}

