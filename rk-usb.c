#include <libusb-1.0/libusb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rk-crc.h"
#include "rk-format.h"

static struct {
	RK_SignedHeader_t Header;
	uint8_t Crc[2];
} Header;

static int SendUsb(struct libusb_device_handle *pHandle, uint16_t Type, void *pBuffer, size_t Length)
{
	uint8_t *pBytes = (uint8_t *)pBuffer;

	while (Length > 0) {
		uint16_t Chunk = Length > 4096U ? 4096U : Length;
		int ret;

		ret = libusb_control_transfer(pHandle, LIBUSB_REQUEST_TYPE_VENDOR, 0x0CU, 0x0000U, Type, pBytes, Chunk, 2000);
		if (ret != Chunk) {
			printf("Failed to transfer data with error %d\n", ret);
			return -1;
		}
		Length -= Chunk;
		pBytes += Chunk;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	libusb_context *pContext = NULL;
	libusb_device_handle *pDeviceHandle = NULL;
	struct libusb_device_descriptor DeviceDescriptor;
	uint8_t *pBuffer = NULL;
	size_t Length;
	uint32_t Crc;
	FILE *fp;
	int ret;

	printf("RK3588 USB Sender. Copyright 2024 Dual Tachyon\n\n");

	if (argc != 2) {
		printf("Usage: %s <file>\n", argv[0]);
		return 1;
	}

	fp = fopen(argv[1], "rb");
	if (!fp) {
		perror("Failed to open file!\n");
		return 1;
	}

	fseek(fp, 0, SEEK_END);
	Length = ftell(fp);
	if (Length <= 0x804U) {
		printf("File is too small!\n");
		ret = 1;
		goto Error;
	}

	ret = libusb_init(&pContext);
	if (ret != LIBUSB_SUCCESS) {
		printf("Failed to initialise USB library with error %d\n", ret);
		ret = 1;
		goto Error;
	}

	pDeviceHandle = libusb_open_device_with_vid_pid(pContext, 0x2207, 0x350B);
	if (!pDeviceHandle) {
		printf("Cannot find RK3588 device!\n");
		ret = 1;
		goto Error;
	}

	ret = libusb_get_device_descriptor(libusb_get_device(pDeviceHandle), &DeviceDescriptor);
	if (ret != LIBUSB_SUCCESS) {
		printf("Failed to retrieve device descriptor with error %d\n", ret);
		ret = 1;
		goto Error;
	}

	ret = libusb_claim_interface(pDeviceHandle, 0);
	if (ret != LIBUSB_SUCCESS) {
		printf("Failed to claim interface with error %d\n", ret);
		ret = 1;
		goto Error;
	}
	ret = 1;

	if (DeviceDescriptor.bcdUSB & 1) {
		printf("RK3588 device is not in MaskROM mod!\n");
		goto Error;
	}

	fseek(fp, 0, SEEK_SET);

	pBuffer = (uint8_t *)calloc(1, Length);
	if (!pBuffer) {
		printf("Failed to allocate memory!\n");
		goto Error;
	}

	if (fread(pBuffer, 1, Length - 4, fp) != Length - 4) {
		printf("Failed to read image!\n");
		goto Error;
	}
	if (fread(&Crc, 1, sizeof(Crc), fp) != sizeof(Crc)) {
		printf("Failed to read checksum!\n");
		goto Error;
	}

	fclose(fp);
	fp = NULL;

	Crc16Init();

	printf("Sending 471...\n");
	memcpy(&Header, pBuffer, sizeof(Header.Header));
	Crc = Crc16(0xFFFFU, &Header.Header, sizeof(Header.Header));
	Header.Crc[0] = (Crc >> 8) & 0xFF;
	Header.Crc[1] = (Crc >> 0) & 0xFF;
	ret = SendUsb(pDeviceHandle, 0x0471U, &Header, sizeof(Header)) ? 1 : 0;
	if (!ret) {
		uint8_t Backup[2];
		uint8_t *pPtr;

		Length = Header.Header.Signed.Table[0].Count * 512;
		pPtr = pBuffer + Header.Header.Signed.Table[0].Lba * 512;
		Crc = Crc16(0xFFFFU, pPtr, Length);
		Backup[0] = pPtr[Length + 0];
		Backup[1] = pPtr[Length + 1];
		pPtr[Length + 0] = (Crc >> 8) & 0xFF;
		pPtr[Length + 1] = (Crc >> 0) & 0xFF;

		ret = SendUsb(pDeviceHandle, 0x0471U, pPtr, Length + 2U) ? 1 : 0;
		if (!ret && Header.Header.Signed.Table[1].Count) {
			printf("Sending 472...\n");
			pPtr[Length + 0] = Backup[0];
			pPtr[Length + 1] = Backup[1];
			Length = Header.Header.Signed.Table[1].Count * 512;
			pPtr = pBuffer + Header.Header.Signed.Table[1].Lba * 512;
			Crc = Crc16(0xFFFFU, pPtr, Length);
			pPtr[Length + 0] = (Crc >> 8) & 0xFF;
			pPtr[Length + 1] = (Crc >> 0) & 0xFF;
			ret = SendUsb(pDeviceHandle, 0x0472U, pPtr, Length + 2);
		}
	}


Error:
	if (pBuffer) {
		free(pBuffer);
	}
	if (pDeviceHandle) {
		libusb_close(pDeviceHandle);
	}
	if (pContext) {
		libusb_exit(pContext);
	}
	if (fp) {
		fclose(fp);
	}

	return ret;
}

