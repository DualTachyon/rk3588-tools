TARGET_PACK = rk-packsign
OBJS_PACK = rk-crc.o rk-packsign.o

TARGET_RESIGN = rk-resign
OBJS_RESIGN = rk-resign.o

TARGET_OTP = rk-genotp
OBJS_OTP = rk-genotp.o

TARGET_USB = rk-usb
OBJS_USB = rk-crc.o rk-usb.o

CC = gcc
LD = gcc

CFLAGS = -O2 -MMD
LDCRYPTO = /opt/mbedtls/lib/libmbedcrypto.a
LDUSB = -lusb-1.0

INC = -I /opt/mbedtls/include

DEPS = $(OBJS_PACK:.o=.d) $(OBJS_OTP:.o=.d) $(OBJS_USB:.o=.d)

all: $(TARGET_PACK) $(TARGET_RESIGN) $(TARGET_OTP) $(TARGET_USB)

$(TARGET_PACK): $(OBJS_PACK)
	$(LD) $^ -o $@ $(LDFLAGS) $(LDCRYPTO)

$(TARGET_RESIGN): $(OBJS_RESIGN)
	$(LD) $^ -o $@ $(LDFLAGS) $(LDCRYPTO)

$(TARGET_OTP): $(OBJS_OTP)
	$(LD) $^ -o $@ $(LDFLAGS) $(LDCRYPTO)

$(TARGET_USB): $(OBJS_USB)
	$(LD) $^ -o $@ $(LDFLAGS) $(LDUSB)

%.o: %.c
	$(CC) $(CFLAGS) $(INC) -c $< -o $@

-include $(DEPS)

clean:
	rm -f $(TARGET_USB) $(OBJS_USB) $(TARGET_OTP) $(OBJS_OTP) $(TARGET_RESIGN) $(OBJS_RESIGN) $(TARGET_PACK) $(OBJS_PACK) $(DEPS)

