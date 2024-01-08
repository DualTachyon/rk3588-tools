TARGET_PACK = rk-packsign
OBJS_PACK = rk-crc.o rk-packsign.o

TARGET_OTP = rk-genotp
OBJS_OTP = rk-genotp.o

CC = gcc
LD = gcc

CFLAGS = -O2
LDFLAGS = /opt/mbedtls/lib/libmbedcrypto.a

INC = -I /opt/mbedtls/include

DEPS = $(OBJS:.o=.d)

all: $(TARGET_PACK) $(TARGET_OTP)

$(TARGET_PACK): $(OBJS_PACK)
	$(LD) $^ -o $@ $(LDFLAGS)

$(TARGET_OTP): $(OBJS_OTP)
	$(LD) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(INC) -c $< -o $@

-include $(DEPS)

clean:
	rm -f $(TARGET_OTP) $(OBJS_OTP) $(TARGET_PACK) $(OBJS_PACK) $(DEPS)

