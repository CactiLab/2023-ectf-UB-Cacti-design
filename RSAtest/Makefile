CC=gcc
CFLAGS=-Wall
TARGET=rsatest
# OBJS=main.o rsa_test.o rsa.object
# mbedtls/md_wrap.c		 
SRCS = main.c	\
	rsa_test.c	\
	mbedtls/aes.c	\
	mbedtls/aesni.c	\
	mbedtls/padlock.c	\
	mbedtls/md.c	\
	mbedtls/md5.c	\
	mbedtls/sha1.c	\
	mbedtls/sha256.c	\
	mbedtls/pk.c	\
	mbedtls/pkparse.c	\
	mbedtls/pk_wrap.c	\
	mbedtls/asn1write.c	\
	mbedtls/base64.c	\
	mbedtls/cipher.c	\
	mbedtls/cipher_wrap.c	\
	mbedtls/des.c	\
	mbedtls/pem.c	\
	mbedtls/pkwrite.c	\
	mbedtls/asn1parse.c	\
	mbedtls/bignum.c	\
	mbedtls/ctr_drbg.c	\
	mbedtls/entropy.c	\
	mbedtls/entropy_poll.c	\
	mbedtls/oid.c	\
	mbedtls/rsa.c	\
	mbedtls/timing.c	\
	mbedtls/platform_util.c	\
	mbedtls/constant_time.c	\
	mbedtls/rsa_alt_helpers.c

INC+=-I./mbedtls

# SRCS := $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

# all: ${BINS}

$(TARGET):$(OBJS)
	@echo "Checking.."
	${CC} ${INC} -o $@ $^

%.o: %.c
	@echo "Creating object.."
	$(CC) $(CFLAGS) $(INC) -o $@ -c $<


# aestest: $(OBJS)

# test: rsatest
# 	./rsatest

clean:
	rm -rf $(TARGET) $(OBJS)

# INC=
# gcc main.c rsa_test.c mbedtls/rsa.c -Irsa -Iaes -Imd5 -Isha