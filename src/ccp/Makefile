include ../../make.settings

CC = $(PLATFORM_CC)
AR = $(PLATFORM_AR)

#sdk directory
SDK_DIR = ../..

LIB_DIR = .
LIB_NAME = libccp.a
LIB_TARGET = ${LIB_DIR}/${LIB_NAME}

#common directory
COMMON_DIR = $(SDK_DIR)/common

#platform directory
PLATFORM_DIR = $(SDK_DIR)/platform/$(PLATFORM)

#mbedtls directory
MBEDTLS_DIR = $(SDK_DIR)/public_libs/mbedtls
MBEDTLS_INCLUDE_DIR = -I $(MBEDTLS_DIR)/include/mbedtls
MBEDTLS_INCLUDE_DIR += -I $(MBEDTLS_DIR)/include
MBEDTLS_INCLUDE_DIR += -I $(MBEDTLS_DIR)/configs/aliyun_iot/
MBEDTLS_INCLUDE_DIR += -I $(MBEDTLS_DIR)/configs/aliyun_iot/mbedtls

#include directory
INCLUDE_DIRS = -I $(COMMON_DIR)/inc
INCLUDE_DIRS += -I $(PLATFORM_DIR)/inc
INCLUDE_DIRS += -I $(SDK_DIR)/include/ccp
INCLUDE_DIRS += -I $(SDK_DIR)/src/ccp/include

#aggregate all include and src directories
INCLUDE_ALL_DIRS = $(INCLUDE_DIRS)
INCLUDE_ALL_DIRS += $(MBEDTLS_INCLUDE_DIR)

SRC_FILES = $(wildcard $(COMMON_DIR)/src/*.c)
SRC_FILES += $(wildcard $(PLATFORM_DIR)/src/*.c)
SRC_FILES += $(wildcard $(SDK_DIR)/src/ccp/*.c)

OBJ = $(patsubst %.c,%.o, ${SRC_FILES})

CFLAGS = -Wall $(INCLUDE_ALL_DIRS)
ARFLAGS = rcs

${LIB_TARGET}:${OBJ}
	$(AR) $(ARFLAGS) $@ $(OBJ)

${OBJ}:%.o:%.c
	$(CC) $(CFLAGS) -c $^ -o $@

.PHONY:clean
clean:
	rm -f ${OBJ} ${LIB_TARGET}

