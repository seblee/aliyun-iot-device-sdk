include ../../../make.settings

CC = $(PLATFORM_CC)
CFLAGS = -std=c99 -Wall

AR = $(PLATFORM_AR)
ARFLAGS = rcs

LIB = ../../lib/

SRC_PACKET_PATH  = ../MQTTPacket/src/
SRC_CLIENT1_PATH = ./src/

ifeq ($(MBEDTLS_LIB_ENABLE), y)
SRC_NETTYPE_PATH = ./nettype/tls/
else
SRC_NETTYPE_PATH = ./nettype/tcp/
endif

SRC_PACKET  = ${wildcard ${SRC_PACKET_PATH}}
SRC_CLIENT1 = ${wildcard ${SRC_CLIENT1_PATH}}
SRC_NETTYPE = ${wildcard ${SRC_NETTYPE_PATH}}

SRC_FILE = ${wildcard ${SRC_PACKET}*.c}
SRC_FILE += ${wildcard ${SRC_CLIENT1}*.c}
SRC_FILE += ${wildcard ${SRC_NETTYPE}*.c}

INCLUD_PATH = -I$(SRC_PACKET_PATH)
INCLUD_PATH += -I$(SRC_CLIENT1_PATH)
INCLUD_PATH += -I${SRC_NETTYPE_PATH}
INCLUD_PATH += $(PORTING_INCLUDE)
INCLUD_PATH += -I../../../include/
INCLUD_PATH += -I../../../include/mqtt/
INCLUD_PATH += -I../../../common/inc/

ifeq ($(MBEDTLS_LIB_ENABLE), y)
INCLUD_PATH += -I../../../public_libs/mbedtls/
INCLUD_PATH += -I../../../public_libs/mbedtls/include/mbedtls/
INCLUD_PATH += -I../../../public_libs/mbedtls/include/
INCLUD_PATH += -I../../../public_libs/mbedtls/configs/aliyun_iot/
INCLUD_PATH += -I../../../public_libs/mbedtls/configs/aliyun_iot/mbedtls
INCLUD_PATH += -I../../../public_libs/porting/$(SSL_LIB_NAME)/
endif

INCLUD_PATH += -I../../../platform/$(PLATFORM)/inc/

OBJ = $(patsubst %.c,%.o, ${SRC_FILE})

TARGET_STATIC = $(MQTTMBED_LIB_NAME).a

CFLAGS += ${INCLUD_PATH}

all:$(TARGET_STATIC)

$(TARGET_STATIC):${OBJ}
	$(AR) $(ARFLAGS) $@ $^
   
${OBJ}:%.o:%.c
	$(CC) $(CFLAGS) -c $^ -o $@
	
clean:
	-rm ${OBJ} $(TARGET_STATIC)
	 
	 
