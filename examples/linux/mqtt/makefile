include ../../../make.settings
CC=$(PLATFORM_CC)
CFLAGS =-std=gnu99 -Wall -g
        
INCDIR = -I../../../src/mqtt/MQTTClient-C/src/
INCDIR += -I../../../src/mqtt/MQTTPacket/src/

ifeq ($(MBEDTLS_LIB_ENABLE), y)
INCDIR += -I../../../src/mqtt/MQTTClient-C/nettype/tls/
INCDIR += -I../../../public_libs/mbedtls/include/mbedtls/
INCDIR += -I../../../public_libs/mbedtls/include/
INCDIR += -I../../../public_libs/mbedtls/configs/aliyun_iot/
INCDIR += -I../../../public_libs/mbedtls/configs/aliyun_iot/mbedtls
INCDIR += -I../../../public_libs/porting/$(SSL_LIB_NAME)/
else
INCDIR += -I../../../src/mqtt/MQTTClient-C/nettype/tcp/
endif

INCDIR += -I../../../platform/linux/inc/
INCDIR += -I../../../include/mqtt/
INCDIR += -I../../../common/inc/

TARGET = demo

all:
	$(CC) $(CFLAGS) $(INCDIR) -o $(TARGET) demo.c ../../../libiotsdk.a -lm -lpthread
	
clean:
	 rm $(TARGET)
