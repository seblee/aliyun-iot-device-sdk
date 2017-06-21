include ./make.settings

#path of include files
INCLUD_PATH = -I./include/
INCLUD_PATH += -I./common/inc/
INCLUD_PATH += -I./platform/$(PLATFORM)/inc/

#path of include files of mbedtls
ifeq ($(MBEDTLS_LIB_ENABLE), y)
INCLUD_PATH += -I./public_libs/mbedtls/include/
INCLUD_PATH += -I./public_libs/mbedtls/include/mbedtls/
INCLUD_PATH += -I./public_libs/mbedtls/configs/aliyun_iot/
INCLUD_PATH += -I./public_libs/mbedtls/configs/aliyun_iot/mbedtls
endif

INCLUD_PATH += -I./src/mqtt/MQTTClient-C/src/
INCLUD_PATH += $(PORTING_INCLUDE)

#path of ccp or mqtt
ifeq ($(CCP_LIB_ENABLE),y)
INCLUD_PATH += -I./include/ccp/
else
INCLUD_PATH += -I./include/mqtt/
endif

#path of src files
SRC_PATH = ./src/
COMMON_SRC_PATH = ./common/src/
PLATFORM_SRC_PATH = ./platform/$(PLATFORM)/src/
SSL_PORTING_SRC_PATH = ./public_libs/porting/$(SSL_LIB_NAME)/

SRC = $(wildcard ${SRC_PATH})
COMMON_SRC = $(wildcard ${COMMON_SRC_PATH})
PLATFORM_SRC = $(wildcard ${PLATFORM_SRC_PATH})
SSL_PORTING_SRC = $(wildcard ${SSL_PORTING_SRC_PATH})

SRC_FILE = $(wildcard ${SRC}*.c)  
SRC_FILE += $(wildcard ${COMMON_SRC}*.c) 
SRC_FILE += $(wildcard ${PLATFORM_SRC}*.c)

#path of src files of tls interface
ifeq ($(MBEDTLS_LIB_ENABLE), y)
SRC_FILE += $(wildcard ${SSL_PORTING_SRC}*.c)
endif

OBJ = $(patsubst %.c,%.o, ${SRC_FILE})
CFILE = $(patsubst %.o,%.c, ${OBJ})

LIB_STATIC = ${IOT_SDK_LIB_NAME}.a

CC = $(PLATFORM_CC)
AR = $(PLATFORM_AR)

CFLAGS = -Wall ${INCLUD_PATH}
ARFLAGS = rcs

#编译子目录路径
BUILD_OUT_PATH = ./Build/
TLS_LIB_PATH = ./public_libs/mbedtls/
MQTT_LIB_PATH = ./src/mqtt/MQTTClient-C/
CCP_LIB_PATH = ./src/ccp/
EMBED_TLS_CREATE_PATH = ./public_libs/mbedtls/library/

CCP_EXAMPLE_PATH = ./examples/$(PLATFORM)/ccp/
MQTT_EXAMPLE_PATH = ./examples/$(PLATFORM)/mqtt/

.PHONY:clean libs demo

all: ${LIB_STATIC} demo 

demo:
ifeq ($(PLATFORM), linux)
ifeq ($(CCP_LIB_ENABLE), y)
	make -C $(CCP_EXAMPLE_PATH)
endif
ifeq ($(MQTT_MBED_LIB_ENABLE), y)
	make -C $(MQTT_EXAMPLE_PATH)
endif
endif

${LIB_STATIC}: libs ${OBJ}
	$(AR) $(ARFLAGS) $@ $(OBJ) ${BUILD_OUT_PATH}*.o 
	-rm -rf ${BUILD_OUT_PATH}*.o
	
libs:
	mkdir -p ${BUILD_OUT_PATH}
ifeq ($(MBEDTLS_LIB_ENABLE), y)
	make -C $(TLS_LIB_PATH) lib -e CC=$(PLATFORM_CC) AR=$(PLATFORM_AR)
	cp -RP $(EMBED_TLS_CREATE_PATH)libmbedtls.*    $(BUILD_OUT_PATH)
	cp -RP $(EMBED_TLS_CREATE_PATH)libmbedx509.*   $(BUILD_OUT_PATH)
	cp -RP $(EMBED_TLS_CREATE_PATH)libmbedcrypto.* $(BUILD_OUT_PATH)
	cd $(BUILD_OUT_PATH) && $(AR) x libmbedtls.a
	cd $(BUILD_OUT_PATH) && $(AR) x libmbedx509.a
	cd $(BUILD_OUT_PATH) && $(AR) x libmbedcrypto.a
endif
	
ifeq ($(MQTT_MBED_LIB_ENABLE), y)
	make -C $(MQTT_LIB_PATH)
	cp -RP $(MQTT_LIB_PATH)$(MQTTMBED_LIB_NAME).* ${BUILD_OUT_PATH}
	cd $(BUILD_OUT_PATH) && $(AR) x $(MQTTMBED_LIB_NAME).a
endif
	
ifeq ($(CCP_LIB_ENABLE), y)
	make -C $(CCP_LIB_PATH)
	cp -RP $(CCP_LIB_PATH)$(CCP_LIB_NAME).* ${BUILD_OUT_PATH}
	cd $(BUILD_OUT_PATH) && $(AR) x $(CCP_LIB_NAME).a
endif

${OBJ}:%.o:%.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	-rm -rf ${BUILD_OUT_PATH}
	-rm ${OBJ} ${LIB_STATIC}
	-make -C $(MQTT_LIB_PATH) clean
	-make -C $(CCP_LIB_PATH) clean
	-make -C $(TLS_LIB_PATH) clean
	-make -C $(CCP_EXAMPLE_PATH) clean
	-make -C $(MQTT_EXAMPLE_PATH) clean
	
