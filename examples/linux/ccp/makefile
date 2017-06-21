include ../../../make.settings

CC = $(PLATFORM_CC)

SDK_DIR = ../../..

INCLUDE_DIRS = -I $(SDK_DIR)/include/ccp
INCLUDE_DIRS += -I $(SDK_DIR)/common/inc/
INCLUDE_DIRS += -I $(SDK_DIR)/platform/linux/inc/

CFLAGS = -g -Wall $(INCLUDE_DIRS)

LIB_DIRS = -L $(SDK_DIR)

LDFLAGS = $(LIB_DIRS) -liotsdk -lm -lpthread

TARGET = demo

all:
	$(CC) $(CFLAGS) -o $(TARGET) demo.c $(LDFLAGS)

clean:
	rm -f $(TARGET)

