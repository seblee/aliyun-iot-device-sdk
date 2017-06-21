#ifndef __CCP_PACKET_
#define __CCP_PACKET_

#include "CCPTypeDef.h"

unsigned char readChar(unsigned char **pptr);

unsigned short readShort(unsigned char **pptr);

void writeChar(unsigned char **pptr, unsigned char c);

void writeShort(unsigned char **pptr, unsigned short value);

void encodeString(unsigned char **pptr, const char *str, unsigned short strLen);

void decodeString(unsigned char **pptr, char *str);

int encodeVariableNumber(unsigned char *buf, unsigned int value);

int decodeVariableNumber(unsigned char *buf, unsigned int *value);

int decodeVariableNumberNetwork(CLIENT_S *c, unsigned int *value, int timeout_ms);

int packetLen(unsigned int remainLen);

#endif /* __CCP_PACKET_ */

