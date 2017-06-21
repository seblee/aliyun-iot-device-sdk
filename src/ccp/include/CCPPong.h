#ifndef __CCP_PONG_
#define __CCP_PONG_

#include "CCPTypeDef.h"

int CCPSerializePongMsg(unsigned char *buf, int bufLen);

int CCPSendPongMsg(CLIENT_S *c);

#endif /* __CCP_PONG_ */

