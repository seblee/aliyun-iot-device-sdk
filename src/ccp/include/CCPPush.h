#ifndef __CCP_PUSH_
#define __CCP_PUSH_

#include "CCPTypeDef.h"

int CCPDeserializePushMsg(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_PUSH_S *req);

int onCCPPush(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_PUSH_S *req);

#endif /* __CCP_PUSH_ */

