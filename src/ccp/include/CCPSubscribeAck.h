#ifndef __CCP_SUBSCRIBE_ACK_
#define __CCP_SUBSCRIBE_ACK_

#include "CCPTypeDef.h"

int CCPDeserializeSubscribeAckMsg(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_SUBSCRIBE_ACK_S *resp);

int onCCPSubscribeAck(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_SUBSCRIBE_ACK_S *resp);

#endif /* __CCP_SUBSCRIBE_ACK_ */

