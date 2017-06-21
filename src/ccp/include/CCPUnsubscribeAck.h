#ifndef __CCP_UNSUBSCRIBE_ACK_
#define __CCP_UNSUBSCRIBE_ACK_

#include "CCPTypeDef.h"

int CCPDeserializeUnsubscribeAckMsg(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_UNSUBSCRIBE_ACK_S *resp);

int onCCPUnsubscribeAck(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_UNSUBSCRIBE_ACK_S *resp);

#endif /* __CCP_UNSUBSCRIBE_ACK_ */

