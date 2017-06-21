#ifndef __CCP_PUBLISH_ACK_
#define __CCP_PUBLISH_ACK_

#include "CCPTypeDef.h"

int CCPSerializePublishAckMsg(CLIENT_S *c, const CCP_PUBLISH_ACK_S *resp);

int CCPDeserializePublishAckMsg(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_PUBLISH_ACK_S *resp);

int CCPSendPublishAckMsg(CLIENT_S *c, const CCP_PUBLISH_ACK_S *resp);

int onCCPPublishAck(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_PUBLISH_ACK_S *resp);

#endif /* __CCP_PUBLISH_ACK_ */

