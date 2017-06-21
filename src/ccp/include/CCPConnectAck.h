#ifndef __CCP_CONNECT_ACK_
#define __CCP_CONNECT_ACK_

#include <stdio.h>

#include "aliyun_iot_common_log.h"

#include "CCPTypeDef.h"

int CCPDeserializeConnectAckMsg(unsigned char *buf, CCP_CONNECT_ACK_S *resp);

#endif /* __CCP_CONNECT_ACK_ */

