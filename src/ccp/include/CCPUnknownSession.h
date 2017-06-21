#ifndef __CCP_UNKNOWN_SESSION_
#define __CCP_UNKNOWN_SESSION_

#include "aliyun_iot_common_log.h"

#include "CCPTypeDef.h"

int CCPDeserializeUnknownSessionMsg(unsigned char *buf, CCP_UNKNOWN_SESSION_S *resp);

int onCCPUnknownSession(unsigned char *buf, CCP_UNKNOWN_SESSION_S *resp);

#endif /* __CCP_UNKNOWN_SESSION_ */

