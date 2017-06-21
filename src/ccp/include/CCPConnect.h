#ifndef __CCP_CONNECT_
#define __CCP_CONNECT_

#include <string.h>

#include "aliyun_iot_common_log.h"

#include "CCPIoTSDK.h"

int CCPSerializeConnectMsg(CLIENT_S *c, const CCP_CONNECT_S *req);

#endif /* __CCP_CONNECT_ */

