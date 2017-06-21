#ifndef __CCP_NETWORK_
#define __CCP_NETWORK_

#include <string.h>

#include "aliyun_iot_common_log.h"

#include "aliyun_iot_platform_timer.h"
#include "aliyun_iot_platform_network.h"

#include "CCPTypeDef.h"

int ccpread(NETWORK_S *n, unsigned char *buffer, int len, int timeout_ms);

int ccpwrite(NETWORK_S *n, unsigned char *buffer, int len, int timeout_ms);

void disconnect(NETWORK_S *n);

void initNetwork(NETWORK_S *n);

int connectNetwork(NETWORK_S *n, char *addr, int port);

#endif /* __CCP_NETWORK_ */

