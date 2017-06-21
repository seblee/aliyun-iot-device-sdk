#ifndef __CCP_SUBSCRIBE_
#define __CCP_SUBSCRIBE_

#include "CCPIoTSDK.h"

int CCPSerializeSubscribeMsg(CLIENT_S *c, CCP_SUBSCRIBE_S *req);

int pushSubReqIntoUnackList(CLIENT_S *c, CCP_SUBSCRIBE_S *req, list_node_t **node);

#endif /* __CCP_SUBSCRIBE_ */

