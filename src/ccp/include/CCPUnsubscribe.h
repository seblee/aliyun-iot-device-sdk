#ifndef __CCP_UNSUBSCRIBE_
#define __CCP_UNSUBSCRIBE_

#include "CCPIoTSDK.h"

int CCPSerializeUnsubscribeMsg(CLIENT_S *c, CCP_UNSUBSCRIBE_S *req);

int pushUnsubReqIntoUnackList(CLIENT_S *c, CCP_UNSUBSCRIBE_S *req, list_node_t **node);

#endif /* __CCP_UNSUBSCRIBE_ */

