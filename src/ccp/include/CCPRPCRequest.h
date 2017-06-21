#ifndef __CCP_RPC_REQUEST_
#define __CCP_RPC_REQUEST_

#include "CCPIoTSDK.h"

int CCPSerializeRPCRequestMsg(CLIENT_S *c, CCP_RPC_REQ_S *req);

int pushRPCReqIntoUnackList(CLIENT_S *c, CCP_RPC_REQ_S *req, list_node_t **node);

#endif /* __CCP_RPC_REQUEST_ */

