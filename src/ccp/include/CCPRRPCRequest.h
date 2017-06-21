#ifndef __CCP_RRPC_REQUEST_
#define __CCP_RRPC_REQUEST_

#include "CCPTypeDef.h"

int CCPDeserializeRRPCRequestMsg(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_RRPC_REQ_S *req);

int onCCPRRPCRequest(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_RRPC_REQ_S *req);

#endif /* __CCP_RRPC_REQUEST_ */

