#ifndef __CCP_RPC_RESPONSE_
#define __CCP_RPC_RESPONSE_

#include "CCPTypeDef.h"

int CCPDeserializeRPCResponseMsg(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_RPC_RESP_S *resp);

int onCCPRPCResponse(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_RPC_RESP_S *resp);

#endif /* __CCP_RPC_RESPONSE_ */

