#ifndef __CCP_PUBLISH_
#define __CCP_PUBLISH_

#include "CCPIoTSDK.h"

int CCPSerializePublishMsg(CLIENT_S *c, CCP_PUBLISH_S *req);

int CCPDeserializePublishMsg(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_PUBLISH_S *req);

int CCPResendPublishMsg(CLIENT_S *c, CCP_PUBLISH_S *req);

int onCCPPublish(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_PUBLISH_S *req);

int pushPubReqIntoRepubList(CLIENT_S *c, CCP_PUBLISH_S *req, list_node_t **node);

#endif /* __CCP_PUBLISH_ */

