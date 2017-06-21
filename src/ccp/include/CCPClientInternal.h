#ifndef __CCP_CLIENT_INTERNAL_
#define __CCP_CLIENT_INTERNAL_

#include "aliyun_iot_common_log.h"

#include "aliyun_iot_platform_timer.h"
#include "aliyun_iot_platform_network.h"
#include "aliyun_iot_platform_pthread.h"

#include "CCPTypeDef.h"

int sendPacket(CLIENT_S *c, int length, int timeout_ms);

int readPacket(CLIENT_S *c, int timeout_ms);

void keepAlive(CLIENT_S *c);

int connectCycle(CLIENT_S *c, int timeout_ms);

int receiveCycle(CLIENT_S *c, int timeout_ms);

void setStatus(CLIENT_S *c, CLIENT_STATUS_E status);

CLIENT_STATUS_E getStatus(CLIENT_S *c);

void checkStatus(CLIENT_S *c);

void dealException(CLIENT_S *c, STATUS_CODE_E statusCode);

void *reconnectThread(void *arg);

void *receiveThread(void *arg);

void notifyUnackTimeout(CLIENT_S *c);

int createReconnectThread(CLIENT_S *c);

int createReceiveThread(CLIENT_S *c);

int createRetransThread(CLIENT_S *c);

void removeRepublishListNode(CLIENT_S *c, unsigned int sequenceId);

void removeUnackListNode(CLIENT_S *c, MESSAGE_TYPE_E msgType, unsigned int sequenceId);

void freeRepublishList(CLIENT_S *c);

void freeUnackList(CLIENT_S *c);

#endif /* __CCP_CLIENT_INTERNAL_ */

