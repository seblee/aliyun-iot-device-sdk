#ifndef __CCP_PUSH_ACK_
#define __CCP_PUSH_ACK_

#include "CCPTypeDef.h"

int CCPSerializePushAckMsg(CLIENT_S *c, const CCP_PUSH_ACK_S *resp);

/**
 * @brief 发送PushAck消息接口
 *
 * @param c client句柄
 * @param resp PushAck响应结构体，详见CCP_PUSH_ACK_S定义
 *
 * @return 如果成功返回0，其它错误返回值详见IOT_RETURN_CODES_E定义
 *
 * @note 请确保入参resp已经初始化
 */
int CCPSendPushAckMsg(CLIENT_S *c, const CCP_PUSH_ACK_S *resp);

#endif /* __CCP_PUSH_ACK_ */

