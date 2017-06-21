#ifndef __CCP_RECONNECT_
#define __CCP_RECONNECT_

#include "CCPTypeDef.h"

int CCPSerializeReconnectMsg(CLIENT_S *c, const CCP_RECONNECT_S *req);

/**
 * @brief 发送Reconnect消息接口
 *
 * @param c client句柄
 * @param req Reconnect请求结构体，详见CCP_RECONNECT_S定义
 *
 * @return 如果成功返回0，其它错误返回值详见IOT_RETURN_CODES_E定义
 *
 * @note 只支持单线程调用，请确保入参req已经初始化，字符串需要以'\0'结尾
 */
int CCPSendReconnectMsg(CLIENT_S *c, const CCP_RECONNECT_S *req);

#endif /* __CCP_RECONNECT_ */

