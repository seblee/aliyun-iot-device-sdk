#ifndef __CCP_IOT_SDK_H_
#define __CCP_IOT_SDK_H_

#if defined(__cplusplus) /* If this is a C++ compiler, use C linkage */
extern "C"
{
#endif

#include "CCPTypeDef.h"

/**
 * @brief client句柄初始化接口
 *
 * @param c client句柄
 * @param authConfig 鉴权配置信息
 * @param commandTimeout 命令超时时间，单位为毫秒
 * @param writeBuf 写缓存地址
 * @param writeBufSize 写缓存大小，单位为字节
 * @param readBuf 读缓存地址
 * @param readBufSize 读缓存大小，单位为字节
 * @param onMessage 消息回调函数指针
 * @param onConnect 连接成功回调函数指针，可以为NULL
 * @param onDisconnect 连接断开回调函数指针，可以为NULL
 * @param onTimeout 消息响应超时回调函数指针，可以为NULL
 *
 * @return 如果成功返回0，其它错误返回值详见IOT_RETURN_CODES_E定义
 *
 * @note 请确保所有入参已经初始化，字符串需要以'\0'结尾
 */
int CCPInit(CLIENT_S *c, AUTH_CONFIG_S *authConfig, unsigned int commandTimeout, unsigned char *writeBuf,
            unsigned int writeBufSize, unsigned char *readBuf, unsigned int readBufSize, messageHandler onMessage,
            connectHandler onConnect, disconnectHandler onDisconnect, timeoutHandler onTimeout);

/**
 * @brief client句柄释放接口
 *
 * @param c client句柄
 *
 * @return 如果成功返回0，其它错误返回值详见IOT_RETURN_CODES_E定义
 *
 * @note 销毁内部线程、互斥锁和链表、关闭套接字FD、client状态初始化
 */
int CCPRelease(CLIENT_S *c);

/**
 * @brief 鉴权接口
 *
 * @param c client句柄
 *
 * @return 如果成功返回0，其它错误返回值详见IOT_RETURN_CODES_E定义
 *
 * @note 无
 */
int CCPAuth(CLIENT_S *c);

/**
 * @brief 发送Connect消息接口
 *
 * @param c client句柄
 * @param req Connect请求结构体，详见CCP_CONNECT_S定义
 *
 * @return 如果成功返回0，其它错误返回值详见IOT_RETURN_CODES_E定义
 *
 * @note 只支持单线程调用，请确保入参req已经初始化，断线时不需要调用，SDK内部有自动重连机制
 */
int CCPSendConnectMsg(CLIENT_S *c, const CCP_CONNECT_S *req);

/**
 * @brief 发送Disconnect消息接口
 *
 * @param c client句柄
 *
 * @return 如果成功返回0，其它错误返回值详见IOT_RETURN_CODES_E定义
 *
 * @note 无
 */
int CCPSendDisconnectMsg(CLIENT_S *c);

/**
 * @brief 发送RPCRequest消息接口
 *
 * @param c client句柄
 * @param req RPC请求结构体，详见CCP_RPC_REQ_S定义
 *
 * @return 如果成功返回0，其它错误返回值详见IOT_RETURN_CODES_E定义
 *
 * @note 请确保入参req已经初始化，字符串需要以'\0'结尾
 */
int CCPSendRPCRequestMsg(CLIENT_S *c, CCP_RPC_REQ_S *req);

/**
 * @brief 发送RRPCResponse消息接口
 *
 * @param c client句柄
 * @param resp RRPC响应结构体，详见CCP_RRPC_RESP_S定义
 *
 * @return 如果成功返回0，其它错误返回值详见IOT_RETURN_CODES_E定义
 *
 * @note 请确保入参resp已经初始化
 */
int CCPSendRRPCResponseMsg(CLIENT_S *c, const CCP_RRPC_RESP_S *resp);

/**
 * @brief 发送Subscribe消息接口
 *
 * @param c client句柄
 * @param req Subscribe请求结构体，详见CCP_SUBSCRIBE_S定义
 *
 * @return 如果成功返回0，其它错误返回值详见IOT_RETURN_CODES_E定义
 *
 * @note 请确保入参req已经初始化，字符串需要以'\0'结尾
 */
int CCPSendSubscribeMsg(CLIENT_S *c, CCP_SUBSCRIBE_S *req);

/**
 * @brief 发送Publish消息接口
 *
 * @param c client句柄
 * @param req Publish请求结构体，详见CCP_PUBLISH_S定义
 *
 * @return 如果成功返回0，其它错误返回值详见IOT_RETURN_CODES_E定义
 *
 * @note 请确保入参req已经初始化，字符串需要以'\0'结尾
 */
int CCPSendPublishMsg(CLIENT_S *c, CCP_PUBLISH_S *req);

/**
 * @brief 发送Unsubscribe消息接口
 *
 * @param c client句柄
 * @param req Unsubscribe请求结构体，详见CCP_UNSUBSCRIBE_S定义
 *
 * @return 如果成功返回0，其它错误返回值详见IOT_RETURN_CODES_E定义
 *
 * @note 请确保入参req已经初始化，字符串需要以'\0'结尾
 */
int CCPSendUnsubscribeMsg(CLIENT_S *c, CCP_UNSUBSCRIBE_S *req);

#if defined(__cplusplus) /* If this is a C++ compiler, use C linkage */
}
#endif

#endif /* __CCP_IOT_SDK_H_ */

