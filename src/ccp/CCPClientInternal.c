#include "CCPTypeDefInternal.h"
#include "CCPPacket.h"
#include "CCPAuth.h"
#include "CCPPong.h"
#include "CCPPush.h"
#include "CCPReconnect.h"
#include "CCPReconnectAck.h"
#include "CCPRPCResponse.h"
#include "CCPRRPCRequest.h"
#include "CCPPublish.h"
#include "CCPPublishAck.h"
#include "CCPSubscribeAck.h"
#include "CCPUnsubscribeAck.h"
#include "CCPUnknownSession.h"
#include "CCPClientInternal.h"

int sendPacket(CLIENT_S *c, int length, int timeout_ms)
{
    int rc;

    rc = c->network.ccpwrite(&c->network, c->writeBuf, length, timeout_ms);
    if (rc == length)
    {
        rc = SUCCESS_RETURN;
    }
    else
    {
        aliyun_iot_mutex_lock(&c->clientStatusMutex);

        CLIENT_STATUS_E status = getStatus(c);
        if (CLIENT_STATUS_NETWORK_ERROR != status)
        {
            WRITE_IOT_WARNING_LOG("client status changes to CLIENT_STATUS_NETWORK_ERROR!");
            setStatus(c, CLIENT_STATUS_NETWORK_ERROR);

            aliyun_iot_mutex_lock(&c->reconnectIntervalMutex);
            c->reconnectInterval = RECONNECT_MIN_INTERVAL;
            aliyun_iot_mutex_unlock(&c->reconnectIntervalMutex);

            if (NULL != c->onDisconnect)
            {
                WRITE_IOT_WARNING_LOG("network error notify disconnect!");
                c->onDisconnect(CLIENT_STATUS_NETWORK_ERROR);
            }
        }
        aliyun_iot_mutex_unlock(&c->clientStatusMutex);

        rc = FAIL_RETURN;
    }

    return rc;
}

int readPacket(CLIENT_S *c, int timeout_ms)
{
    int rc;
    CCP_HEADER_S header = {0};
    MESSAGE_TYPE_E msgType;
    int len = 0;
    unsigned int remainLen = 0;

    /* 1. read the header byte.  This has the packet type in it */
    if ((len = c->network.ccpread(&c->network, c->readBuf, 1, timeout_ms)) != 1)
    {
        if (!len)
        {
            return SUCCESS_RETURN;
        }

        aliyun_iot_mutex_lock(&c->clientStatusMutex);

        CLIENT_STATUS_E status = getStatus(c);
        if (CLIENT_STATUS_NETWORK_ERROR != status)
        {
            WRITE_IOT_WARNING_LOG("client status changes to CLIENT_STATUS_NETWORK_ERROR!");
            setStatus(c, CLIENT_STATUS_NETWORK_ERROR);

            aliyun_iot_mutex_lock(&c->reconnectIntervalMutex);
            c->reconnectInterval = RECONNECT_MIN_INTERVAL;
            aliyun_iot_mutex_unlock(&c->reconnectIntervalMutex);

            if (NULL != c->onDisconnect)
            {
                WRITE_IOT_WARNING_LOG("network error notify disconnect!");
                c->onDisconnect(CLIENT_STATUS_NETWORK_ERROR);
            }
        }
        aliyun_iot_mutex_unlock(&c->clientStatusMutex);

        return FAIL_RETURN;
    }

    aliyun_iot_mutex_lock(&c->keepAliveTimerMutex);
    aliyun_iot_timer_cutdown(&c->keepAliveTimer, c->keepAliveInterval * 1000);
    aliyun_iot_mutex_unlock(&c->keepAliveTimerMutex);

    header.byte = c->readBuf[0];
    msgType = header.bits.msgType;
    if (PING == msgType)
    {
        return msgType;
    }

    /* 2. read the remaining length.  This is variable in itself */
    rc = decodeVariableNumberNetwork(c, &remainLen, timeout_ms);
    if (rc < 0)
    {
        aliyun_iot_mutex_lock(&c->clientStatusMutex);

        CLIENT_STATUS_E status = getStatus(c);
        if (CLIENT_STATUS_NETWORK_ERROR != status)
        {
            WRITE_IOT_WARNING_LOG("client status changes to CLIENT_STATUS_NETWORK_ERROR!");
            setStatus(c, CLIENT_STATUS_NETWORK_ERROR);

            aliyun_iot_mutex_lock(&c->reconnectIntervalMutex);
            c->reconnectInterval = RECONNECT_MIN_INTERVAL;
            aliyun_iot_mutex_unlock(&c->reconnectIntervalMutex);

            if (NULL != c->onDisconnect)
            {
                WRITE_IOT_WARNING_LOG("network error notify disconnect!");
                c->onDisconnect(CLIENT_STATUS_NETWORK_ERROR);
            }
        }
        aliyun_iot_mutex_unlock(&c->clientStatusMutex);
        return rc;
    }

    len = 1;
    len += encodeVariableNumber(c->readBuf + 1, remainLen);  /* put the original remaining length back into the buffer */

    /* 3. read the rest of the buffer using a callback to supply the rest of the data */
    if (remainLen > 0)
    {
        rc = c->network.ccpread(&c->network, c->readBuf + len, remainLen, timeout_ms);
        if (rc != remainLen)
        {
            if (rc > 0)
            {
                aliyun_iot_mutex_lock(&c->keepAliveTimerMutex);
                aliyun_iot_timer_cutdown(&c->keepAliveTimer, c->keepAliveInterval * 1000);
                aliyun_iot_mutex_unlock(&c->keepAliveTimerMutex);
                return FAIL_RETURN;
            }
            else if (rc < 0)
            {
                aliyun_iot_mutex_lock(&c->clientStatusMutex);

                CLIENT_STATUS_E status = getStatus(c);
                if (CLIENT_STATUS_NETWORK_ERROR != status)
                {
                    WRITE_IOT_WARNING_LOG("client status changes to CLIENT_STATUS_NETWORK_ERROR!");
                    setStatus(c, CLIENT_STATUS_NETWORK_ERROR);

                    aliyun_iot_mutex_lock(&c->reconnectIntervalMutex);
                    c->reconnectInterval = RECONNECT_MIN_INTERVAL;
                    aliyun_iot_mutex_unlock(&c->reconnectIntervalMutex);

                    if (NULL != c->onDisconnect)
                    {
                        WRITE_IOT_WARNING_LOG("network error notify disconnect!");
                        c->onDisconnect(CLIENT_STATUS_NETWORK_ERROR);
                    }
                }
                aliyun_iot_mutex_unlock(&c->clientStatusMutex);
            }
            return rc;
        }
    }

    aliyun_iot_mutex_lock(&c->keepAliveTimerMutex);
    aliyun_iot_timer_cutdown(&c->keepAliveTimer, c->keepAliveInterval * 1000);
    aliyun_iot_mutex_unlock(&c->keepAliveTimerMutex);

    return msgType;
}

void keepAlive(CLIENT_S *c)
{
    if (!c->keepAliveInterval)
    {
        return;
    }

    aliyun_iot_mutex_lock(&c->keepAliveTimerMutex);
    if (aliyun_iot_timer_expired(&c->keepAliveTimer))
    {
        aliyun_iot_mutex_lock(&c->clientStatusMutex);

        CLIENT_STATUS_E status = getStatus(c);
        if (CLIENT_STATUS_KEEPALIVE_TIMEOUT != status)
        {
            WRITE_IOT_WARNING_LOG("client status changes to CLIENT_STATUS_KEEPALIVE_TIMEOUT!");
            setStatus(c, CLIENT_STATUS_KEEPALIVE_TIMEOUT);

            aliyun_iot_mutex_lock(&c->reconnectIntervalMutex);
            c->reconnectInterval = RECONNECT_MIN_INTERVAL;
            aliyun_iot_mutex_unlock(&c->reconnectIntervalMutex);

            if (NULL != c->onDisconnect)
            {
                WRITE_IOT_WARNING_LOG("keepalive timeout notify disconnect!");
                c->onDisconnect(CLIENT_STATUS_KEEPALIVE_TIMEOUT);
            }
        }
        aliyun_iot_mutex_unlock(&c->clientStatusMutex);
    }
    aliyun_iot_mutex_unlock(&c->keepAliveTimerMutex);
}

int connectCycle(CLIENT_S *c, int timeout_ms)
{
    int rc = SUCCESS_RETURN;
    CLIENT_STATUS_E status;
    int msgType;

    aliyun_iot_mutex_lock(&c->clientStatusMutex);
    status = getStatus(c);
    aliyun_iot_mutex_unlock(&c->clientStatusMutex);

    msgType = readPacket(c, timeout_ms);
    if (!msgType)
    {
        return SUCCESS_RETURN;
    }
    else if (msgType < 0)
    {
        return CCP_READ_PACKET_ERROR;
    }

    WRITE_IOT_NOTICE_LOG("msgType = %d!",msgType);

    switch (msgType)
    {
        case CONNECT_ACK:
        case RECONNECT_ACK:
            break;
        case UNKNOWN_SESSION:
            {
                CCP_UNKNOWN_SESSION_S resp;
                if (SUCCESS_RETURN != (rc = onCCPUnknownSession(c->readBuf, &resp)))
                {
                    WRITE_IOT_ERROR_LOG("handle unknown session message failed!");
                    break;
                }

                dealException(c, resp.statusCode);
                break;
            }
        default:
            WRITE_IOT_ERROR_LOG("message type is invalid!");
            rc = CCP_INVALID_MESSAGE_TYPE;
            break;
    }

    if (SUCCESS_RETURN == rc)
    {
        rc = msgType;
    }

    return rc;
}

int receiveCycle(CLIENT_S *c, int timeout_ms)
{
    int rc;
    CLIENT_STATUS_E status;
    int msgType;
    CCP_MESSAGE_S msg;

    aliyun_iot_mutex_lock(&c->clientStatusMutex);
    status = getStatus(c);
    aliyun_iot_mutex_unlock(&c->clientStatusMutex);

    if (CLIENT_STATUS_CONNECTED == status)
    {
        msgType = readPacket(c, timeout_ms);
        if (!msgType)
        {
            return SUCCESS_RETURN;
        }
        else if (msgType < 0)
        {
            WRITE_IOT_ERROR_LOG("ccp read packet is error!");
            return CCP_READ_PACKET_ERROR;
        }
        else
        {
            //收到数据包后续进行解析操作
        }
    }
    else
    {
        return CCP_CLIENT_STATUS_ERROR;
    }

    memset(&msg, 0, sizeof(CCP_MESSAGE_S));

    switch (msgType)
    {
        case PUSH:
            {
                CCP_PUSH_S *req = (CCP_PUSH_S *) aliyun_iot_memory_malloc(sizeof(CCP_PUSH_S));
                if (NULL == req)
                {
                    WRITE_IOT_ERROR_LOG("malloc push buf failed!");
                    rc = CCP_MALLOC_ERROR;
                    break;
                }
                memset(req, 0, sizeof(CCP_PUSH_S));

                msg.payload = req;

                if (SUCCESS_RETURN != (rc = onCCPPush(c->readBuf, &msg, req)))
                {
                    WRITE_IOT_ERROR_LOG("handle push message failed!");
                    break;
                }

                c->onMessage(&msg);
                aliyun_iot_memory_free(req->Content);
                break;
            }
        case RPCRESPONSE:
            {
                CCP_RPC_RESP_S *resp = (CCP_RPC_RESP_S *) aliyun_iot_memory_malloc(sizeof(CCP_RPC_RESP_S));
                if (NULL == resp)
                {
                    WRITE_IOT_ERROR_LOG("malloc rpc resp buf failed!");
                    rc = CCP_MALLOC_ERROR;
                    break;
                }
                memset(resp, 0, sizeof(CCP_RPC_RESP_S));

                msg.payload = resp;

                if (SUCCESS_RETURN != (rc = onCCPRPCResponse(c->readBuf, &msg, resp)))
                {
                    WRITE_IOT_ERROR_LOG("handle rpc response message failed!");
                    break;
                }

                c->onMessage(&msg);
                aliyun_iot_memory_free(resp->payload);
                removeUnackListNode(c, msgType, resp->SequenceId);
                break;
            }
        case REVERSE_RPCREQUEST:
            {
                CCP_RRPC_REQ_S *req = (CCP_RRPC_REQ_S *) aliyun_iot_memory_malloc(sizeof(CCP_RRPC_REQ_S));
                if (NULL == req)
                {
                    WRITE_IOT_ERROR_LOG("malloc rrpc request buf failed!");
                    rc = CCP_MALLOC_ERROR;
                    break;
                }
                memset(req, 0, sizeof(CCP_RRPC_REQ_S));

                msg.payload = req;

                if (SUCCESS_RETURN != (rc = onCCPRRPCRequest(c->readBuf, &msg, req)))
                {
                    WRITE_IOT_ERROR_LOG("handle rrpc request message failed!");
                    break;
                }

                c->onMessage(&msg);
                aliyun_iot_memory_free(req->payload);
                break;
            }
        case PING:
            WRITE_IOT_INFO_LOG("recv ping message!");
            if (SUCCESS_RETURN != (rc = CCPSendPongMsg(c)))
            {
                WRITE_IOT_ERROR_LOG("send pong message failed!");
            }
            else
            {
                WRITE_IOT_INFO_LOG("send pong message!");
            }
            break;
        case PUBLISH:
            {
                CCP_PUBLISH_S *req = (CCP_PUBLISH_S *) aliyun_iot_memory_malloc(sizeof(CCP_PUBLISH_S));
                if (NULL == req)
                {
                    WRITE_IOT_ERROR_LOG("malloc publish buf failed!");
                    rc = CCP_MALLOC_ERROR;
                    break;
                }
                memset(req, 0, sizeof(CCP_PUBLISH_S));

                msg.payload = req;

                if (SUCCESS_RETURN != (rc = onCCPPublish(c->readBuf, &msg, req)))
                {
                    WRITE_IOT_ERROR_LOG("handle publish message failed!");
                    break;
                }

                int ret = c->onMessage(&msg);
                aliyun_iot_memory_free(req->payload);

                if (req->aliveSecond > 0)
                {
                    CCP_PUBLISH_ACK_S resp;
                    if (SUCCESS_RETURN == ret)
                    {
                        resp.code = PUBLISH_STATUS_SUCCESS;
                    }
                    else
                    {
                        resp.code = PUBLISH_STATUS_UNKNOWN;
                    }
                    resp.SequenceId = req->SequenceId;

                    if (SUCCESS_RETURN != (rc = CCPSendPublishAckMsg(c, &resp)))
                    {
                        WRITE_IOT_ERROR_LOG("send publish ack message failed!");
                    }
                }
                break;
            }
        case PUBLISH_ACK:
            {
                CCP_PUBLISH_ACK_S *resp = (CCP_PUBLISH_ACK_S *) aliyun_iot_memory_malloc(sizeof(CCP_PUBLISH_ACK_S));
                if (NULL == resp)
                {
                    WRITE_IOT_ERROR_LOG("malloc publish ack buf failed!");
                    rc = CCP_MALLOC_ERROR;
                    break;
                }
                memset(resp, 0, sizeof(CCP_PUBLISH_ACK_S));

                msg.payload = resp;

                if (SUCCESS_RETURN != (rc = onCCPPublishAck(c->readBuf, &msg, resp)))
                {
                    WRITE_IOT_ERROR_LOG("handle publish ack message failed!");
                    break;
                }

                c->onMessage(&msg);
                removeRepublishListNode(c, resp->SequenceId);
                break;
            }
        case SUBSCRIBE_ACK:
            {
                CCP_SUBSCRIBE_ACK_S *resp = (CCP_SUBSCRIBE_ACK_S *) aliyun_iot_memory_malloc(sizeof(CCP_SUBSCRIBE_ACK_S));
                if (NULL == resp)
                {
                    WRITE_IOT_ERROR_LOG("malloc subscribe ack buf failed!");
                    rc = CCP_MALLOC_ERROR;
                    break;
                }
                memset(resp, 0, sizeof(CCP_SUBSCRIBE_ACK_S));

                msg.payload = resp;

                if (SUCCESS_RETURN != (rc = onCCPSubscribeAck(c->readBuf, &msg, resp)))
                {
                    WRITE_IOT_ERROR_LOG("handle subscribe ack message failed!");
                    break;
                }

                c->onMessage(&msg);
                removeUnackListNode(c, msgType, resp->SequenceId);
                break;
            }
        case UNSUBSCRIBE_ACK:
            {
                CCP_UNSUBSCRIBE_ACK_S *resp = (CCP_UNSUBSCRIBE_ACK_S *) aliyun_iot_memory_malloc(sizeof(CCP_UNSUBSCRIBE_ACK_S));
                if (NULL == resp)
                {
                    WRITE_IOT_ERROR_LOG("malloc unsubscribe ack buf failed!");
                    rc = CCP_MALLOC_ERROR;
                    break;
                }
                memset(resp, 0, sizeof(CCP_UNSUBSCRIBE_ACK_S));

                msg.payload = resp;

                if (SUCCESS_RETURN != (rc = onCCPUnsubscribeAck(c->readBuf, &msg, resp)))
                {
                    WRITE_IOT_ERROR_LOG("handle unsubscribe ack message failed!");
                    break;
                }

                c->onMessage(&msg);
                removeUnackListNode(c, msgType, resp->SequenceId);
                break;
            }
        case UNKNOWN_SESSION:
            {
                CCP_UNKNOWN_SESSION_S resp;
                if (SUCCESS_RETURN != (rc = onCCPUnknownSession(c->readBuf, &resp)))
                {
                    WRITE_IOT_ERROR_LOG("handle unknown session message failed!");
                    break;
                }

                dealException(c, resp.statusCode);
                break;
            }
        default:
            WRITE_IOT_ERROR_LOG("message type is invalid!");
            rc = CCP_INVALID_MESSAGE_TYPE;
            break;
    }

    if (NULL != msg.payload)
    {
        aliyun_iot_memory_free(msg.payload);
    }

    if (SUCCESS_RETURN == rc)
    {
        rc = msgType;
    }

    return rc;
}

void setStatus(CLIENT_S *c, CLIENT_STATUS_E status)
{
    c->clientStatus = status;
}

CLIENT_STATUS_E getStatus(CLIENT_S *c)
{
    return c->clientStatus;
}

void checkStatus(CLIENT_S *c)
{
    aliyun_iot_mutex_lock(&c->clientStatusMutex);
    CLIENT_STATUS_E status = getStatus(c);
    aliyun_iot_mutex_unlock(&c->clientStatusMutex);

    int result = 0;

    switch (status)
    {
        case CLIENT_STATUS_INIT:
        case CLIENT_STATUS_CONNECTED:
            break;
        case CLIENT_STATUS_NETWORK_ERROR:
        case CLIENT_STATUS_KEEPALIVE_TIMEOUT:
            {
                aliyun_iot_mutex_lock(&c->reconnectIntervalMutex);
                if (c->reconnectInterval < RECONNECT_MAX_INTERVAL)
                {
                    c->reconnectInterval *= 2;
                    if (c->reconnectInterval > RECONNECT_MAX_INTERVAL)
                    {
                        c->reconnectInterval = RECONNECT_MAX_INTERVAL;
                    }
                }
                aliyun_iot_mutex_unlock(&c->reconnectIntervalMutex);

                //重连超过3次则重新拉取IP
                if(c->reconnectNum > RECONNECT_NUM_MAX)
                {
                    c->reconnectNum = 0;
                    result = CCPAuth(c);
                    if (SUCCESS_RETURN != result)
                    {
                        if(CCP_DEVICE_NOT_EXSIT_ERROR == result)
                        {
                            //设置超长周期时间
                            c->reconnectInterval = RECONNECT_INTERVAL_DEVICE_ABNORMAL;
                        }
                        WRITE_IOT_ERROR_LOG("auth failed!");
                        break;
                    }
                }

                CCP_RECONNECT_S req;
                memset(&req, 0, sizeof(CCP_RECONNECT_S));
                req.limit = c->connect.limit;
                req.keepalive = c->connect.keepalive;
                req.ipSwitchFlag = 0;
                req.network = c->connect.network;
                strncpy(req.ConnectionToken, c->connectionToken, sizeof(req.ConnectionToken) - 1);

                if (0 != CCPSendReconnectMsg(c, &req))
            	{
            		WRITE_IOT_ERROR_LOG("ccp reconnect failed!");
            		c->reconnectNum++;
            	}

                break;
            }
        case CLIENT_STATUS_CERT_EXPIRED:
            {
                aliyun_iot_mutex_lock(&c->reconnectIntervalMutex);
                if (c->reconnectInterval < RECONNECT_MAX_INTERVAL)
                {
                    c->reconnectInterval *= 2;
                    if (c->reconnectInterval > RECONNECT_MAX_INTERVAL)
                    {
                        c->reconnectInterval = RECONNECT_MAX_INTERVAL;
                    }
                }
                aliyun_iot_mutex_unlock(&c->reconnectIntervalMutex);

                result = CCPAuth(c);
                if (SUCCESS_RETURN != result)
            	{
                    if(CCP_DEVICE_NOT_EXSIT_ERROR == result)
                    {
                        //设置超长周期时间
                        c->reconnectInterval = RECONNECT_INTERVAL_DEVICE_ABNORMAL;
                    }
            		WRITE_IOT_ERROR_LOG("auth failed!");
            		break;
            	}

                if (0 != CCPSendConnectMsg(c, &c->connect))
            	{
            		WRITE_IOT_ERROR_LOG("ccp connect failed!");
            	}

                break;
            }
        case CLIENT_STATUS_TOKEN_EXPIRED:
        case CLIENT_STATUS_TOKEN_INVALID:
            {
                aliyun_iot_mutex_lock(&c->reconnectIntervalMutex);
                if (c->reconnectInterval < RECONNECT_MAX_INTERVAL)
                {
                    c->reconnectInterval *= 2;
                    if (c->reconnectInterval > RECONNECT_MAX_INTERVAL)
                    {
                        c->reconnectInterval = RECONNECT_MAX_INTERVAL;
                    }
                }
                aliyun_iot_mutex_unlock(&c->reconnectIntervalMutex);

                //重连超过3次则重新拉取IP
                if(c->reconnectNum > RECONNECT_NUM_MAX)
                {
                    c->reconnectNum = 0;
                    result = CCPAuth(c);
                    if (SUCCESS_RETURN != result)
                    {
                        if(CCP_DEVICE_NOT_EXSIT_ERROR == result)
                        {
                            //设置超长周期时间
                            c->reconnectInterval = RECONNECT_INTERVAL_DEVICE_ABNORMAL;
                        }
                        WRITE_IOT_ERROR_LOG("auth failed!");
                        break;
                    }
                }

                if (0 != CCPSendConnectMsg(c, &c->connect))
            	{
            		WRITE_IOT_ERROR_LOG("ccp connect failed!");
            		c->reconnectNum++;
            	}

                break;
            }
        case CLIENT_STATUS_SID_EXPIRED:
            {
                aliyun_iot_mutex_lock(&c->reconnectIntervalMutex);
                if (c->reconnectInterval < RECONNECT_MAX_INTERVAL)
                {
                    c->reconnectInterval *= 2;
                    if (c->reconnectInterval > RECONNECT_MAX_INTERVAL)
                    {
                        c->reconnectInterval = RECONNECT_MAX_INTERVAL;
                    }
                }
                aliyun_iot_mutex_unlock(&c->reconnectIntervalMutex);

                SERVER_INFO_S server_info;
                ERROR_INFO_S error_info;
                memset(&server_info, 0, sizeof(SERVER_INFO_S));
                memset(&error_info, 0, sizeof(ERROR_INFO_S));
                strncpy(server_info.pkVersion, c->pkVersion, sizeof(server_info.pkVersion) - 1);

                result = CCPGetSid(c, &server_info, &error_info);
                if (SUCCESS_RETURN != result)
            	{
                    if (CCP_CERT_EXPIRE_ERROR == result)
                    {
                        if (SUCCESS_RETURN != CCPAuth(c))
                        {
                            WRITE_IOT_ERROR_LOG("auth failed!");
                        }
                    }

                    if(CCP_DEVICE_NOT_EXSIT_ERROR == result)
                    {
                        //设置超长周期时间
                        c->reconnectInterval = RECONNECT_INTERVAL_DEVICE_ABNORMAL;
                    }

            		WRITE_IOT_ERROR_LOG("get sid failed!");
            		break;
            	}

                if (0 != CCPSendConnectMsg(c, &c->connect))
            	{
            		WRITE_IOT_ERROR_LOG("ccp connect failed!");
            	}

                break;
            }
        default:
            WRITE_IOT_ERROR_LOG("client status is invalid!");
            break;
    }
}

void dealException(CLIENT_S *c, STATUS_CODE_E statusCode)
{
    CLIENT_STATUS_E status;

    aliyun_iot_mutex_lock(&c->clientStatusMutex);
    status = getStatus(c);

    if (EXPIRED_CERT == statusCode)
    {
        if (CLIENT_STATUS_CERT_EXPIRED != status)
        {
            WRITE_IOT_WARNING_LOG("client status changes to CLIENT_STATUS_CERT_EXPIRED!");
            setStatus(c, CLIENT_STATUS_CERT_EXPIRED);

            aliyun_iot_mutex_lock(&c->reconnectIntervalMutex);
            c->reconnectInterval = RECONNECT_MIN_INTERVAL;
            aliyun_iot_mutex_unlock(&c->reconnectIntervalMutex);

            if (NULL != c->onDisconnect)
            {
                WRITE_IOT_WARNING_LOG("certificate expired notify disconnect!");
                c->onDisconnect(CLIENT_STATUS_CERT_EXPIRED);
            }
        }
    }
    else if (EXPIRED_TOKEN == statusCode)
    {
        if (CLIENT_STATUS_TOKEN_EXPIRED != status)
        {
            WRITE_IOT_WARNING_LOG("client status changes to CLIENT_STATUS_TOKEN_EXPIRED!");
            setStatus(c, CLIENT_STATUS_TOKEN_EXPIRED);

            aliyun_iot_mutex_lock(&c->reconnectIntervalMutex);
            c->reconnectInterval = RECONNECT_MIN_INTERVAL;
            aliyun_iot_mutex_unlock(&c->reconnectIntervalMutex);

            if (NULL != c->onDisconnect)
            {
                WRITE_IOT_WARNING_LOG("token expired notify disconnect!");
                c->onDisconnect(CLIENT_STATUS_TOKEN_EXPIRED);
            }
        }
    }
    else if (INVALID_TOKEN == statusCode)
    {
        if (CLIENT_STATUS_TOKEN_INVALID != status)
        {
            WRITE_IOT_WARNING_LOG("client status changes to CLIENT_STATUS_TOKEN_INVALID!");
            setStatus(c, CLIENT_STATUS_TOKEN_INVALID);

            aliyun_iot_mutex_lock(&c->reconnectIntervalMutex);
            c->reconnectInterval = RECONNECT_MIN_INTERVAL;
            aliyun_iot_mutex_unlock(&c->reconnectIntervalMutex);

            if (NULL != c->onDisconnect)
            {
                WRITE_IOT_WARNING_LOG("token invalid notify disconnect!");
                c->onDisconnect(CLIENT_STATUS_TOKEN_EXPIRED);
            }
        }
    }
    else if (ERROR_SID == statusCode)
    {
        if (CLIENT_STATUS_SID_EXPIRED != status)
        {
            WRITE_IOT_WARNING_LOG("client status changes to CLIENT_STATUS_SID_EXPIRED!");
            setStatus(c, CLIENT_STATUS_SID_EXPIRED);

            aliyun_iot_mutex_lock(&c->reconnectIntervalMutex);
            c->reconnectInterval = RECONNECT_MIN_INTERVAL;
            aliyun_iot_mutex_unlock(&c->reconnectIntervalMutex);

            if (NULL != c->onDisconnect)
            {
                WRITE_IOT_WARNING_LOG("sid expired notify disconnect!");
                c->onDisconnect(CLIENT_STATUS_TOKEN_EXPIRED);
            }
        }
    }

    aliyun_iot_mutex_unlock(&c->clientStatusMutex);
}

void *reconnectThread(void *arg)
{
    int delayTime;
    CLIENT_S *c = (CLIENT_S *) arg;

    while (1)
	{
        checkStatus(c);

        if (NULL != c->onTimeout)
        {
            notifyUnackTimeout(c);
        }

        aliyun_iot_mutex_lock(&c->reconnectIntervalMutex);
        delayTime = c->reconnectInterval * 1000;
        aliyun_iot_mutex_unlock(&c->reconnectIntervalMutex);

        aliyun_iot_pthread_taskdelay(delayTime);
	}

    return NULL;
}

void *receiveThread(void *arg)
{
    CLIENT_S *c = (CLIENT_S *) arg;
    CLIENT_STATUS_E status;

    while (1)
	{
        aliyun_iot_mutex_lock(&c->clientStatusMutex);
        status = getStatus(c);
        aliyun_iot_mutex_unlock(&c->clientStatusMutex);

        if (CLIENT_STATUS_CONNECTED == status)
        {
            keepAlive(c);
        }

		if ( receiveCycle(c, c->keepAliveInterval * 1000) < 0)
        {
            aliyun_iot_pthread_taskdelay(1000);
        }
	}

    return NULL;
}

void *retransThread(void *arg)
{
    CLIENT_STATUS_E status;
    CLIENT_S *c = (CLIENT_S *) arg;

    while (1)
    {
        aliyun_iot_mutex_lock(&c->rePublishListMutex);
        if (c->rePublishList->len)
        {
            list_iterator_t *iter = list_iterator_new(c->rePublishList, LIST_TAIL);
            list_node_t *node = NULL;
            list_node_t *tempNode = NULL;
            char timeoutFlag = 0;

            for (;;)
            {
                node = list_iterator_next(iter);
                if (tempNode)
                {
                    list_remove(c->rePublishList, tempNode);
                    tempNode = NULL;
                }

                if (!node)
                {
                    break;
                }

                aliyun_iot_mutex_lock(&c->clientStatusMutex);
                status = getStatus(c);
                aliyun_iot_mutex_unlock(&c->clientStatusMutex);
                if (CLIENT_STATUS_CONNECTED != status)
                {
                    break;
                }

                REPUBLISH_MESSAGE_S *republish = (REPUBLISH_MESSAGE_S *) node->val;
                if (!republish)
                {
                    WRITE_IOT_ERROR_LOG("node's value is invalid!");
                    tempNode = node;
                    continue;
                }

                if (republish->removeFlag)
                {
                    tempNode = node;
                    continue;
                }

                if (timeoutFlag || aliyun_iot_timer_expired(&republish->timer))
                {
                    timeoutFlag = 1;

                    CCP_PUBLISH_S req;
                    memset(&req, 0, sizeof(CCP_PUBLISH_S));
                    req = republish->req;
                    req.payload = NULL;
                    if (req.payloadLen > 0)
                    {
                        req.payload = (unsigned char *) aliyun_iot_memory_malloc(req.payloadLen + 1);
                        if (NULL == req.payload)
                        {
                            WRITE_IOT_ERROR_LOG("malloc payload buf failed!");
                            continue;
                        }
                        memset(req.payload, 0, req.payloadLen + 1);
                        memcpy(req.payload, republish->req.payload, republish->req.payloadLen);
                    }

                    aliyun_iot_mutex_unlock(&c->rePublishListMutex);
                    if (CCPResendPublishMsg(c, &req))
                    {
                        WRITE_IOT_ERROR_LOG("republish failed, SequenceId is %u!", req.SequenceId);
                    }

                    if (NULL != req.payload)
                    {
                        aliyun_iot_memory_free(req.payload);
                    }
                    aliyun_iot_mutex_lock(&c->rePublishListMutex);
                    aliyun_iot_timer_cutdown(&republish->timer, c->commandTimeout * 2);
                }
            }

            list_iterator_destroy(iter);
        }
        aliyun_iot_mutex_unlock(&c->rePublishListMutex);

        aliyun_iot_pthread_taskdelay(50);
    }
}

void notifyUnackTimeout(CLIENT_S *c)
{
    aliyun_iot_mutex_lock(&c->unAckListMutex);
    if (c->unAckList->len)
    {
        list_iterator_t *iter = list_iterator_new(c->unAckList, LIST_TAIL);
        list_node_t *node = NULL;
        list_node_t *tempNode = NULL;
        char timeoutFlag = 0;

        for (;;)
        {
            node = list_iterator_next(iter);
            if (tempNode)
            {
                list_remove(c->unAckList, tempNode);
                tempNode = NULL;
            }

            if (!node)
            {
                break;
            }

            UNACK_MESSAGE_S *unack = (UNACK_MESSAGE_S *) node->val;
            if (!unack)
            {
                WRITE_IOT_ERROR_LOG("node's value is invalid!");
                tempNode = node;
                continue;
            }

            if (unack->removeFlag)
            {
                tempNode = node;
                continue;
            }

            if (timeoutFlag || aliyun_iot_timer_expired(&unack->timer))
            {
                timeoutFlag = 1;

                CCP_MESSAGE_S msg;
                memset(&msg, 0, sizeof(CCP_MESSAGE_S));
                msg = unack->req;
                msg.payload = NULL;
                switch (unack->req.msgType)
                {
                    case RPCREQUEST:
                        {
                            CCP_RPC_REQ_S *rpcReq = (CCP_RPC_REQ_S *) unack->req.payload;
                            CCP_RPC_REQ_S *req = (CCP_RPC_REQ_S *) aliyun_iot_memory_malloc(sizeof(CCP_RPC_REQ_S));
                            if (NULL == req)
                            {
                                WRITE_IOT_ERROR_LOG("malloc rpc request buf failed!");
                                break;
                            }
                            memset(req, 0, sizeof(CCP_RPC_REQ_S));

                            *req = *rpcReq;
                            req->payload = NULL;
                            if (req->payloadLen > 0)
                            {
                                req->payload = (unsigned char *) aliyun_iot_memory_malloc(req->payloadLen + 1);
                                if (NULL == req->payload)
                                {
                                    WRITE_IOT_ERROR_LOG("malloc payload buf failed!");
                                    aliyun_iot_memory_free(req);
                                    break;
                                }
                                memset(req->payload, 0, req->payloadLen + 1);
                                memcpy(req->payload, rpcReq->payload, rpcReq->payloadLen);
                            }
                            msg.payload = req;

                            aliyun_iot_mutex_unlock(&c->unAckListMutex);
                            c->onTimeout(&msg);
                            if (NULL != req->payload)
                            {
                                aliyun_iot_memory_free(req->payload);
                            }
                            aliyun_iot_memory_free(req);
                            aliyun_iot_mutex_lock(&c->unAckListMutex);

                            tempNode = node;
                            break;
                        }
                    case SUBSCRIBE:
                        {
                            CCP_SUBSCRIBE_S *subReq = (CCP_SUBSCRIBE_S *) unack->req.payload;
                            CCP_SUBSCRIBE_S *req = (CCP_SUBSCRIBE_S *) aliyun_iot_memory_malloc(sizeof(CCP_SUBSCRIBE_S));
                            if (NULL == req)
                            {
                                WRITE_IOT_ERROR_LOG("malloc subscribe request buf failed!");
                                break;
                            }
                            memset(req, 0, sizeof(CCP_SUBSCRIBE_S));

                            *req = *subReq;
                            msg.payload = req;

                            aliyun_iot_mutex_unlock(&c->unAckListMutex);
                            c->onTimeout(&msg);
                            aliyun_iot_memory_free(req);
                            aliyun_iot_mutex_lock(&c->unAckListMutex);

                            tempNode = node;
                            break;
                        }
                    case UNSUBSCRIBE:
                        {
                            CCP_UNSUBSCRIBE_S *unsubReq = (CCP_UNSUBSCRIBE_S *) unack->req.payload;
                            CCP_UNSUBSCRIBE_S *req = (CCP_UNSUBSCRIBE_S *) aliyun_iot_memory_malloc(sizeof(CCP_UNSUBSCRIBE_S));
                            if (NULL == req)
                            {
                                WRITE_IOT_ERROR_LOG("malloc unsubscribe request buf failed!");
                                break;
                            }
                            memset(req, 0, sizeof(CCP_UNSUBSCRIBE_S));

                            *req = *unsubReq;
                            msg.payload = req;

                            aliyun_iot_mutex_unlock(&c->unAckListMutex);
                            c->onTimeout(&msg);
                            aliyun_iot_memory_free(req);
                            aliyun_iot_mutex_lock(&c->unAckListMutex);

                            tempNode = node;
                            break;
                        }
                    default:
                        WRITE_IOT_ERROR_LOG("message type is invalid!");
                        tempNode = node;
                        break;
                }
            }
        }

        list_iterator_destroy(iter);
    }
    aliyun_iot_mutex_unlock(&c->unAckListMutex);
}

int createReconnectThread(CLIENT_S *c)
{
    if (c->hasReconnectThread)
    {
        WRITE_IOT_INFO_LOG("keepalive thread has already existed!");
        return SUCCESS_RETURN;
    }

    if (SUCCESS_RETURN != aliyun_iot_pthread_create(&c->reconnectThread, reconnectThread, c, NULL))
    {
        WRITE_IOT_ERROR_LOG("create thread failed!");
        return CCP_CREATE_THREAD_ERROR;
    }

    c->hasReconnectThread = 1;

    return SUCCESS_RETURN;
}

int createReceiveThread(CLIENT_S *c)
{
    if (c->hasReceiveThread)
    {
        WRITE_IOT_INFO_LOG("receive thread has already existed!");
        return SUCCESS_RETURN;
    }

    if (SUCCESS_RETURN != aliyun_iot_pthread_create(&c->receiveThread, receiveThread, c, NULL))
    {
        WRITE_IOT_ERROR_LOG("create thread failed!");
        return CCP_CREATE_THREAD_ERROR;
    }

    c->hasReceiveThread = 1;

    return SUCCESS_RETURN;
}

int createRetransThread(CLIENT_S *c)
{
    if (c->hasRetransThread)
    {
        WRITE_IOT_INFO_LOG("retrans thread has already existed!");
        return SUCCESS_RETURN;
    }

    if (SUCCESS_RETURN != aliyun_iot_pthread_create(&c->retransThread, retransThread, c, NULL))
    {
        WRITE_IOT_ERROR_LOG("create thread failed!");
        return CCP_CREATE_THREAD_ERROR;
    }

    c->hasRetransThread = 1;

    return SUCCESS_RETURN;
}

void removeRepublishListNode(CLIENT_S *c, unsigned int sequenceId)
{
    aliyun_iot_mutex_lock(&c->rePublishListMutex);
    if (c->rePublishList->len)
    {
        list_iterator_t *iter = list_iterator_new(c->rePublishList, LIST_TAIL);
        list_node_t *node = NULL;
        REPUBLISH_MESSAGE_S *republish = NULL;

        for (;;)
        {
            node = list_iterator_next(iter);
            if (!node)
            {
                break;
            }

            republish = (REPUBLISH_MESSAGE_S *) node->val;
            if (!republish)
            {
                WRITE_IOT_ERROR_LOG("node's value is invalid!");
                continue;
            }

            CCP_PUBLISH_S *req = &republish->req;
            if (req->SequenceId == sequenceId)
            {
                republish->removeFlag = 1;
                aliyun_iot_memory_free(req->payload);
            }
        }

        list_iterator_destroy(iter);
    }
    aliyun_iot_mutex_unlock(&c->rePublishListMutex);
}

void removeUnackListNode(CLIENT_S *c, MESSAGE_TYPE_E msgType, unsigned int sequenceId)
{
    aliyun_iot_mutex_lock(&c->unAckListMutex);
    if (c->unAckList->len)
    {
        list_iterator_t *iter = list_iterator_new(c->unAckList, LIST_TAIL);
        list_node_t *node = NULL;
        UNACK_MESSAGE_S *unack = NULL;

        for (;;)
        {
            node = list_iterator_next(iter);
            if (!node)
            {
                break;
            }

            unack = (UNACK_MESSAGE_S *) node->val;
            if (!unack)
            {
                WRITE_IOT_ERROR_LOG("node's value is invalid!");
                continue;
            }

            switch (msgType)
            {
                case RPCRESPONSE:
                    {
                        if (RPCREQUEST == unack->req.msgType)
                        {
                            CCP_RPC_REQ_S *req = (CCP_RPC_REQ_S *) unack->req.payload;
                            if (req->SequenceId == sequenceId)
                            {
                                unack->removeFlag = 1;
                                aliyun_iot_memory_free(req->payload);
                                aliyun_iot_memory_free(req);
                            }
                        }
                        break;
                    }
                case SUBSCRIBE_ACK:
                    {
                        if (SUBSCRIBE == unack->req.msgType)
                        {
                            CCP_SUBSCRIBE_S *req = (CCP_SUBSCRIBE_S *) unack->req.payload;
                            if (req->SequenceId == sequenceId)
                            {
                                unack->removeFlag = 1;
                                aliyun_iot_memory_free(req);
                            }
                        }
                        break;
                    }
                case UNSUBSCRIBE_ACK:
                    {
                        if (UNSUBSCRIBE == unack->req.msgType)
                        {
                            CCP_UNSUBSCRIBE_S *req = (CCP_UNSUBSCRIBE_S *) unack->req.payload;
                            if (req->SequenceId == sequenceId)
                            {
                                unack->removeFlag = 1;
                                aliyun_iot_memory_free(req);
                            }
                        }
                        break;
                    }
                default:
                    WRITE_IOT_ERROR_LOG("message type is invalid!");
                    break;
            }
        }

        list_iterator_destroy(iter);
    }
    aliyun_iot_mutex_unlock(&c->unAckListMutex);
}

void freeRepublishList(CLIENT_S *c)
{
    aliyun_iot_mutex_lock(&c->rePublishListMutex);
    if (c->rePublishList->len)
    {
        list_iterator_t *iter = list_iterator_new(c->rePublishList, LIST_TAIL);
        list_node_t *node = NULL;

        for (;;)
        {
            node = list_iterator_next(iter);
            if (!node)
            {
                break;
            }

            REPUBLISH_MESSAGE_S *republish = (REPUBLISH_MESSAGE_S *) node->val;
            if (!republish)
            {
                continue;
            }

            if (republish->req.payload)
            {
                free(republish->req.payload);
            }
        }

        list_iterator_destroy(iter);
    }

    list_destroy(c->rePublishList);
    aliyun_iot_mutex_unlock(&c->rePublishListMutex);
}

void freeUnackList(CLIENT_S *c)
{
    aliyun_iot_mutex_lock(&c->unAckListMutex);
    if (c->unAckList->len)
    {
        list_iterator_t *iter = list_iterator_new(c->unAckList, LIST_TAIL);
        list_node_t *node = NULL;

        for (;;)
        {
            node = list_iterator_next(iter);
            if (!node)
            {
                break;
            }

            UNACK_MESSAGE_S *unack = (UNACK_MESSAGE_S *) node->val;
            if (!unack)
            {
                continue;
            }

            switch (unack->req.msgType)
            {
                case RPCREQUEST:
                    {
                        CCP_RPC_REQ_S *rpcReq = (CCP_RPC_REQ_S *) unack->req.payload;
                        if (rpcReq->payload)
                        {
                            free(rpcReq->payload);
                        }
                        free(rpcReq);
                    }
                case SUBSCRIBE:
                case UNSUBSCRIBE:
                    {
                        free(unack->req.payload);
                    }
                default:
                    break;
            }
        }

        list_iterator_destroy(iter);
    }

    list_destroy(c->unAckList);
    aliyun_iot_mutex_unlock(&c->unAckListMutex);
}

