#include "CCPTypeDefInternal.h"
#include "CCPClientInternal.h"
#include "CCPNetwork.h"
#include "CCPClient.h"

int CCPInit(CLIENT_S *c, AUTH_CONFIG_S *authConfig, unsigned int commandTimeout, unsigned char *writeBuf,
            unsigned int writeBufSize, unsigned char *readBuf, unsigned int readBufSize, messageHandler onMessage,
            connectHandler onConnect, disconnectHandler onDisconnect, timeoutHandler onTimeout)
{
    aliyun_iot_common_log_init();

    if ((NULL == c) || (NULL == authConfig) || (NULL == writeBuf) || (NULL == readBuf) || (NULL == onMessage))
    {
        WRITE_IOT_ERROR_LOG("invalid parameter!");
        return CCP_INVALID_PARAMETER;
    }

    if (commandTimeout < COMMAND_TIMEOUT_MIN_TIME)
    {
        c->commandTimeout = COMMAND_TIMEOUT_MIN_TIME;
    }
    else if (commandTimeout > COMMAND_TIMEOUT_MAX_TIME)
    {
        c->commandTimeout = COMMAND_TIMEOUT_MAX_TIME;
    }
    else
    {
        c->commandTimeout = commandTimeout;
    }

    c->authConfig = *authConfig;
    c->sequenceId = 1;
    c->writeBuf = writeBuf;
    c->writeBufSize = writeBufSize;
    c->readBuf = readBuf;
    c->readBufSize = readBufSize;
    c->reconnectInterval = RECONNECT_MIN_INTERVAL;
    c->reconnectNum = 0;
    c->hasReceiveThread = 0;
    c->keepAliveInterval = 0;
    c->onMessage = onMessage;
    c->onConnect = onConnect;
    c->onDisconnect = onDisconnect;
    c->onTimeout = onTimeout;
    aliyun_iot_mutex_init(&c->writeBufMutex);
    aliyun_iot_mutex_init(&c->reconnectIntervalMutex);
    aliyun_iot_mutex_init(&c->keepAliveTimerMutex);
    aliyun_iot_mutex_init(&c->clientStatusMutex);
    aliyun_iot_mutex_init(&c->rePublishListMutex);
    aliyun_iot_mutex_init(&c->unAckListMutex);
    aliyun_iot_timer_init(&c->keepAliveTimer);
    setStatus(c, CLIENT_STATUS_INIT);
    srand(aliyun_iot_timer_now());

    c->rePublishList = list_new();
    if (NULL == c->rePublishList)
    {
        WRITE_IOT_ERROR_LOG("new rePublishList failed!");
        return FAIL_RETURN;
    }
    c->rePublishList->free = aliyun_iot_memory_free;

    c->unAckList = list_new();
    if (NULL == c->unAckList)
    {
        WRITE_IOT_ERROR_LOG("new unAckList failed!");
        return FAIL_RETURN;
    }
    c->unAckList->free = aliyun_iot_memory_free;

    initNetwork(&c->network);

    WRITE_IOT_INFO_LOG("ccp init success!");

    return SUCCESS_RETURN;
}

int CCPRelease(CLIENT_S *c)
{
    int rc = SUCCESS_RETURN;

    if (NULL == c)
    {
        WRITE_IOT_ERROR_LOG("invalid parameter!");
        return CCP_INVALID_PARAMETER;
    }

    if (c->hasReconnectThread)
    {
        if (SUCCESS_RETURN != aliyun_iot_pthread_cancel(&c->reconnectThread))
        {
            WRITE_IOT_ERROR_LOG("cancel thread failed!");
            rc = CCP_CANCEL_THREAD_ERROR;
        }
        else
        {
            c->hasReconnectThread = 0;
        }
    }
    else
    {
        WRITE_IOT_INFO_LOG("keepalive thread is not existed!");
    }

    if (c->hasReceiveThread)
    {
        if (SUCCESS_RETURN != aliyun_iot_pthread_cancel(&c->receiveThread))
        {
            WRITE_IOT_ERROR_LOG("cancel thread failed!");
            rc = CCP_CANCEL_THREAD_ERROR;
        }
        else
        {
            c->hasReceiveThread = 0;
        }
    }
    else
    {
        WRITE_IOT_INFO_LOG("receive thread is not existed!");
    }

    if (c->hasRetransThread)
    {
        if (SUCCESS_RETURN != aliyun_iot_pthread_cancel(&c->retransThread))
        {
            WRITE_IOT_ERROR_LOG("cancel thread failed!");
            rc = CCP_CANCEL_THREAD_ERROR;
        }
        else
        {
            c->hasRetransThread = 0;
        }
    }
    else
    {
        WRITE_IOT_INFO_LOG("retrans thread is not existed!");
    }
	
	aliyun_iot_pthread_taskdelay(1000);

    c->network.disconnect(&c->network);

    setStatus(c, CLIENT_STATUS_INIT);

    freeRepublishList(c);
    freeUnackList(c);

    aliyun_iot_mutex_destory(&c->writeBufMutex);
    aliyun_iot_mutex_destory(&c->reconnectIntervalMutex);
    aliyun_iot_mutex_destory(&c->keepAliveTimerMutex);
    aliyun_iot_mutex_destory(&c->clientStatusMutex);
    aliyun_iot_mutex_destory(&c->rePublishListMutex);
    aliyun_iot_mutex_destory(&c->unAckListMutex);

    if (SUCCESS_RETURN == rc)
    {
         WRITE_IOT_INFO_LOG("ccp release success!");
    }

    aliyun_iot_common_log_release();
    return rc;
}

