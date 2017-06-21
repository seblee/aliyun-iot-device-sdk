#include "CCPTypeDefInternal.h"
#include "CCPNetwork.h"
#include "CCPPacket.h"
#include "CCPClientInternal.h"
#include "CCPAuth.h"
#include "CCPConnectAck.h"
#include "CCPConnect.h"

int CCPSerializeConnectMsg(CLIENT_S *c, const CCP_CONNECT_S *req)
{
	CCP_HEADER_S header = {0};
	unsigned int remainLen;
    unsigned char data[128] = {0};
    int dataLen;
    unsigned char needAesData[32] = {0};
    unsigned char aesData[32] = {0};
    int aesDataLen;
    int platformId = 2;
    char *appAccount = "";
    char *packageName = "";
    int msgLen;
    unsigned char *ptr;

    ptr = data;
    ptr += encodeVariableNumber(ptr, c->sequenceId);
    c->sequenceId++;
    writeChar(&ptr, CCP_PROTOCOL_VERSION);
    ptr += encodeVariableNumber(ptr, platformId);
    encodeString(&ptr, c->sid, strlen(c->sid));

    dataLen = ptr - data;
    remainLen = dataLen;

    ptr = needAesData;
    writeChar(&ptr, req->network);
    encodeString(&ptr, appAccount, strlen(appAccount));
    encodeString(&ptr, packageName, strlen(packageName));
    ptr += encodeVariableNumber(ptr, req->limit);
    ptr += encodeVariableNumber(ptr, req->keepalive);

    if (SUCCESS_RETURN != aesEcbEncrypt((unsigned char *) c->seedKey, needAesData, aesData, ptr - needAesData, &aesDataLen))
    {
        WRITE_IOT_ERROR_LOG("aes encrypt failed!");
        return CCP_AES_ENCRYPT_ERROR;
    }

    remainLen += aesDataLen;

    if (packetLen(remainLen) > c->writeBufSize)
	{
        WRITE_IOT_ERROR_LOG("buffer is too short!");
        return CCP_BUFFER_TOO_SHORT;
	}

    ptr = c->writeBuf;
    header.byte = 0;
    header.bits.hasData = 1;
	header.bits.msgType = CONNECT;
	writeChar(&ptr, header.byte);  /* write header */

	ptr += encodeVariableNumber(ptr, remainLen);  /* write remaining length */

    memcpy(ptr, data, dataLen);
    ptr += dataLen;
    memcpy(ptr, aesData, aesDataLen);
    ptr += aesDataLen;

    msgLen = ptr - c->writeBuf;
    if (msgLen > 0)
    {
        return msgLen;
    }
    else
    {
        return CCP_DATA_ERROR;
    }
}

int CCPSendConnectMsg(CLIENT_S *c, const CCP_CONNECT_S *req)
{
    int rc;
    int msgLen;
    CCP_CONNECT_ACK_S resp;

    if ((NULL == c) || (NULL == req))
    {
        WRITE_IOT_ERROR_LOG("invalid parameter!");
        return CCP_INVALID_PARAMETER;
    }

    aliyun_iot_mutex_lock(&c->clientStatusMutex);
    if (CLIENT_STATUS_CONNECTED == getStatus(c))
    {
        WRITE_IOT_INFO_LOG("ccp has already connected!");
        aliyun_iot_mutex_unlock(&c->clientStatusMutex);
        return SUCCESS_RETURN;
    }
    aliyun_iot_mutex_unlock(&c->clientStatusMutex);

    //使用过程中调用此次接口时避免泄露没有释放的fd
    if(NULL != c->network.disconnect)
    {
        c->network.disconnect(&c->network);
    }

    if (SUCCESS_RETURN != connectNetwork(&c->network, c->serverIp, c->serverPort))
	{
		WRITE_IOT_ERROR_LOG("connect network failed!");
		return CCP_CONNECT_NETWORK_ERROR;
	}

    aliyun_iot_mutex_lock(&c->writeBufMutex);
    msgLen = CCPSerializeConnectMsg(c, req);
    if (msgLen < 0)
    {
        WRITE_IOT_ERROR_LOG("serialize connect message failed!");
        aliyun_iot_mutex_unlock(&c->writeBufMutex);
        c->network.disconnect(&c->network);
        return msgLen;
    }

    if (SUCCESS_RETURN != sendPacket(c, msgLen, c->commandTimeout))
    {
        WRITE_IOT_ERROR_LOG("send packet failed!");
        aliyun_iot_mutex_unlock(&c->writeBufMutex);
        c->network.disconnect(&c->network);
        return CCP_SEND_PACKET_ERROR;
    }
    aliyun_iot_mutex_unlock(&c->writeBufMutex);

    memset(&resp, 0, sizeof(CCP_CONNECT_ACK_S));

    // this will be a blocking call, wait for the connect ack
    if (CONNECT_ACK == (rc = connectCycle(c, c->commandTimeout)))
    {
        if (SUCCESS_RETURN != (rc = CCPDeserializeConnectAckMsg(c->readBuf, &resp)))
        {
            WRITE_IOT_ERROR_LOG("deserialize connect ack message failed!");
            c->network.disconnect(&c->network);
            return rc;
        }
    }
    else
    {
        WRITE_IOT_ERROR_LOG("wait for connect ack failed!");
        c->network.disconnect(&c->network);
        return rc;
    }

    if (RESPONSE_SUCCESS == resp.StatusCode)
    {
        WRITE_IOT_INFO_LOG("ccp connect success!");
        c->keepAliveInterval = resp.keepalive;

        aliyun_iot_mutex_lock(&c->keepAliveTimerMutex);
        aliyun_iot_timer_cutdown(&c->keepAliveTimer, c->keepAliveInterval * 1000);
        aliyun_iot_mutex_unlock(&c->keepAliveTimerMutex);

        memset(c->connectionToken, 0, sizeof(c->connectionToken));
        strncpy(c->connectionToken, resp.ConnectionToken, sizeof(c->connectionToken) - 1);
        c->connect = *req;

        aliyun_iot_mutex_lock(&c->clientStatusMutex);
        setStatus(c, CLIENT_STATUS_CONNECTED);
        aliyun_iot_mutex_unlock(&c->clientStatusMutex);

        aliyun_iot_mutex_lock(&c->reconnectIntervalMutex);
        c->reconnectInterval = RECONNECT_MIN_INTERVAL;
        aliyun_iot_mutex_unlock(&c->reconnectIntervalMutex);

        if (NULL != c->onConnect)
        {
            WRITE_IOT_INFO_LOG("ccp connect success notify connect!");
            c->onConnect();
        }

        if (!c->hasReconnectThread)
        {
            if (SUCCESS_RETURN != (rc = createReconnectThread(c)))
            {
                WRITE_IOT_ERROR_LOG("create keepalive thread failed!");
                return rc;
            }
            c->hasReconnectThread = 1;
        }
        else
        {
            WRITE_IOT_INFO_LOG("keepalive thread has already existed!");
        }

        if (!c->hasReceiveThread)
        {
            if (SUCCESS_RETURN != (rc = createReceiveThread(c)))
            {
                WRITE_IOT_ERROR_LOG("create receive thread failed!");
                return rc;
            }
            c->hasReceiveThread = 1;
        }
        else
        {
            WRITE_IOT_INFO_LOG("receive thread has already existed!");
        }

        if (!c->hasRetransThread)
        {
            if (SUCCESS_RETURN != (rc = createRetransThread(c)))
            {
                WRITE_IOT_ERROR_LOG("create retrans thread failed!");
                return rc;
            }
            c->hasRetransThread = 1;
        }
        else
        {
            WRITE_IOT_INFO_LOG("retrans thread has already existed!");
        }

        return SUCCESS_RETURN;
    }
    else
    {
        WRITE_IOT_ERROR_LOG("ccp connect failed!");
        c->network.disconnect(&c->network);
        return CCP_CONNECT_ERROR;
    }
}

