#include "CCPTypeDefInternal.h"
#include "CCPPacket.h"
#include "CCPClientInternal.h"
#include "CCPAuth.h"
#include "CCPRPCRequest.h"
#include "aliyun_iot_platform_stdio.h"

int CCPSerializeRPCRequestMsg(CLIENT_S *c, CCP_RPC_REQ_S *req)
{
	CCP_HEADER_S header = {0};
	unsigned int remainLen;
    int needAesDataBufSize;
    int aesDataLen;
    int msgLen;
    char resourceUrl[64] = {0};
    unsigned char *ptr;

    if ((req->payloadLen < 0) || (req->payloadLen > 0 && !req->payload))
    {
        WRITE_IOT_ERROR_LOG("payload is invalid!");
        return CCP_INVALID_PAYLOAD;
    }

    needAesDataBufSize = req->payloadLen + 128;
    if (needAesDataBufSize > DATA_MAX_LEN)
    {
        WRITE_IOT_ERROR_LOG("data is too long!");
        return CCP_DATA_TOO_LONG;
    }

    unsigned char *needAesData = (unsigned char *) aliyun_iot_memory_malloc(needAesDataBufSize);
    if (NULL == needAesData)
    {
        WRITE_IOT_ERROR_LOG("malloc need aes data buf failed!");
        return CCP_MALLOC_ERROR;
    }
    memset(needAesData, 0, needAesDataBufSize);

    ptr = needAesData;
    if (req->SequenceId)
    {
        ptr += encodeVariableNumber(ptr, req->SequenceId);
    }
    else
    {
        ptr += encodeVariableNumber(ptr, c->sequenceId);
        req->SequenceId = c->sequenceId++;
    }
    ptr += encodeVariableNumber(ptr, RPC_VERSION);
    ptr += encodeVariableNumber(ptr, RPC_PLATFORM_ID);
    encodeString(&ptr, c->sid, strlen(c->sid));
    writeChar(&ptr, RPC_API_TYPE);
    writeChar(&ptr, RPC_RESOURCE_TYPE);
    aliyun_iot_stdio_snprintf(resourceUrl, sizeof(resourceUrl) - 1, "%s;%s;1", c->authConfig.productKey, c->authConfig.productKey);
    encodeString(&ptr, resourceUrl, strlen(resourceUrl));
    writeChar(&ptr, RPC_CONTENT_TYPE);
    writeChar(&ptr, RPC_RESERVE_HEADERS);
    if (req->payloadLen > 0)
    {
        memcpy(ptr, req->payload, req->payloadLen);
        ptr += req->payloadLen;
    }

    unsigned char *aesData = (unsigned char *) aliyun_iot_memory_malloc(ptr - needAesData + AES_BLOCK_SIZE);
    if (NULL == aesData)
    {
        WRITE_IOT_ERROR_LOG("malloc aes data buf failed!");
        return CCP_MALLOC_ERROR;
    }
    memset(aesData, 0, ptr - needAesData + AES_BLOCK_SIZE);

    if (SUCCESS_RETURN != aesEcbEncrypt((unsigned char *) c->seedKey, needAesData, aesData, ptr - needAesData, &aesDataLen))
    {
        WRITE_IOT_ERROR_LOG("aes encrypt failed!");
        aliyun_iot_memory_free(needAesData);
        aliyun_iot_memory_free(aesData);
        return CCP_AES_ENCRYPT_ERROR;
    }

    aliyun_iot_memory_free(needAesData);
    remainLen = aesDataLen;

    if (packetLen(remainLen) > c->writeBufSize)
	{
        WRITE_IOT_ERROR_LOG("buffer is too short!");
        aliyun_iot_memory_free(aesData);
        return CCP_BUFFER_TOO_SHORT;
	}

    ptr = c->writeBuf;
    header.byte = 0;
    header.bits.hasData = 1;
	header.bits.msgType = RPCREQUEST;
	writeChar(&ptr, header.byte);  /* write header */

	ptr += encodeVariableNumber(ptr, remainLen);  /* write remaining length */

    memcpy(ptr, aesData, aesDataLen);
    aliyun_iot_memory_free(aesData);
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

int CCPSendRPCRequestMsg(CLIENT_S *c, CCP_RPC_REQ_S *req)
{
    int msgLen;
    int rc = SUCCESS_RETURN;

    if ((NULL == c) || (NULL == req))
    {
        WRITE_IOT_ERROR_LOG("invalid parameter!");
        return CCP_INVALID_PARAMETER;
    }

    aliyun_iot_mutex_lock(&c->clientStatusMutex);
    if (CLIENT_STATUS_CONNECTED != getStatus(c))
    {
        WRITE_IOT_ERROR_LOG("is not connected!");
        aliyun_iot_mutex_unlock(&c->clientStatusMutex);
        return CCP_NOT_CONNECTED;
    }
    aliyun_iot_mutex_unlock(&c->clientStatusMutex);

    aliyun_iot_mutex_lock(&c->writeBufMutex);
    msgLen = CCPSerializeRPCRequestMsg(c, req);
    if (msgLen < 0)
    {
        WRITE_IOT_ERROR_LOG("serialize rpc request message failed!");
        aliyun_iot_mutex_unlock(&c->writeBufMutex);
        return msgLen;
    }

    list_node_t *node = NULL;
    if (NULL != c->onTimeout)
    {
        if (SUCCESS_RETURN != (rc = pushRPCReqIntoUnackList(c, req, &node)))
        {
            WRITE_IOT_ERROR_LOG("push rpc request into unack list failed!");
            aliyun_iot_mutex_unlock(&c->writeBufMutex);
            return rc;
        }
    }

    if (SUCCESS_RETURN != sendPacket(c, msgLen, c->commandTimeout))
    {
        WRITE_IOT_ERROR_LOG("send packet failed!");
        rc = CCP_SEND_PACKET_ERROR;
        if (NULL != node)
        {
            aliyun_iot_mutex_lock(&c->unAckListMutex);
            UNACK_MESSAGE_S *unack = (UNACK_MESSAGE_S *) node->val;
            CCP_RPC_REQ_S *rpcReq = (CCP_RPC_REQ_S *) unack->req.payload;
            unack->removeFlag = 1;
            if (rpcReq->payload)
            {
                aliyun_iot_memory_free(rpcReq->payload);
            }
            aliyun_iot_memory_free(rpcReq);
            aliyun_iot_mutex_unlock(&c->unAckListMutex);
        }
    }
    aliyun_iot_mutex_unlock(&c->writeBufMutex);

    return rc;
}

int pushRPCReqIntoUnackList(CLIENT_S *c, CCP_RPC_REQ_S *req, list_node_t **node)
{
    aliyun_iot_mutex_lock(&c->unAckListMutex);
    if (UNACK_LIST_MAX_LEN == c->unAckList->len)
    {
        WRITE_IOT_ERROR_LOG("unack list is full!");
        aliyun_iot_mutex_unlock(&c->unAckListMutex);
        return CCP_UNACK_LIST_FULL;
    }

    UNACK_MESSAGE_S *unack = (UNACK_MESSAGE_S *) aliyun_iot_memory_malloc(sizeof(UNACK_MESSAGE_S));
    if (NULL == unack)
    {

        WRITE_IOT_ERROR_LOG("malloc unack buf failed!");
        aliyun_iot_mutex_unlock(&c->unAckListMutex);
        return CCP_MALLOC_ERROR;
    }
    memset(unack, 0, sizeof(UNACK_MESSAGE_S));

    aliyun_iot_timer_cutdown(&unack->timer, c->commandTimeout * 2);

    unack->req.msgType = RPCREQUEST;
    unack->req.hasData = 1;
    CCP_RPC_REQ_S *rpcReq = (CCP_RPC_REQ_S *) aliyun_iot_memory_malloc(sizeof(CCP_RPC_REQ_S));
    if (NULL == rpcReq)
    {
        WRITE_IOT_ERROR_LOG("malloc rpc request buf failed!");
        aliyun_iot_memory_free(unack);
        aliyun_iot_mutex_unlock(&c->unAckListMutex);
        return CCP_MALLOC_ERROR;
    }
    memset(rpcReq, 0, sizeof(CCP_RPC_REQ_S));

    *rpcReq = *req;
    rpcReq->payload = NULL;
    if (rpcReq->payloadLen > 0)
    {
        rpcReq->payload = (unsigned char *) aliyun_iot_memory_malloc(req->payloadLen + 1);
        if (NULL == rpcReq->payload)
        {
            WRITE_IOT_ERROR_LOG("malloc payload buf failed!");
            aliyun_iot_memory_free(rpcReq);
            aliyun_iot_memory_free(unack);
            aliyun_iot_mutex_unlock(&c->unAckListMutex);
            return CCP_MALLOC_ERROR;
        }
        memset(rpcReq->payload, 0, req->payloadLen + 1);
        memcpy(rpcReq->payload, req->payload, req->payloadLen);
    }

    unack->req.payload = rpcReq;

    *node = list_node_new(unack);
    if (NULL == *node)
    {
        WRITE_IOT_ERROR_LOG("malloc node buf failed!");
        if (rpcReq->payload)
        {

            aliyun_iot_memory_free(rpcReq->payload);
        }
        aliyun_iot_memory_free(rpcReq);
        aliyun_iot_memory_free(unack);
        aliyun_iot_mutex_unlock(&c->unAckListMutex);
        return CCP_MALLOC_ERROR;
    }

    list_rpush(c->unAckList, *node);
    aliyun_iot_mutex_unlock(&c->unAckListMutex);

    return SUCCESS_RETURN;
}

