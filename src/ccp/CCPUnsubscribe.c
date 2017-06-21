#include "CCPTypeDefInternal.h"
#include "CCPPacket.h"
#include "CCPClientInternal.h"
#include "CCPAuth.h"
#include "CCPUnsubscribe.h"
#include "aliyun_iot_common_util.h"

int CCPSerializeUnsubscribeMsg(CLIENT_S *c, CCP_UNSUBSCRIBE_S *req)
{
	CCP_HEADER_S header = {0};
	unsigned int remainLen;
    int needAesDataBufSize;
    int aesDataLen;
    int i;
    int msgLen;
    unsigned char *ptr;

    needAesDataBufSize = req->topicsSize * (64 + 2) + 8;
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
    writeChar(&ptr, req->topicsSize);
    for (i = 0; i < req->topicsSize; i++)
    {
        encodeString(&ptr, req->topics[i], strlen(req->topics[i]));
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
	header.bits.msgType = UNSUBSCRIBE;
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

int CCPSendUnsubscribeMsg(CLIENT_S *c, CCP_UNSUBSCRIBE_S *req)
{
    int i;
    int msgLen;
    int rc = SUCCESS_RETURN;

    if ((NULL == c) || (NULL == req))
    {
        WRITE_IOT_ERROR_LOG("invalid parameter!");
        return CCP_INVALID_PARAMETER;
    }

    for (i = 0; i < req->topicsSize; i++)
    {
        if(0 != aliyun_iot_common_check_topic(req->topics[i],TOPIC_NAME_TYPE))
        {
            WRITE_IOT_ERROR_LOG("invalid topic name!");
            return CCP_INVALID_TOPIC_NAME;
        }
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
    msgLen = CCPSerializeUnsubscribeMsg(c, req);
    if (msgLen < 0)
    {
        WRITE_IOT_ERROR_LOG("serialize unsubscribe message failed!");
        aliyun_iot_mutex_unlock(&c->writeBufMutex);
        return msgLen;
    }

    list_node_t *node = NULL;
    if (NULL != c->onTimeout)
    {
        if (SUCCESS_RETURN != (rc = pushUnsubReqIntoUnackList(c, req, &node)))
        {
            WRITE_IOT_ERROR_LOG("push unsubscribe request into unack list failed!");
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
            CCP_UNSUBSCRIBE_S *unsubReq = (CCP_UNSUBSCRIBE_S *) unack->req.payload;
            unack->removeFlag = 1;
            aliyun_iot_memory_free(unsubReq);
            aliyun_iot_mutex_unlock(&c->unAckListMutex);
        }
    }
    aliyun_iot_mutex_unlock(&c->writeBufMutex);

    return rc;
}

int pushUnsubReqIntoUnackList(CLIENT_S *c, CCP_UNSUBSCRIBE_S *req, list_node_t **node)
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

    unack->req.msgType = UNSUBSCRIBE;
    unack->req.hasData = 1;
    CCP_UNSUBSCRIBE_S *unsubReq = (CCP_UNSUBSCRIBE_S *) aliyun_iot_memory_malloc(sizeof(CCP_UNSUBSCRIBE_S));
    if (NULL == unsubReq)
    {
        WRITE_IOT_ERROR_LOG("malloc unsubscribe request buf failed!");
        aliyun_iot_memory_free(unack);
        aliyun_iot_mutex_unlock(&c->unAckListMutex);
        return CCP_MALLOC_ERROR;
    }
    memset(unsubReq, 0, sizeof(CCP_UNSUBSCRIBE_S));

    *unsubReq = *req;
    unack->req.payload = unsubReq;

    *node = list_node_new(unack);
    if (NULL == *node)
    {
        WRITE_IOT_ERROR_LOG("malloc node buf failed!");
        aliyun_iot_memory_free(unsubReq);
        aliyun_iot_memory_free(unack);
        aliyun_iot_mutex_unlock(&c->unAckListMutex);
        return CCP_MALLOC_ERROR;
    }

    list_rpush(c->unAckList, *node);
    aliyun_iot_mutex_unlock(&c->unAckListMutex);

    return SUCCESS_RETURN;
}

