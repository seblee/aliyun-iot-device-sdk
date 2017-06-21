#include "CCPTypeDefInternal.h"
#include "CCPPacket.h"
#include "CCPClientInternal.h"
#include "CCPAuth.h"
#include "CCPPublish.h"
#include "aliyun_iot_common_util.h"

int CCPSerializePublishMsg(CLIENT_S *c, CCP_PUBLISH_S *req)
{
	CCP_HEADER_S header = {0};
	unsigned int remainLen;
    int needAesDataBufSize;
    int aesDataLen;
    int msgLen;
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
    encodeString(&ptr, req->topic, strlen(req->topic));
    ptr += encodeVariableNumber(ptr, req->aliveSecond);
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
	header.bits.msgType = PUBLISH;
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

int CCPDeserializePublishMsg(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_PUBLISH_S *req)
{
	CCP_HEADER_S header = {0};
	unsigned int value;
    int dataLen;
    int payloadLen;
    unsigned char *ptr = buf;

	header.byte = readChar(&ptr);
	if (header.bits.msgType != PUBLISH)
	{
        WRITE_IOT_ERROR_LOG("message type is invalid!");
        return CCP_INVALID_MESSAGE_TYPE;
	}

    msg->msgType = header.bits.msgType;
    msg->compress = header.bits.compress;
    msg->hasData = header.bits.hasData;

	ptr += decodeVariableNumber(ptr, &value);  /* read remaining length */
	if (value < AES_BLOCK_SIZE)
	{
        WRITE_IOT_ERROR_LOG("remaining length is invalid!");
        return CCP_INVALID_REMAIN_LENGTH;
	}

    if (value > DATA_MAX_LEN)
    {
        WRITE_IOT_ERROR_LOG("data is too long!");
        return CCP_DATA_TOO_LONG;
    }

    unsigned char *data = (unsigned char *) aliyun_iot_memory_malloc(value);
    if (NULL == data)
    {
        WRITE_IOT_ERROR_LOG("malloc data buf failed!");
        return CCP_MALLOC_ERROR;
    }
    memset(data, 0, value);

    if (SUCCESS_RETURN != aesEcbDecrypt(ptr, data, value, &dataLen))
    {
        WRITE_IOT_ERROR_LOG("aes decrypt failed!");
        aliyun_iot_memory_free(data);
        return CCP_AES_DECRYPT_ERROR;
    }

    ptr = data;
    ptr += decodeVariableNumber(ptr, &value);
    req->SequenceId = value;
    decodeString(&ptr, req->topic);
    ptr += decodeVariableNumber(ptr, &value);
    req->aliveSecond = value;

    payloadLen = dataLen - (ptr - data);
    if (payloadLen > 0)
    {
        req->payload = (unsigned char *) aliyun_iot_memory_malloc(payloadLen + 1);
        if (NULL == req->payload)
        {
            WRITE_IOT_ERROR_LOG("malloc payload buf failed!");
            aliyun_iot_memory_free(data);
            return CCP_MALLOC_ERROR;
        }
        memset(req->payload, 0, payloadLen + 1);
        memcpy(req->payload, ptr, payloadLen);
    }
    else if (payloadLen < 0)
    {
        WRITE_IOT_ERROR_LOG("payload is invalid!");
        aliyun_iot_memory_free(data);
        return CCP_INVALID_PAYLOAD;
    }

    req->payloadLen = payloadLen;
    aliyun_iot_memory_free(data);

	return SUCCESS_RETURN;
}

int CCPSendPublishMsg(CLIENT_S *c, CCP_PUBLISH_S *req)
{
    int msgLen;
    int rc = SUCCESS_RETURN;

    if ((NULL == c) || (NULL == req))
    {
        WRITE_IOT_ERROR_LOG("invalid parameter!");
        return CCP_INVALID_PARAMETER;
    }

    if(0 != aliyun_iot_common_check_topic(req->topic,TOPIC_NAME_TYPE))
    {
        WRITE_IOT_ERROR_LOG("invalid topic name!");
        return CCP_INVALID_TOPIC_NAME;
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
    msgLen = CCPSerializePublishMsg(c, req);
    if (msgLen < 0)
    {
        WRITE_IOT_ERROR_LOG("serialize publish message failed!");
        aliyun_iot_mutex_unlock(&c->writeBufMutex);
        return msgLen;
    }

    list_node_t *node = NULL;
    if (req->aliveSecond > 0)
    {
        if (SUCCESS_RETURN != (rc = pushPubReqIntoRepubList(c, req, &node)))
        {
            WRITE_IOT_ERROR_LOG("push publish request into republish list failed!");
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
            aliyun_iot_mutex_lock(&c->rePublishListMutex);
            REPUBLISH_MESSAGE_S *republish = (REPUBLISH_MESSAGE_S *) node->val;
            republish->removeFlag = 1;
            if (republish->req.payload)
            {
                aliyun_iot_memory_free(republish->req.payload);
            }
            aliyun_iot_mutex_unlock(&c->rePublishListMutex);
        }
    }
    aliyun_iot_mutex_unlock(&c->writeBufMutex);

    return rc;
}

int CCPResendPublishMsg(CLIENT_S *c, CCP_PUBLISH_S *req)
{
    int msgLen;
    int rc = SUCCESS_RETURN;

    if ((NULL == c) || (NULL == req))
    {
        WRITE_IOT_ERROR_LOG("invalid parameter!");
        return CCP_INVALID_PARAMETER;
    }

    if(0 != aliyun_iot_common_check_topic(req->topic,TOPIC_NAME_TYPE))
    {
        WRITE_IOT_ERROR_LOG("invalid topic name!");
        return CCP_INVALID_TOPIC_NAME;
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
    msgLen = CCPSerializePublishMsg(c, req);
    if (msgLen < 0)
    {
        WRITE_IOT_ERROR_LOG("serialize publish message failed!");
        aliyun_iot_mutex_unlock(&c->writeBufMutex);
        return msgLen;
    }

    if (SUCCESS_RETURN != sendPacket(c, msgLen, c->commandTimeout))
    {
        WRITE_IOT_ERROR_LOG("send packet failed!");
        rc = CCP_SEND_PACKET_ERROR;
    }
    aliyun_iot_mutex_unlock(&c->writeBufMutex);

    return rc;
}

int onCCPPublish(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_PUBLISH_S *req)
{
    int rc;

    if (SUCCESS_RETURN != (rc = CCPDeserializePublishMsg(buf, msg, req)))
    {
        WRITE_IOT_ERROR_LOG("deserialize publish message failed!");
        return rc;
    }

    return SUCCESS_RETURN;
}

int pushPubReqIntoRepubList(CLIENT_S *c, CCP_PUBLISH_S *req, list_node_t **node)
{
    aliyun_iot_mutex_lock(&c->rePublishListMutex);
    if (REPUBLISH_LIST_MAX_LEN == c->rePublishList->len)
    {
        WRITE_IOT_ERROR_LOG("republish list is full!");
        aliyun_iot_mutex_unlock(&c->rePublishListMutex);
        return CCP_REPUBLISH_LIST_FULL;
    }

    REPUBLISH_MESSAGE_S *republish = (REPUBLISH_MESSAGE_S *) aliyun_iot_memory_malloc(sizeof(REPUBLISH_MESSAGE_S));
    if (NULL == republish)
    {
        WRITE_IOT_ERROR_LOG("malloc republish buf failed!");
        aliyun_iot_mutex_unlock(&c->rePublishListMutex);
        return CCP_MALLOC_ERROR;
    }
    memset(republish, 0, sizeof(REPUBLISH_MESSAGE_S));

    aliyun_iot_timer_cutdown(&republish->timer, c->commandTimeout * 2);

    republish->req = *req;
    republish->req.payload = NULL;
    if (republish->req.payloadLen > 0)
    {
        republish->req.payload = (unsigned char *) aliyun_iot_memory_malloc(req->payloadLen + 1);
        if (NULL == republish->req.payload)
        {
            WRITE_IOT_ERROR_LOG("malloc payload buf failed!");
            aliyun_iot_memory_free(republish);
            aliyun_iot_mutex_unlock(&c->rePublishListMutex);
            return CCP_MALLOC_ERROR;
        }
        memset(republish->req.payload, 0, req->payloadLen + 1);
        memcpy(republish->req.payload, req->payload, req->payloadLen);
    }

    *node = list_node_new(republish);
    if (NULL == *node)
    {
        WRITE_IOT_ERROR_LOG("malloc node buf failed!");
        if (republish->req.payload)
        {
            aliyun_iot_memory_free(republish->req.payload);
        }
        aliyun_iot_memory_free(republish);
        aliyun_iot_mutex_unlock(&c->rePublishListMutex);
        return CCP_MALLOC_ERROR;
    }

    list_rpush(c->rePublishList, *node);
    aliyun_iot_mutex_unlock(&c->rePublishListMutex);

    return SUCCESS_RETURN;
}

