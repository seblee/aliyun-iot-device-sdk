#include "CCPTypeDefInternal.h"
#include "CCPPacket.h"
#include "CCPClientInternal.h"
#include "CCPAuth.h"
#include "CCPRRPCResponse.h"

int CCPSerializeRRPCResponseMsg(CLIENT_S *c, const CCP_RRPC_RESP_S *resp)
{
	CCP_HEADER_S header = {0};
	unsigned int remainLen;
    int needAesDataBufSize;
    int aesDataLen;
    int msgLen;
    unsigned char *ptr;

    if ((resp->payloadLen < 0) || (resp->payloadLen > 0 && !resp->payload))
    {
        WRITE_IOT_ERROR_LOG("payload is invalid!");
        return CCP_INVALID_PAYLOAD;
    }

    needAesDataBufSize = resp->payloadLen + 16;
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
    ptr += encodeVariableNumber(ptr, resp->SequenceId);
    writeChar(&ptr, resp->statusCode);
    ptr += encodeVariableNumber(ptr, resp->payloadLen);
    if (resp->payloadLen > 0)
    {
        memcpy(ptr, resp->payload, resp->payloadLen);
        ptr += resp->payloadLen;
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
	header.bits.msgType = REVERSE_RPCRESPONSE;
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

int CCPSendRRPCResponseMsg(CLIENT_S *c, const CCP_RRPC_RESP_S *resp)
{
    int msgLen;
    int rc = SUCCESS_RETURN;

    if ((NULL == c) || (NULL == resp))
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
    msgLen = CCPSerializeRRPCResponseMsg(c, resp);
    if (msgLen < 0)
    {
        WRITE_IOT_ERROR_LOG("serialize rrpc response message failed!");
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

