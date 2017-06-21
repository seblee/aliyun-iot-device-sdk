#include "CCPTypeDefInternal.h"
#include "CCPPacket.h"
#include "CCPClientInternal.h"
#include "CCPAuth.h"
#include "CCPPushAck.h"

int CCPSerializePushAckMsg(CLIENT_S *c, const CCP_PUSH_ACK_S *resp)
{
	CCP_HEADER_S header = {0};
	unsigned int remainLen;
    unsigned char needAesData[32] = {0};
    unsigned char aesData[32] = {0};
    int aesDataLen;
    int msgLen;
    unsigned char *ptr;

    ptr = needAesData;
    ptr += encodeVariableNumber(ptr, resp->SequenceId);
    ptr += encodeVariableNumber(ptr, resp->MessageId);
    ptr += encodeVariableNumber(ptr, APP_ID);
    writeChar(&ptr, resp->type);

    if (SUCCESS_RETURN != aesEcbEncrypt((unsigned char *) c->seedKey, needAesData, aesData, ptr - needAesData, &aesDataLen))
    {
        WRITE_IOT_ERROR_LOG("aes encrypt failed!");
        return CCP_AES_ENCRYPT_ERROR;
    }

    remainLen = aesDataLen;

    if (packetLen(remainLen) > c->writeBufSize)
	{
        WRITE_IOT_ERROR_LOG("buffer is too short!");
        return CCP_BUFFER_TOO_SHORT;
	}

    ptr = c->writeBuf;
    header.byte = 0;
    header.bits.hasData = 1;
	header.bits.msgType = PUSH_ACK;
	writeChar(&ptr, header.byte);  /* write header */

	ptr += encodeVariableNumber(ptr, remainLen);  /* write remaining length */

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

int CCPSendPushAckMsg(CLIENT_S *c, const CCP_PUSH_ACK_S *resp)
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
    msgLen = CCPSerializePushAckMsg(c, resp);
    if (msgLen < 0)
    {
        WRITE_IOT_ERROR_LOG("serialize push ack message failed!");
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

