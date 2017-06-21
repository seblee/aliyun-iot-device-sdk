#include "CCPTypeDefInternal.h"
#include "CCPPacket.h"
#include "CCPClientInternal.h"
#include "CCPAuth.h"
#include "CCPPublishAck.h"

int CCPSerializePublishAckMsg(CLIENT_S *c, const CCP_PUBLISH_ACK_S *resp)
{
	CCP_HEADER_S header = {0};
	unsigned int remainLen;
    unsigned char needAesData[16] = {0};
    unsigned char aesData[32] = {0};
    int aesDataLen;
    int msgLen;
    unsigned char *ptr;

    ptr = needAesData;
    ptr += encodeVariableNumber(ptr, resp->SequenceId);
    writeChar(&ptr, resp->code);

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
	header.bits.msgType = PUBLISH_ACK;
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

int CCPDeserializePublishAckMsg(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_PUBLISH_ACK_S *resp)
{
	CCP_HEADER_S header = {0};
	unsigned int value;
    int dataLen;
    unsigned char data[32] = {0};
    unsigned char *ptr = buf;

	header.byte = readChar(&ptr);
	if (header.bits.msgType != PUBLISH_ACK)
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

    if (value > sizeof(data))
    {
        WRITE_IOT_ERROR_LOG("data is too long!");
        return CCP_DATA_TOO_LONG;
    }

    if (SUCCESS_RETURN != aesEcbDecrypt(ptr, data, value, &dataLen))
    {
        WRITE_IOT_ERROR_LOG("aes decrypt failed!");
        return CCP_AES_DECRYPT_ERROR;
    }

    ptr = data;
    ptr += decodeVariableNumber(ptr, &value);
    resp->SequenceId = value;
    resp->code = readChar(&ptr);

	return SUCCESS_RETURN;
}

int CCPSendPublishAckMsg(CLIENT_S *c, const CCP_PUBLISH_ACK_S *resp)
{
    int msgLen;
    int rc = SUCCESS_RETURN;

    aliyun_iot_mutex_lock(&c->clientStatusMutex);
    if (CLIENT_STATUS_CONNECTED != getStatus(c))
    {
        WRITE_IOT_ERROR_LOG("is not connected!");
        aliyun_iot_mutex_unlock(&c->clientStatusMutex);
        return CCP_NOT_CONNECTED;
    }
    aliyun_iot_mutex_unlock(&c->clientStatusMutex);

    aliyun_iot_mutex_lock(&c->writeBufMutex);
    msgLen = CCPSerializePublishAckMsg(c, resp);
    if (msgLen < 0)
    {
        WRITE_IOT_ERROR_LOG("serialize publish ack message failed!");
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

int onCCPPublishAck(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_PUBLISH_ACK_S *resp)
{
    int rc;

    if (SUCCESS_RETURN != (rc = CCPDeserializePublishAckMsg(buf, msg, resp)))
    {
        WRITE_IOT_ERROR_LOG("deserialize publish ack message failed!");
        return rc;
    }

    return SUCCESS_RETURN;
}

