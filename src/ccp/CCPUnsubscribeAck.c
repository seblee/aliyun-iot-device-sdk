#include "CCPTypeDefInternal.h"
#include "CCPPacket.h"
#include "CCPAuth.h"
#include "CCPUnsubscribeAck.h"

int CCPDeserializeUnsubscribeAckMsg(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_UNSUBSCRIBE_ACK_S *resp)
{
	CCP_HEADER_S header = {0};
	unsigned int value;
    int dataLen;
    int i;
    unsigned char *ptr = buf;

	header.byte = readChar(&ptr);
	if (header.bits.msgType != UNSUBSCRIBE_ACK)
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
    resp->SequenceId = value;
    resp->codesLen = readChar(&ptr);
    for (i = 0; i < resp->codesLen; i++)
    {
        resp->codes[i] = readChar(&ptr);
    }

    aliyun_iot_memory_free(data);

	return SUCCESS_RETURN;
}

int onCCPUnsubscribeAck(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_UNSUBSCRIBE_ACK_S *resp)
{
    int rc;

    if (SUCCESS_RETURN != (rc = CCPDeserializeUnsubscribeAckMsg(buf, msg, resp)))
    {
        WRITE_IOT_ERROR_LOG("deserialize unsubscribe ack message failed!");
        return rc;
    }

    return SUCCESS_RETURN;
}

