#include "CCPTypeDefInternal.h"
#include "CCPPacket.h"
#include "CCPAuth.h"
#include "CCPPush.h"

int CCPDeserializePushMsg(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_PUSH_S *req)
{
	CCP_HEADER_S header = {0};
	unsigned int value;
    int dataLen;
    int contentLen;
    int appId;
    unsigned char *ptr = buf;

	header.byte = readChar(&ptr);
	if (header.bits.msgType != PUSH)
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
    ptr += decodeVariableNumber(ptr, &value);
    req->MessageId = value;
    ptr += decodeVariableNumber(ptr, &value);
    appId = value;

    contentLen = dataLen - (ptr - data);
    if (contentLen > 0)
    {
        req->Content = (unsigned char *) aliyun_iot_memory_malloc(contentLen + 1);
        if (NULL == req->Content)
        {
            WRITE_IOT_ERROR_LOG("malloc content buf failed!");
            aliyun_iot_memory_free(data);
            return CCP_MALLOC_ERROR;
        }
        memset(req->Content, 0, contentLen + 1);
        memcpy(req->Content, ptr, contentLen);
    }
    else if (contentLen < 0)
    {
        WRITE_IOT_ERROR_LOG("payload is invalid!");
        aliyun_iot_memory_free(data);
        return CCP_INVALID_PAYLOAD;
    }

    req->contentLen = contentLen;
    aliyun_iot_memory_free(data);

	return SUCCESS_RETURN;
}

int onCCPPush(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_PUSH_S *req)
{
    int rc;

    if (SUCCESS_RETURN != (rc = CCPDeserializePushMsg(buf, msg, req)))
    {
        WRITE_IOT_ERROR_LOG("deserialize push message failed!");
        return rc;
    }

    return SUCCESS_RETURN;
}

