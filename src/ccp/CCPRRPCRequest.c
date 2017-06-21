#include "CCPTypeDefInternal.h"
#include "CCPPacket.h"
#include "CCPAuth.h"
#include "CCPRRPCResponse.h"

int CCPDeserializeRRPCRequestMsg(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_RRPC_REQ_S *req)
{
	CCP_HEADER_S header = {0};
	unsigned int value;
    int dataLen;
    int appId;
    unsigned char *ptr = buf;

	header.byte = readChar(&ptr);
	if (header.bits.msgType != REVERSE_RPCREQUEST)
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
    appId = value;
    ptr += decodeVariableNumber(ptr, &value);
    req->payloadLen = value;

    if (req->payloadLen > 0)
    {
        req->payload = (unsigned char *) aliyun_iot_memory_malloc(req->payloadLen + 1);
        if (NULL == req->payload)
        {
            WRITE_IOT_ERROR_LOG("malloc payload buf failed!");
            aliyun_iot_memory_free(data);
            return CCP_MALLOC_ERROR;
        }
        memset(req->payload, 0, req->payloadLen + 1);
        memcpy(req->payload, ptr, req->payloadLen);
    }
    else if (req->payloadLen < 0)
    {
        WRITE_IOT_ERROR_LOG("payload is invalid!");
        aliyun_iot_memory_free(data);
        return CCP_INVALID_PAYLOAD;
    }

    aliyun_iot_memory_free(data);

	return SUCCESS_RETURN;
}

int onCCPRRPCRequest(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_RRPC_REQ_S *req)
{
    int rc;

    if (SUCCESS_RETURN != (rc = CCPDeserializeRRPCRequestMsg(buf, msg, req)))
    {
        WRITE_IOT_ERROR_LOG("deserialize rrpc request message failed!");
        return rc;
    }

    return SUCCESS_RETURN;
}

