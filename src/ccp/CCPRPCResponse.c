#include "CCPTypeDefInternal.h"
#include "CCPPacket.h"
#include "CCPAuth.h"
#include "CCPRPCResponse.h"

int CCPDeserializeRPCResponseMsg(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_RPC_RESP_S *resp)
{
	CCP_HEADER_S header = {0};
	unsigned int value;
    int dataLen;
    int payloadLen;
    int ResponseStatus;
    unsigned char ContentType;
    unsigned char responseheader;
    unsigned char responseConfig;
    unsigned char *ptr = buf;

	header.byte = readChar(&ptr);
	if (header.bits.msgType != RPCRESPONSE)
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
    resp->StatusCode = readChar(&ptr);
    ptr += decodeVariableNumber(ptr, &value);
    ResponseStatus = value;
    if (RESPONSE_SUCCESS != resp->StatusCode)
    {
        WRITE_IOT_WARNING_LOG("rpc failed, status code is %d!", resp->StatusCode);
		aliyun_iot_memory_free(data);
        return SUCCESS_RETURN;
    }
    else if (RPC_RESP_STATUS_SUCCESS != ResponseStatus)
    {
        WRITE_IOT_WARNING_LOG("rpc failed, response status is %d!", ResponseStatus);
        resp->StatusCode = ResponseStatus;
		aliyun_iot_memory_free(data);
        return SUCCESS_RETURN;
    }
    resp->StatusCode = ResponseStatus;
    ContentType = readChar(&ptr);
    responseheader = readChar(&ptr);
    responseConfig = readChar(&ptr);

    payloadLen = dataLen - (ptr - data);
    if (payloadLen > 0)
    {
        resp->payload = (unsigned char *) aliyun_iot_memory_malloc(payloadLen + 1);
        if (NULL == resp->payload)
        {
            WRITE_IOT_ERROR_LOG("malloc payload buf failed!");
            aliyun_iot_memory_free(data);
            return CCP_MALLOC_ERROR;
        }
        memset(resp->payload, 0, payloadLen + 1);
        memcpy(resp->payload, ptr, payloadLen);
    }
    else if (payloadLen < 0)
    {
        WRITE_IOT_ERROR_LOG("payload is invalid!");
        aliyun_iot_memory_free(data);
        return CCP_INVALID_PAYLOAD;
    }

    resp->payloadLen = payloadLen;
    aliyun_iot_memory_free(data);

	return SUCCESS_RETURN;
}

int onCCPRPCResponse(unsigned char *buf, CCP_MESSAGE_S *msg, CCP_RPC_RESP_S *resp)
{
    int rc;

    if (SUCCESS_RETURN != (rc = CCPDeserializeRPCResponseMsg(buf, msg, resp)))
    {
        WRITE_IOT_ERROR_LOG("deserialize rpc response message failed!");
        return rc;
    }

    return SUCCESS_RETURN;
}

