#include "CCPTypeDefInternal.h"
#include "CCPPacket.h"
#include "CCPAuth.h"
#include "CCPConnectAck.h"

int CCPDeserializeConnectAckMsg(unsigned char *buf, CCP_CONNECT_ACK_S *resp)
{
	CCP_HEADER_S header = {0};
	unsigned int value;
    int dataLen;
    unsigned char data[128] = {0};
    char lastestSDKPath[32] = {0};
    unsigned int appId;
    unsigned char *ptr = buf;

	header.byte = readChar(&ptr);
	if (header.bits.msgType != CONNECT_ACK)
	{
        WRITE_IOT_ERROR_LOG("message type is invalid!");
        return CCP_INVALID_MESSAGE_TYPE;
	}

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
    resp->StatusCode = readChar(&ptr);
    decodeString(&ptr, resp->ConnectionToken);
    decodeString(&ptr, resp->SuggestionIPs);
    resp->keepalive = readShort(&ptr);
    decodeString(&ptr, lastestSDKPath);
    ptr += decodeVariableNumber(ptr, &value);
    appId = value;

	return SUCCESS_RETURN;
}

