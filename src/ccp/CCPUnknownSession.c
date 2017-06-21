#include "CCPTypeDefInternal.h"
#include "CCPPacket.h"
#include "CCPUnknownSession.h"

int CCPDeserializeUnknownSessionMsg(unsigned char *buf, CCP_UNKNOWN_SESSION_S *resp)
{
	CCP_HEADER_S header = {0};
    unsigned int value;
    unsigned char *ptr = buf;

	header.byte = readChar(&ptr);
	if (header.bits.msgType != UNKNOWN_SESSION)
	{
        WRITE_IOT_ERROR_LOG("message type is invalid!");
        return CCP_INVALID_MESSAGE_TYPE;
	}

	ptr += decodeVariableNumber(ptr, &value);  /* read remaining length */
	if (value < 2)
	{
        WRITE_IOT_ERROR_LOG("remaining length is invalid!");
        return CCP_INVALID_REMAIN_LENGTH;
	}

    resp->srcMsgType = readChar(&ptr);
    resp->statusCode = readChar(&ptr);

	return SUCCESS_RETURN;
}

int onCCPUnknownSession(unsigned char *buf, CCP_UNKNOWN_SESSION_S *resp)
{
    int rc;

    if (SUCCESS_RETURN != (rc = CCPDeserializeUnknownSessionMsg(buf, resp)))
    {
        WRITE_IOT_ERROR_LOG("deserialize unknown session message failed!");
        return rc;
    }

    return SUCCESS_RETURN;
}

