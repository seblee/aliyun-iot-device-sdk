#include "CCPTypeDefInternal.h"
#include "CCPPacket.h"
#include "CCPClientInternal.h"
#include "CCPPong.h"

int CCPSerializePongMsg(unsigned char *buf, int bufLen)
{
    CCP_HEADER_S header = {0};
	int msgLen;
	unsigned char *ptr = buf;

	if (bufLen < 1)
	{
        WRITE_IOT_ERROR_LOG("buffer is too short");
        return CCP_BUFFER_TOO_SHORT;
	}

	header.byte = 0;
	header.bits.msgType = PONG;
	writeChar(&ptr, header.byte);  /* write header */
	msgLen = ptr - buf;

    if (msgLen > 0)
    {
        return msgLen;
    }
    else
    {
        return CCP_DATA_ERROR;
    }
}

int CCPSendPongMsg(CLIENT_S *c)
{
    int msgLen;
    int rc = SUCCESS_RETURN;

    aliyun_iot_mutex_lock(&c->writeBufMutex);
    msgLen = CCPSerializePongMsg(c->writeBuf, c->writeBufSize);
    if (msgLen < 0)
    {
        WRITE_IOT_ERROR_LOG("serialize pong message failed!");
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

