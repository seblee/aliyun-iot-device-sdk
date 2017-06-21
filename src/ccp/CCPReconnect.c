#include "CCPTypeDefInternal.h"
#include "CCPNetwork.h"
#include "CCPPacket.h"
#include "CCPClientInternal.h"
#include "CCPAuth.h"
#include "CCPReconnectAck.h"
#include "CCPReconnect.h"

int CCPSerializeReconnectMsg(CLIENT_S *c, const CCP_RECONNECT_S *req)
{
	CCP_HEADER_S header = {0};
	unsigned int remainLen;
    unsigned char rsaDeviceId[256];
    unsigned int rsaDeviceIdLen;
    unsigned char data[256] = {0};
    int dataLen;
    unsigned char needAesData[128] = {0};
    unsigned char aesData[128] = {0};
    int aesDataLen;
    int msgLen;
    unsigned char *ptr;

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt crt;
    mbedtls_rsa_context *rsa;

    if (SUCCESS_RETURN != genRsaKeyFromCrt((unsigned char *) c->pubKey, strlen(c->pubKey) + 1, &ctr_drbg, &crt))
    {
        WRITE_IOT_ERROR_LOG("generate rsa key failed!");
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_x509_crt_free(&crt);
        return CCP_GEN_RSA_KEY_ERROR;
    }

    rsa = mbedtls_pk_rsa(crt.pk);

    if (0 != mbedtls_rsa_pkcs1_encrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC,
                                  strlen(c->deviceId), (unsigned char *) c->deviceId, rsaDeviceId))
    {
        WRITE_IOT_ERROR_LOG("deviceId rsa encrypt failed!");
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_x509_crt_free(&crt);
        return CCP_RSA_ENCRYPT_ERROR;
    }

    rsaDeviceIdLen = rsa->len;

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_x509_crt_free(&crt);

    ptr = data;
    writeChar(&ptr, CCP_PROTOCOL_VERSION);
    writeChar(&ptr, rsaDeviceIdLen);
    memcpy(ptr, rsaDeviceId, rsaDeviceIdLen);
    ptr += rsaDeviceIdLen;
    writeChar(&ptr, req->ipSwitchFlag);

    dataLen = ptr - data;
    remainLen = dataLen;

    ptr = needAesData;
    ptr += encodeVariableNumber(ptr, c->sequenceId);
    c->sequenceId++;
    writeChar(&ptr, req->network);
    encodeString(&ptr, req->ConnectionToken, strlen(req->ConnectionToken));
    ptr += encodeVariableNumber(ptr, req->limit);
    writeShort(&ptr, req->keepalive);

    if (SUCCESS_RETURN != aesEcbEncrypt((unsigned char *) c->seedKey, needAesData, aesData, ptr - needAesData, &aesDataLen))
    {
        WRITE_IOT_ERROR_LOG("aes encrypt failed!");
        return CCP_AES_ENCRYPT_ERROR;
    }

    remainLen += aesDataLen;

    if (packetLen(remainLen) > c->writeBufSize)
	{
        WRITE_IOT_ERROR_LOG("buffer is too short!");
        return CCP_BUFFER_TOO_SHORT;
	}

    ptr = c->writeBuf;
    header.byte = 0;
    header.bits.hasData = 1;
	header.bits.msgType = RECONNECT;
	writeChar(&ptr, header.byte);  /* write header */

	ptr += encodeVariableNumber(ptr, remainLen);  /* write remaining length */

    memcpy(ptr, data, dataLen);
    ptr += dataLen;
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

int CCPSendReconnectMsg(CLIENT_S *c, const CCP_RECONNECT_S *req)
{
    int rc;
    int msgLen;
    CCP_RECONNECT_ACK_S resp;


    if ((NULL == c) || (NULL == req))
    {
        WRITE_IOT_ERROR_LOG("invalid parameter!");
        return CCP_INVALID_PARAMETER;
    }

    aliyun_iot_mutex_lock(&c->clientStatusMutex);
    if (CLIENT_STATUS_CONNECTED == getStatus(c))
    {
        WRITE_IOT_INFO_LOG("ccp has already connected!");
        aliyun_iot_mutex_unlock(&c->clientStatusMutex);
        return SUCCESS_RETURN;
    }
    aliyun_iot_mutex_unlock(&c->clientStatusMutex);

    //使用过程中调用此次接口时避免泄露没有释放的fd
    if(NULL != c->network.disconnect)
    {
        //此接口需要判断，如果套接字不用关闭则直接退出
        c->network.disconnect(&c->network);
    }

    if (SUCCESS_RETURN != connectNetwork(&c->network, c->serverIp, c->serverPort))
	{
		WRITE_IOT_ERROR_LOG("connect network failed!");
		return CCP_CONNECT_NETWORK_ERROR;
	}

    aliyun_iot_mutex_lock(&c->writeBufMutex);
    msgLen = CCPSerializeReconnectMsg(c, req);
    if (msgLen < 0)
    {
        WRITE_IOT_ERROR_LOG("serialize reconnect message failed!");
        aliyun_iot_mutex_unlock(&c->writeBufMutex);
        c->network.disconnect(&c->network);
        return msgLen;
    }

    if (SUCCESS_RETURN != sendPacket(c, msgLen, c->commandTimeout))
    {
        WRITE_IOT_ERROR_LOG("send packet failed!");
        aliyun_iot_mutex_unlock(&c->writeBufMutex);
        c->network.disconnect(&c->network);
        return CCP_SEND_PACKET_ERROR;
    }
    aliyun_iot_mutex_unlock(&c->writeBufMutex);

    memset(&resp, 0, sizeof(CCP_RECONNECT_ACK_S));

    // this will be a blocking call, wait for the reconnect ack
    if (RECONNECT_ACK == (rc = connectCycle(c, c->commandTimeout)))
    {
        if (SUCCESS_RETURN != (rc = CCPDeserializeReconnectAckMsg(c->readBuf, &resp)))
        {
            WRITE_IOT_ERROR_LOG("deserialize reconnect ack message failed!");
            c->network.disconnect(&c->network);
            return rc;
        }
    }
    else
    {
        WRITE_IOT_ERROR_LOG("wait for reconnect ack failed!");
        c->network.disconnect(&c->network);
        return rc;
    }

    if (RESPONSE_SUCCESS == resp.StatusCode)
    {
        WRITE_IOT_INFO_LOG("ccp reconnect success!");
        c->keepAliveInterval = resp.keepalive;

        aliyun_iot_mutex_lock(&c->keepAliveTimerMutex);
        aliyun_iot_timer_cutdown(&c->keepAliveTimer, c->keepAliveInterval * 1000);
        aliyun_iot_mutex_unlock(&c->keepAliveTimerMutex);

        memset(c->connectionToken, 0, sizeof(c->connectionToken));
        strncpy(c->connectionToken, resp.ConnectionToken, sizeof(c->connectionToken) - 1);

        aliyun_iot_mutex_lock(&c->clientStatusMutex);
        setStatus(c, CLIENT_STATUS_CONNECTED);
        aliyun_iot_mutex_unlock(&c->clientStatusMutex);

        aliyun_iot_mutex_lock(&c->reconnectIntervalMutex);
        c->reconnectInterval = RECONNECT_MIN_INTERVAL;
        aliyun_iot_mutex_unlock(&c->reconnectIntervalMutex);

        if (NULL != c->onConnect)
        {
            WRITE_IOT_INFO_LOG("ccp reconnect success notify connect!");
            c->onConnect();
        }

        return SUCCESS_RETURN;
    }
    else
    {
        WRITE_IOT_ERROR_LOG("ccp reconnect failed!");
        c->network.disconnect(&c->network);
        return CCP_RECONNECT_ERROR;
    }
}

