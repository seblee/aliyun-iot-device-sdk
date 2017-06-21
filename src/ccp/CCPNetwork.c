#include "CCPNetwork.h"
#define SOCKET_READ_TIMEOUT_MS 50
#define SOCKET_WRITE_TIMEOUT_MS 50

int ccpread(NETWORK_S *n, unsigned char *buffer, int len, int timeout_ms)
{
    int rc;
    int ret;
    INT32 lefttime;
    INT32 recvlen = 0;
    ALIYUN_IOT_TIME_TYPE_S endTime;

    aliyun_iot_timer_init(&endTime);
    aliyun_iot_timer_cutdown(&endTime, timeout_ms);

    do
    {

        lefttime = aliyun_iot_timer_remain(&endTime);
        if (lefttime <= 0)
        {
            WRITE_IOT_ERROR_LOG("ccp read timeout!");
            return -1;
        }

        IOT_NET_FD_ISSET_E result;
        ret = aliyun_iot_network_select(n->socketFd,IOT_NET_TRANS_RECV,lefttime,&result);
        if (ret < 0)
        {
            if (NETWORK_SIGNAL_INTERRUPT == ret)
            {
                continue;
            }

            WRITE_IOT_ERROR_LOG("ccp read select failed ret = %d!", ret);
            return -1;
        }
        else if (0 == ret)
        {
            WRITE_IOT_ERROR_LOG("ccp read select timeout!");
            return -1;
        }
        else if (1 == ret)
        {
            if (IOT_NET_FD_NO_ISSET == result)
            {
                WRITE_IOT_ERROR_LOG("another fd readable!");
                continue;
            }

            aliyun_iot_network_settimeout(n->socketFd,SOCKET_READ_TIMEOUT_MS,IOT_NET_TRANS_RECV);

            rc = aliyun_iot_network_recv(n->socketFd, buffer + recvlen, len - recvlen, IOT_NET_FLAGS_DEFAULT);
            if (rc > 0)
            {
                recvlen += rc;
            }
            else if (0 == rc)
            {
                WRITE_IOT_ERROR_LOG("connection is closed by peer, recvlen = %d!", recvlen);
                return -1;
            }
            else
            {
                int err = aliyun_iot_get_errno();
                if ((EINTR_IOT == err) || (EWOULDBLOCK_IOT == err) || (EAGAIN_IOT == err))
                {
                    continue;
                }
                else
                {
                    WRITE_IOT_ERROR_LOG("ccp read failed, rc = %d, err = %d, recvlen = %d", rc, err, recvlen);
                    return -1;
                }
            }
        }
    }while(recvlen < len);

    return recvlen;
}

int ccpwrite(NETWORK_S *n, unsigned char *buffer, int len, int timeout_ms)
{
    int rc;
    int ret;
    INT32 lefttime;
    INT32 sendlen = 0;
    ALIYUN_IOT_TIME_TYPE_S endTime;
    aliyun_iot_timer_init(&endTime);
    aliyun_iot_timer_cutdown(&endTime, timeout_ms);

    do
    {
        lefttime = aliyun_iot_timer_remain(&endTime);
        if (lefttime <= 0)
        {
            WRITE_IOT_ERROR_LOG("ccp write timeout!");
            return -1;
        }

        IOT_NET_FD_ISSET_E result;
        ret = aliyun_iot_network_select(n->socketFd,IOT_NET_TRANS_SEND,lefttime,&result);
        if (ret < 0)
        {
            if (NETWORK_SIGNAL_INTERRUPT == ret)
            {
                continue;
            }

            WRITE_IOT_ERROR_LOG("ccp write select failed, ret = %d!", ret);
            return -1;
        }
        else if (0 == ret)
        {
            WRITE_IOT_ERROR_LOG("ccp write select timeout!");
            return -1;
        }
        else if (1 == ret)
        {
            if (IOT_NET_FD_NO_ISSET == result)
            {
                WRITE_IOT_ERROR_LOG("another fd writeable!");
                continue;
            }

            aliyun_iot_network_settimeout(n->socketFd,SOCKET_WRITE_TIMEOUT_MS,IOT_NET_TRANS_SEND);

            rc = aliyun_iot_network_send(n->socketFd, buffer, len, IOT_NET_FLAGS_DEFAULT);
            if(rc > 0)
            {
                sendlen += rc;
            }
            else if(rc == 0)
            {
                WRITE_IOT_ERROR_LOG("ccp network is broken, sendlen = %d!", sendlen);

                return -1;
            }
            else
            {
                int err = aliyun_iot_get_errno();
                if ((EINTR_IOT == err) || (EWOULDBLOCK_IOT == err) || (EAGAIN_IOT == err))
                {
                    continue;
                }
                else
                {
                    WRITE_IOT_ERROR_LOG("ccp write failed, rc = %d, err = %d, sendlen = %d!", rc, err, sendlen);
                    return -3;
                }
            }
        }
    }while(sendlen < len);

    return sendlen;
}

void disconnect(NETWORK_S *n)
{
    if( n->socketFd < 0 )
    {
        return;
    }

    aliyun_iot_network_shutdown( n->socketFd, 2 );
    aliyun_iot_pthread_taskdelay(20);
    aliyun_iot_network_close(n->socketFd);

    n->socketFd = -1;
}

void initNetwork(NETWORK_S *n)
{
	n->socketFd = -1;
	n->ccpread = ccpread;
	n->ccpwrite = ccpwrite;
	n->disconnect = disconnect;
}

int connectNetwork(NETWORK_S *n, char *addr, int port)
{	
	char serverPort[8] = {0};
	sprintf(serverPort, "%d", port);
    n->socketFd = aliyun_iot_network_create(addr, serverPort,IOT_NET_PROTOCOL_TCP);
    if(n->socketFd < 0 )
    {
        return n->socketFd;
    }
	return SUCCESS_RETURN;
}

