#include "aliyun_iot_mqtt_nettype.h"
#include "aliyun_iot_platform_network.h"
#include "aliyun_iot_platform_timer.h"
#include "aliyun_iot_common_log.h"

int ConnectNetwork(Network* pNetwork, char* addr, char* port)
{
    pNetwork->my_socket = aliyun_iot_network_create(addr,port,IOT_NET_PROTOCOL_TCP);
    if(pNetwork->my_socket < 0 )
    {
        return pNetwork->my_socket;
    }

    return SUCCESS_RETURN;
}

int aliyun_iot_mqtt_nettype_read(Network *pNetwork, unsigned char *buffer, int len, int timeout_ms)
{
    int rc = 0;
    int recvlen = 0;
    int ret = -1;

    ALIYUN_IOT_TIME_TYPE_S endTime;
    aliyun_iot_timer_cutdown(&endTime,timeout_ms);
    do
    {
        INT32 lefttime = aliyun_iot_timer_remain(&endTime);
        if(lefttime <= 0)
        {
            WRITE_IOT_ERROR_LOG("mqtt read timeout");
            return -2;
        }

        WRITE_IOT_DEBUG_LOG("mqtt read left time=%d ms", lefttime);

        IOT_NET_FD_ISSET_E result;
        ret = aliyun_iot_network_select(pNetwork->my_socket,IOT_NET_TRANS_RECV,lefttime,&result);
        if (ret < 0)
        {
            INT32 err = aliyun_iot_get_errno();
            if(err == EINTR_IOT)
            {
                continue;
            }
            else
            {
                WRITE_IOT_ERROR_LOG("mqtt read(select) fail ret=%d", ret);
                return -1;
            }
        }
        else if (ret == 0)
        {
            WRITE_IOT_ERROR_LOG("mqtt read(select) timeout");
            return -2;
        }
        else if (ret == 1)
        {
            if(IOT_NET_FD_NO_ISSET == result)
            {
                WRITE_IOT_DEBUG_LOG("another fd readable!");
                continue;
            }

            aliyun_iot_network_settimeout(pNetwork->my_socket,50,IOT_NET_TRANS_RECV);

            WRITE_IOT_DEBUG_LOG("mqtt read recv len = %d, recvlen = %d", len, recvlen);
            rc = aliyun_iot_network_recv(pNetwork->my_socket, buffer + recvlen, len - recvlen, IOT_NET_FLAGS_DEFAULT);
            if (rc > 0)
            {
                recvlen += rc;
                WRITE_IOT_DEBUG_LOG("mqtt read ret=%d, rc = %d, recvlen = %d", ret, rc, recvlen);
            }
            else if(rc == 0)
            {
                WRITE_IOT_ERROR_LOG("The network is broken!,recvlen = %d", recvlen);
                return -3;
            }
            else
            {
                INT32 err = aliyun_iot_get_errno();
                if (err == EINTR_IOT || err == EWOULDBLOCK_IOT || err == EAGAIN_IOT)
                {
                    continue;
                }
                else
                {
                    WRITE_IOT_ERROR_LOG("mqtt read fail: ret=%d, rc = %d, recvlen = %d", ret, rc, recvlen);
                    return -3;
                }
            }
        }

    }while(recvlen < len);

    return recvlen;
}


int aliyun_iot_mqtt_nettype_write(Network *pNetwork, unsigned char *buffer, int len, int timeout_ms)
{
    int rc = 0;
    int ret = -1;
    INT32 sendlen = 0;

    INT32 timeout = timeout_ms;
    ALIYUN_IOT_TIME_TYPE_S endTime;
    aliyun_iot_timer_cutdown(&endTime,timeout);

    do
    {
        INT32 lefttime = aliyun_iot_timer_remain(&endTime);
        if(lefttime <= 0)
        {
            WRITE_IOT_ERROR_LOG("mqtt write timeout");
            return -2;
        }

        IOT_NET_FD_ISSET_E result;
        ret = aliyun_iot_network_select(pNetwork->my_socket,IOT_NET_TRANS_SEND,lefttime,&result);
        if (ret < 0)
        {
            INT32 err = aliyun_iot_get_errno();
            if(err == EINTR_IOT)
            {
                continue;
            }
            else
            {
                WRITE_IOT_ERROR_LOG("mqtt write fail");
                return -1;
            }
        }
        else if (ret == 0)
        {
            WRITE_IOT_ERROR_LOG("mqtt write timeout");
            return -2;
        }
        else if (ret == 1)
        {
            if(IOT_NET_FD_NO_ISSET == result)
            {
                WRITE_IOT_DEBUG_LOG("another fd readable!");
                continue;
            }

            aliyun_iot_network_settimeout(pNetwork->my_socket,50,IOT_NET_TRANS_SEND);

            rc = aliyun_iot_network_send(pNetwork->my_socket, buffer, len, IOT_NET_FLAGS_DEFAULT);
            if(rc > 0)
            {
                sendlen += rc;
            }
            else if(rc == 0)
            {
                WRITE_IOT_ERROR_LOG("The network is broken!");
                return -1;
            }
            else
            {
                INT32 err = aliyun_iot_get_errno();
                if(err == EINTR_IOT || err == EWOULDBLOCK_IOT || err == EAGAIN_IOT)
                {
                    continue;
                }
                else
                {
                    WRITE_IOT_ERROR_LOG("mqtt read fail: ret=%d, rc = %d, err = %d", ret, rc,err);
                    return -3;
                }
            }
        }
    }while(sendlen < len);

    return sendlen;
}

void aliyun_iot_mqtt_nettype_disconnect(Network *pNetwork)
{
    if( pNetwork->my_socket < 0 )
        return;

    aliyun_iot_network_shutdown(pNetwork->my_socket, 2);
    aliyun_iot_pthread_taskdelay(20);
    aliyun_iot_network_close(pNetwork->my_socket);

    pNetwork->my_socket = -1;
}

int aliyun_iot_mqtt_nettype_connect(Network *pNetwork)
{
    if(NULL == pNetwork)
    {
        WRITE_IOT_ERROR_LOG("network is null");
        return 1;
    }

    return ConnectNetwork(pNetwork,pNetwork->connectparams.pHostAddress, pNetwork->connectparams.pHostPort);
}

