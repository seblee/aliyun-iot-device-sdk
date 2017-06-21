#include "aliyun_iot_mqtt_nettype.h"
#include "aliyun_iot_common_log.h"

int aliyun_iot_mqtt_nettype_read(Network *pNetwork, unsigned char *buffer, int len, int timeout_ms)
{
    if(NULL == pNetwork)
    {
        WRITE_IOT_ERROR_LOG("network is null");
        return 1;
    }

    return aliyun_iot_network_ssl_read(&pNetwork->tlsdataparams, buffer, len, timeout_ms);
}

int aliyun_iot_mqtt_nettype_write(Network *pNetwork, unsigned char *buffer, int len, int timeout_ms)
{
    if(NULL == pNetwork)
    {
        WRITE_IOT_ERROR_LOG("network is null");
        return 1;
    }

    return aliyun_iot_network_ssl_write(&pNetwork->tlsdataparams, buffer, len, timeout_ms);
}

void aliyun_iot_mqtt_nettype_disconnect(Network *pNetwork)
{
    if(NULL == pNetwork)
    {
        WRITE_IOT_ERROR_LOG("network is null");
        return;
    }

    aliyun_iot_network_ssl_disconnect(&pNetwork->tlsdataparams);
}

int aliyun_iot_mqtt_nettype_connect(Network *pNetwork)
{
    if(NULL == pNetwork)
    {
        WRITE_IOT_ERROR_LOG("network is null");
        return 1;
    }

    return aliyun_iot_network_ssl_connect(&pNetwork->tlsdataparams, pNetwork->connectparams.pHostAddress, pNetwork->connectparams.pHostPort,
                             pNetwork->connectparams.pPubKey, strlen(pNetwork->connectparams.pPubKey)+1);
}

