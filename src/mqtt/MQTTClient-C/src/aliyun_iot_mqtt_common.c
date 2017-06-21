/*******************************************************************************
 * Copyright (c) 2014 IBM Corp.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *   http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Allan Stockdill-Mander - initial API and implementation and/or initial documentation
 *******************************************************************************/
#include "aliyun_iot_mqtt_common.h"

char expired(Timer* timer)
{
	return (char)aliyun_iot_timer_expired(&timer->end_time);
}

void countdown_ms(Timer* timer, unsigned int timeout)
{
	aliyun_iot_timer_cutdown(&timer->end_time,timeout);
}

void countdown(Timer* timer, unsigned int timeout)
{
	aliyun_iot_timer_cutdown(&timer->end_time,(timeout*1000));
}

int left_ms(Timer* timer)
{
	return aliyun_iot_timer_remain(&timer->end_time);
}

int spend_ms(Timer* timer)
{
    return aliyun_iot_timer_spend(&timer->end_time);
}

void InitTimer(Timer* timer)
{
    aliyun_iot_timer_init(&timer->end_time);
}

void StartTimer(Timer* timer)
{
    aliyun_iot_timer_start_clock(&timer->end_time);
}

void aliyun_iot_mqtt_set_network_param(Network *pNetwork, char *addr, char *port, char *ca_crt)
{
    pNetwork->connectparams.pHostAddress = addr;
    pNetwork->connectparams.pHostPort = port;
    pNetwork->connectparams.pPubKey = ca_crt;
}

int aliyun_iot_mqtt_network_init(Network *pNetwork, char *addr, char *port, char *ca_crt)
{
    aliyun_iot_mqtt_set_network_param(pNetwork, addr, port, ca_crt);

    pNetwork->my_socket = -1;
    pNetwork->mqttread = aliyun_iot_mqtt_nettype_read;
    pNetwork->mqttwrite= aliyun_iot_mqtt_nettype_write;
    pNetwork->disconnect = aliyun_iot_mqtt_nettype_disconnect;
    pNetwork->mqttConnect = aliyun_iot_mqtt_nettype_connect;

    return 0;
}
