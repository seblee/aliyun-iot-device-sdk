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

#ifndef ALIYUN_IOT_MQTT_NET_H
#define ALIYUN_IOT_MQTT_NET_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aliyun_iot_platform_timer.h"
#include "aliyun_iot_platform_network.h"
#include "aliyun_iot_platform_memory.h"
#include "aliyun_iot_common_log.h"
#include "aliyun_iot_mqtt_nettype.h"


typedef struct Timer Timer;

struct Timer {
    ALIYUN_IOT_TIME_TYPE_S end_time;
};

int aliyun_iot_mqtt_network_init(Network *pNetwork, char *addr, char *port,char *ca_crt);
void aliyun_iot_mqtt_set_network_param(Network *pNetwork, char *addr, char *port, char *ca_crt);

char expired(Timer*);
void countdown_ms(Timer*, unsigned int);
void countdown(Timer*, unsigned int);
int left_ms(Timer*);
int spend_ms(Timer*);
void InitTimer(Timer*);
void StartTimer(Timer* timer);

/** Define 0 to disable logging, define 1 to enable logging. */
#define ALI_IOT_MQTT_DEBUG 0

#endif
