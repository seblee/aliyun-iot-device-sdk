/*********************************************************************************
 * 文件名称: aliyun_iot_platform_timer.c
 * 作       者:
 * 版       本:
 * 日       期: 2016-05-30
 * 描       述:
 * 其       它:
 * 历       史:
 **********************************************************************************/

#include <stdlib.h>
#include "aliyun_iot_platform_timer.h"
#include <windows.h>

void aliyun_iot_timer_assignment(INT32 millisecond,ALIYUN_IOT_TIME_TYPE_S *timer)
{
    timer->time = millisecond;
}

INT32 aliyun_iot_timer_start_clock(ALIYUN_IOT_TIME_TYPE_S *timer)
{
    timer->time = GetTickCount();

    return (INT32)SUCCESS_RETURN;
}

INT32 aliyun_iot_timer_spend(ALIYUN_IOT_TIME_TYPE_S *start)
{
    DWORD now, res;

    now = GetTickCount();
    res = now - start->time;
    return res;
}

INT32 aliyun_iot_timer_remain(ALIYUN_IOT_TIME_TYPE_S *end)
{
    DWORD now, res;

    now = GetTickCount();
    res = end->time - now;
    return res;
}

INT32 aliyun_iot_timer_expired(ALIYUN_IOT_TIME_TYPE_S *timer)
{
    DWORD cur_time = 0;
    cur_time = GetTickCount();
    if (timer->time < cur_time || timer->time == cur_time)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

void aliyun_iot_timer_init(ALIYUN_IOT_TIME_TYPE_S* timer)
{
    timer->time = 0;
}

void aliyun_iot_timer_cutdown(ALIYUN_IOT_TIME_TYPE_S* timer,UINT32 millisecond)
{
    timer->time = GetTickCount() + millisecond;
}

UINT32 aliyun_iot_timer_now()
{
    return (UINT32)(GetTickCount());
}

INT32 aliyun_iot_timer_interval(ALIYUN_IOT_TIME_TYPE_S *start,ALIYUN_IOT_TIME_TYPE_S *end)
{
    return (end->time - start->time);
}
