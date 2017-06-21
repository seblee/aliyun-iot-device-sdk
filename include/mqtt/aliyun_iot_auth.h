/*********************************************************************************
 * 文件名称: aliyun_iot_auth.h
 * 版       本:
 * 日       期: 2016-05-30
 * 描       述: iot鉴权
 * 说       明: 此文件包含设备端IOTsdk的鉴权接口和数据相关内容
 * 历       史:
 **********************************************************************************/
#ifndef ALIYUN_IOT_AUTH_H
#define ALIYUN_IOT_AUTH_H

#if defined(__cplusplus) /* If this is a C++ compiler, use C linkage */
extern "C"
{
#endif

#include "aliyun_iot_common_datatype.h"
#include "aliyun_iot_common_error.h"

#define MQTT_SDK_VERSION  "1.0.1"

/*******************************************
 * IOTsdk中真假判断标志
*******************************************/
typedef enum IOT_BOOL_VALUE
{
    IOT_VALUE_FALSE = 0,
    IOT_VALUE_TRUE,
}IOT_BOOL_VALUE_E;

/*******************************************
 * 鉴权状态类型
*******************************************/
typedef enum USER_AUTH_STATE
{
    AUTH_NONE = 0,     //没有鉴权
    AUTH_SUCCESS,      //鉴权成功
    AUTH_FAILS,        //鉴权失败
}USER_AUTH_STATE_E;

/*******************************************
 * 签名类型
*******************************************/
typedef enum SIGN_DATA_TYPE
{
    HMAC_MD5_SIGN_TYPE = 0, //Hmac_MD5（默认）
    HMAC_SHA1_SIGN_TYPE,    //Hmac_SHA1
    MD5_SIGN_TYPE,          //MD5
}SIGN_DATA_TYPE_E;

/*******************************************
 * 设备信息影子数据类型，只用于参数传递
*******************************************/
typedef struct IOT_DEVICEINFO_SHADOW
{
    INT8* hostName;           //鉴权服务器
    INT8* productKey;         //产品key
    INT8* productSecret;      //产品密钥
    INT8* deviceName;         //设备名称
    INT8* deviceSecret;       //设备密钥
}IOT_DEVICEINFO_SHADOW_S;

/***********************************************************
* 函数名称: aliyun_iot_auth_init
* 描       述: auth初始化函数
* 输入参数: VOID
* 输出参数: VOID
* 返 回  值: 0 成功，-1 失败
* 说       明: 初始化日志级别，设备信息，鉴权信息文件的保存路径
************************************************************/
INT32 aliyun_iot_auth_init();

/***********************************************************
* 函数名称: aliyun_iot_auth_release
* 描       述: auth释放函数
* 输入参数: VOID
* 输出参数: VOID
* 返 回  值: 0:成功 -1:失败
* 说      明: 释放authInfo内存
************************************************************/
INT32 aliyun_iot_auth_release();

/***********************************************************
* 函数名称: aliyun_iot_set_device_info
* 描       述: 设置设备信息
* 输入参数: IOT_DEVICEINFO_SHADOW_S*deviceInfo
* 输出参数: VOID
* 返 回  值: 0：成功  -1：失败
* 说       明: 将在aliyun注册的设备信息设置到SDK中的设备变量中
************************************************************/
INT32 aliyun_iot_set_device_info(IOT_DEVICEINFO_SHADOW_S*deviceInfo);

/***********************************************************
* 函数名称: aliyun_iot_auth
* 描       述: sdk用户鉴权函数
* 输入参数: SIGN_DATA_TYPE_E signDataType 签名类型
*          IOT_BOOL_VALUE_E haveFilesys 是否有文件系统
* 返 回  值: 0：成功  -1：失败
* 说       明: 鉴权得到公钥证书并生成用户信息
************************************************************/
INT32 aliyun_iot_auth(SIGN_DATA_TYPE_E signDataType,IOT_BOOL_VALUE_E haveFilesys);

#if defined(__cplusplus) /* If this is a C++ compiler, use C linkage */
}
#endif


#endif
