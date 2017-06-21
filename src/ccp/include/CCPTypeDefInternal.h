#ifndef __CCP_TYPE_DEF_INTERNAL_
#define __CCP_TYPE_DEF_INTERNAL_

#include "aliyun_iot_platform_timer.h"

#include "CCPTypeDef.h"

#define SDK_VERSION "1.0.0"

#define DATA_MAX_LEN 262144    // 256KB

#define CCP_PROTOCOL_VERSION 21

#define RPC_VERSION 2
#define RPC_PLATFORM_ID 2
#define RPC_API_TYPE 3
#define RPC_RESOURCE_TYPE 2
#define RPC_CONTENT_TYPE 2
#define RPC_RESERVE_HEADERS 0

#define APP_ID 0

#define COMMAND_TIMEOUT_MIN_TIME 500    // 单位为毫秒
#define COMMAND_TIMEOUT_MAX_TIME 5000    // 单位为毫秒

#define RECONNECT_MIN_INTERVAL 1    // 单位为秒
#define RECONNECT_MAX_INTERVAL 60    // 单位为秒
#define RECONNECT_NUM_MAX       2   //重连数量最大值

#define RECONNECT_INTERVAL_DEVICE_ABNORMAL 0xffffffff

#define REPUBLISH_LIST_MAX_LEN 20
#define UNACK_LIST_MAX_LEN 10

// PushAck类型
typedef enum PushAckType {
    PUSH_ACCEPT = 0x03,    // Push消息已接受
    PUSH_OPEN = 0x04,    // Push消息已打开
    PUSH_DELETE = 0x08    // Push消息已删除
} PUSH_ACK_TYPE_E;

// 服务器信息
typedef struct ServerInfo {
    char deviceId[64];    // 设备ID
    char pkVersion[16];    // 证书版本(如果不传，则默认使用最新版本证书校验)
    char pubKey[3072];    // 服务器证书(未base64解码)
    char servers[32];    // 应用服务器地址(包含多个端口)
    char sign[64];    // 服务器签名
    char sid[128];    // sessionID(未解密)
} SERVER_INFO_S;

// ConnectAck响应结构体
typedef struct CCPConnectAck {
    unsigned int SequenceId;    // 服务器响应的消息ID
    short keepalive;    // 服务器返回的保活时长，单位为秒
    char StatusCode;    // 服务器返回状态码，详见STATUS_CODE_E定义
    char ConnectionToken[64];    // 连接的token
    char SuggestionIPs[32];    // 下一次连接的推荐IP地址, 用于下一次连接就近网络, 返回空则不用处理
} CCP_CONNECT_ACK_S;

// Reconnect请求结构体
typedef struct CCPReconnect {
    int limit;    // 离线消息最大限制数
    short keepalive;  // 设置的保活时长，单位为秒，必须大于60秒
    char ipSwitchFlag;    // 连接的IP是否发生了切换，1表示发生了切换，0表示没有发生切换
    char network;    // 网络信息，高4位_网络类型 0(未知)、2(WIFI)、3(2g)、4(3g)、5(4g)，低4位_运营商类型 0(未知)、2(移动)、3(联通)、4(电信)
    char ConnectionToken[64];    // 连接的token
} CCP_RECONNECT_S;

// ReconnectAck响应结构体
typedef struct CCPReconnectAck {
    unsigned int SequenceId;    // 服务器响应的消息ID
    short keepalive;    // 服务端返回的保活时长，单位为秒
    char StatusCode;    // 服务器返回状态码，详见STATUS_CODE_E定义
    char ConnectionToken[64];    // 连接的token
} CCP_RECONNECT_ACK_S;

// UnknownSession响应结构体
typedef struct CCPUnknownSession {
    char srcMsgType;    // 源消息类型
    char statusCode;    // 服务器返回状态码，详见STATUS_CODE_E定义
} CCP_UNKNOWN_SESSION_S;

// Push请求结构体
typedef struct CCPPush {
    unsigned int SequenceId;    // 服务器请求的消息ID
    unsigned int MessageId;    // Push消息ID
    int contentLen;    // Push数据长度，可以等于0
    unsigned char *Content;    // Push数据指针，数据长度等于0时为NULL
} CCP_PUSH_S;

// PushAck响应结构体
typedef struct CCPPushAck {
    unsigned int SequenceId;    // 客户端响应的消息ID，需要与服务器请求的消息ID一致
    unsigned int MessageId;    // PushAck消息ID
    char type;    // PushAck类型，详见PUSH_ACK_TYPE_E定义
} CCP_PUSH_ACK_S;

//#ifndef _BIG_ENDIAN_
//#define _BIG_ENDIAN_ 1
//#endif

typedef union CCPHeader {
	unsigned char byte;
	struct {
	#ifdef _BIG_ENDIAN_
		unsigned int msgType : 5;
		unsigned int compress : 1;
		unsigned int qosLevel : 1;
		unsigned int hasData : 1;
	#else
        unsigned int hasData : 1;
        unsigned int qosLevel : 1;
        unsigned int compress : 1;
		unsigned int msgType : 5;
	#endif
	} bits;
} CCP_HEADER_S;

typedef struct ErrorInfo {
    char errorCode[16];
    char message[32];
} ERROR_INFO_S;

typedef struct RepublishMessage {
    char removeFlag;
    ALIYUN_IOT_TIME_TYPE_S timer;
    CCP_PUBLISH_S req;
} REPUBLISH_MESSAGE_S;

typedef struct UnackMessage {
    char removeFlag;
    ALIYUN_IOT_TIME_TYPE_S timer;
    CCP_MESSAGE_S req;
} UNACK_MESSAGE_S;

#endif /* __CCP_TYPE_DEF_INTERNAL_ */

