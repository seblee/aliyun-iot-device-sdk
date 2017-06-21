#ifndef __CCP_TYPE_DEF_H_
#define __CCP_TYPE_DEF_H_

#if defined(__cplusplus) /* If this is a C++ compiler, use C linkage */
extern "C"
{
#endif

#include "aliyun_iot_common_list.h"
#include "aliyun_iot_platform_timer.h"
#include "aliyun_iot_platform_pthread.h"

#define TOPIC_MAX_NUM 16    // topic数量最大限制
#define TOPIC_MAX_LEN 64    // topic长度最大限制

// 消息类型
typedef enum MessageType {
	CONNECT_ACK = 0x02,
	PUSH = 0x03,
	PUSH_ACK = 0x04,
	PING = 0x05,
	PONG = 0x06,
	DISCONNECT = 0x07,
	RECONNECT = 0x0C,
	RECONNECT_ACK = 0x0D,
	UNKNOWN_SESSION = 0x10,
	RPCREQUEST = 0x11,
	RPCRESPONSE = 0x12,
	CONNECT = 0x13,
	REVERSE_RPCREQUEST = 0x17,
	REVERSE_RPCRESPONSE = 0x18,
	PUBLISH = 0x19,
	PUBLISH_ACK = 0x1A,
	SUBSCRIBE = 0x1B,
	SUBSCRIBE_ACK = 0x1C,
	UNSUBSCRIBE = 0x1D,
	UNSUBSCRIBE_ACK = 0x1E
} MESSAGE_TYPE_E;

// 服务器返回状态码
typedef enum StatusCode {
    RESPONSE_SUCCESS = 0x00,    // 返回成功
    ERROR_VERSION = 0x01,    // 协议版本不正确
    AUTH_FAILED = 0x02,    // 身份验证失败
    EXPIRED_CERT = 0x03,    // 证书已过期
    INVALID_TOKEN = 0x04,    // 无效的token
    UNSAFE_DATA = 0x05,    // 不安全的数据内容
    EXPIRED_TOKEN = 0x06,    // token过期
    INTERNAL_ERROR = 0x07,    // 服务器内部错误
    ERROR_PACKNAME = 0x08,    // app认证packagename不正确(已过期)
    RPC_FAILED = 0x09,    // RPC服务调用失败
    ERROR_SID = 0x0A    // 不正确的sid
} STATUS_CODE_E;

// 签名方式
typedef enum SignMethod {
    SIGN_HMAC_MD5 = 0x00,    // HmacMD5签名方式
    SIGN_HMAC_SHA1 = 0x01,    // HmacSHA1签名方式
    SIGN_MD5 = 0x02    // MD5签名方式
} SIGN_METHOD_E;

// client状态
typedef enum ClientStatus {
    CLIENT_STATUS_INIT = 0x00,    // 初始化
    CLIENT_STATUS_CONNECTED = 0x01,    // 已连接
    CLIENT_STATUS_NETWORK_ERROR = 0x02,    // 网络错误
    CLIENT_STATUS_CERT_EXPIRED = 0x03,    // 证书过期
    CLIENT_STATUS_TOKEN_EXPIRED = 0x04,    // token过期
    CLIENT_STATUS_TOKEN_INVALID = 0x05,    // 无效的token
    CLIENT_STATUS_SID_EXPIRED = 0x06,    // sid过期
    CLIENT_STATUS_KEEPALIVE_TIMEOUT = 0x07    // 保活超时
} CLIENT_STATUS_E;

// Publish响应状态
typedef enum PublishStatus {
    PUBLISH_STATUS_SUCCESS = 0x00,    // Publish成功
    PUBLISH_STATUS_NOAUTH = 0x01,    // Publish无权限
    PUBLISH_STATUS_UNKNOWN = 0x08    // Publish未知错误
} PUBLISH_STATUS_E;

// RPC服务响应状态
typedef enum RPCRespStatus {
    RPC_RESP_STATUS_INTERNAL_ERROR = 9,    // RPC服务调用内部错误
	RPC_RESP_STATUS_SUCCESS = 200,    // RPC服务调用成功
	RPC_RESP_STATUS_FORBIDDEN = 403,    // RPC服务调用没有权限
	RPC_RESP_STATUS_NOTFOUND = 404    // RPC服务调用不存在
} RPC_RESP_STATUS_E;

// 鉴权配置信息
typedef struct AuthConfig {
	char productKey[64];    // 产品Key
	char productSecret[64];    // 产品密钥
	char deviceName[64];    // 设备名称
	char deviceSecret[64];    // 设备密钥
	char hostName[64];    // 鉴权服务器域名
    SIGN_METHOD_E signMethod;    // 签名方式，详见SIGN_METHOD_E定义
} AUTH_CONFIG_S;

typedef struct Network NETWORK_S;

// network句柄
struct Network {
	int socketFd;    // socket文件描述符
	int (*ccpread) (NETWORK_S *, unsigned char *, int, int);     // read函数指针
	int (*ccpwrite) (NETWORK_S *, unsigned char *, int, int);    // write函数指针
	void (*disconnect) (NETWORK_S *);                            // disconnect函数指针，此函数close socket后需要初始化为-1，如果为-1则不再执行close操作
};

// 回调消息结构体
typedef struct CCPMessage {
    MESSAGE_TYPE_E msgType;    // 消息类型，详见MESSAGE_TYPE_E定义
    unsigned char compress;    // 数据是否压缩，暂都为0，不压缩
    unsigned char hasData;    // 是否有数据，1表示有，0表示没有
    void *payload;  // 消息内容，根据消息类型强转成对应的结构体指针后使用，使用后无需释放，详见CCP协议的demo
} CCP_MESSAGE_S;

typedef int (*messageHandler) (CCP_MESSAGE_S *);    // 消息回调函数指针，参数详见CCP_MESSAGE_S定义

typedef void (*connectHandler) (void);    // 连接成功回调函数指针

typedef void (*disconnectHandler) (CLIENT_STATUS_E);    // 断线回调函数指针，参数详见CLIENT_STATUS_E定义

typedef void (*timeoutHandler) (CCP_MESSAGE_S *);    // 消息响应超时回调函数指针，参数详见CCP_MESSAGE_S定义

// Connect请求结构体
typedef struct CCPConnect {
    unsigned int limit;    // 离线消息最大限制数
    unsigned short keepalive;  // 设置的保活时长，单位为秒，必须大于60秒
	unsigned char network;    // 网络信息，高4位_网络类型 0(未知)、2(WIFI)、3(2g)、4(3g)、5(4g)，低4位_运营商类型 0(未知)、2(移动)、3(联通)、4(电信)
} CCP_CONNECT_S;

// RPC请求结构体
typedef struct CCPRPCReq {
    unsigned int SequenceId;    // 客户端请求的消息ID，填0表示新消息，会自动赋值，重传消息时需填写和之前消息一致的ID
    unsigned int payloadLen;    // RPCReq数据长度，可以等于0
    unsigned char *payload;    // RPCReq数据指针，数据长度等于0时为NULL
} CCP_RPC_REQ_S;

// RPC响应结构体
typedef struct CCPRPCResp {
    unsigned int SequenceId;    // 服务器响应的消息ID
    unsigned int StatusCode;    // 服务器响应状态码，详见RPC_RESP_STATUS_E定义，其它响应状态码可以由调用服务自行定义
    unsigned int payloadLen;    // RPCResp数据长度，可以等于0
    unsigned char *payload;    // RPCResp数据指针，数据长度等于0时为NULL
} CCP_RPC_RESP_S;

// RRPC请求结构体
typedef struct CCPRRPCReq {
    unsigned int SequenceId;    // 服务器请求的消息ID
    unsigned int payloadLen;    // RRPCReq数据长度，可以等于0
    unsigned char *payload;    // RRPCReq数据指针，数据长度等于0时为NULL
} CCP_RRPC_REQ_S;

// RRPC响应结构体
typedef struct CCPRRPCResp {
    unsigned int SequenceId;    // 客户端响应的消息ID，需要与服务器请求的消息ID一致
    unsigned char statusCode;    // 客户端响应状态码，详见STATUS_CODE_E定义
    unsigned int payloadLen;    // RRPCResp数据长度，可以等于0
    unsigned char *payload;    // RRPCResp数据指针，数据长度等于0时为NULL
} CCP_RRPC_RESP_S;

// Publish请求结构体
typedef struct CCPPublish {
    unsigned int SequenceId;    // 消息ID，发送时为客户端请求的消息ID，填0表示新消息，会自动赋值，重传消息时需填写和之前消息一致的ID，接收时为服务器请求的消息ID
    unsigned int aliveSecond;    // 需要ACK的消息(至少发送一次的消息)存活的时间，如果该值为0，则说明不需要保存(至多发送一次的消息)
    char topic[TOPIC_MAX_LEN + 1];    // topic名称，需要以'/'开头
    unsigned int payloadLen;    // Publish数据长度，可以等于0
    unsigned char *payload;    // Publish数据指针，数据长度等于0时为NULL
} CCP_PUBLISH_S;

// PublishAck响应结构体
typedef struct CCPPublishAck {
    unsigned int SequenceId;    // 消息ID，发送时为客户端响应的消息ID，需要与服务器请求的消息ID一致，接收时为服务器响应的消息ID
    unsigned char code;    // Publish响应状态码，详见PUBLISH_STATUS_E定义
} CCP_PUBLISH_ACK_S;

// Subscribe请求结构体
typedef struct CCPSubscribe {
    unsigned int SequenceId;    // 客户端请求的消息ID，填0表示新消息，会自动赋值，重传消息时需填写和之前消息一致的ID
    unsigned char topicsSize;    // topic数量，至少1个，最多64个
    char topics[TOPIC_MAX_NUM][TOPIC_MAX_LEN + 1];    // topic名称数组，名称需要以'/'开头
} CCP_SUBSCRIBE_S;

// SubscribeAck响应结构体
typedef struct CCPSubscribeAck {
    unsigned int SequenceId;    // 服务器响应的消息ID
    unsigned char codesLen;    // 返回码总长度，至少1个，最多64个返回码
    unsigned char messagesLen;    // 返回消息总长度，至少1个，最多64个返回消息
    unsigned char codes[TOPIC_MAX_NUM];    // 返回码数组
    char messages[TOPIC_MAX_NUM][64];    // 返回消息数组
} CCP_SUBSCRIBE_ACK_S;

// Unsubscribe请求结构体
typedef struct CCPUnsubscribe {
    unsigned int SequenceId;    // 客户端请求的消息ID，填0表示新消息，会自动赋值，重传消息时需填写和之前消息一致的ID
    unsigned char topicsSize;    // topic数量，至少1个，最多64个
    char topics[TOPIC_MAX_NUM][TOPIC_MAX_LEN + 1];    // topic名称数组，名称需要以'/'开头
} CCP_UNSUBSCRIBE_S;

// UnsubscribeAck响应结构体
typedef struct CCPUnsubscribeAck {
    unsigned int SequenceId;    // 服务器响应的消息ID
    unsigned char codesLen;    // 返回码总长度，至少1个，最多64个返回码
    unsigned char codes[TOPIC_MAX_NUM];    // 返回码数组
} CCP_UNSUBSCRIBE_ACK_S;

#define VERSION_STR_LEN       16
#define SERVER_IP_STR_LEN     32
#define SEEDKEY_STR_LEN       32
#define PUBKEY_STR_LEN        2048
#define SID_STR_LEN           128
#define CONNECT_TOKEN_STR_LEN 64
#define DEVICEID_STR_LEN      64

// client句柄
typedef struct Client {
    unsigned int sequenceId;    // 客户端请求的消息ID，从1开始
    unsigned int commandTimeout;    // 发送命令超时时间，单位为毫秒，范围500-5000，等待响应超时时间为这个值的2倍
    unsigned int writeBufSize;    // 写缓存大小，单位为字节
    unsigned int readBufSize;    // 读缓存大小，单位为字节
    unsigned char *writeBuf;    // 写缓存地址
    ALIYUN_IOT_MUTEX_S writeBufMutex;    // 写缓存互斥锁
    unsigned char *readBuf;    // 读缓存地址
	AUTH_CONFIG_S authConfig;    // 鉴权配置信息，详见AUTH_CONFIG_S定义
    int serverPort;    // 应用服务器端口
    char pkVersion[VERSION_STR_LEN];    // 证书版本(如果不传，则默认使用最新版本证书校验)
    char serverIp[SERVER_IP_STR_LEN];    // 应用服务器IP
    char seedKey[SEEDKEY_STR_LEN];    // client端随机生成的16字节字符串
    char pubKey[PUBKEY_STR_LEN];    // 服务器证书(已base64解码)
    char sid[SID_STR_LEN];    // sessionID(已解密)
    char connectionToken[CONNECT_TOKEN_STR_LEN];    // 连接的token
    char deviceId[DEVICEID_STR_LEN];    // 设备ID
    unsigned int reconnectInterval;    // 重连时间间隔，单位为秒
    unsigned int reconnectNum;         // 重连数量
	ALIYUN_IOT_MUTEX_S reconnectIntervalMutex;    // 重连时间间隔互斥锁
	NETWORK_S network;    // network句柄，详见NETWORK_S定义
    CCP_CONNECT_S connect;    // connect请求信息，详见CCP_CONNECT_S定义
	unsigned char hasReconnectThread;    // 是否已有重连线程
    ALIYUN_IOT_PTHREAD_S reconnectThread;    // 重连线程
    unsigned char hasReceiveThread;    // 是否已有接收线程
    ALIYUN_IOT_PTHREAD_S receiveThread;    // 接收线程
	unsigned char hasRetransThread;    // 是否已有重传线程
	ALIYUN_IOT_PTHREAD_S retransThread;    // 重传线程
	unsigned short keepAliveInterval;    // 服务端返回的保活时长，单位为秒
	list_t *rePublishList;    // Publish消息重传队列指针
	ALIYUN_IOT_MUTEX_S rePublishListMutex;    // Publish消息重传队列互斥锁
    list_t *unAckList;    // 等待响应的消息队列指针
	ALIYUN_IOT_MUTEX_S unAckListMutex;    // 等待响应的消息队列互斥锁
    ALIYUN_IOT_TIME_TYPE_S keepAliveTimer;    // 保活定时器
	ALIYUN_IOT_MUTEX_S keepAliveTimerMutex;    // 保活定时器互斥锁
	CLIENT_STATUS_E clientStatus;    // client状态，详见CLIENT_STATUS_E定义
    ALIYUN_IOT_MUTEX_S clientStatusMutex;    // client状态互斥锁
    messageHandler onMessage;    // 消息回调函数指针
	connectHandler onConnect;    // 连接成功回调函数指针
    disconnectHandler onDisconnect;    // 连接断开回调函数指针
	timeoutHandler onTimeout;    // 消息响应超时回调函数指针
} CLIENT_S;

#if defined(__cplusplus) /* If this is a C++ compiler, use C linkage */
}
#endif

#endif /* __CCP_TYPE_DEF_H_ */

