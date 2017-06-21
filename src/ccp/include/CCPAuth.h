#ifndef __CCP_AUTH_
#define __CCP_AUTH_

#include "mbedtls/x509_crt.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
//#include "mbedtls/md5.h"

#include "aliyun_iot_common_log.h"
#include "aliyun_iot_common_base64.h"
#include "aliyun_iot_common_md5.h"
#include "aliyun_iot_common_hmac.h"
#include "aliyun_iot_common_httpclient.h"
#include "aliyun_iot_common_json.h"
#include "aliyun_iot_common_urlencode.h"

#include "aliyun_iot_platform_memory.h"

#include "CCPIoTSDK.h"

#define AES_BLOCK_SIZE 16

int parseResponse(CLIENT_S *c, const char *resp, SERVER_INFO_S *info, ERROR_INFO_S *error);

int parseServers(const char *servers, char *serverIp, int *serverPort);

void genRandomString(int length, unsigned char *randstr);

int genRsaKeyFromCrt(const unsigned char *buf, unsigned int bufLen, mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_x509_crt *crt);

void genSign(CLIENT_S *c, const char *input, int inputLen, char *output, const char *key, int keyLen);

int aesEcbEncrypt(const unsigned char *key, unsigned char *input, unsigned char *output, int in_len, int *out_len);

int aesEcbDecrypt(const unsigned char *input, unsigned char *output, int in_len, int *out_len);

int CCPGetServerInfo(CLIENT_S *c, SERVER_INFO_S *server_info);

int CCPGetSid(CLIENT_S *c, SERVER_INFO_S *server_info, ERROR_INFO_S *error_info);

#endif /* __CCP_AUTH_ */

