#include "CCPTypeDefInternal.h"
#include "CCPAuth.h"
#include "aliyun_iot_platform_stdio.h"

#define HTTP_RESP_MAX_LEN 4096
#define SERVER_SIGN_MAX_LEN 3072
#define CCP_DEVICE_NOT_EXIST_ERRORCODE "InvalidDevice"

static unsigned char g_seedKey[32] = {0};

int parseResponse(CLIENT_S *c, const char *resp, SERVER_INFO_S *info, ERROR_INFO_S *error)
{
    int rc = SUCCESS_RETURN;
    cJSON *json = aliyun_iot_common_json_parse(resp);
    if(NULL == json)
    {
        WRITE_IOT_ERROR_LOG("get NULL pointer of json!");
        return FAIL_RETURN;
    }

    cJSON *result = json->child;

    while (result)
    {
        if (!strcmp(result->string, "deviceId"))
        {
            memset(c->deviceId,0x0,DEVICEID_STR_LEN);
            strncpy(info->deviceId, result->valuestring, sizeof(info->deviceId) - 1);
            strncpy(c->deviceId, result->valuestring, sizeof(c->deviceId) - 1);
        }
        else if (!strcmp(result->string, "pkVersion"))
        {
            memset(c->pkVersion,0x0,VERSION_STR_LEN);
            strncpy(info->pkVersion, result->valuestring, sizeof(info->pkVersion) - 1);
            strncpy(c->pkVersion, result->valuestring, sizeof(c->pkVersion) - 1);
        }
        else if (!strcmp(result->string, "pubkey"))
        {
            char *key = result->valuestring;
            unsigned int pubKeyLen;

            strncpy(info->pubKey, key, sizeof(info->pubKey) - 1);

            if (SUCCESS_RETURN != aliyun_iot_common_base64decode((unsigned char *) key, strlen(key),
                sizeof(c->pubKey), (unsigned char *) c->pubKey, &pubKeyLen))
            {
                WRITE_IOT_ERROR_LOG("base64 decode failed!");
                rc = CCP_BASE64_DECODE_ERROR;
                break;
            }

            c->pubKey[pubKeyLen] = 0;
        }
        else if (!strcmp(result->string, "servers"))
        {
            memset(c->serverIp,0x0,SERVER_IP_STR_LEN);
            strncpy(info->servers, result->valuestring, sizeof(info->servers) - 1);

            if (SUCCESS_RETURN != parseServers(info->servers, c->serverIp, &(c->serverPort)))
            {
                WRITE_IOT_ERROR_LOG("parse servers failed!");
                rc = CCP_PARSE_SERVER_ADDR_ERROR;
                break;
            }
        }
        else if (!strcmp(result->string, "sign"))
        {
            strncpy(info->sign, result->valuestring, sizeof(info->sign) - 1);
        }
        else if (!strcmp(result->string, "sid"))
        {
            char *value = result->valuestring;
            unsigned char aesSid[64];
            unsigned int aesSidLen;
            int sidLen;

            strncpy(info->sid, value, sizeof(info->sid) - 1);

            if (SUCCESS_RETURN != aliyun_iot_common_base64decode((unsigned char *) value,
                strlen(value), sizeof(aesSid), aesSid, &aesSidLen))
            {
                WRITE_IOT_ERROR_LOG("base64 decode failed!");
                rc = CCP_BASE64_DECODE_ERROR;
                break;
            }

            if (SUCCESS_RETURN != aesEcbDecrypt(aesSid, (unsigned char *) c->sid, aesSidLen, &sidLen))
            {
                WRITE_IOT_ERROR_LOG("aes decrypt failed!");
                rc = CCP_AES_DECRYPT_ERROR;
                break;
            }

            c->sid[sidLen] = 0;
        }
        else if (!strcmp(result->string, "errorCode"))
        {
            strncpy(error->errorCode, result->valuestring, sizeof(error->errorCode) - 1);
        }
        else if (!strcmp(result->string, "message"))
        {
            strncpy(error->message, result->valuestring, sizeof(error->message) - 1);
        }

        result = result->next;
    }

    aliyun_iot_common_json_delete(json);

    return rc;
}

int parseServers(const char *servers, char *serverIp, int *serverPort)
{
    char *pos1 = strchr(servers, '|');
    if (NULL == pos1)
    {
        WRITE_IOT_ERROR_LOG("servers is invalid!");
        return FAIL_RETURN;
    }

    char *pos2 = strchr(servers, ':');
    if (NULL == pos2)
    {
        WRITE_IOT_ERROR_LOG("servers is invalid!");
        return FAIL_RETURN;
    }

    int len = pos2 - servers;
    strncpy(serverIp,servers,len);
    char port[8] = {0};
    len = pos1 - pos2;
    strncpy(port,(pos2 + 1),len-1);
    *serverPort = atoi(port);

    return SUCCESS_RETURN;
}

void genRandomString(int length, unsigned char *randstr)
{
    int i;
	int flag;

	for (i = 0; i < length; i++)
	{
		flag = rand() % 3;
		switch (flag)
		{
		case 0:
			randstr[i] = 'A' + rand() % 26;
			break;
		case 1:
			randstr[i] = 'a' + rand() % 26;
			break;
		case 2:
			randstr[i] = '0' + rand() % 10;
			break;
		default:
			randstr[i] = 'x';
			break;
		}
	}
}

int genRsaKeyFromCrt(const unsigned char *buf, unsigned int bufLen, mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_x509_crt *crt)
{
    char *pers = "rsa_genkey";
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(ctr_drbg);
    mbedtls_x509_crt_init(crt);

    if (0 != mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *) pers, strlen(pers)))
    {
        mbedtls_entropy_free(&entropy);
        WRITE_IOT_ERROR_LOG("ctr drbg init failed!");
        return FAIL_RETURN;
    }

    if (0 != mbedtls_x509_crt_parse(crt, buf, bufLen))
    {
        mbedtls_entropy_free(&entropy);
        WRITE_IOT_ERROR_LOG("crt parse failed!");
        return FAIL_RETURN;
    }

    mbedtls_entropy_free(&entropy);
    return SUCCESS_RETURN;
}

void genSign(CLIENT_S *c, const char *input, int inputLen, char *output, const char *key, int keyLen)
{
    if (SIGN_HMAC_MD5 == c->authConfig.signMethod)
    {
        aliyun_iot_common_hmac_md5(input, inputLen, output, key, keyLen);
    }
    else if (SIGN_HMAC_SHA1 == c->authConfig.signMethod)
    {
        aliyun_iot_common_hmac_sha1(input, inputLen, output, key, keyLen);
    }
    else
    {
        aliyun_iot_common_md5(input, inputLen, output);
    }
}

int aesEcbEncrypt(const unsigned char *key, unsigned char *input, unsigned char *output, int in_len, int *out_len)
{
    int i = 0;
    int j;
    char byte;

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if (0 != mbedtls_aes_setkey_enc(&aes, key, 128))
    {
        WRITE_IOT_ERROR_LOG("aes set key failed!");
        mbedtls_aes_free(&aes);
        return FAIL_RETURN;
    }

    while (i <= in_len)
    {
        if (i + AES_BLOCK_SIZE > in_len)
        {
            byte = i + AES_BLOCK_SIZE - in_len;
            for (j = in_len; j < i + AES_BLOCK_SIZE; j++)
            {
                input[j] = byte;
            }
        }
        mbedtls_aes_encrypt(&aes, &input[i], &output[i]);
        i += AES_BLOCK_SIZE;
    }

    mbedtls_aes_free(&aes);

    if (i < in_len)
    {
        WRITE_IOT_ERROR_LOG("aes ecb encrypt failed!");
        return FAIL_RETURN;
    }

    *out_len = i;

    return SUCCESS_RETURN;
}

int aesEcbDecrypt(const unsigned char *input, unsigned char *output, int in_len, int *out_len)
{
    int i = 0;

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if (0 != mbedtls_aes_setkey_dec(&aes, g_seedKey, 128))
    {
        WRITE_IOT_ERROR_LOG("aes set key failed!");
        mbedtls_aes_free(&aes);
        return FAIL_RETURN;
    }

    while (i < in_len)
    {
        mbedtls_aes_decrypt(&aes, &input[i], &output[i]);
        i += AES_BLOCK_SIZE;
    }

    mbedtls_aes_free(&aes);

    if (i != in_len)
    {
        WRITE_IOT_ERROR_LOG("aes ecb decrypt failed!");
        return FAIL_RETURN;
    }

    *out_len = in_len - output[in_len - 1];

    return SUCCESS_RETURN;
}

int CCPGetServerInfo(CLIENT_S *c, SERVER_INFO_S *server_info)
{
    int rc;
    const char *page = "/iot/auth";
    char *signMethod;
	char signData[256];
    char signKey[128] = {0};
    char sign[64] = {0};
    char poststr[256];
    char serverSign[64] = {0};
    ERROR_INFO_S error_info;

    if (SIGN_MD5 == c->authConfig.signMethod)
    {
        signMethod = "MD5";
        aliyun_iot_stdio_snprintf(signData, sizeof(signData) - 1, "%sdeviceName%sproductKey%ssdkVersion%ssignMethod%s%s", c->authConfig.productSecret,
                 c->authConfig.deviceName, c->authConfig.productKey, SDK_VERSION, signMethod, c->authConfig.deviceSecret);
    }
    else
    {
        if (SIGN_HMAC_MD5 == c->authConfig.signMethod)
        {
            signMethod = "HmacMD5";
        }
        else
        {
            signMethod = "HmacSHA1";
        }

        aliyun_iot_stdio_snprintf(signKey, sizeof(signKey) - 1, "%s%s", c->authConfig.productSecret, c->authConfig.deviceSecret);
        aliyun_iot_stdio_snprintf(signData, sizeof(signData) - 1, "deviceName%sproductKey%ssdkVersion%ssignMethod%s",
                 c->authConfig.deviceName, c->authConfig.productKey, SDK_VERSION, signMethod);
    }

    genSign(c, signData, strlen(signData), sign, signKey, strlen(signKey));

    httpclient_t client;
    httpclient_data_t client_data;
    memset(&client, 0, sizeof(httpclient_t));
    memset(&client_data, 0, sizeof(httpclient_data_t));

    aliyun_iot_stdio_snprintf(poststr, sizeof(poststr) - 1, "http://%s%s?&deviceName=%s&productKey=%s&sdkVersion=%s&signMethod=%s&sign=%s",
             c->authConfig.hostName, page, c->authConfig.deviceName, c->authConfig.productKey, SDK_VERSION, signMethod, sign);

    char *response_buf = (char *) aliyun_iot_memory_malloc(HTTP_RESP_MAX_LEN);
    if (NULL == response_buf)
    {
        WRITE_IOT_ERROR_LOG("malloc http response buf failed!");
        return CCP_MALLOC_ERROR;
    }
    memset(response_buf, 0, HTTP_RESP_MAX_LEN);

    client_data.response_buf = response_buf;
    client_data.response_buf_len = HTTP_RESP_MAX_LEN;

    if (SUCCESS_RETURN != (rc = aliyun_iot_common_post(&client, poststr, 80, &client_data)))
    {
        WRITE_IOT_ERROR_LOG("send http request failed!");
        aliyun_iot_memory_free(response_buf);
        return rc;
    }

    memset(&error_info, 0, sizeof(ERROR_INFO_S));

    if (SUCCESS_RETURN != (rc = parseResponse(c, response_buf, server_info, &error_info)))
    {
        WRITE_IOT_ERROR_LOG("parse http response failed!");
        aliyun_iot_memory_free(response_buf);
        return rc;
    }

    aliyun_iot_memory_free(response_buf);

    if (0 != error_info.errorCode[0])
    {
        WRITE_IOT_ERROR_LOG("get server info failed, errorCode is %s, message is %s!", error_info.errorCode, error_info.message);

        if(0 == strncmp(error_info.errorCode,CCP_DEVICE_NOT_EXIST_ERRORCODE,sizeof(CCP_DEVICE_NOT_EXIST_ERRORCODE)))
        {
            return CCP_DEVICE_NOT_EXSIT_ERROR;
        }

        return CCP_GET_SERVER_INFO_ERROR;
    }

    char *serverSignData = (char *) aliyun_iot_memory_malloc(SERVER_SIGN_MAX_LEN);
    if (NULL == serverSignData)
    {
        WRITE_IOT_ERROR_LOG("malloc server sign buf failed!");
        return CCP_MALLOC_ERROR;
    }
    memset(serverSignData, 0, SERVER_SIGN_MAX_LEN);

    if (SIGN_MD5 == c->authConfig.signMethod)
    {
        aliyun_iot_stdio_snprintf(serverSignData, SERVER_SIGN_MAX_LEN - 1, "%sdeviceId%spkVersion%spubkey%sservers%s%s", c->authConfig.productSecret,
                 server_info->deviceId, server_info->pkVersion, server_info->pubKey, server_info->servers, c->authConfig.deviceSecret);
    }
    else
    {
        aliyun_iot_stdio_snprintf(serverSignData, SERVER_SIGN_MAX_LEN - 1, "deviceId%spkVersion%spubkey%sservers%s",
                 server_info->deviceId, server_info->pkVersion, server_info->pubKey, server_info->servers);
    }

    WRITE_IOT_INFO_LOG("servers:%s",server_info->servers);

    genSign(c, serverSignData, strlen(serverSignData), serverSign, signKey, strlen(signKey));

    aliyun_iot_memory_free(serverSignData);

    if (0 != strcmp(serverSign, server_info->sign))
    {
        WRITE_IOT_ERROR_LOG("server sign is invalid!");
        return CCP_SERVER_SIGN_ERROR;
    }

	return SUCCESS_RETURN;
}

int CCPGetSid(CLIENT_S *c, SERVER_INFO_S *server_info, ERROR_INFO_S *error_info)
{
    int rc;
    const char *page = "/iot/sid";
    unsigned char rsaSeedKey[256];
    unsigned int rsaSeedKeyLen;
    unsigned char base64SeedKey[512] = {0};
    unsigned int seedKeyLen;
	unsigned char data[128];
    unsigned char aesData[128];
    unsigned char base64Data[256] = {0};
    int aesDataLen;
    unsigned int base64DataLen;
    char *signMethod;
	char signData[512];
    char signKey[128] = {0};
    char sign[64] = {0};
    char poststr[512];
    char serverSignData[256] = {0};
    char serverSign[64] = {0};

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt crt;
    mbedtls_rsa_context *rsa;

    if (SUCCESS_RETURN != genRsaKeyFromCrt((unsigned char *) c->pubKey, strlen(c->pubKey) + 1, &ctr_drbg, &crt))
    {
        WRITE_IOT_ERROR_LOG("generate rsa key failed!");
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_x509_crt_free(&crt);
        return CCP_GEN_RSA_KEY_ERROR;
    }

    rsa = mbedtls_pk_rsa(crt.pk);

    memset(g_seedKey, 0, sizeof(g_seedKey));
    genRandomString(16, g_seedKey);
    strncpy(c->seedKey, (char *) g_seedKey, strlen((char *) g_seedKey));

    if (0 != mbedtls_rsa_pkcs1_encrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC,
                                       strlen(c->seedKey), (unsigned char *) c->seedKey, rsaSeedKey))
    {
        WRITE_IOT_ERROR_LOG("seedkey rsa encrypt failed!");
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_x509_crt_free(&crt);
        return CCP_RSA_ENCRYPT_ERROR;
    }

    rsaSeedKeyLen = rsa->len;

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_x509_crt_free(&crt);

    if (SUCCESS_RETURN != aliyun_iot_common_base64encode(rsaSeedKey, rsaSeedKeyLen, sizeof(base64SeedKey), base64SeedKey, &seedKeyLen))
    {
        WRITE_IOT_ERROR_LOG("base64 encode failed!");
        return CCP_BASE64_ENCODE_ERROR;
    }

    aliyun_iot_stdio_snprintf((char *) data, sizeof(data) - 1, "{deviceName:\"%s\",productKey:\"%s\"}", c->authConfig.deviceName, c->authConfig.productKey);
    if (SUCCESS_RETURN != aesEcbEncrypt((unsigned char *) c->seedKey, data, aesData, strlen((char *) data), &aesDataLen))
    {
        WRITE_IOT_ERROR_LOG("aes encrypt failed!");
        return CCP_AES_ENCRYPT_ERROR;
    }

    if (SUCCESS_RETURN != aliyun_iot_common_base64encode(aesData, aesDataLen, sizeof(base64Data), base64Data, &base64DataLen))
    {
        WRITE_IOT_ERROR_LOG("base64 encode failed!");
        return CCP_BASE64_ENCODE_ERROR;
    }

    if (SIGN_MD5 == c->authConfig.signMethod)
    {
        signMethod = "MD5";
        aliyun_iot_stdio_snprintf(signData, sizeof(signData) - 1, "%sdata%spkVersion%sseedKey%ssignMethod%s%s", c->authConfig.productSecret,
                 base64Data, server_info->pkVersion, base64SeedKey, signMethod, c->authConfig.deviceSecret);
    }
    else
    {
        if (SIGN_HMAC_MD5 == c->authConfig.signMethod)
        {
            signMethod = "HmacMD5";
        }
        else
        {
            signMethod = "HmacSHA1";
        }

        aliyun_iot_stdio_snprintf(signKey, sizeof(signKey) - 1, "%s%s", c->authConfig.productSecret, c->authConfig.deviceSecret);
        aliyun_iot_stdio_snprintf(signData, sizeof(signData) - 1, "data%spkVersion%sseedKey%ssignMethod%s",
                 base64Data, server_info->pkVersion, base64SeedKey, signMethod);
    }

    genSign(c, signData, strlen(signData), sign, signKey, strlen(signKey));

	char *urlEnData = aliyun_iot_common_url_encode((char *) base64Data);
	char *urlEnSeedKey = aliyun_iot_common_url_encode((char *) base64SeedKey);
	if (NULL == urlEnData || NULL == urlEnSeedKey)
	{
		WRITE_IOT_ERROR_LOG("url encode failed!");
		return CCP_URL_ENCODE_ERROR;
	}

	aliyun_iot_stdio_snprintf(poststr, sizeof(poststr) - 1, "http://%s%s?&data=%s&pkVersion=%s&seedKey=%s&signMethod=%s&sign=%s",
             c->authConfig.hostName, page, urlEnData, server_info->pkVersion, urlEnSeedKey, signMethod, sign);

	aliyun_iot_memory_free(urlEnData);
	aliyun_iot_memory_free(urlEnSeedKey);

    httpclient_t client;
    httpclient_data_t client_data;
    memset(&client, 0, sizeof(httpclient_t));
    memset(&client_data, 0, sizeof(httpclient_data_t));

    char *response_buf = (char *) aliyun_iot_memory_malloc(HTTP_RESP_MAX_LEN);
    if (NULL == response_buf)
    {
        WRITE_IOT_ERROR_LOG("malloc http response buf failed!");
        return CCP_MALLOC_ERROR;
    }
    memset(response_buf, 0, HTTP_RESP_MAX_LEN);

    client_data.response_buf = response_buf;
    client_data.response_buf_len = HTTP_RESP_MAX_LEN;

    if (SUCCESS_RETURN != (rc = aliyun_iot_common_post(&client, poststr, 80, &client_data)))
    {
        WRITE_IOT_ERROR_LOG("send http message failed!");
        aliyun_iot_memory_free(response_buf);
        return rc;
    }

    if (SUCCESS_RETURN != (rc = parseResponse(c, response_buf, server_info, error_info)))
    {
        WRITE_IOT_ERROR_LOG("parse http response failed!");
        aliyun_iot_memory_free(response_buf);
        return rc;
    }

    aliyun_iot_memory_free(response_buf);

    if (0 != error_info->errorCode[0])
    {
        WRITE_IOT_ERROR_LOG("get sid failed, errorCode is %s, message is %s!", error_info->errorCode, error_info->message);
        if(0 == strncmp(error_info->errorCode,CCP_DEVICE_NOT_EXIST_ERRORCODE,sizeof(CCP_DEVICE_NOT_EXIST_ERRORCODE)))
        {
            return CCP_DEVICE_NOT_EXSIT_ERROR;
        }

        if (0 == strcmp(error_info->errorCode, "CertExpired"))
        {
            return CCP_CERT_EXPIRE_ERROR;
        }

        return CCP_GET_SID_ERROR;
    }

    if (SIGN_MD5 == c->authConfig.signMethod)
    {
        aliyun_iot_stdio_snprintf(serverSignData, sizeof(serverSignData) - 1, "%ssid%s%s", c->authConfig.productSecret, server_info->sid, c->authConfig.deviceSecret);
    }
    else
    {
        aliyun_iot_stdio_snprintf(serverSignData, sizeof(serverSignData) - 1, "sid%s", server_info->sid);
    }

    genSign(c, serverSignData, strlen(serverSignData), serverSign, signKey, strlen(signKey));

    if (0 != strcmp(serverSign, server_info->sign))
    {
        WRITE_IOT_ERROR_LOG("server sign is invalid!");
        return CCP_SERVER_SIGN_ERROR;
    }

	return SUCCESS_RETURN;
}

int CCPAuth(CLIENT_S *c)
{
    int rc;
    SERVER_INFO_S server_info;
    ERROR_INFO_S error_info;

    if (NULL == c)
    {
        WRITE_IOT_ERROR_LOG("invalid parameter!");
        return CCP_INVALID_PARAMETER;
    }

    memset(&server_info, 0, sizeof(SERVER_INFO_S));
    memset(&error_info, 0, sizeof(ERROR_INFO_S));

    if (SUCCESS_RETURN != (rc = CCPGetServerInfo(c, &server_info)))
    {
        WRITE_IOT_ERROR_LOG("get server info failed!");
        return rc;
    }

    if (SUCCESS_RETURN != (rc = CCPGetSid(c, &server_info, &error_info)))
    {
        WRITE_IOT_ERROR_LOG("get sid failed!");
        return rc;
    }

    return SUCCESS_RETURN;
}

