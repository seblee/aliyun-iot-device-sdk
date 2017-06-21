#include <errno.h>
#include <string.h>
#include "aliyun_iot_platform_network.h"
#include "aliyun_iot_common_log.h"
#include "aliyun_iot_platform_memory.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib,"Ws2_32.lib")

#define CANONNAME_MAX 128

typedef struct NETWORK_ERRNO_TRANS
{
    INT32 systemData;
    ALIYUN_NETWORK_ERROR_E netwokErrno;
    INT32 privateData;
}NETWORK_ERRNO_TRANS_S;

static NETWORK_ERRNO_TRANS_S g_networkErrnoTrans[]=
{
	{ WSAEINTR, NETWORK_SIGNAL_INTERRUPT, EINTR_IOT },
	{ WSAEBADF, NETWORK_BAD_FILEFD, EBADF_IOT },
	{ WSAEFAULT, NETWORK_BADADDRESS, EFAULT_IOT },
	{ WSAEINVAL, NETWORK_INVALID_ARGUMENT, EINVAL_IOT },
	{ WSAEMFILE, NETWORK_TOO_MANY_OPEN_FILES, EMFILE_IOT },
	{ WSAEWOULDBLOCK, NETWORK_OPERATION_BLOCK, EWOULDBLOCK_IOT },
	{ WSAENOTSOCK, NETWORK_OPERATION_ON_NONSOCKET, ENOTSOCK_IOT },
	{ WSAENOPROTOOPT, NETWORK_PROTOCOL_NOT_AVAILABLE, ENOPROTOOPT_IOT },
	{ WSAEADDRINUSE, NETWORK_ADDRESS_ALREADY_IN_USE, EADDRINUSE_IOT },
	{ WSAEADDRNOTAVAIL, NETWORK_CANNOT_ASSIGN_REQUESTED_ADDRESS, EADDRNOTAVAIL_IOT },
	{ WSAENETDOWN, NETWORK_NETWORK_IS_DOWN, ENETDOWN_IOT },
	{ WSAENETUNREACH, NETWORK_NETWORK_IS_UNREACHABLE, ENETUNREACH_IOT },
	{ WSAENETRESET, NETWORK_CONNECT_RESET, ENETRESET_IOT },
	{ WSAECONNRESET, NETWORK_CONNECT_RESET_BY_PEER, ECONNRESET_IOT },
	{ WSAENOBUFS, NETWORK_NO_BUFFER_SPACE, ENOBUFS_IOT },
	{ WSAEISCONN, NETWORK_ALREADY_CONNECTED, EISCONN_IOT },
	{ WSAENOTCONN, NETWORK_IS_NOT_CONNECTED, ENOTCONN_IOT },
	{ WSAETIMEDOUT, NETWORK_CONNECTION_TIMED_OUT, ETIMEDOUT_IOT },
	{ WSAECONNREFUSED, NETWORK_CONNECTION_REFUSED, ECONNREFUSED_IOT },
	{ WSAEHOSTUNREACH, NETWORK_NO_ROUTE_TO_HOST, EHOSTUNREACH_IOT },
	{ WSAEMSGSIZE, NETWORK_MSG_TOO_LONG, EMSGSIZE_IOT }
};

INT32 errno_transform(INT32 systemErrno,ALIYUN_NETWORK_ERROR_E *netwokErrno,INT32 *privateErrno)
{
    INT32 num = sizeof(g_networkErrnoTrans);
    INT32 i = 0;
    for(i = 0;i<num;i++)
    {
        if(g_networkErrnoTrans[i].systemData == systemErrno)
        {
            *netwokErrno = g_networkErrnoTrans[i].netwokErrno;
            *privateErrno = g_networkErrnoTrans[i].privateData;
            return NETWORK_SUCCESS;
        }
    }

    return NETWORK_FAIL;
}

INT32 aliyun_iot_get_errno(void)
{
    ALIYUN_NETWORK_ERROR_E networkErrno = NETWORK_FAIL;
    INT32 private = 0;
	INT32 result = errno_transform(GetLastError(), &networkErrno, &private);
    if(0 != result)
    {
        WRITE_IOT_ERROR_LOG("network errno = %d",errno);
        return NETWORK_FAIL;
    }

    return private;
}

INT32 aliyun_iot_network_send(INT32 sockFd, void *buf, INT32 nbytes, IOT_NET_TRANS_FLAGS_E flags)
{
    UINT32 flag = 0;

    if( sockFd < 0 )
    {
        return NETWORK_FAIL;
    }

    if(IOT_NET_FLAGS_DEFAULT == flags)
    {
        flag = 0;
    }

    return send(sockFd,buf,nbytes,flag);
}

INT32 aliyun_iot_network_recv(INT32 sockFd, void *buf, INT32 nbytes, IOT_NET_TRANS_FLAGS_E flags)
{
    UINT32 flag = 0;
	INT32 ret = 0;
	unsigned long ul = 1;

    if( sockFd < 0 )
    {
        return NETWORK_FAIL;
    }

	if (IOT_NET_FLAGS_DONTWAIT == flags)
	{
		ul = 1;
		ret = ioctlsocket(sockFd, FIONBIO, (unsigned long *)&ul);
	}
	else
	{
		ul = 0;
		ret = ioctlsocket(sockFd, FIONBIO, (unsigned long *)&ul);
	}

	return recv(sockFd, buf, nbytes, flag);
}

INT32 aliyun_iot_network_select(INT32 fd,IOT_NET_TRANS_TYPE_E type,int timeoutMs,IOT_NET_FD_ISSET_E* result)
{
    struct timeval *timePointer = NULL;
    fd_set *rd_set = NULL;
    fd_set *wr_set = NULL;
    fd_set *ep_set = NULL;
    int rc = 0;
    fd_set sets;

    *result = IOT_NET_FD_NO_ISSET;

    if( fd < 0 )
    {
        return NETWORK_FAIL;
    }

    FD_ZERO(&sets);
    FD_SET(fd, &sets);

    if(IOT_NET_TRANS_RECV == type)
    {
        rd_set = &sets;
    }
    else
    {
        wr_set = &sets;
    }

    struct timeval timeout = {timeoutMs/1000, (timeoutMs%1000)*1000};
    if(0 != timeoutMs)
    {
        timePointer = &timeout;
    }
    else
    {
        timePointer = NULL;
    }

    rc = select(fd+1,rd_set,wr_set,ep_set,timePointer);
    if(rc > 0)
    {
        if( fd < 0 )
        {
            return NETWORK_FAIL;
        }

        if (0 != FD_ISSET(fd, &sets))
        {
            *result = IOT_NET_FD_ISSET;
        }
    }

    return rc;
}

INT32 aliyun_iot_network_settimeout(INT32 fd,int timeoutMs,IOT_NET_TRANS_TYPE_E type)
{
    struct timeval timeout = {timeoutMs/1000, (timeoutMs%1000)*1000};

    int optname = type == IOT_NET_TRANS_RECV ? SO_RCVTIMEO:SO_SNDTIMEO;

    if( fd < 0 )
    {
        return NETWORK_FAIL;
    }

    if(0 != setsockopt(fd, SOL_SOCKET, optname, (char *)&timeout, sizeof(timeout)))
    {
        WRITE_IOT_ERROR_LOG("setsockopt error, errno = %d",errno);
        return ERROR_NET_SETOPT_TIMEOUT;
    }

    return SUCCESS_RETURN;
}

INT32 aliyun_iot_network_get_nonblock(INT32 fd)
{
    if( fd < 0 )
    {
        return NETWORK_FAIL;
    }

    return 0 ;
}

INT32 aliyun_iot_network_set_nonblock(INT32 fd)
{
	int rc = 0;
	u_long mode = 1;

	if( fd < 0 )
    {
        return NETWORK_FAIL;
    }

	rc = ioctlsocket(fd, FIONBIO, &mode);
	if (rc != NO_ERROR)
	{
		return NETWORK_FAIL;
	}

	return NETWORK_SUCCESS;
}

INT32 aliyun_iot_network_set_block(INT32 fd)
{
	int rc = 0;
	u_long mode = 0;

    if( fd < 0 )
    {
        return NETWORK_FAIL;
    }

	rc = ioctlsocket(fd, FIONBIO, &mode);
	if (rc != NO_ERROR)
    {
		return NETWORK_FAIL;
	}

	return NETWORK_SUCCESS;
}

INT32 aliyun_iot_network_close(INT32 fd)
{
    closesocket(fd);
    WSACleanup();
    return 0;
}

INT32 aliyun_iot_network_shutdown(INT32 fd,INT32 how)
{
    return shutdown(fd,how);
}

INT32 aliyun_iot_network_create(const INT8*host,const INT8*service,IOT_NET_PROTOCOL_TYPE type)
{
	WSADATA wsaData;
    struct addrinfo hints;
    struct addrinfo *addrInfoList = NULL;
    struct addrinfo *cur = NULL;
    int fd = 0;
    int rc = ERROR_NET_UNKNOWN_HOST;

	// Initialize Winsock
	rc = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (rc != 0)
	{
		WRITE_IOT_ERROR_LOG("WSAStartup failed: %d", rc);
		return FAIL_RETURN;
	}

    memset( &hints, 0, sizeof(hints));

    //默认支持IPv4的服务
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if ((rc = getaddrinfo( host, service, &hints, &addrInfoList ))!= 0 )
    {
        WRITE_IOT_ERROR_LOG("getaddrinfo error! rc = %d, errno = %d",rc,errno);
        return ERROR_NET_UNKNOWN_HOST;
    }

    for( cur = addrInfoList; cur != NULL; cur = cur->ai_next )
    {
        //默认只支持IPv4
        if (cur->ai_family != AF_INET)
        {
            WRITE_IOT_ERROR_LOG("socket type error");
            rc = ERROR_NET_SOCKET;
            continue;
        }

        fd = (int) socket( cur->ai_family, cur->ai_socktype,cur->ai_protocol );
        if( fd < 0 )
        {
            WRITE_IOT_ERROR_LOG("create socket error,fd = %d, errno = %d",fd,errno);
            rc = ERROR_NET_SOCKET;
            continue;
        }

        if( connect( fd,cur->ai_addr,cur->ai_addrlen ) == 0 )
        {
            rc = fd;
            break;
        }

        closesocket( fd );
        WRITE_IOT_ERROR_LOG("connect error,errno = %d",errno);
        rc = ERROR_NET_CONNECT;
    }

    freeaddrinfo(addrInfoList);

    return rc;
}

INT32 aliyun_iot_network_bind(const INT8*host,const INT8*service,IOT_NET_PROTOCOL_TYPE type)
{
    int fd = 0;
    int n = 0;
    int ret = FAIL_RETURN;
    struct addrinfo hints, *addrList, *cur;

    /* Bind to IPv6 and/or IPv4, but only in the desired protocol */
    memset( &hints, 0, sizeof( hints ) );
    hints.ai_family = AF_INET;
    hints.ai_socktype = type == IOT_NET_PROTOCOL_UDP ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = type == IOT_NET_PROTOCOL_UDP ? IPPROTO_UDP : IPPROTO_TCP;
    if( host == NULL )
    {
        hints.ai_flags = AI_PASSIVE;
    }

    if( getaddrinfo( host, service, &hints, &addrList ) != 0 )
    {
        return( ERROR_NET_UNKNOWN_HOST );
    }

    for( cur = addrList; cur != NULL; cur = cur->ai_next )
    {
        fd = (int) socket( cur->ai_family, cur->ai_socktype,cur->ai_protocol );
        if( fd < 0 )
        {
            ret = ERROR_NET_SOCKET;
            continue;
        }

        n = 1;
        if( setsockopt( fd, SOL_SOCKET, SO_REUSEADDR,(const char *) &n, sizeof( n ) ) != 0 )
        {
            closesocket(fd);
            ret = ERROR_NET_SOCKET;
            continue;
        }

        if( bind(fd, cur->ai_addr, cur->ai_addrlen ) != 0 )
        {
            closesocket( fd );
            ret = ERROR_NET_BIND;
            continue;
        }

        /* Listen only makes sense for TCP */
        if(type == IOT_NET_PROTOCOL_TCP)
        {
            if( listen( fd, 10 ) != 0 )
            {
                closesocket( fd );
                ret = ERROR_NET_LISTEN;
                continue;
            }
        }

        /* I we ever get there, it's a success */
        ret = fd;
        break;
    }

    freeaddrinfo( addrList );

    return( ret );
}

