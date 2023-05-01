
#include "fido.h"

#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
static bool winsock_initialized = false;
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#define closesocket closesocket
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <errno.h>
#define closesocket close
#define INVALID_SOCKET -1
#define SOCKET int
#endif

#define DEFAULT_LISTEN_PORT "13231"
#define VIRTUAL_DEVICE_MANUFACTURER "Simulated"
#define VIRTUAL_DEVICE_PRODUCT "Virtual Device"
#define DEFAULT_TIMEOUT_MS 3000
#define MAX_PATH_LEN 256

typedef struct _vdev
{
    SOCKET fd;
} vdev_t;

bool fido_is_virtual(const char *path)
{
#ifdef USE_VIRTUAL
    return memcmp(path, FIDO_VIRTUAL_PATH, sizeof(FIDO_VIRTUAL_PATH) - 1) == 0;
#endif
}

static bool isport(const char *port)
{
    bool result = !!port[0];
    for (char c = *port; *port; port++)
    {
        if (c < '0' || c > '9')
        {
            result = false;
            break;
        }
    }

    return result;
}

static int fido_virtual_connect(const char *path, vdev_t *pvd)
{
#ifdef WIN32
    if (!winsock_initialized)
    {
        winsock_initialized = true;

        WSADATA wsaData;
        int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != 0)
        {
            fido_log_debug("%s: WSAStartup failed with error: %d\n", __func__, iResult);
            return -1;
        }
    }
#endif

    // make sure the path starts with virtual
    if (!fido_is_virtual(path))
    {
        fido_log_debug("%s: invalid path for virtual device", __func__);
        return -1;
    }

    // find the colon
    path += sizeof(FIDO_VIRTUAL_PATH) - 1;
    const char *port = strrchr(path, ':');
    size_t pathlen;
    if (port)
    {
        if (!isport(port + 1))
        {
            fido_log_debug("%s: invalid port for virtual device", __func__);
            return -1;
        }

        pathlen = (size_t)port - (size_t)path;
        if (pathlen > MAX_PATH_LEN || pathlen == 0)
        {
            fido_log_debug("%s: invalid path for virtual device", __func__);
            return -1;
        }
    }
    else
    {
        pathlen = strlen(path);
        port = DEFAULT_LISTEN_PORT;
    }

    if (pathlen >= MAX_PATH_LEN)
    {
        fido_log_debug("%s: invalid path for virtual device", __func__);
        return -1;
    }

    char node[MAX_PATH_LEN] = {0};
    memcpy(node, path, pathlen);
    port++;

    // get listen address
    struct addrinfo hints = {
        .ai_flags = AI_PASSIVE,
        .ai_family = AF_INET6,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = 0,
    };

    struct addrinfo *listenaddrs;
    int s = getaddrinfo(node, port, &hints, &listenaddrs);
    if (s != 0)
    {
        fido_log_debug("%s: getaddrinfo: %s", __func__, gai_strerror(s));
        return -1;
    }

    // try each address and try to connect
    struct addrinfo *rp = NULL;
    SOCKET sfd = INVALID_SOCKET;
    for (rp = listenaddrs; rp != NULL; rp = rp->ai_next)
    {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == INVALID_SOCKET)
            continue;

        s = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &(char){1}, sizeof(int));
        if (s == -1)
            continue;

        if (connect(sfd, rp->ai_addr, (int)rp->ai_addrlen) == 0)
            break;

        closesocket(sfd);
        sfd = INVALID_SOCKET;
    }

    if (sfd == INVALID_SOCKET)
    {
        fido_log_debug("%s: could not connect", __func__);
        return -1;
    }

#ifdef WIN32
    uint32_t tval = DEFAULT_TIMEOUT_MS;
#else
    struct timeval tval = {
        .tv_sec = DEFAULT_TIMEOUT_MS / 1000,
        .tv_usec = (DEFAULT_TIMEOUT_MS % 1000) * 1000,
    };
#endif

    s = setsockopt(sfd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tval, sizeof(tval));
    if (s == -1)
    {
        fido_log_error(errno, "%s: could not set send timeout. Returned %d. Errno is %d", __func__, s, errno);
    }
    s = setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tval, sizeof(tval));
    if (s == -1)
    {
        fido_log_error(errno, "%s: could not set reveive timeout. Returned %d. Errno is %d", __func__, s, errno);
    }

    pvd->fd = sfd;

    return 0;
}

int fido_virtual_manifest(fido_dev_info_t *devlist, size_t ilen, size_t *olen)
{
    (void)ilen;
    (void)devlist;
    *olen = 0;

    if (ilen == 0)
        return FIDO_OK;

    fido_dev_t tmp = {0};
    if (fido_dev_set_virtual(&tmp) == 0)
    {
        tmp.io_handle = tmp.io.open(tmp.path);
        if (tmp.io_handle)
        {
            fido_virtual_close(tmp.io_handle);
            tmp.io_handle = NULL;

            devlist[*olen].io = tmp.io;
            devlist[*olen].manufacturer = strdup(VIRTUAL_DEVICE_MANUFACTURER);
            devlist[*olen].path = strdup(tmp.path);
            devlist[*olen].product = strdup(VIRTUAL_DEVICE_PRODUCT);
            devlist[*olen].product_id = 1;
            devlist[*olen].transport = tmp.transport;
            devlist[*olen].vendor_id = 1;
            (*olen)++;
        }
    }

    return FIDO_OK;
}

int fido_dev_set_virtual(fido_dev_t *d)
{
    if (d->io_handle != NULL)
    {
        fido_log_debug("%s: device already open", __func__);
        return -1;
    }

    d->io = (fido_dev_io_t){
        &fido_virtual_open,
        &fido_virtual_close,
        &fido_virtual_read,
        &fido_virtual_write,
    };
    d->transport = (fido_dev_transport_t){0};
    d->io_own = true;
    d->io_handle = NULL;
    d->path = strdup(FIDO_VIRTUAL_PATH "localhost:" DEFAULT_LISTEN_PORT);
    d->rx_len = CTAP_MAX_REPORT_LEN;
    d->tx_len = CTAP_MAX_REPORT_LEN;
    d->flags = FIDO_DEV_VIRTUAL;

    return 0;
}

void *fido_virtual_open(const char *path)
{
    if (!fido_is_virtual(path))
    {
        fido_log_debug("%s: invalid path for virtual device", __func__);
        return NULL;
    }

    vdev_t *pvd = calloc(1, sizeof(vdev_t));

    if (!pvd)
    {
        fido_log_debug("%s: out of memory", __func__);
        return NULL;
    }

    if (fido_virtual_connect(path, pvd) != 0)
    {
        free(pvd);
        return NULL;
    }

    return pvd;
}

void fido_virtual_close(void *h)
{
    if (h == NULL)
    {
        fido_log_debug("%s: device not open", __func__);
    }

    vdev_t *pvd = (vdev_t *)h;
    if (pvd->fd != INVALID_SOCKET)
    {
        closesocket(pvd->fd);
        pvd->fd = INVALID_SOCKET;
    }

    free(h);
}

int fido_virtual_read(void *handle, unsigned char *buf, size_t len, int m)
{
    (void)m;

    vdev_t *v = (vdev_t *)handle;
    if (!v || v->fd == INVALID_SOCKET)
    {
        fido_log_debug("%s: invalid handle", __func__);
        return -1;
    }
    if (len != CTAP_MAX_REPORT_LEN)
    {
        fido_log_debug("%s: invalid read length: %zu (must be %d)", __func__, len, CTAP_MAX_REPORT_LEN);
        return -1;
    }

    int nread = recv(v->fd, (char *)buf, (int)len, 0);

    if (nread != len)
    {
        fido_log_error(errno, "%s: Receive error. Return code: %d  errno is %d", __func__, nread, errno);
        return -1;
    }

    return (int)len;
}

int fido_virtual_write(void *handle, const unsigned char *buf, size_t len)
{
    vdev_t *v = (vdev_t *)handle;
    if (!v || v->fd == INVALID_SOCKET)
    {
        fido_log_debug("%s: invalid handle", __func__);
        return -1;
    }
    if (len != CTAP_MAX_REPORT_LEN + 1)
    {
        fido_log_debug("%s: invalid write length: %zu (must be %d)", __func__, len, CTAP_MAX_REPORT_LEN + 1);
        return -1;
    }

    int nwrite = send(v->fd, (const char *)buf + 1, (int)len - 1, 0);

    if (nwrite != len - 1)
    {
        fido_log_error(errno, "%s: Send error. Return code: %d  errno is %d", __func__, nwrite, errno);
        return -1;
    }

    return (int)len;
}
