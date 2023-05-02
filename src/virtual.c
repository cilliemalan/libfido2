
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
#define MAX_DIRECT_DEVICES 16
#define VDEV_ID_LEN 16

typedef struct vdev_direct
{
    char path[sizeof(FIDO_VIRTUAL_PATH) + VDEV_ID_LEN];
    void *user;
    fido_dev_direct_open_t *open;
    fido_dev_direct_close_t *close;
    fido_dev_io_read_t *read;
    fido_dev_io_write_t *write;
} vdev_direct_t;

fido_dev_io_t direct_io = {
    fido_virtual_open,
    fido_virtual_close,
    fido_virtual_read,
    fido_virtual_write,
};

static vdev_direct_t direct_devices[MAX_DIRECT_DEVICES] = {0};

static void fillrandchars(char *c, size_t l)
{
    fido_get_random(c, l);
    for (size_t i = 0; i < l; i++)
    {
        int ci = ((int)(uint8_t)c[i]) % 64;
        if (ci < 26)
            c[i] = (char)('a' + ci);
        else if (ci < 52)
            c[i] = (char)('A' + (ci - 26));
        else if (ci < 62)
            c[i] = (char)('0' + (ci - 52));
        else
            c[i] = (char)('5' + (ci - 62));
    }
    c[l] = 0;
}

static vdev_direct_t *find_virtual_device(const char *path)
{
    if (strlen(path) != sizeof(direct_devices[0].path) - 1)
        return NULL;

    for (int i = 0; i < MAX_DIRECT_DEVICES; i++)
    {
        vdev_direct_t *dev = &direct_devices[i];
        if (dev->path[0] && memcmp(path, dev->path, sizeof(dev->path)) == 0)
        {
            return dev;
        }
    }

    return NULL;
}

const char *fido_register_virtual_device(
    fido_dev_direct_open_t *open,
    fido_dev_direct_close_t *close,
    fido_dev_io_read_t *read,
    fido_dev_io_write_t *write,
    void *user)
{
    for (int i = 0; i < MAX_DIRECT_DEVICES; i++)
    {
        vdev_direct_t *dev = &direct_devices[i];
        if (dev->path[0] == 0)
        {
            strcpy(dev->path, FIDO_VIRTUAL_PATH);
            char *idpart = dev->path + sizeof(FIDO_VIRTUAL_PATH) - 1;
            size_t idlen = sizeof(dev->path) - sizeof(FIDO_VIRTUAL_PATH);
            fillrandchars(idpart, idlen);
            dev->path[sizeof(dev->path) - 1] = 0;
            dev->user = user;
            dev->open = open;
            dev->close = close;
            dev->read = read;
            dev->write = write;
            return dev->path;
        }
    }

    return NULL;
}

void fido_unregister_virtual_device(const char *path)
{
    if (strlen(path) != sizeof(direct_devices[0].path) - 1)
        return;

    for (int i = 0; i < MAX_DIRECT_DEVICES; i++)
    {
        if (memcmp(path, direct_devices[i].path, sizeof(direct_devices[0].path)) == 0)
        {
            memset(direct_devices[i].path, 0, sizeof(direct_devices[i].path));
            return;
        }
    }
}

bool fido_is_virtual(const char *path)
{
    return find_virtual_device(path) != NULL;
}

int fido_virtual_manifest(fido_dev_info_t *devlist, size_t ilen, size_t *olen)
{
    (void)ilen;
    (void)devlist;
    *olen = 0;

    for (int i = 0; i < MAX_DIRECT_DEVICES; i++)
    {
        vdev_direct_t *dev = &direct_devices[i];
        if (dev->path[0])
        {
            devlist[*olen].io = direct_io;
            devlist[*olen].manufacturer = strdup(VIRTUAL_DEVICE_MANUFACTURER);
            devlist[*olen].path = strdup(dev->path);
            devlist[*olen].product = strdup(VIRTUAL_DEVICE_PRODUCT);
            devlist[*olen].product_id = 1;
            devlist[*olen].transport = (fido_dev_transport_t){0};
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
    d->rx_len = CTAP_MAX_REPORT_LEN;
    d->tx_len = CTAP_MAX_REPORT_LEN;
    d->flags = FIDO_DEV_VIRTUAL;

    return 0;
}

void *fido_virtual_open(const char *path)
{
    vdev_direct_t *dev = find_virtual_device(path);
    if (!dev)
    {
        fido_log_debug("%s: could not find virtual device", __func__);
        return NULL;
    }

    if (dev->open)
        dev->open(dev->user);

    return dev;
}

void fido_virtual_close(void *h)
{
    if (h == NULL)
    {
        fido_log_debug("%s: device not open", __func__);
        return;
    }

    vdev_direct_t *dev = (vdev_direct_t *)h;
    if (dev->close)
        dev->close(dev->user);
}

int fido_virtual_read(void *handle, unsigned char *buf, size_t len, int m)
{
    vdev_direct_t *dev = (vdev_direct_t *)handle;

    if (len != CTAP_MAX_REPORT_LEN)
    {
        fido_log_debug("%s: invalid read length: %zu (must be %d)", __func__, len, CTAP_MAX_REPORT_LEN);
        return -1;
    }

    return dev->read(dev->user, buf, len, m);
}

int fido_virtual_write(void *handle, const unsigned char *buf, size_t len)
{
    vdev_direct_t *dev = (vdev_direct_t *)handle;

    if (len != CTAP_MAX_REPORT_LEN + 1)
    {
        fido_log_debug("%s: invalid write length: %zu (must be %d)", __func__, len, CTAP_MAX_REPORT_LEN + 1);
        return -1;
    }

    int r = dev->write(dev->user, buf + 1, len - 1);
    if ((size_t)r == len - 1)
        return (int)len;
    return r;
}
