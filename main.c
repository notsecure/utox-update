#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <sodium.h>
#include "xz/xz.h"

#ifdef __x86_64
#define ARCH "64"
#else
#define ARCH "32"
#endif

#ifdef __WIN32__
#define OS "win"
#define EXT ".exe"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#define close(x) closesocket(x)
#else
#define OS "linux"
#define EXT ""
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

#define GET_NAME OS ARCH "-latest"
#define HOST "dl.utox.org"

#define VERSION 0

static const uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES] = {
    0x88, 0x90, 0x5F, 0x29, 0x46, 0xBE, 0x7C, 0x4B, 0xBD, 0xEC, 0xE4, 0x67, 0x14, 0x9C, 0x1D, 0x78,
    0x48, 0xF4, 0xBC, 0x4F, 0xEC, 0x1A, 0xD1, 0xAD, 0x6F, 0x97, 0x78, 0x6E, 0xFE, 0xF3, 0xCD, 0xA1
};

static const uint8_t self_update_public_key[crypto_sign_ed25519_PUBLICKEYBYTES] = {
    0x52, 0xA7, 0x9B, 0xCA, 0x48, 0x35, 0xD6, 0x34, 0x5E, 0x7D, 0xEF, 0x8B, 0x97, 0xC3, 0x54, 0x2D,
    0x37, 0x9A, 0x9A, 0x8B, 0x00, 0xEB, 0xF3, 0xA8, 0xAD, 0x03, 0x92, 0x3E, 0x0E, 0x50, 0x77, 0x58
};

static const char request_version[] =
    "GET /version HTTP/1.0\r\n"
    "Host: " HOST "\r\n"
    "\r\n";

static char request[] =
    "GET /" GET_NAME " HTTP/1.0\r\n"
    "Host: " HOST "\r\n"
    "\r\n";

static char filename[] = GET_NAME;
static uint8_t recvbuf[0x10000];

uint32_t inflate(void *dest, void *src, uint32_t dest_size, uint32_t src_len)
{
    xz_crc32_init();

    struct xz_dec *dec = xz_dec_init(XZ_SINGLE, 0);
    if(!dec) {
        return 0;
    }

    struct xz_buf buf = {
        .in = src,
        .in_pos = 0,
        .in_size = src_len,

        .out = dest,
        .out_pos = 0,
        .out_size = dest_size,
    };

    int r = xz_dec_run(dec, &buf);
    xz_dec_end(dec);

    printf("%i\n", r);

    /* out_pos is only set on success*/
    return buf.out_pos;
}

void* checksignature(void *data, uint32_t dlen, const uint8_t *pk, unsigned long long *olen)
{
    void *mdata;
    int r;

    mdata = malloc(dlen);
    if(!mdata) {
        printf("malloc failed\n");
        free(data);
        return NULL;
    }

    r = crypto_sign_ed25519_open(mdata, olen, data, dlen, public_key);
    free(data);

    if(r == -1) {
        printf("invalid signature\n");
        free(mdata);
        return NULL;
    }

    return mdata;
}

void* download(int family, const void *addr, size_t addrlen, const char *request, uint16_t requestlen, uint32_t *olen, uint32_t maxlen)
{
    uint32_t sock, len, rlen, dlen;
    void *data;
    _Bool header = 0;

    sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if(sock == ~0) {
        printf("socket failed\n");
        return NULL;
    }

    if(connect(sock, addr, addrlen) != 0) {
        printf("connect failed\n");
        close(sock);
        return NULL;
    }

    if(send(sock, request, requestlen, 0) != requestlen) {
        printf("send failed\n");
        close(sock);
        return NULL;
    }

    while((len = recv(sock, recvbuf, 0xFFFF, 0)) > 0) {
        if(!header) {
            /* work with a null-terminated buffer */
            recvbuf[len] = 0;

            /* check for "Not Found" response (todo: only check first line of response)*/
            if(strstr((char*)recvbuf, "404 Not Found\r\n")) {
                printf("Not Found: %s\n", GET_NAME);
                break;
            }

            /* find the length field */
            char *str = strstr((char*)recvbuf, "Content-Length: ");
            if(!str) {
                printf("invalid HTTP response (1)\n");
                break;
            }

            /* parse the length field */
            str += sizeof("Content-Length: ") - 1;
            dlen = strtol(str, NULL, 10);
            if(dlen > maxlen) {
                printf("too large\n");
                break;
            }

            /* find the end of the http response header */
            str = strstr(str, "\r\n\r\n");
            if(!str) {
                printf("invalid HTTP response (2)\n");
                break;
            }

            str += sizeof("\r\n\r\n") - 1;

            /* allocate buffer to read into) */
            data = malloc(dlen);
            if(!data) {
                printf("malloc failed (1) (%u)\n", dlen);
                break;
            }

            printf("Download size: %u\n", dlen);

            /* read the first piece */
            rlen = len - (str - (char*)recvbuf);
            memcpy(data, str, rlen);

            header = 1;
            continue;
        }

        /* check if recieved too much */
        if(rlen + len > dlen) {
            printf("bad download\n");
            break;
        }

        memcpy(data + rlen, recvbuf, len); rlen += len;
    }

    close(sock);

    if(!header) {
        /* read nothing or invalid header */
        printf("error...\n");
        return NULL;
    } else if(rlen != dlen) {
        printf("number of bytes read does not match (%u)\n", rlen);
        free(data);
        return NULL;
    }

    *olen = dlen;
    return data;
}

void *download_signed_compressed(int family, const void *addr, size_t addrlen, const char *request, uint16_t requestlen, uint32_t *olen, uint32_t maxlen, const uint8_t *pk)
{
    void *data, *mdata;
    uint32_t len, t;
    time_t now;
    unsigned long long mlen;

    data = download(family, addr,addrlen, request, requestlen, &len, 1024 * 1024 * 4);
    if(!data) {
        printf("file download failed\n");
        return NULL;
    }

    mdata = checksignature(data, len, pk, &mlen);

    time(&now);
    memcpy(&t, mdata, 4);

    printf("built %u, now %u\n", t, now);

    if(t < now && now - t >= 60 * 60 * 24 * 7) {
        /* build is more than 1 week old: expired */
        printf("expired build (%u)\n", now - t);
        free(mdata);
        return NULL;
    }

    /* inflate (todo: not constant size) */
#define SIZE 4 * 1024 * 1024
    data = malloc(SIZE);
    if(!data) {
        printf("malloc failed (2) (%u)\n", SIZE);
        free(mdata);
        return NULL;
    }

    len = inflate(data, mdata + 4, SIZE, mlen - 4);
#undef SIZE
    free(mdata);
    if(len == 0) {
        printf("inflate failed\n");
        free(data);
        return NULL;
    }

    *olen = len;
    return data;
}

static _Bool selfupdate(void *data, uint32_t dlen)
{
    #ifdef __WIN32__
    char file_path[MAX_PATH], new_path[MAX_PATH];
    uint32_t len;
    FILE *file;

    len = GetModuleFileName(NULL, file_path, MAX_PATH);
    memcpy(new_path, file_path, len);
    new_path[len++] = '.';
    new_path[len++] = 'o';
    new_path[len++] = 'l';
    new_path[len++] = 'd';
    new_path[len] = 0;

    DeleteFile(new_path);
    MoveFile(file_path, new_path);

    file = fopen(file_path, "wb");
    if(!file) {
        return 0;
    }

    fwrite(data, 1, dlen, file);
    fclose(file);
    return 1;
    #else
    /* self update not implemented */
    return 0;
    #endif
}

int main(void)
{
    char *str;
    void *data;
    FILE *file;
    struct addrinfo *root, *info;
    uint32_t len, rlen;
    _Bool force = 0;

    #ifdef __WIN32__
    /* initialize winsock */
    WSADATA wsaData;
    if(WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    /* check if we are on a 64-bit system*/
    _Bool iswow64 = 0;
    _Bool (WINAPI *fnIsWow64Process)(HANDLE, _Bool*)  = (void*)GetProcAddress(GetModuleHandleA("kernel32"),"IsWow64Process");
    if(fnIsWow64Process) {
        fnIsWow64Process(GetCurrentProcess(), &iswow64);
    }

    if(iswow64) {
        /* replace the arch in the request/filename strings (todo: not use constants for offsets) */
        request[8] = '6';
        request[9] = '4';
        filename[3] = '6';
        filename[4] = '4';
        printf("detected 64bit system\n");
    }
    #endif

    file = fopen("version", "rb");
    if(file) {
        len = fread(filename + sizeof(OS ARCH), 1, 6, file);
        filename[sizeof(OS ARCH) + len] = 0;
        fclose(file);
    }

    if(getaddrinfo(HOST, "80", NULL, &root) != 0) {
        printf("getaddrinfo failed\n");
        return 1;
    }

    info = root;
    do {
        printf("trying...\n");

        /* check if new version is available */
        if(!force) {
            str = download(info->ai_family, info->ai_addr, info->ai_addrlen, request_version, sizeof(request_version) - 1, &len, 7);
            if(!str) {
                printf("version download failed\n");
                continue;
            }

            if(len != 7) {
                printf("invalid version length (%u)\n", len);
                free(str);
                continue;
            }

            if(str[6] != VERSION + '0') {
                printf("invalid updater version (%u)\n", str[6]);
                free(str);

                /* update the updater */
                memcpy(request + 8, "toxupdate", sizeof("toxupdate") - 1);
                data = download_signed_compressed(info->ai_family, info->ai_addr, info->ai_addrlen, request, sizeof(request) - 1, &len, 1024 * 1024 * 4, self_update_public_key);
                if(!data) {
                    printf("self update download failed\n");
                    break;
                }

                if(selfupdate(data, len)) {
                    printf("successful self update\n");
                    filename[0] = 0;
                }
                free(data);
                break;
            }

            if(str[5] == ' ') {
                str[5] = 0;
            } else {
                str[6] = 0;
            }

            strcpy(filename + sizeof(OS ARCH), str);
            printf("Version: %s\n", str);
            free(str);

            /* check if we already have this version */
            file = fopen(filename, "rb");
            if(file) {
                printf("Already up to date\n");
                fclose(file);
                break;
            }
        }

        data = download_signed_compressed(info->ai_family, info->ai_addr, info->ai_addrlen, request, sizeof(request) - 1, &len, 1024 * 1024 * 4, public_key);

        printf("Inflated size: %u\n", len);

        file = fopen(filename, "wb");
        if(!file) {
            printf("fopen failed\n");
            free(data);
            break;
        }

        rlen = fwrite(data, 1, len, file);
        fclose(file);
        if(rlen != len) {
            printf("write failed (%u)\n", rlen);
        }
        free(data);

        /* write the version to a file */
            file = fopen("version", "wb");
        if(file) {
            fwrite(filename + sizeof(OS ARCH), strlen(filename + sizeof(OS ARCH)), 1, file);
            fclose(file);
        }

        break;
    } while(info = info->ai_next);

    freeaddrinfo(root);
    system(filename);
    return 0;
}
