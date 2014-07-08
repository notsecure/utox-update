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

static const uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES] = {
    0x88, 0x90, 0x5F, 0x29, 0x46, 0xBE, 0x7C, 0x4B, 0xBD, 0xEC, 0xE4, 0x67, 0x14, 0x9C, 0x1D, 0x78,
    0x48, 0xF4, 0xBC, 0x4F, 0xEC, 0x1A, 0xD1, 0xAD, 0x6F, 0x97, 0x78, 0x6E, 0xFE, 0xF3, 0xCD, 0xA1
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

int main(void)
{
    char *str;
    void *data, *mdata;
    FILE *file;
    struct addrinfo *root, *info;
    uint32_t sock, len, dlen, rlen;
    unsigned long long mlen;
    uint8_t recvbuf[0x10000];
    _Bool header, force = 0;

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

    if(getaddrinfo(HOST, "80", NULL, &root) != 0) {
        printf("getaddrinfo failed\n");
        return 1;
    }

    info = root;
    do {
        printf("trying...\n");

        sock = socket(info->ai_family, SOCK_STREAM, IPPROTO_TCP);
        if(sock == ~0) {
            printf("socket failed (1)\n");
            continue;
        }

        if(connect(sock, info->ai_addr, info->ai_addrlen) != 0) {
            printf("connect failed (1)\n");
            close(sock);
            continue;
        }

        /* check if new version is available */
        if(!force) {
            if(send(sock, request_version, sizeof(request_version) - 1, 0) != sizeof(request_version) - 1) {
                printf("send failed (1)\n");
                close(sock);
                continue;
            }

            len = recv(sock, recvbuf, 0xFFFF, 0);
            close(sock);

            if(len <= 0) {
                printf("no/empty response\n");
                continue;
            }

            /* work with a null-terminated buffer */
            recvbuf[len] = 0;

            /* find the end of the http response header */
            str = strstr((char*)recvbuf, "\r\n\r\n");
            if(!str) {
                printf("invalid HTTP response (3)\n");
                continue;
            }

            str += sizeof("\r\n\r\n") - 1;

            /* check for valid version string */
            if(strlen(str) > 6) {
                printf("invalid version string\n");
                continue;
            }

            strcpy(filename + sizeof(OS ARCH), str);
            printf("Version: %s\n", str);

            /* check if we already have this version */
            file = fopen(filename, "rb");
            if(file) {
                printf("Already up to date\n");
                fclose(file);
                break;
            }

            /* reconnect for download */
            sock = socket(info->ai_family, SOCK_STREAM, IPPROTO_TCP);
            if(sock == ~0) {
                printf("socket failed (2)\n");
                continue;
            }

            if(connect(sock, info->ai_addr, info->ai_addrlen) != 0) {
                printf("connect failed (2) \n");
                close(sock);
                continue;
            }
        }

        if(send(sock, request, sizeof(request) - 1, 0) != sizeof(request) - 1) {
            printf("send failed (2)\n");
            close(sock);
            continue;
        }

        header = 1;
        while((len = recv(sock, recvbuf, 0xFFFF, 0)) > 0) {
            if(header) {
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
                if(dlen < crypto_sign_ed25519_BYTES) {
                    printf("invalid length\n");
                    break;
                }

                /* find the end of the http response header */
                str = strstr(str, "\r\n\r\n");
                if(!str) {
                    printf("invalid HTTP response (2)\n");
                    break;
                }

                str += sizeof("\r\n\r\n") - 1;

                /* allocate buffer to read into + make room for signature checking (times 2) */
                mdata = malloc(dlen * 2);
                if(!mdata) {
                    printf("malloc failed (1) (%u)\n", dlen);
                    break;
                }

                printf("Download size: %u\n", dlen);

                /* read the first piece */
                rlen = len - (str - (char*)recvbuf);
                data = mdata + dlen;
                memcpy(data, str, rlen);

                header = 0;
                continue;
            }
            memcpy(data + rlen, recvbuf, len); rlen += len;
        }

        close(sock);
        if(header) {
            /* read nothing or invalid header */
            printf("error...\n");
            continue;
        } else if(rlen != dlen) {
            printf("number of bytes read does not match (%u)\n", rlen);
            free(mdata);
            continue;
        }

        /* check signature */
        if(crypto_sign_ed25519_open(mdata, &mlen, data, dlen, public_key) == -1) {
            printf("invalid signature\n");
            free(mdata);
            break;
        }

        time_t now;
        uint32_t t;
        time(&now);
        memcpy(&t, mdata, 4);

        printf("built %u, now %u\n", t, now);

        if(t < now && now - t >= 60 * 24 * 7) {
            /* build is more than 1 week old: expired */
            printf("expired build (%u)\n", now - t);
            free(mdata);
            break;
        }

        /* inflate (todo: not constant size) */
#define SIZE 4 * 1024 * 1024
        data = malloc(SIZE);
        if(!data) {
            printf("malloc failed (2) (%u)\n", SIZE);
            free(mdata);
            break;
        }

        len = inflate(data, mdata + 4, SIZE, mlen - 4);
#undef SIZE
        free(mdata);
        if(len == 0) {
            printf("inflate failed\n");
            free(data);
            break;
        }

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
        break;
    } while(info = info->ai_next);

    freeaddrinfo(root);
    system(filename);
    return 0;
}
