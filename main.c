#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <sodium.h>

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

#define GET_NAME "latest-" OS "-" ARCH
#define FILE_NAME "uTox" EXT
#define HOST "dl.utox.org"

static const uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES] = {
    0x88, 0x90, 0x5F, 0x29, 0x46, 0xBE, 0x7C, 0x4B, 0xBD, 0xEC, 0xE4, 0x67, 0x14, 0x9C, 0x1D, 0x78,
    0x48, 0xF4, 0xBC, 0x4F, 0xEC, 0x1A, 0xD1, 0xAD, 0x6F, 0x97, 0x78, 0x6E, 0xFE, 0xF3, 0xCD, 0xA1
};

static const char request[] =
    "GET /" GET_NAME " HTTP/1.0\r\n"
    "Host: " HOST "\r\n"
    "\r\n";

int main(void)
{
    char *str;
    void *data, *mdata;
    FILE *file;
    struct addrinfo *root, *info;
    uint32_t sock, len, dlen, rlen;
    unsigned long long mlen;
    uint8_t recvbuf[0x10000];
    _Bool header;

    #ifdef __WIN32__
    WSADATA wsaData;
    if(WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }
    #endif

    if(getaddrinfo(HOST, "80", NULL, &root) != 0) {
        printf("getaddrinfo failed\n");
        return 1;
    }

    info = root;
    do {
        printf("trying...\n");

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(sock == ~0) {
            printf("socket failed\n");
            continue;
        }

        if(connect(sock, info->ai_addr, info->ai_addrlen) != 0) {
            printf("connect failed\n");
            close(sock);
            continue;
        }

        send(sock, request, sizeof(request) - 1, 0);

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
                data = malloc(dlen * 2);
                if(!data) {
                    printf("malloc failed (1) (%u)\n", dlen);
                    break;
                }

                printf("Download size: %u\n", dlen);

                /* read the first piece */
                rlen = len - (str - (char*)recvbuf);
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
            free(data);
            continue;
        }

        mdata = data + dlen;
        if(crypto_sign_ed25519_open(mdata, &mlen, data, dlen, public_key) == -1) {
            printf("invalid signature\n");
            free(data);
            break;
        }

        file = fopen(FILE_NAME, "wb");
        if(!file) {
            printf("fopen failed\n");
            free(data);
            break;
        }

        rlen = fwrite(mdata, 1, mlen, file);
        fclose(file);
        if(rlen != mlen) {
            printf("write failed (%u)\n", rlen);
        }
        free(data);
        break;
    } while(info = info->ai_next);

    freeaddrinfo(root);
    return 0;
}
