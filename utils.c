#include "utils.h"

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

void* checksignature(void *data, uint32_t dlen, const uint8_t *self_public_key, unsigned long long *downloaded_len)
{
    void *mdata;
    int r;

    mdata = malloc(dlen);
    if(!mdata) {
        printf("malloc failed\n");
        free(data);
        return NULL;
    }

    r = crypto_sign_ed25519_open(mdata, downloaded_len, data, dlen, self_public_key);
    free(data);

    if(r == -1) {
        printf("invalid signature\n");
        free(mdata);
        return NULL;
    }

    return mdata;
}


void* download(char *host, size_t host_len, char *request, uint16_t request_len, uint32_t *downloaded_length, uint32_t downloaded_len_max)
{
    uint32_t sock, len, rlen, dlen;
    char *data = 0;
    _Bool header = 0;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sock == ~0) {
        printf("socket failed\n");
        return NULL;
    }

	struct hostent *host_ent;
	host_ent = gethostbyname(host);

	if (!host_ent)
		return NULL;

	SOCKADDR_IN sock_addr;
	sock_addr.sin_port = htons(80);
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_addr.s_addr = *((unsigned long*)host_ent->h_addr);

	if (connect(sock, (SOCKADDR*)(&sock_addr), sizeof(sock_addr)) != 0) {
        printf("connect failed\n");
        close(sock);
        return NULL;
    }

    if(send(sock, request, request_len, 0) != request_len) {
        printf("send failed\n");
        close(sock);
        return NULL;
    }

    while((len = recv(sock, (char*)recvbuf, 0xFFFF, 0)) > 0) {
        if(!header) {
            /* work with a null-terminated buffer */
            recvbuf[len] = 0;

            /* check for "Not Found" response (todo: only check first line of response)*/
            if(strstr((char*)recvbuf, "404 Not Found\r\n")) {
                printf("Not Found\n");
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
            if(dlen > downloaded_len_max) {
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

        /* check if received too much */
        if(rlen + len > dlen) {
            printf("bad download\n");
            break;
        }

        memcpy(data + rlen, recvbuf, len); rlen += len;
		set_download_progress((rlen * 100) / dlen);
    }

    close(sock);

    if(!header) {
        /* read nothing or invalid header */
        printf("download() failed\n");
        return NULL;
    } else if(rlen != dlen) {
        printf("number of bytes read does not match (%u)\n", rlen);
        free(data);
        return NULL;
    }

	*downloaded_length = dlen;
    return data;
}

void* download_signed(char *host, size_t host_len, char *request, uint16_t request_len, uint32_t *downloaded_len, uint32_t downloaded_len_max, const uint8_t *self_public_key)
{
    void *data, *mdata;
    uint32_t len, t;
    time_t now;
    unsigned long long mlen;

    data = download(host, host_len, request, request_len, &len, downloaded_len_max + crypto_sign_ed25519_BYTES);
    if(!data) {
        return NULL;
    }

    mdata = checksignature(data, len, self_public_key, &mlen);
    if(!mdata) {
        return NULL;
    }

    time(&now);
    memcpy(&t, mdata, 4);

    printf("signed %u, now %u\n", (uint32_t)t, (uint32_t)now);

    if(t < now && now - t >= 60 * 60 * 24 * 8) {
        /* build is more than 1 week old: expired */
        printf("expired signature (%u)\n", (uint32_t)(now - t));
        free(mdata);
        return NULL;
    }

    *downloaded_len = mlen;
    return mdata;
}

void* download_signed_compressed(void *host, size_t host_len, char *REQUEST, uint16_t request_len, uint32_t *downloaded_len, uint32_t downloaded_len_max, const uint8_t *self_public_key)
{
    char *data, *mdata;
    uint32_t len, mlen;

    mdata = download_signed(host, host_len, REQUEST, request_len, &mlen, downloaded_len_max, self_public_key);
    if(!mdata) {
        printf("file download failed\n");
        return NULL;
    }

    /* inflate */
    data = malloc(downloaded_len_max);
    if(!data) {
        printf("malloc failed (2) (%u)\n", downloaded_len_max);
        free(mdata);
        return NULL;
    }

    len = inflate(data, mdata + 4, downloaded_len_max, mlen - 4);
    free(mdata);
    if(len == 0) {
        printf("inflate failed\n");
        free(data);
        return NULL;
    }

    *downloaded_len = len;
    return data;
}
