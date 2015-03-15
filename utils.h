#ifndef TOX_UTILS
#define TOX_UTILS

#include <winsock2.h>
#define close(x) closesocket(x)

#define SODIUM_STATIC
#include <sodium.h>

#include "xz/xz.h"

uint32_t inflate(void *dest, void *src, uint32_t dest_size, uint32_t src_len);

void* checksignature(void *data, uint32_t dlen, const uint8_t *pk, unsigned long long *olen);

void* download(char *host, size_t host_len, char *request, uint16_t request_len, uint32_t *downloaded_length, uint32_t downloaded_len_max);

void* download_signed(char *host, size_t host_len, char *request, uint16_t request_len, uint32_t *downloaded_len, uint32_t downloaded_len_max, const uint8_t *self_public_key);

void* download_signed_compressed(void *host, size_t host_len, char *REQUEST, uint16_t request_len, uint32_t *downloaded_len, uint32_t downloaded_len_max, const uint8_t *self_public_key);

#endif