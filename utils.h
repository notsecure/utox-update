#ifndef TOX_UTILS
#define TOX_UTILS

#include <winsock2.h>
#include <ws2tcpip.h>
#define close(x) closesocket(x)

#define SODIUM_STATIC
#include <sodium.h>

#include "xz/xz.h"

#define UPDATE_EXPIRE_DAYS 9

void *download_loop_all_host_ips(_Bool compressed, const char *hosts[], size_t number_hosts, const char *filename, size_t filename_len, uint32_t *downloaded_len, uint32_t downloaded_len_max, const uint8_t *self_public_key, const uint8_t *cmp_end_file, size_t cmp_end_file_len);

#endif