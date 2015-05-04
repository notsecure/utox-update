#ifndef TOX_UTILS
#define TOX_UTILS

#define UPDATE_EXPIRE_DAYS 9

FILE* LOG_FILE;
#define LOG_TO_FILE(...) (LOG_FILE ? fprintf(LOG_FILE, __VA_ARGS__) : -1)

/* in main.c */
void set_download_progress(int progress);

void *download_loop_all_host_ips(_Bool compressed, const char *hosts[], size_t number_hosts, const char *filename, size_t filename_len, uint32_t *downloaded_len, uint32_t downloaded_len_max, const uint8_t *self_public_key, const char *cmp_end_file, size_t cmp_end_file_len);

#endif