#include <stdint.h>
#include <string.h>

uint32_t inflate(void *dest, void *src, uint32_t dest_size, uint32_t src_len)
{
    memcpy(dest, src, src_len);
    return src_len;
}
