#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void MD5(unsigned char *dst, const unsigned char *src, unsigned int len);

static char *bin2hexstr(unsigned char *data, unsigned int len, char *buf)
{
    static const char hex[16]="0123456789abcdef";
    unsigned int i;
    char *p = buf;

    if (p == NULL)
        return 0;

    for (i = 0; i < len; i++) {
        p[i + i] = hex[data[i] >> 4];
        p[i + i + 1] = hex[data[i] & 0x0f];
    }
    p[i + i] = '\0';
    return(p);
}

void *md5sum_open(uint8_t channels)
{
  return 1;
}

void md5sum_write_flt(void *_ao, float *buf, uint32_t sz)
{
  unsigned char md5out[16];
  char md5str[33];
  MD5(md5out, (uint8_t*)buf, sz * sizeof(float));
  bin2hexstr(md5out, 16, md5str);
  md5str[32] = '\n';
  write(1, md5str, 33);
}

void md5sum_write_s16(void *_ao, int16_t *buf, uint32_t sz)
{
  unsigned char md5out[16];
  char md5str[33];
  MD5(md5out, (uint8_t*)buf, sz * sizeof(float));
  bin2hexstr(md5out, 16, md5str);
  md5str[32] = '\n';
  write(1, md5str, 33);
}

void md5sum_close(void *_ao)
{
}

