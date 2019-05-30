
#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdint.h>
// #include <stddef.h>


#define __DEBUG__ 1
#ifdef __DEBUG__
#define dlog(xx_fmt, ...) \
      do {                                 \
        printf(xx_fmt, ##__VA_ARGS__);     \
        printf("\n");                      \
      } while (0)
#else
#define dlog(xx_fmt, ...)
#endif

void random_bytes(uint16_t size, uint8_t* out);
uint32_t random32(void);
void print_hex(uint8_t* comment, uint8_t* hex, uint16_t len);
#endif